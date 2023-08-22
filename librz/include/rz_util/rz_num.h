#ifndef RZ_NUM_H
#define RZ_NUM_H

#include <rz_list.h>
#include <rz_vector.h>
#include <rz_util/rz_big.h>
#include <rz_util/rz_bitvector.h>
#include <rz_util/rz_strbuf.h>
#include <rz_util/ht_sp.h>

#define RZ_NUMCALC_STRSZ 1024

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Kind of value held by an RzNumValue.
 *
 * Most expressions evaluate to a simple ut64. The other kinds are produced
 * when the source expression makes the wider precision or representation
 * explicit - for example a literal that exceeds 64 bits, an explicit
 * fractional part, or a bit-vector with an explicit width.
 */
typedef enum {
	RZ_NUM_KIND_NONE = 0, ///< default / uninitialised
	RZ_NUM_KIND_UT64, ///< ordinary 64-bit unsigned integer
	RZ_NUM_KIND_BIG, ///< arbitrary-precision integer, see RzNumBig
	RZ_NUM_KIND_BITVECTOR, ///< fixed-width bit-vector, see RzBitVector
	RZ_NUM_KIND_FLOAT, ///< IEEE-754 float, currently double-precision
} RzNumKind;

/**
 * \brief Tagged-union value produced by the RzNum evaluator.
 *
 * For RZ_NUM_KIND_BIG and RZ_NUM_KIND_BITVECTOR, the union member is a
 * pointer owned by this RzNumValue (RzNumBig's underlying representation
 * depends on the configured crypto backend and RzBitVector owns a
 * heap-allocated payload, so neither can portably be stored by value).
 * RZ_NUM_KIND_FLOAT carries a plain double for now; extended-precision
 * IEEE-754 values (via RzFloat) will be added in follow-up work as new
 * kinds rather than overloading this one.
 */
/**
 * \brief Reasons an evaluation can fail.
 *
 * Encoded out-of-band on RzNumValue.err so that callers can dispatch
 * on the error category without parsing a human-readable string. The
 * string form is still available via the optional error_msg out-
 * parameter on rz_num_math_value() for diagnostic output, but new
 * code should switch on .err.
 *
 * The categories are deliberately coarse: a single error code does
 * not pin down the exact source token, only the nature of the
 * problem. The text in error_msg carries that detail when it matters.
 */
typedef enum {
	RZ_NUM_ERR_OK = 0, ///< no error
	RZ_NUM_ERR_PARSE, ///< syntactic problem: unbalanced parens, unexpected token, ...
	RZ_NUM_ERR_EMPTY, ///< the input was empty or whitespace only
	RZ_NUM_ERR_RESERVED_WORD, ///< a reserved word was used as a bare variable
	RZ_NUM_ERR_UNDEFINED_VAR, ///< a special variable was not found in the host's table
	RZ_NUM_ERR_DIV_ZERO, ///< / or % with a zero divisor
	RZ_NUM_ERR_OVERFLOW, ///< a literal exceeded the supported precision
	RZ_NUM_ERR_TYPE_MISMATCH, ///< operands incompatible (e.g. rotate on a bignum)
	RZ_NUM_ERR_TIMEOUT, ///< evaluation exceeded the configured wall-clock budget
	RZ_NUM_ERR_UNCOMPUTABLE, ///< well-formed but mathematically undefined (log(<=0) etc.)
	RZ_NUM_ERR_NOT_IMPLEMENTED, ///< feature parsed but evaluator does not yet support it
	RZ_NUM_ERR_OUT_OF_MEMORY, ///< heap allocation failed
} RzNumError;

/**
 * \brief Tagged-union value produced by the RzNum evaluator.
 *
 * For RZ_NUM_KIND_BIG and RZ_NUM_KIND_BITVECTOR, the union member is a
 * pointer owned by this RzNumValue (RzNumBig's underlying representation
 * depends on the configured crypto backend and RzBitVector owns a
 * heap-allocated payload, so neither can portably be stored by value).
 * RZ_NUM_KIND_FLOAT carries a plain double for now; extended-precision
 * IEEE-754 values (via RzFloat) will be added in follow-up work as new
 * kinds rather than overloading this one.
 *
 * The `err` field carries an RzNumError out-of-band. A value with
 * err != RZ_NUM_ERR_OK is still required to be a valid RzNumValue
 * (well-formed kind+val) so that callers can release it with
 * rz_num_value_fini() unconditionally; on error the payload is
 * typically RZ_NUM_KIND_UT64 / 0 but consumers must not rely on that.
 */
typedef struct rz_num_value_t {
	RzNumKind kind;
	RzNumError err;
	union {
		ut64 n; ///< valid when kind == RZ_NUM_KIND_UT64
		double d; ///< valid when kind == RZ_NUM_KIND_FLOAT
		RzNumBig *big; ///< valid when kind == RZ_NUM_KIND_BIG (owned)
		RzBitVector *bv; ///< valid when kind == RZ_NUM_KIND_BITVECTOR (owned)
	} val;
} RzNumValue;

/**
 * \brief Initialise an RzNumValue to RZ_NUM_KIND_NONE / RZ_NUM_ERR_OK.
 */
static inline void rz_num_value_init(RzNumValue *v) {
	if (!v) {
		return;
	}
	v->kind = RZ_NUM_KIND_NONE;
	v->err = RZ_NUM_ERR_OK;
	v->val.n = 0;
}

/**
 * \brief Project an RzNumValue to a ut64.
 *
 * UT64 values pass through unchanged. FLOAT truncates toward zero.
 * BIG truncates to the low 64 bits (matching a C narrowing cast);
 * the full value remains accessible on the RzNumValue itself.
 * NONE / BITVECTOR project to 0.
 *
 * \param v The value to project. Must be non-NULL.
 * \return The ut64 projection.
 */
static inline ut64 rz_num_value_to_ut64(const RzNumValue *v) {
	if (!v) {
		return 0;
	}
	switch (v->kind) {
	case RZ_NUM_KIND_UT64:
		return v->val.n;
	case RZ_NUM_KIND_FLOAT:
		return (ut64)v->val.d;
	case RZ_NUM_KIND_BIG:
		return (ut64)rz_big_to_int(v->val.big);
	case RZ_NUM_KIND_BITVECTOR:
		return v->val.bv ? rz_bv_to_ut64(v->val.bv) : 0;
	default:
		return 0;
	}
}


/**
 * \brief Project an RzNumValue to a double.
 *
 * Mirrors the floating value that the legacy rz_num_math() kept in
 * num->fvalue. A UT64 is read as a *signed* st64 so the projection
 * matches the signed int32/int64 line of the `%` breakdown (e.g.
 * 0xffffffffffffffff projects to -1.0, not ~1.8e19). FLOAT passes
 * through; BIG and BITVECTOR project their value (BIG via the same
 * low-64-bit narrowing as rz_num_value_to_ut64()).
 *
 * \param v The value to project. Must be non-NULL.
 * \return The double projection.
 */
static inline double rz_num_value_to_double(const RzNumValue *v) {
	if (!v) {
		return 0.0;
	}
	switch (v->kind) {
	case RZ_NUM_KIND_UT64:
		return (double)(st64)v->val.n;
	case RZ_NUM_KIND_FLOAT:
		return v->val.d;
	case RZ_NUM_KIND_BIG:
		return v->val.big ? (double)rz_big_to_int(v->val.big) : 0.0;
	case RZ_NUM_KIND_BITVECTOR:
		return v->val.bv ? (double)rz_bv_to_ut64(v->val.bv) : 0.0;
	default:
		return 0.0;
	}
}


/**
 * \brief Release any owned payload held by an RzNumValue.
 *
 * Safe to call on an RZ_NUM_KIND_NONE / RZ_NUM_KIND_UT64 / RZ_NUM_KIND_FLOAT
 * value. After the call the value is reset to RZ_NUM_KIND_NONE.
 */
static inline void rz_num_value_fini(RzNumValue *v) {
	if (!v) {
		return;
	}
	switch (v->kind) {
	case RZ_NUM_KIND_BIG:
		rz_big_free(v->val.big);
		break;
	case RZ_NUM_KIND_BITVECTOR:
		rz_bv_free(v->val.bv);
		break;
	default:
		break;
	}
	v->kind = RZ_NUM_KIND_NONE;
	v->err = RZ_NUM_ERR_OK;
	v->val.n = 0;
}

typedef struct {
	double d;
	ut64 n;
} RzNumCalcValue;

typedef enum {
	RNCNAME,
	RNCNUMBER,
	RNCEND,
	RNCINC,
	RNCDEC,
	RNCLT, // comparison operator <
	RNCGT, // comparison operator >
	RNCPLUS = '+',
	RNCMINUS = '-',
	RNCMUL = '*',
	RNCEXP = 'E',
	RNCDIV = '/',
	RNCMOD = '%',
	// RNCXOR='^', RNCOR='|', RNCAND='&',
	RNCNEG = '~',
	RNCAND = '&',
	RNCORR = '|',
	RNCXOR = '^',
	RNCPRINT = ';',
	RNCASSIGN = '=',
	RNCLEFTP = '(',
	RNCRIGHTP = ')',
	RNCSHL = '<',
	RNCSHR = '>',
	RNCROL = '#',
	RNCROR = '$'
} RzNumCalcToken;

typedef struct rz_num_calc_t {
	RzNumCalcToken curr_tok;
	RzNumCalcValue number_value;
	char string_value[RZ_NUMCALC_STRSZ];
	int errors;
	char oc;
	const char *calc_err;
	int calc_i;
	const char *calc_buf;
	int calc_len;
	bool under_calc;
} RzNumCalc;

typedef struct rz_num_t {
	ut64 (*callback)(struct rz_num_t *userptr, const char *str, int *ok);
	const char *(*cb_from_value)(struct rz_num_t *userptr, ut64 value, int *ok);
	//	RzNumCallback callback;
	ut64 value;
	double fvalue;
	void *userptr;
	int dbz; /// division by zero happened
	RzNumCalc nc;
	RZ_NULLABLE HtSP *expr_vars; ///< persistent RzNum expression variables, lazily created
} RzNum;

typedef ut64 (*RzNumCallback)(struct rz_num_t *self, const char *str, int *ok);
typedef const char *(*RzNumCallback2)(struct rz_num_t *self, ut64, int *ok);

RZ_API RzNum *rz_num_new(RzNumCallback cb, RzNumCallback2 cb2, void *ptr);
RZ_API void rz_num_free(RzNum *num);
RZ_API char *rz_num_units(char *buf, size_t len, ut64 number);
RZ_API int rz_num_conditional(RzNum *num, const char *str);
RZ_API ut64 rz_num_calc(RzNum *num, const char *str, const char **err);
RZ_API const char *rz_num_calc_index(RzNum *num, const char *p);
RZ_API int rz_num_is_valid_input(RzNum *num, const char *input_value);
RZ_API ut64 rz_num_get_input_value(RzNum *num, const char *input_value);
RZ_API char *rz_num_as_string(RzNum *___, ut64 n, bool printable_only);
RZ_API ut64 rz_num_tail(RzNum *num, ut64 addr, const char *hex);
RZ_API ut64 rz_num_tail_base(RzNum *num, ut64 addr, ut64 off);
RZ_API void rz_num_minmax_swap(ut64 *a, ut64 *b);
RZ_API void rz_num_minmax_swap_i(int *a, int *b); // XXX this can be a cpp macro :??
RZ_API ut64 rz_num_math_ut64(RzNum *num, const char *str);

/**
 * \brief Backwards-compatible wrapper around rz_num_math_ut64().
 *
 * New code should use rz_num_math_ut64() (or, once introduced,
 * rz_num_math_value() for typed evaluation).
 */
static inline ut64 rz_num_math(RzNum *num, const char *str) {
	return rz_num_math_ut64(num, str);
}

/**
 * \brief Result of a custom function or IO-read callback.
 *
 * Callbacks fill in a kind + payload (mirroring RzNumValue's union)
 * and set ok=false to signal an error, in which case the evaluator
 * surfaces RZ_NUM_ERR_UNCOMPUTABLE with the optional message.
 *
 * Big-number and bit-vector payloads returned here transfer
 * ownership to the evaluator, which will release them via
 * rz_num_value_fini() in the normal course of evaluation.
 */
typedef struct rz_num_callback_result_t {
	bool ok; ///< false => evaluation error
	RzNumKind kind; ///< kind of the value on success
	union {
		ut64 n;
		double d;
		RzNumBig *big;
		RzBitVector *bv;
	} val;
} RzNumCallbackResult;

/**
 * \brief Signature of a user-registered expression function.
 *
 * \param user   The opaque pointer supplied at registration time.
 * \param args   Evaluated argument values (read-only).
 * \param argc   Number of arguments actually supplied.
 * \param out    Out-parameter for the result.
 */
typedef void (*RzNumFuncCallback)(void *user, const RzNumValue *args,
	int argc, RzNumCallbackResult *out);

/**
 * \brief Callback that reads raw bytes from the host's memory layer
 *        for an address-typed dereference.
 *
 * Invoked for `<addr>:le32`, `<addr>:be64`, `<addr>:s32`, `<addr>:f64`,
 * `<addr>:128`, `<addr>:f128`, etc. The evaluator decodes the bytes
 * into the appropriate kind itself (endian swap, sign-extension for
 * `:sN`, IEEE-754 decode for `:fN`, two-qword assembly for `:128` /
 * `:f128`), so the callback simply hands back the requested bytes.
 *
 * The signature is intentionally identical to RzPfReadAtCb in
 * <rz_pf.h>, so a single host-side function can serve both
 * subsystems and the core's IO bridge is not duplicated.
 *
 * If no callback is registered the evaluator returns the literal
 * address unchanged (the legacy parser's behaviour).
 *
 * \param user  The opaque pointer supplied alongside the callback.
 * \param addr  The address to read from.
 * \param buf   Destination buffer of at least \p len bytes.
 * \param len   Number of bytes to read.
 * \return      The number of bytes actually written into \p buf
 *              (>= 0). A return < \p len signals a short read; the
 *              evaluator treats it as RZ_NUM_ERR_UNCOMPUTABLE.
 */
typedef int (*RzNumIOReadCallback)(void *user, ut64 addr, ut8 *buf, int len);

/**
 * \brief A named, registrable expression function.
 *
 * Held in an RzNumFuncRegistry. Arity -1 means variadic.
 */
typedef struct rz_num_func_entry_t {
	char *name; ///< owned UTF-8 name
	int arity; ///< exact arg count, or -1 for variadic
	RzNumFuncCallback fn; ///< dispatcher
	void *user; ///< opaque, passed to fn
} RzNumFuncEntry;

/**
 * \brief A set of user-registered expression functions.
 *
 * Created with rz_num_func_registry_new(), populated with
 * rz_num_func_registry_add(), and passed to the evaluator through
 * RzNumMathOptions.funcs. The evaluator consults the registry
 * *before* its own built-in table, so a registered function can
 * shadow a built-in of the same name.
 */
typedef struct rz_num_func_registry_t {
	RzPVector /*<RzNumFuncEntry *>*/ entries;
} RzNumFuncRegistry;

/**
 * \brief Allocate an empty function registry.
 * \return A new registry, or NULL on allocation failure. Free with
 *         rz_num_func_registry_free().
 */
RZ_API RZ_OWN RzNumFuncRegistry *rz_num_func_registry_new(void);

/**
 * \brief Free a function registry and all entries it owns.
 * \param reg The registry to free. NULL is accepted and ignored.
 */
RZ_API void rz_num_func_registry_free(RZ_NULLABLE RzNumFuncRegistry *reg);

/**
 * \brief Register a function in the registry.
 *
 * \param reg    The registry. Must be non-NULL.
 * \param name   Function name (copied). Must be non-NULL.
 * \param arity  Exact argument count, or -1 for variadic.
 * \param fn     Dispatcher. Must be non-NULL.
 * \param user   Opaque pointer passed to \p fn on every call.
 * \return true on success, false on allocation failure.
 */
RZ_API bool rz_num_func_registry_add(RZ_NONNULL RzNumFuncRegistry *reg,
	RZ_NONNULL const char *name, int arity,
	RZ_NONNULL RzNumFuncCallback fn, RZ_NULLABLE void *user);

/**
 * \brief Optional configuration for rz_num_math_value_ex().
 *
 * All fields default to zero/NULL, which means "no limit / standard
 * behaviour". A non-zero timeout_ms is checked at each node of the
 * evaluator's tree walk; if exceeded, RZ_NUM_ERR_TIMEOUT is
 * returned. funcs, if set, supplies user-registered functions that
 * take precedence over the built-ins. io_read, if set, backs the
 * typed-address dereference syntax. vars, if set, is a caller-owned
 * variable store (string name -> RzNumValue*) that PERSISTS across
 * calls: bindings made by `x = expr` / `let x = expr` are written
 * into it and remain visible to later evaluations sharing the same
 * store. When NULL, bindings are confined to a single evaluation.
 */
typedef struct rz_num_math_options_t {
	ut64 timeout_ms; ///< wall-clock budget, 0 = unlimited
	RZ_NULLABLE RzNumFuncRegistry *funcs; ///< extra functions, may be NULL
	RZ_NULLABLE RzNumIOReadCallback io_read; ///< typed-address reader, may be NULL
	void *io_read_user; ///< opaque passed to io_read
	RZ_NULLABLE HtSP *vars; ///< persistent variable store, may be NULL
} RzNumMathOptions;

/**
 * \brief Evaluate a numerical expression with full type awareness.
 *
 * Unlike rz_num_math_ut64() this entry point reports the kind of the
 * result (ut64 / float / bit-vector / big number). Out-of-band errors
 * are reported through \p error_msg (which the caller must free).
 *
 * \param num         Optional RzNum instance (used for the variable
 *                    resolution callback). May be NULL.
 * \param expr        The expression to evaluate. Must be non-NULL.
 * \param out_value   Out-parameter receiving the evaluated value.
 *                    The caller must finalise it with
 *                    rz_num_value_fini() once done.
 * \param error_msg   Optional out-parameter. If non-NULL and a parse
 *                    or evaluation error occurs, set to an owned
 *                    diagnostic string.
 * \return true on success, false on parse or evaluation error.
 */
RZ_API bool rz_num_math_value(RZ_NULLABLE RzNum *num, RZ_NONNULL const char *expr,
	RZ_OUT RZ_NONNULL RzNumValue *out_value, RZ_OUT RZ_NULLABLE char **error_msg);

/**
 * \brief Same as rz_num_math_value() but accepts an options struct.
 *
 * Use this entry point when you need to set a wall-clock evaluation
 * timeout. Passing NULL for \p options is equivalent to calling
 * rz_num_math_value().
 */
RZ_API bool rz_num_math_value_ex(RZ_NULLABLE RzNum *num, RZ_NONNULL const char *expr,
	RZ_NULLABLE const RzNumMathOptions *options,
	RZ_OUT RZ_NONNULL RzNumValue *out_value, RZ_OUT RZ_NULLABLE char **error_msg);

/**
 * \brief Create a persistent variable store for rz_num_math_value_ex().
 *
 * Pass the returned handle via RzNumMathOptions.vars to make variable
 * bindings (`x = expr`, `let x = expr`) survive across evaluations.
 * Free it with rz_num_value_store_free(). Returns NULL on allocation
 * failure.
 */
RZ_API RZ_OWN HtSP *rz_num_value_store_new(void);

/**
 * \brief Free a variable store created by rz_num_value_store_new().
 */
RZ_API void rz_num_value_store_free(RZ_NULLABLE HtSP *store);

/**
 * \brief Options controlling how an RzNumValue is rendered.
 *
 * Extensible for future formatting knobs; today it carries a single
 * flag selecting a Unicode-enriched layout for kinds that benefit
 * from it (currently bit-vectors, which gain a subscript width
 * annotation matching the RzIL Unicode export).
 */
typedef struct rz_num_print_options_t {
	bool utf8; ///< when true, use Unicode glyphs where applicable
} RzNumPrintOptions;

/**
 * \brief Format an RzNumValue into a multi-representation textual block.
 *
 * Each kind produces a different layout:
 *   UT64       hex / dec (signed + unsigned) / octal / binary /
 *              IEC byte unit / segment:offset / character form
 *   FLOAT      decimal scientific / shortest / hex bit pattern
 *   BIG        decimal + hex (lossless)
 *   BITVECTOR  bit-width / hex / binary
 *
 * On a value with v->err != RZ_NUM_ERR_OK, a single 'error <category>'
 * line is appended instead. The caller owns the RzStrBuf and is
 * responsible for releasing it.
 *
 * \param v   The value to format. Must be a valid (initialised)
 *            RzNumValue.
 * \param sb  Destination buffer. Must be non-NULL.
 */
RZ_API void rz_num_value_print(RZ_NONNULL const RzNumValue *v, RZ_NONNULL RzStrBuf *sb);

/**
 * \brief Like rz_num_value_print() but with explicit formatting options.
 *
 * With opts->utf8 set, a bit-vector additionally renders a compact
 * Unicode form (hex value with the bit-width as a subscript, e.g.
 * 0x2c\u2088), mirroring how RzIL renders bit-vectors in its Unicode
 * export. Other kinds are unaffected for now.
 *
 * \param v    The value to format. Must be a valid RzNumValue.
 * \param opts Formatting options. NULL selects the ASCII defaults.
 * \param sb   Destination buffer. Must be non-NULL.
 */
RZ_API void rz_num_value_print_ex(RZ_NONNULL const RzNumValue *v,
	RZ_NULLABLE const RzNumPrintOptions *opts, RZ_NONNULL RzStrBuf *sb);

/**
 * \brief Compact one-line stringification of an RzNumValue.
 *
 * Suitable for inline display where the multi-line print would be
 * too noisy. Returns a freshly-allocated, caller-owned string.
 * On error returns NULL.
 */
RZ_API RZ_OWN char *rz_num_value_tostring(RZ_NONNULL const RzNumValue *v);

/**
 * \brief Human-readable name of an RzNumError category.
 *
 * Stable string suitable for diagnostics. Returns "unknown" for
 * values outside the enum.
 */
RZ_API const char *rz_num_error_name(RzNumError err);

RZ_API ut64 rz_num_get(RZ_NULLABLE RzNum *num, RZ_NULLABLE const char *str);
RZ_API int rz_num_to_bits(char *out, ut64 num);
RZ_API int rz_num_to_trits(char *out, ut64 num); // Rename this please
RZ_API ut32 rz_num_rand32(ut32 max);
RZ_API ut64 rz_num_rand64(ut64 max);
RZ_API void rz_num_irand(void);
RZ_API ut64 rz_get_input_num_value(RzNum *num, const char *input_value);
RZ_API bool rz_is_valid_input_num_value(RzNum *num, const char *input_value);
RZ_API int rz_num_between(RzNum *num, const char *input_value);
RZ_API int rz_num_str_len(const char *str);
RZ_API int rz_num_str_split(char *str);
RZ_API RzList /*<char *>*/ *rz_num_str_split_list(char *str);
RZ_API void *rz_num_dup(ut64 n);
RZ_API size_t rz_num_base_of_string(RzNum *num, RZ_NONNULL const char *str);
RZ_API double rz_num_get_float(RzNum *num, const char *str);
RZ_API bool rz_num_is_hex_prefix(const char *p);

/**
 * \brief Base prefix of a numeric literal, as returned by rz_num_base_prefix().
 */
typedef enum {
	RZ_NUM_BASE_PREFIX_NONE = 0, ///< no prefix; plain decimal
	RZ_NUM_BASE_PREFIX_HEX, ///< 0x / 0X
	RZ_NUM_BASE_PREFIX_BINARY, ///< 0b / 0B
	RZ_NUM_BASE_PREFIX_OCTAL, ///< 0o / 0O
	RZ_NUM_BASE_PREFIX_TERNARY, ///< 0t / 0T
	RZ_NUM_BASE_PREFIX_OCTAL_C, ///< C style leading zero, e.g. 034
} RzNumBasePrefix;

RZ_API RzNumBasePrefix rz_num_base_prefix(RZ_NONNULL const char *p, RZ_NULLABLE RZ_OUT ut32 *base,
	RZ_NULLABLE RZ_OUT size_t *prefix_len);

/**
 * \brief Absolute value of a 64-bit number. Store result in `ut64`
 * \return unsigned 64-bit number
 */
static inline ut64 rz_num_abs(st64 num) {
	if (num == ST64_MIN) {
		return UT64_GT0;
	}
	return num < 0 ? -num : num;
}

/**
 * \brief Padding to align v to the next alignment-boundary.
 * \return the least `d` such that `(v + d) % alignment == 0`.
 */
static inline ut64 rz_num_align_delta(ut64 v, ut64 alignment) {
	if (!alignment) {
		return 0;
	}
	ut64 excess = v % alignment;
	if (!excess) {
		return 0;
	}
	return alignment - excess;
}

/**
 * \brief Get the 64-bit value that has exactly its \p width lowest bits set to 1.
 * e.g.
 *     rz_num_bitmask(2) == 0b11
 *     rz_num_bitmask(3) == 0b111
 *     ...
 */
static inline ut64 rz_num_bitmask(ut8 width) {
	if (width >= 64) {
		return 0xffffffffffffffffull;
	}
	return (1ull << (ut64)width) - 1;
}

#define CONVERT_TO_TWO_COMPLEMENT(x) \
	static inline st##x convert_to_two_complement_##x(ut##x value) { \
		if (value <= ST##x##_MAX) { \
			return (st##x)value; \
		} \
\
		value = ~value + 1; \
		return -(st##x)value; \
	}

CONVERT_TO_TWO_COMPLEMENT(8)
CONVERT_TO_TWO_COMPLEMENT(16)
CONVERT_TO_TWO_COMPLEMENT(32)
CONVERT_TO_TWO_COMPLEMENT(64)

/// Typical comparison (1/0/-1) for two numbers of arbitrary types, including unsigned
#define RZ_NUM_CMP(a, b) ((a) > (b) ? 1 : ((b) > (a) ? -1 : 0))

/**
 * Divide 2^64 by the given divisor
 *
 * Idea: https://stackoverflow.com/a/55584872
 * Proof: https://git.sr.ht/~thestr4ng3r/isa-bit-twiddling/tree/808253ab4d262f9e7dd7b87d0396f1afd7c5804b/item/Bit_Twiddling.thy#L26-43
 *
 * \param divisor must be non-zero
 */
static inline ut64 rz_num_2_pow_64_div(ut64 divisor) {
	return (-(st64)divisor) / divisor + 1;
}

#ifdef __cplusplus
}
#endif

#endif //  RZ_NUM_H
