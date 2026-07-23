// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Tree-walking evaluator for the RzNum expression language.
 *
 * Consumes the tree-sitter parse tree produced by parser.c and
 * computes a typed RzNumValue (ut64 / float / big number). Handles
 * the full operator set with bignum-aware arithmetic, built-in and
 * host-registered functions, the typed-address dereference syntax,
 * per-evaluation variable bindings, categorised errors, and an
 * optional wall-clock timeout. Also implements the public
 * rz_num_math_value* entry points and the RzNumFuncRegistry API.
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <rz_types.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_bits.h>
#include <rz_util/rz_hex.h>
#include <rz_util/rz_regex.h>
#include <rz_util/rz_time.h>
#include <rz_util/ht_sp.h>
#include <tree_sitter/api.h>

#include "parser.h"

// g_sym resolves to the shared grammar-symbol cache in parser.h, so this
// evaluator and the RzNumExpression builder dispatch on the same symbol IDs.
#define g_sym (*rz_num_parse_syms())

// Reserved words the grammar cannot forbid in variable position (see
// grammar.js). `let` is already reserved at the parser level.

static const char *const RESERVED_WORDS[] = {
	"mod", "log", "le", "be", "sdiv", "smod", "sar", NULL
};

static bool is_reserved_word(const char *s) {
	for (size_t i = 0; RESERVED_WORDS[i]; i++) {
		if (!strcmp(s, RESERVED_WORDS[i])) {
			return true;
		}
	}
	return false;
}

typedef struct {
	RzNum *num; ///< callback host
	const char *src; ///< source text
	char *err; ///< first error message
	RzNumError err_code; ///< category of the first error
	ut64 deadline_us; ///< monotonic wall-clock deadline; 0 = unlimited
	ut32 node_count; ///< nodes visited so far (used to amortise the clock check)
	ut32 depth; ///< current tree-walk recursion depth (bounded to keep deep nesting off the C stack)
	RZ_NULLABLE RzNumFuncRegistry *funcs; ///< user-registered functions
	RZ_NULLABLE RzNumIOReadCallback io_read; ///< typed-address reader
	void *io_read_user; ///< opaque for io_read
	RZ_NULLABLE HtSP *vars; ///< variable bindings `let x = y` / `x = y`
	bool vars_owned; ///< whether `vars` is this context's own store rather than the caller's persistent one
} EvalCtx;

// User-registered function registry

static void func_entry_free(void *p) {
	RzNumFuncEntry *e = (RzNumFuncEntry *)p;
	if (!e) {
		return;
	}
	free(e->name);
	free(e);
}

/**
 * \brief Allocate an empty function registry.
 * \return A new registry, or NULL on allocation failure. Free with
 *         rz_num_func_registry_free().
 */
RZ_API RZ_OWN RzNumFuncRegistry *rz_num_func_registry_new(void) {
	RzNumFuncRegistry *reg = RZ_NEW0(RzNumFuncRegistry);
	if (!reg) {
		return NULL;
	}
	rz_pvector_init(&reg->entries, func_entry_free);
	return reg;
}

/**
 * \brief Free a function registry and all entries it owns.
 */
RZ_API void rz_num_func_registry_free(RZ_NULLABLE RzNumFuncRegistry *reg) {
	if (!reg) {
		return;
	}
	rz_pvector_fini(&reg->entries);
	free(reg);
}

/**
 * \brief Register a function in the registry.
 *
 * \param reg    The registry.
 * \param name   Function name.
 * \param arity  Exact argument count, or -1 for variadic.
 * \param fn     Dispatcher.
 * \param user   Opaque pointer passed to \p fn on every call.
 * \return true on success, false on allocation failure.
 */
RZ_API bool rz_num_func_registry_add(RZ_NONNULL RzNumFuncRegistry *reg,
	RZ_NONNULL const char *name, int arity,
	RZ_NONNULL RzNumFuncCallback fn, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(reg && name && fn, false);
	RzNumFuncEntry *e = RZ_NEW0(RzNumFuncEntry);
	if (!e) {
		return false;
	}
	e->name = rz_str_dup(name);
	if (!e->name) {
		free(e);
		return false;
	}
	e->arity = arity;
	e->fn = fn;
	e->user = user;
	if (!rz_pvector_push(&reg->entries, e)) {
		func_entry_free(e);
		return false;
	}
	return true;
}

// Look up a user-registered function by name. Returns NULL if not
// found or if the registry is absent.
static const RzNumFuncEntry *func_registry_find(const RzNumFuncRegistry *reg,
	const char *name) {
	if (!reg) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (&reg->entries, it) {
		const RzNumFuncEntry *e = (const RzNumFuncEntry *)*it;
		if (e && e->name && !strcmp(e->name, name)) {
			return e;
		}
	}
	return NULL;
}

// Record an error. The first error wins: subsequent calls are
// no-ops so an evaluation that fails midway still reports the root
// cause rather than the cascade of follow-on failures.
static void set_err_code(EvalCtx *c, RzNumError code, const char *fmt, ...) {
	if (c->err) {
		return;
	}
	c->err_code = code;
	va_list ap;
	va_start(ap, fmt);
	va_list ap2;
	va_copy(ap2, ap);
	int n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0) {
		va_end(ap2);
		return;
	}
	char *buf = malloc((size_t)n + 1);
	if (!buf) {
		va_end(ap2);
		return;
	}
	vsnprintf(buf, (size_t)n + 1, fmt, ap2);
	va_end(ap2);
	c->err = buf;
}

// Slice the source text spanned by a node into a fresh heap buffer.
static char *node_text(TSNode node, const char *src) {
	uint32_t s = ts_node_start_byte(node);
	uint32_t e = ts_node_end_byte(node);
	uint32_t len = e - s;
	char *buf = malloc((size_t)len + 1);
	if (!buf) {
		return NULL;
	}
	memcpy(buf, src + s, len);
	buf[len] = '\0';
	return buf;
}

// Literal parsing

// A literal is float if it has '.' or an exponent marker. In hex, 'e'/'E'
// are digits, not exponents, so floatness there comes from '.' or 'p'/'P'.
static bool literal_is_float(const char *t) {
	size_t prefix_len = 0;
	if (rz_num_base_prefix(t, NULL, &prefix_len) == RZ_NUM_BASE_PREFIX_HEX) {
		// In a hex literal 'e' is a digit, so only a radix point or a
		// 'p' binary exponent makes it a float.
		return rz_regex_contains("[.pP]", t + prefix_len, RZ_REGEX_ZERO_TERMINATED,
			RZ_REGEX_DEFAULT, RZ_REGEX_DEFAULT);
	}
	return rz_regex_contains("[.eEpP]", t, RZ_REGEX_ZERO_TERMINATED,
		RZ_REGEX_DEFAULT, RZ_REGEX_DEFAULT);
}

// Parse an unsigned integer literal. Returns true on success. On
// ERANGE, sets *overflow=true so the caller can promote to bignum.
static bool parse_int_literal(const char *t, ut64 *out, bool *overflow, char **err) {
	const char *p = t;
	ut32 base = 10;
	size_t prefix_len = 0;
	// A C style leading zero reports prefix_len 0: the zero is an octal
	// digit, so strtoull() must still see it.
	rz_num_base_prefix(p, &base, &prefix_len);
	p += prefix_len;
	if (!*p) {
		if (err && !*err) {
			*err = rz_str_newf("empty integer literal: %s", t);
		}
		return false;
	}
	errno = 0;
	char *endp = NULL;
	unsigned long long v = strtoull(p, &endp, base);
	if (errno == ERANGE) {
		if (overflow) {
			*overflow = true;
		}
		return false;
	}
	if (endp == p) {
		if (err && !*err) {
			*err = rz_str_newf("not an integer: %s", t);
		}
		return false;
	}
	if (*endp != '\0') {
		// Trailing junk after the digit run: a digit not valid for the
		// detected base. This catches C-style octal with an out-of-range
		// digit (the '8' in 08 / 0187), which the permissive decimal
		// digit class in the grammar lets through to here. Leave *err
		// unset so the caller can categorise it as a parse error.
		return false;
	}
	*out = (ut64)v;
	return true;
}

static bool parse_float_literal(const char *t, double *out, char **err) {
	errno = 0;
	char *endp = NULL;
	double v = strtod(t, &endp);
	if (errno == ERANGE) {
		if (err && !*err) {
			*err = rz_str_newf("float literal out of range: %s", t);
		}
		return false;
	}
	if (endp == t) {
		if (err && !*err) {
			*err = rz_str_newf("not a float: %s", t);
		}
		return false;
	}
	*out = v;
	return true;
}

// SI / IEC byte unit multiplier. Mirrors what rz_num_units() prints
// on the output side, with the addition of PiB / PB and the decimal
// counterparts.
#define RZ_NUM_KIB (1ULL << 10)
#define RZ_NUM_MIB (1ULL << 20)
#define RZ_NUM_GIB (1ULL << 30)
#define RZ_NUM_TIB (1ULL << 40)
#define RZ_NUM_PIB (1ULL << 50)
#define RZ_NUM_EIB (1ULL << 60)
#define RZ_NUM_KB  1000ULL
#define RZ_NUM_MB  (RZ_NUM_KB * 1000)
#define RZ_NUM_GB  (RZ_NUM_MB * 1000)
#define RZ_NUM_TB  (RZ_NUM_GB * 1000)
#define RZ_NUM_PB  (RZ_NUM_TB * 1000)
#define RZ_NUM_EB  (RZ_NUM_PB * 1000)

static ut64 unit_multiplier(const char *u) {
	if (RZ_STR_EQ(u, "KiB")) {
		return RZ_NUM_KIB;
	}
	if (RZ_STR_EQ(u, "MiB")) {
		return RZ_NUM_MIB;
	}
	if (RZ_STR_EQ(u, "GiB")) {
		return RZ_NUM_GIB;
	}
	if (RZ_STR_EQ(u, "TiB")) {
		return RZ_NUM_TIB;
	}
	if (RZ_STR_EQ(u, "PiB")) {
		return RZ_NUM_PIB;
	}
	if (RZ_STR_EQ(u, "EiB")) {
		return RZ_NUM_EIB;
	}
	if (RZ_STR_EQ(u, "KB")) {
		return RZ_NUM_KB;
	}
	if (RZ_STR_EQ(u, "MB")) {
		return RZ_NUM_MB;
	}
	if (RZ_STR_EQ(u, "GB")) {
		return RZ_NUM_GB;
	}
	if (RZ_STR_EQ(u, "TB")) {
		return RZ_NUM_TB;
	}
	if (RZ_STR_EQ(u, "PB")) {
		return RZ_NUM_PB;
	}
	if (RZ_STR_EQ(u, "EB")) {
		return RZ_NUM_EB;
	}
	return 1;
}

// RzNumValue helpers

static RzNumValue val_u64(ut64 n) {
	RzNumValue v = { .kind = RZ_NUM_KIND_UT64 };
	v.val.n = n;
	return v;
}

static RzNumValue val_f64(double d) {
	RzNumValue v = { .kind = RZ_NUM_KIND_FLOAT };
	v.val.d = d;
	return v;
}

// val_bigdecimal transfers ownership of `d` into the returned value.
static RzNumValue val_bigdecimal(RzBigDecimal *d) {
	RzNumValue v = { .kind = RZ_NUM_KIND_BIGDECIMAL };
	v.val.bigdec = d;
	return v;
}

// Truthiness for the ternary's condition: a value is "true" when it
// is non-zero. Floats are tested as floats (so 0.0 is false but a
// tiny non-zero value is true) rather than via the integer
// projection, which would truncate 0.5 to 0. Big numbers and
// bit-vectors are true when any bit is set.
static bool value_is_truthy(const RzNumValue *v) {
	switch (v->kind) {
	case RZ_NUM_KIND_FLOAT:
		return v->val.d != 0.0;
	case RZ_NUM_KIND_BIGDECIMAL:
		return v->val.bigdec && !rz_big_decimal_is_zero(v->val.bigdec);
	case RZ_NUM_KIND_BIG:
		return v->val.big && !rz_big_is_zero(v->val.big);
	case RZ_NUM_KIND_BITVECTOR:
		return v->val.bv && !rz_bv_is_zero_vector(v->val.bv);
	case RZ_NUM_KIND_UT64:
		return v->val.n != 0;
	case RZ_NUM_KIND_NONE:
		return false;
	}
	return false;
}

// val_big transfers ownership of `b` into the returned RzNumValue.
// The caller must not free `b` afterwards.
static RzNumValue val_big(RzNumBig *b) {
	RzNumValue v = { .kind = RZ_NUM_KIND_BIG };
	v.val.big = b;
	return v;
}

// Build an RzNumValue from a successful RzNumCallbackResult, taking
// ownership of any BIG / BITVECTOR payload. Used by both the
// host-registered function path and the typed-address IO-read path.
static RzNumValue value_from_callback_result(const RzNumCallbackResult *res) {
	RzNumValue v = { .kind = res->kind, .err = RZ_NUM_ERR_OK };
	switch (res->kind) {
	case RZ_NUM_KIND_FLOAT:
		v.val.d = res->val.d;
		break;
	case RZ_NUM_KIND_BIG:
		v.val.big = res->val.big;
		break;
	case RZ_NUM_KIND_BITVECTOR:
		v.val.bv = res->val.bv;
		break;
	case RZ_NUM_KIND_UT64:
	default:
		v.val.n = res->val.n;
		break;
	}
	return v;
}

// Make a new RzNumBig holding the given ut64 value. NULL on
// allocation failure.
static RzNumBig *big_from_u64(ut64 n) {
	RzNumBig *b = rz_big_new();
	if (!b) {
		return NULL;
	}
	if (n <= (ut64)INT64_MAX) {
		rz_big_from_int(b, (st64)n);
	} else {
		// rz_big_from_int takes a signed value; for values that
		// don't fit in st64, build the bignum via a hex string.
		char buf[32];
		snprintf(buf, sizeof(buf), "%" PRIx64, n);
		rz_big_from_hexstr(b, buf);
	}
	return b;
}

// The default rz_big representation is a fixed RZ_BIG_ARRAY_SIZE words
// of RZ_BIG_WORD_SIZE bytes each, i.e. a hard ceiling on how wide a
// big number can be before it silently overflows. Anything at or
// above this many bits cannot be represented exactly.
#define RZ_BIG_MAX_BITS (RZ_BIG_ARRAY_SIZE * RZ_BIG_WORD_SIZE * 8)

// Significant bit width of an integer-kind value's *magnitude*. A
// ut64 with its top bit set is read as a negative st64, so its width
// is that of the absolute value, not of the two's-complement pattern
// (-76 is 7 bits, not 64). For a BIG operand the exact count is not
// exposed by rz_big, so we bound it from the hex-string length (each
// hex digit is at most 4 bits, and the leading '-' is skipped); this
// is an upper bound, which is exactly what the overflow guard needs.
static ut32 value_int_bit_width(const RzNumValue *v) {
	if (v->kind == RZ_NUM_KIND_UT64) {
		ut64 n = v->val.n;
		ut64 mag = ((st64)n < 0) ? (0 - n) : n; // |n|, INT64_MIN-safe
		return rz_bits_ut64_width(mag);
	}
	if (v->kind == RZ_NUM_KIND_BIG && v->val.big) {
		char *h = rz_big_to_hexstr(v->val.big);
		if (!h) {
			return RZ_BIG_MAX_BITS; // be conservative: treat as too wide
		}
		const char *p = h;
		if (p[0] == '-') {
			p++;
		}
		size_t prefix_len = 0;
		if (rz_num_base_prefix(p, NULL, &prefix_len) == RZ_NUM_BASE_PREFIX_HEX) {
			p += prefix_len;
		}
		ut32 bits = (ut32)strlen(p) * 4;
		free(h);
		return bits;
	}
	return 0;
}

// Parse a run of digits in the given base into a freshly-allocated
// RzNumBig. base must be one of {2, 8, 10, 16}; returns NULL on an
// invalid digit or allocation failure.
//
// This compensates for rz_big lacking a generic from-string parser:
// rz_big_from_hexstr is the only one, so for decimal/binary/octal/
// ternary literals that overflow ut64 we have to build the big
// number ourselves.
static RzNumBig *big_from_base(const char *digits, int base) {
	if (!digits || !*digits) {
		return NULL;
	}
	RzNumBig *acc = rz_big_new();
	RzNumBig *mul = rz_big_new();
	RzNumBig *digit = rz_big_new();
	RzNumBig *tmp = rz_big_new();
	if (!acc || !mul || !digit || !tmp) {
		rz_big_free(acc);
		rz_big_free(mul);
		rz_big_free(digit);
		rz_big_free(tmp);
		return NULL;
	}
	rz_big_from_int(acc, 0);
	rz_big_from_int(mul, base);
	for (const char *p = digits; *p; p++) {
		ut8 v = 0;
		if (rz_hex_to_byte(&v, (ut8)*p) || v >= base) {
			rz_big_free(acc);
			rz_big_free(mul);
			rz_big_free(digit);
			rz_big_free(tmp);
			return NULL;
		}
		// acc = acc * base + v
		rz_big_mul(tmp, acc, mul);
		rz_big_from_int(digit, v);
		rz_big_add(acc, tmp, digit);
	}
	rz_big_free(mul);
	rz_big_free(digit);
	rz_big_free(tmp);
	return acc;
}

// Make a new RzNumBig holding the same value as the given RzNumValue.
// NULL on allocation failure or on RZ_NUM_KIND_FLOAT (callers must
// project float to a numeric kind first via to_double / round).
static RzNumBig *value_to_big(const RzNumValue *v) {
	if (!v) {
		return NULL;
	}
	switch (v->kind) {
	case RZ_NUM_KIND_UT64:
		return big_from_u64(v->val.n);
	case RZ_NUM_KIND_BIG: {
		RzNumBig *dst = rz_big_new();
		if (!dst) {
			return NULL;
		}
		rz_big_assign(dst, v->val.big);
		return dst;
	}
	case RZ_NUM_KIND_FLOAT:
		return big_from_u64((ut64)v->val.d);
	case RZ_NUM_KIND_BIGDECIMAL:
		return big_from_u64(v->val.bigdec ? rz_big_decimal_to_ut64(v->val.bigdec) : 0);
	default:
		return rz_big_new();
	}
}

// New RzBigDecimal holding the same value (for exact decimal arithmetic).
// Integer kinds use their *signed* value, matching to_double()'s signed
// projection so e.g. 0.5 + (-1 as ut64) behaves the same in both paths.
static RzBigDecimal *value_to_bigdecimal(const RzNumValue *v) {
	if (!v) {
		return NULL;
	}
	switch (v->kind) {
	case RZ_NUM_KIND_BIGDECIMAL:
		return v->val.bigdec ? rz_big_decimal_dup(v->val.bigdec) : NULL;
	case RZ_NUM_KIND_UT64:
		return rz_big_decimal_new_from_int((st64)v->val.n);
	case RZ_NUM_KIND_BIG: {
		char *dec = v->val.big ? rz_big_to_decstr(v->val.big) : NULL;
		RzBigDecimal *d = dec ? rz_big_decimal_new_from_str(dec) : NULL;
		free(dec);
		return d;
	}
	case RZ_NUM_KIND_BITVECTOR:
		return rz_big_decimal_new_from_int((st64)(v->val.bv ? rz_bv_to_ut64(v->val.bv) : 0));
	case RZ_NUM_KIND_FLOAT: {
		// Defensive: decimal arithmetic never mixes in a raw double, but
		// if asked, round-trip through the double's shortest decimal.
		char buf[32];
		snprintf(buf, sizeof(buf), "%.17g", v->val.d);
		return rz_big_decimal_new_from_str(buf);
	}
	case RZ_NUM_KIND_NONE:
		return rz_big_decimal_new_from_int(0);
	}
	return rz_big_decimal_new_from_int(0);
}

static double to_double(const RzNumValue *v) {
	switch (v->kind) {
	case RZ_NUM_KIND_UT64:
		return (double)v->val.n;
	case RZ_NUM_KIND_FLOAT:
		return v->val.d;
	case RZ_NUM_KIND_BIG: {
		// Convert the whole magnitude, not just the low 64 bits: go
		// through the decimal string so the result is the nearest
		// double to the true value (and +/-inf when it exceeds the
		// double range), matching what float(2**100) would give.
		char *dec = rz_big_to_decstr(v->val.big);
		if (!dec) {
			return 0.0;
		}
		double d = strtod(dec, NULL);
		free(dec);
		return d;
	}
	case RZ_NUM_KIND_BITVECTOR:
		return v->val.bv ? (double)rz_bv_to_ut64(v->val.bv) : 0.0;
	case RZ_NUM_KIND_BIGDECIMAL:
		return v->val.bigdec ? rz_big_decimal_to_double(v->val.bigdec) : 0.0;
	case RZ_NUM_KIND_NONE:
		return 0.0;
	}
	return 0.0;
}

static ut64 to_u64(const RzNumValue *v) {
	switch (v->kind) {
	case RZ_NUM_KIND_UT64:
		return v->val.n;
	case RZ_NUM_KIND_FLOAT:
		return (ut64)to_double(v);
	case RZ_NUM_KIND_BIG:
		return (ut64)rz_big_to_int(v->val.big);
	case RZ_NUM_KIND_BITVECTOR:
		return v->val.bv ? rz_bv_to_ut64(v->val.bv) : 0;
	case RZ_NUM_KIND_BIGDECIMAL:
		return v->val.bigdec ? rz_big_decimal_to_ut64(v->val.bigdec) : 0;
	case RZ_NUM_KIND_NONE:
		return 0;
	}
	return 0;
}

// True when an integer-kind value represents a negative number: a
// ut64 is read as a two's-complement st64 (top bit set => negative),
// and a BIG carries its own sign. Float and bit-vector kinds are
// never treated as signed integers here.
static bool value_int_is_negative(const RzNumValue *v) {
	switch (v->kind) {
	case RZ_NUM_KIND_UT64:
		return (st64)v->val.n < 0;
	case RZ_NUM_KIND_BIG:
		return v->val.big && v->val.big->sign < 0;
	default:
		return false;
	}
}

// Signed-aware double projection. Identical to to_double() except that
// a ut64 with its top bit set is read as a negative st64 (so -2
// becomes -2.0, not ~1.8e19). Used by the operators whose result
// depends on operand sign (** with a negative base or exponent).
static double to_double_signed(const RzNumValue *v) {
	if (v->kind == RZ_NUM_KIND_UT64) {
		return (double)(st64)v->val.n;
	}
	return to_double(v);
}

// Signed-aware bignum construction. Like value_to_big() but a ut64
// with its top bit set becomes a negative bignum of the corresponding
// magnitude rather than a ~2^64 positive, so (-76) ** 2 squares 76,
// not 2^64-76. BIG operands already carry their sign.
static RzNumBig *value_to_big_signed(const RzNumValue *v) {
	if (v->kind == RZ_NUM_KIND_UT64) {
		RzNumBig *b = rz_big_new();
		if (b) {
			rz_big_from_int(b, (st64)v->val.n);
		}
		return b;
	}
	return value_to_big(v);
}

// Map a number suffix string to a bit-vector width, or 0 if the
// suffix carries no width (a bare letter run like "u" / "ul" / "f").
// The grammar guarantees the suffix is letters followed by an
// optional 8/16/32/64/128 tail.
// Largest bit-vector width an explicit suffix may request. Bounded so a
// typo like `1u99999999` fails cleanly instead of trying to allocate.
#define RZ_NUM_MAX_BV_WIDTH 65536

static ut32 bitvector_width_from_suffix(const char *suf, bool *has_width) {
	const char *p = suf;
	while (*p && !isdigit((ut8)*p)) {
		p++;
	}
	if (has_width) {
		*has_width = *p != '\0';
	}
	if (!*p) {
		return 0;
	}
	return (ut32)strtoul(p, NULL, 10);
}

// Make an RzNumValue of bit-vector kind holding the low \p width bits
// of \p src. Consumes (finalises) \p src. On allocation failure
// returns the source unchanged.
// Widen a big number's magnitude into a bit-vector. The hex string is
// the only exact accessor rz_big offers, so decode it a nibble at a
// time; bits above `width` are dropped, matching the ut64 path.
static RzBitVector *bitvector_from_big(RzNumBig *big, ut32 width) {
	char *hex = rz_big_to_hexstr(big);
	if (!hex) {
		return NULL;
	}
	RzBitVector *bv = rz_bv_new(width);
	if (!bv) {
		free(hex);
		return NULL;
	}
	const char *p = hex;
	if (*p == '-') {
		p++;
	}
	size_t prefix_len = 0;
	if (rz_num_base_prefix(p, NULL, &prefix_len) == RZ_NUM_BASE_PREFIX_HEX) {
		p += prefix_len;
	}
	size_t ndigits = strlen(p);
	for (size_t i = 0; i < ndigits; i++) {
		ut8 nib = 0;
		if (rz_hex_to_byte(&nib, (ut8)p[ndigits - 1 - i])) {
			continue;
		}
		for (ut32 b = 0; b < 4; b++) {
			ut32 pos = (ut32)(i * 4) + b;
			if (pos >= width) {
				break;
			}
			rz_bv_set(bv, pos, (nib >> b) & 1);
		}
	}
	free(hex);
	return bv;
}

static RzNumValue value_to_bitvector_width(RzNumValue *src, ut32 width) {
	if (width == 0) {
		return *src;
	}
	RzBitVector *bv = NULL;
	if (src->kind == RZ_NUM_KIND_BIG && src->val.big) {
		bv = bitvector_from_big(src->val.big, width);
	} else if (src->kind == RZ_NUM_KIND_BITVECTOR && src->val.bv) {
		bv = rz_bv_new(width);
		if (bv) {
			ut32 common = RZ_MIN(width, src->val.bv->len);
			for (ut32 i = 0; i < common; i++) {
				rz_bv_set(bv, i, rz_bv_get(src->val.bv, i));
			}
		}
	} else {
		bv = rz_bv_new_from_ut64(width, to_u64(src));
	}
	if (!bv) {
		return *src;
	}
	rz_num_value_fini(src);
	RzNumValue out = { .kind = RZ_NUM_KIND_BITVECTOR, .err = RZ_NUM_ERR_OK };
	out.val.bv = bv;
	return out;
}

// Coerce any value to a freshly-allocated bit-vector of \p width bits.
// Truncates / zero-extends through a ut64 intermediate. NULL on OOM.
static RzBitVector *value_to_bv_width(const RzNumValue *v, ut32 width) {
	if (v->kind == RZ_NUM_KIND_BITVECTOR && v->val.bv &&
		rz_bv_len(v->val.bv) == width) {
		return rz_bv_dup(v->val.bv);
	}
	return rz_bv_new_from_ut64(width, to_u64(v));
}

// True if either operand is float-like (IEEE double or arbitrary-precision
// decimal); such operands take the float dispatch. Whether the arithmetic
// stays exact (decimal) or projects to double is decided by
// any_bigdecimal()/any_real_float() at the call site.
static bool any_float(const RzNumValue *a, const RzNumValue *b) {
	return a->kind == RZ_NUM_KIND_FLOAT || b->kind == RZ_NUM_KIND_FLOAT ||
		a->kind == RZ_NUM_KIND_BIGDECIMAL || b->kind == RZ_NUM_KIND_BIGDECIMAL;
}

static bool any_bigdecimal(const RzNumValue *a, const RzNumValue *b) {
	return a->kind == RZ_NUM_KIND_BIGDECIMAL || b->kind == RZ_NUM_KIND_BIGDECIMAL;
}

static bool any_real_float(const RzNumValue *a, const RzNumValue *b) {
	return a->kind == RZ_NUM_KIND_FLOAT || b->kind == RZ_NUM_KIND_FLOAT;
}

static inline bool value_is_float_like(const RzNumValue *v) {
	return v->kind == RZ_NUM_KIND_FLOAT || v->kind == RZ_NUM_KIND_BIGDECIMAL;
}

static bool any_big(const RzNumValue *a, const RzNumValue *b) {
	return a->kind == RZ_NUM_KIND_BIG || b->kind == RZ_NUM_KIND_BIG;
}

static bool any_bitvector(const RzNumValue *a, const RzNumValue *b) {
	return a->kind == RZ_NUM_KIND_BITVECTOR || b->kind == RZ_NUM_KIND_BITVECTOR;
}

// The result width when combining two values, at least one of which
// is a bit-vector: the larger of the two operand widths (a non-bv
// operand contributes no width constraint, so the bv operand's width
// wins). Defaults to 64 if neither carries a width (shouldn't happen).
static ut32 combined_bv_width(const RzNumValue *a, const RzNumValue *b) {
	ut32 wa = (a->kind == RZ_NUM_KIND_BITVECTOR && a->val.bv) ? rz_bv_len(a->val.bv) : 0;
	ut32 wb = (b->kind == RZ_NUM_KIND_BITVECTOR && b->val.bv) ? rz_bv_len(b->val.bv) : 0;
	ut32 w = wa > wb ? wa : wb;
	return w ? w : 64;
}

// If a BIG-kind value's magnitude fits in ut64, demote it in place.
// Saves callers from carrying bignum bookkeeping for trivially-sized
// intermediate results. No-op for other kinds.
//
// "Fits in ut64" here is checked by round-tripping the value through
// big_from_u64(rz_big_to_int(b) cast to ut64) and comparing. This
// catches both small positive bignums and ut64-shaped values whose
// bit pattern, when reinterpreted as signed, would look negative
// (e.g. 0xffffffffffffffff). True bignums whose magnitude exceeds
// 64 bits do not round-trip and are left alone.
static void demote_big_if_fits(RzNumValue *v) {
	if (!v || v->kind != RZ_NUM_KIND_BIG || !v->val.big) {
		return;
	}
	st64 i = rz_big_to_int(v->val.big);
	ut64 u = (ut64)i;
	// Round-trip the candidate ut64 bit pattern back to a bignum with
	// the original's sign and require an exact match. A non-negative
	// value is rebuilt as unsigned (so 0xffffffffffffffff, i.e.
	// 2^64-1, still demotes); a negative value is rebuilt as signed
	// (so -15625 demotes to its two's-complement ut64 pattern).
	// Magnitudes wider than 64 bits fail the round-trip and stay big.
	RzNumBig *check;
	if (v->val.big->sign < 0) {
		check = rz_big_new();
		if (check) {
			rz_big_from_int(check, i);
		}
	} else {
		check = big_from_u64(u);
	}
	if (!check) {
		return;
	}
	if (rz_big_cmp(v->val.big, check) == 0) {
		rz_big_free(v->val.big);
		v->kind = RZ_NUM_KIND_UT64;
		v->val.n = u;
	}
	rz_big_free(check);
}

// Variable store (for `let x = y` / `x = y`)

// Deep-copy an RzNumValue onto the heap. BIG and BITVECTOR payloads
// are cloned so the stored copy owns its own memory independent of
// the source. Returns NULL on allocation failure.
static RzNumValue *value_dup_heap(const RzNumValue *src) {
	RzNumValue *dst = RZ_NEW0(RzNumValue);
	if (!dst) {
		return NULL;
	}
	dst->kind = src->kind;
	dst->err = src->err;
	switch (src->kind) {
	case RZ_NUM_KIND_BIG:
		dst->val.big = rz_big_new();
		if (!dst->val.big) {
			free(dst);
			return NULL;
		}
		rz_big_assign(dst->val.big, src->val.big);
		break;
	case RZ_NUM_KIND_BITVECTOR:
		dst->val.bv = src->val.bv ? rz_bv_dup(src->val.bv) : NULL;
		break;
	case RZ_NUM_KIND_BIGDECIMAL:
		dst->val.bigdec = src->val.bigdec ? rz_big_decimal_dup(src->val.bigdec) : NULL;
		break;
	case RZ_NUM_KIND_FLOAT:
		dst->val.d = src->val.d;
		break;
	case RZ_NUM_KIND_UT64:
	case RZ_NUM_KIND_NONE:
		dst->val.n = src->val.n;
		break;
	}
	return dst;
}

// HtSP value-free callback for the variable store.
static void value_store_free(void *p) {
	RzNumValue *v = (RzNumValue *)p;
	if (!v) {
		return;
	}
	rz_num_value_fini(v);
	free(v);
}

// Tree walking

static RzNumValue eval_node(EvalCtx *c, TSNode n);

// Wrap an owned RzBitVector as an RzNumValue (defined further down,
// alongside the other bit-vector helpers); declared here so the
// string-bytes literal handler can build one.
static RzNumValue val_bv(EvalCtx *c, RzBitVector *bv);

// Skip wrappers: the top-level `expression` rule, the
// `parenthesized_expression` rule (whose single named child is the
// inner expression), and the single-child `argument` wrapper.
static TSNode skip_wrappers(TSNode n) {
	for (;;) {
		TSSymbol s = ts_node_symbol(n);
		bool wrapper =
			s == g_sym.sym_expression ||
			s == g_sym.sym_parenthesized_expression ||
			s == g_sym.sym_argument;
		if (!wrapper) {
			return n;
		}
		uint32_t nc = ts_node_named_child_count(n);
		if (nc != 1) {
			return n;
		}
		n = ts_node_named_child(n, 0);
	}
}

// Legacy single-letter literal suffix support (see grammar.js
// number_legacy_suffix). Two disjoint families: a base family
// (o/b/t/h) that re-reads the preceding decimal-looking digit run in
// another base, and a scale family (k/m/g, case-insensitive) that
// multiplies the value by 1024^n.

// Base for a legacy base-suffix letter, or 0 if it is not one.
static int legacy_base_of(char s) {
	switch (s) {
	case 'o': return 8;
	case 'b': return 2;
	case 't': return 3;
	case 'h':
	case 'H': return 16;
	default: return 0;
	}
}

// Power-of-1024 exponent for a legacy scale-suffix letter, or 0 if it
// is not one. k/K -> 1, m/M -> 2, g/G -> 3.
static int legacy_scale_pow_of(char s) {
	switch (s) {
	case 'k':
	case 'K': return 1;
	case 'm':
	case 'M': return 2;
	case 'g':
	case 'G': return 3;
	default: return 0;
	}
}

// Evaluate a number whose tail is a legacy single-letter suffix.
// `digits` is the number_value text (no 0x/0b/... prefix, since the
// grammar only matches a decimal-looking run before the suffix);
// `suffix` is the suffix letter.
static RzNumValue eval_legacy_suffix(EvalCtx *c, const char *digits, char suffix) {
	int base = legacy_base_of(suffix);
	if (base) {
		// strtoull validates the digit run for us: an out-of-range
		// digit (e.g. the '8' in 383o or the '3' in 131t) leaves
		// *endp short of the terminator and is reported as a parse
		// error, mirroring the legacy "invalid <base> number"
		// diagnostic so the seek command leaves the cursor put.
		errno = 0;
		char *endp = NULL;
		unsigned long long v = strtoull(digits, &endp, base);
		if (endp == digits || *endp != '\0') {
			set_err_code(c, RZ_NUM_ERR_PARSE,
				"invalid base-%d literal: %s%c", base, digits, suffix);
			return val_u64(0);
		}
		char pfx = base == 8 ? 'o' : base == 2 ? 'b'
			: base == 3                    ? 't'
						       : 'x';
		RZ_LOG_WARN("'%s%c' uses a deprecated trailing base suffix; "
			    "use the 0%c prefix (0%c%s) instead\n",
			digits, suffix, pfx, pfx, digits);
		if (errno == ERANGE) {
			RzNumBig *b = big_from_base(digits, base);
			if (!b) {
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
				return val_u64(0);
			}
			return val_big(b);
		}
		return val_u64((ut64)v);
	}
	int pw = legacy_scale_pow_of(suffix);
	if (pw < 1) {
		// Unreachable: the grammar only emits base or scale letters.
		set_err_code(c, RZ_NUM_ERR_PARSE, "invalid numeric suffix: %c", suffix);
		return val_u64(0);
	}
	// Size suffixes (K/M/G == 1024^n) are a standard, widely-used shorthand
	// (rizin's own config defaults use "63K", "256K", "10M", ...), so unlike
	// the base suffixes they are accepted without a deprecation warning.
	ut64 mult = 1ULL << (10 * pw);
	// A decimal point is allowed on a scaled value (`1.5K`). The
	// scaled result is an integer byte count, matching the legacy
	// (ut64)(d * KB) projection.
	if (strchr(digits, '.')) {
		double d = 0.0;
		if (!parse_float_literal(digits, &d, &c->err)) {
			return val_u64(0);
		}
		return val_u64((ut64)(d * (double)mult));
	}
	errno = 0;
	char *endp = NULL;
	unsigned long long v = strtoull(digits, &endp, 10);
	if (endp == digits || *endp != '\0' || errno == ERANGE) {
		set_err_code(c, RZ_NUM_ERR_PARSE, "invalid scaled literal: %s%c", digits, suffix);
		return val_u64(0);
	}
	return val_u64((ut64)v * mult);
}

static RzNumValue eval_number(EvalCtx *c, TSNode n) {
	// number := number_value [ number_suffix | number_unit | number_legacy_suffix ]
	TSNode val = ts_node_named_child(n, 0);
	char *txt = node_text(val, c->src);
	if (!txt) {
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
		return val_u64(0);
	}
	// A digit-leading legacy hex literal ("3a7fh") is lexed as a single
	// number_legacy_hex token, because number_value's digit run stops at
	// the first hex letter. Drop the trailing 'h'/'H' and read the run in
	// base 16 through the shared legacy-suffix path, which validates the
	// digits, promotes a >64-bit value to a bignum and emits the same
	// deprecation note as the other trailing-base forms.
	if (!strcmp(ts_node_type(val), "number_legacy_hex")) {
		size_t len = strlen(txt);
		char sc = txt[len - 1];
		txt[len - 1] = '\0';
		RzNumValue lv = eval_legacy_suffix(c, txt, sc);
		free(txt);
		return lv;
	}
	// A legacy single-letter suffix (o/b/t/h/k/m/g) reinterprets or
	// scales the digit run; handle it before the default decimal /
	// float reading below.
	if (ts_node_named_child_count(n) > 1) {
		TSNode tail0 = ts_node_named_child(n, 1);
		if (!strcmp(ts_node_type(tail0), "number_legacy_suffix")) {
			char *s = node_text(tail0, c->src);
			char sc = s ? s[0] : 0;
			free(s);
			RzNumValue lv = eval_legacy_suffix(c, txt, sc);
			free(txt);
			return lv;
		}
	}
	RzNumValue out;
	if (literal_is_float(txt)) {
		double d = 0.0;
		if (!parse_float_literal(txt, &d, &c->err)) {
			free(txt);
			return val_u64(0);
		}
		// Validated as a float above; now keep full precision by parsing
		// the literal text into an exact decimal rather than collapsing
		// to a double. Exotic forms the decimal parser rejects (e.g. a
		// hex float) fall back to the double value.
		RzBigDecimal *bd = rz_big_decimal_new_from_str(txt);
		out = bd ? val_bigdecimal(bd) : val_f64(d);
	} else {
		ut64 u = 0;
		bool overflow = false;
		if (!parse_int_literal(txt, &u, &overflow, &c->err)) {
			if (overflow) {
				// Promote to RZ_NUM_KIND_BIG. The base prefix tells
				// us how to interpret the digit string. Hex goes
				// through rz_big_from_hexstr (the only direct
				// rz_big parser); the other bases go through
				// big_from_base, which builds the bignum by
				// shift-and-add on rz_big_mul / rz_big_add.
				ut32 base = 10;
				size_t prefix_len = 0;
				rz_num_base_prefix(txt, &base, &prefix_len);
				const char *digits = txt + prefix_len;
				RzNumBig *b = NULL;
				if (base == 16) {
					b = rz_big_new();
					if (b) {
						rz_big_from_hexstr(b, digits);
					}
				} else {
					b = big_from_base(digits, base);
				}
				if (!b) {
					set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
					free(txt);
					return val_u64(0);
				}
				out = val_big(b);
			} else {
				// Non-overflow integer parse failure (e.g. an invalid
				// C-octal digit). parse_int_literal leaves c->err unset
				// in that case so we can stamp the proper category here.
				set_err_code(c, RZ_NUM_ERR_PARSE, "invalid integer literal: %s", txt);
				free(txt);
				return val_u64(0);
			}
		} else {
			out = val_u64(u);
		}
	}
	free(txt);

	uint32_t nc = ts_node_named_child_count(n);
	if (nc <= 1) {
		return out;
	}
	TSNode tail = ts_node_named_child(n, 1);
	const char *tt = ts_node_type(tail);
	if (!strcmp(tt, "number_unit")) {
		char *unit = node_text(tail, c->src);
		if (unit) {
			ut64 m = unit_multiplier(unit);
			if (out.kind == RZ_NUM_KIND_FLOAT) {
				double d = to_double(&out);
				rz_num_value_fini(&out);
				out = val_f64(d * (double)m);
			} else if (out.kind == RZ_NUM_KIND_BIGDECIMAL) {
				RzBigDecimal *mul = rz_big_decimal_new_from_int((st64)m);
				RzBigDecimal *res = mul ? rz_big_decimal_mul(out.val.bigdec, mul) : NULL;
				rz_big_decimal_free(mul);
				if (res) {
					rz_num_value_fini(&out);
					out = val_bigdecimal(res);
				}
			} else {
				out.val.n *= m;
			}
			free(unit);
		}
	} else if (!strcmp(tt, "number_suffix")) {
		// A suffix carrying an explicit bit-width (e.g. u1, u7,
		// u8, u128, u1024) turns the literal into a fixed-width
		// bit-vector. A bare letter run (u, l, ul, f, ...) stays
		// informational and does not change the kind.
		char *suf = node_text(tail, c->src);
		if (suf) {
			bool has_width = false;
			ut32 width = bitvector_width_from_suffix(suf, &has_width);
			if (has_width && (width < 1 || width > RZ_NUM_MAX_BV_WIDTH)) {
				set_err_code(c, RZ_NUM_ERR_PARSE,
					"bit-vector width must be 1..%u, got %u",
					RZ_NUM_MAX_BV_WIDTH, width);
				free(suf);
				rz_num_value_fini(&out);
				return val_u64(0);
			}
			if (width > 0) {
				out = value_to_bitvector_width(&out, width);
			}
			free(suf);
		}
	}
	return out;
}

// Parse the leading sign-less integer text of a number_value into a
// ut64. Used by address_typed where the numeric prefix is a bare
// integer literal. Hex/bin/oct/ternary prefixes are honoured.
static bool parse_addr_number(const char *t, ut64 *out, char **err) {
	bool overflow = false;
	return parse_int_literal(t, out, &overflow, err);
}

// Sign-extend the low `width_bits` of `bits` to a full 64-bit two's
// complement value (returned as its ut64 bit pattern). width_bits is
// one of 8/16/32/64; 64 is returned unchanged.
static ut64 sign_extend_u64(ut64 bits, int width_bits) {
	if (width_bits >= 64) {
		return bits;
	}
	ut64 sign_bit = (ut64)1 << (width_bits - 1);
	ut64 mask = (sign_bit << 1) - 1; // low width_bits set
	bits &= mask;
	if (bits & sign_bit) {
		bits |= ~mask; // set the high bits
	}
	return bits;
}

// Reinterpret the low `width_bits` of a raw bit pattern as an
// IEEE-754 float and widen to double. Supports half (16), single
// (32) and double (64) precision. Half precision is decoded
// manually; single/double reuse the native representations.
static double decode_ieee_float(ut64 bits, int width_bits) {
	if (width_bits == 64) {
		double d;
		ut64 b = bits;
		memcpy(&d, &b, sizeof(d));
		return d;
	}
	if (width_bits == 32) {
		float f;
		ut32 b = (ut32)bits;
		memcpy(&f, &b, sizeof(f));
		return (double)f;
	}
	// Half precision (binary16): 1 sign, 5 exponent, 10 mantissa.
	ut32 h = (ut32)(bits & 0xffff);
	ut32 sign = (h >> 15) & 0x1;
	ut32 exp = (h >> 10) & 0x1f;
	ut32 mant = h & 0x3ff;
	double value;
	if (exp == 0) {
		// Subnormal (or zero): value = mant * 2^-24.
		value = (double)mant * (1.0 / 16777216.0);
	} else if (exp == 0x1f) {
		// Inf / NaN. Assemble the IEEE-754 double bit pattern and copy
		// it out rather than using 0.0 / 0.0 and 1.0 / 0.0: MSVC rejects
		// those as a constant divide by zero (C2124), and its <math.h>
		// exposes neither NAN nor INFINITY. The sign is applied below.
		ut64 nan_inf = mant ? 0x7ff8000000000000ULL // quiet NaN
				    : 0x7ff0000000000000ULL; // +infinity
		memcpy(&value, &nan_inf, sizeof(value));
	} else {
		// Normalised: (1 + mant/1024) * 2^(exp-15).
		value = (1.0 + (double)mant / 1024.0) * pow(2.0, (double)exp - 15.0);
	}
	return sign ? -value : value;
}

static RzNumValue eval_address_typed(EvalCtx *c, TSNode n) {
	// address_typed := number_value ":" address_width
	// The first named child is number_value, the second is address_width.
	TSNode nv = ts_node_named_child(n, 0);
	TSNode aw = ts_node_named_child(n, 1);
	char *nv_text = node_text(nv, c->src);
	char *aw_text = node_text(aw, c->src);
	if (!nv_text || !aw_text) {
		free(nv_text);
		free(aw_text);
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
		return val_u64(0);
	}

	ut64 addr = 0;
	if (!parse_addr_number(nv_text, &addr, &c->err)) {
		free(nv_text);
		free(aw_text);
		return val_u64(0);
	}

	// Parse the width tail: optional "le"/"be" prefix, then an
	// optional "s" (signed) or "f" (float) marker, then the bit
	// width.
	//   le32   little-endian unsigned 32-bit
	//   s32    native-endian signed 32-bit
	//   lef32  little-endian 32-bit float
	//   f16    native-endian half-precision float
	const char *w = aw_text;
	bool big_endian = false;
	if (!strncmp(w, "le", 2)) {
		w += 2;
	} else if (!strncmp(w, "be", 2)) {
		w += 2;
		big_endian = true;
	}
	bool is_signed = false;
	bool is_float = false;
	if (w[0] == 's') {
		is_signed = true;
		w++;
	} else if (w[0] == 'f') {
		is_float = true;
		w++;
	}
	int width_bits = atoi(w);
	free(nv_text);
	free(aw_text);

	if (is_float) {
		if (width_bits != 16 && width_bits != 32 && width_bits != 64 && width_bits != 128) {
			set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED,
				"unsupported float read width: %d", width_bits);
			return val_u64(0);
		}
	} else if (width_bits != 8 && width_bits != 16 && width_bits != 32 &&
		width_bits != 64 && width_bits != 128) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "unsupported address width: %d", width_bits);
		return val_u64(0);
	}

	// If a host has registered an IO-read callback (rz_core_math
	// does, backed by RzIO), perform the dereference: read
	// width_bits/8 raw bytes at addr through the callback, then
	// decode them here according to the requested endianness, the
	// signed marker, and the float marker. The callback only hands
	// back bytes; all interpretation lives in the evaluator.
	if (c->io_read && width_bits <= 64) {
		int width_bytes = width_bits / 8;
		ut8 buf[8] = { 0 };
		ut64 got = c->io_read(c->io_read_user, addr, buf, width_bytes);
		if (got < (ut64)width_bytes) {
			set_err_code(c, RZ_NUM_ERR_UNCOMPUTABLE,
				"failed to read %d bytes at 0x%" PFMT64x, width_bytes, addr);
			return val_u64(0);
		}
		// Assemble the raw bytes into a ut64 in the requested
		// endianness. The lowest-addressed byte is the MSB for
		// big-endian and the LSB for little-endian.
		ut64 bits = 0;
		if (big_endian) {
			for (int i = 0; i < width_bytes; i++) {
				bits = (bits << 8) | buf[i];
			}
		} else {
			for (int i = 0; i < width_bytes; i++) {
				bits |= ((ut64)buf[i]) << (8 * i);
			}
		}
		if (is_float) {
			// Reinterpret the raw bit pattern as an IEEE-754 float.
			return val_f64(decode_ieee_float(bits, width_bits));
		}
		if (is_signed) {
			// Sign-extend the width_bits value to a full st64, stored
			// back as ut64 (its two's-complement bit pattern).
			return val_u64(sign_extend_u64(bits, width_bits));
		}
		return val_u64(bits);
	}

	// 128-bit typed read: a single 16-byte raw read assembled into a
	// width-128 bit-vector, with the byte-to-qword placement chosen
	// to match how the value normally appears in memory - little-
	// endian puts the low qword at the low address, big-endian puts
	// the high qword at the low address. The result is the same
	// bit-vector for both `:128` (integer) and `:f128` (IEEE-754
	// quad): RzNum's FLOAT kind is double, so the quad value cannot
	// be decoded to a native float, but the bit-vector preserves
	// every bit for inspection, bit-for-bit comparison and
	// bit-vector arithmetic.
	if (c->io_read && width_bits == 128) {
		ut8 buf[16] = { 0 };
		ut64 got = c->io_read(c->io_read_user, addr, buf, 16);
		if (got < 16) {
			set_err_code(c, RZ_NUM_ERR_UNCOMPUTABLE,
				"failed to read 16 bytes at 0x%" PFMT64x, addr);
			return val_u64(0);
		}
		// Reassemble two qwords from the raw bytes in the requested
		// endianness, then place them into the bit-vector: 'lo' in
		// bits [0..63] (LSB half) and 'hi' in bits [64..127] (MSB
		// half), so rz_bv_to_ut64 returns the low qword.
		ut64 lo = 0, hi = 0;
		if (big_endian) {
			for (int i = 0; i < 8; i++) {
				hi = (hi << 8) | buf[i];
				lo = (lo << 8) | buf[i + 8];
			}
		} else {
			for (int i = 0; i < 8; i++) {
				lo |= ((ut64)buf[i]) << (8 * i);
				hi |= ((ut64)buf[i + 8]) << (8 * i);
			}
		}
		RzBitVector *bv = rz_bv_new(128);
		if (!bv) {
			set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
			return val_u64(0);
		}
		for (ut32 i = 0; i < 64; i++) {
			rz_bv_set(bv, i, (lo >> i) & 1);
			rz_bv_set(bv, i + 64, (hi >> i) & 1);
		}
		return val_bv(c, bv);
	}

	// No IO callback registered (e.g. plain rz_num_math_value with
	// no host context): the :width suffix is accepted by the
	// parser but the literal address is returned, matching the
	// legacy calc parser which stops at the colon.
	return val_u64(addr);
}

static RzNumValue eval_string_bytes(EvalCtx *c, TSNode n) {
	char *raw = node_text(n, c->src);
	if (!raw) {
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
		return val_u64(0);
	}
	size_t len = strlen(raw);
	if (len < 2 || raw[0] != '"' || raw[len - 1] != '"') {
		set_err_code(c, RZ_NUM_ERR_PARSE, "malformed string literal: %s", raw);
		free(raw);
		return val_u64(0);
	}
	// Strip the surrounding quotes and process backslash escapes
	// (only \\, \", \n, \t, \r, \0 and \xHH are recognised). The
	// decoded bytes are collected into a heap buffer so a string of
	// any length is representable; the result is a bit-vector of
	// 8 * byte-count bits, packed little-endian (first source byte is
	// the least-significant).
	size_t cap = len; // upper bound: decoded bytes <= raw length
	ut8 *bytes = malloc(cap ? cap : 1);
	if (!bytes) {
		free(raw);
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
		return val_u64(0);
	}
	size_t bcount = 0;
	for (size_t i = 1; i + 1 < len; i++) {
		ut8 b;
		if (raw[i] == '\\' && i + 1 < len - 1) {
			char esc = raw[i + 1];
			switch (esc) {
			case '\\': b = '\\'; break;
			case '"': b = '"'; break;
			case 'n': b = '\n'; break;
			case 't': b = '\t'; break;
			case 'r': b = '\r'; break;
			case '0': b = 0; break;
			case 'x':
				if (i + 3 < len - 1 && isxdigit((ut8)raw[i + 2]) && isxdigit((ut8)raw[i + 3])) {
					char hh[3] = { raw[i + 2], raw[i + 3], 0 };
					b = (ut8)strtoul(hh, NULL, 16);
					i += 2;
				} else {
					set_err_code(c, RZ_NUM_ERR_PARSE, "malformed \\x escape in string literal");
					free(bytes);
					free(raw);
					return val_u64(0);
				}
				break;
			default:
				b = (ut8)esc;
				break;
			}
			i += 1;
		} else {
			b = (ut8)raw[i];
		}
		bytes[bcount++] = b;
	}
	free(raw);

	// An empty string ("") is a zero-width edge case; represent it as
	// a 0 ut64.
	if (bcount == 0) {
		free(bytes);
		return val_u64(0);
	}
	// Build a bit-vector of bcount bytes, little-endian: byte i sits
	// at bit offset 8*i, so the first source byte is the LSB.
	RzBitVector *bv = rz_bv_new((ut32)(bcount * 8));
	if (!bv) {
		free(bytes);
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
		return val_u64(0);
	}
	for (size_t i = 0; i < bcount; i++) {
		for (int bit = 0; bit < 8; bit++) {
			rz_bv_set(bv, (ut32)(i * 8 + bit), (bytes[i] >> bit) & 1);
		}
	}
	free(bytes);
	return val_bv(c, bv);
}

static RzNumValue eval_variable(EvalCtx *c, TSNode n) {
	char *name = node_text(n, c->src);
	if (!name) {
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
		return val_u64(0);
	}
	if (is_reserved_word(name)) {
		set_err_code(c, RZ_NUM_ERR_RESERVED_WORD, "reserved word '%s' cannot be used as an identifier", name);
		free(name);
		return val_u64(0);
	}
	// Local bindings established by `let x = y` / `x = y` earlier in
	// this same evaluation take precedence over the host callback.
	if (c->vars) {
		RzNumValue *bound = ht_sp_find(c->vars, name, NULL);
		if (bound) {
			free(name);
			// Return a deep copy so the caller can fini() it freely
			// without disturbing the stored binding.
			RzNumValue *copy = value_dup_heap(bound);
			if (!copy) {
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
				return val_u64(0);
			}
			RzNumValue out = *copy;
			free(copy);
			return out;
		}
	}
	int ok = 0;
	ut64 v = 0;
	if (c->num && c->num->callback) {
		// The host callback expects the opaque userptr supplied to
		// rz_num_new() as its first argument (e.g. RzCore), not the
		// RzNum itself - matching how the historical single-token reader
		// invokes it. Passing c->num here would make the callback
		// cast the wrong pointer and crash.
		v = c->num->callback(c->num->userptr, name, &ok);
	}
	if (ok) {
		free(name);
		return val_u64(v);
	}
	// Before folding an unresolved identifier to 0, try the legacy
	// trailing-'h' hexadecimal form: a run of hex digits followed
	// by a single 'h'/'H' (`beach` == 0xbeac, `cafeh` == 0xcafe).
	// The host callback was consulted first (above), so a flag or
	// register named `beach` still wins; only an otherwise unknown
	// name is reinterpreted. This mirrors the legacy rz_num_get(),
	// which tried the callback before number parsing.
	size_t nlen = strlen(name);
	if (nlen >= 2 && (name[nlen - 1] == 'h' || name[nlen - 1] == 'H')) {
		bool all_hex = true;
		for (size_t i = 0; i + 1 < nlen; i++) {
			if (!isxdigit((ut8)name[i])) {
				all_hex = false;
				break;
			}
		}
		if (all_hex) {
			errno = 0;
			char *endp = NULL;
			unsigned long long hv = strtoull(name, &endp, 16);
			if (errno != ERANGE && endp != name && (*endp == 'h' || *endp == 'H')) {
				RZ_LOG_WARN("'%s' uses the deprecated trailing-'h' hex form; "
					    "use the 0x prefix (0x%.*s) instead\n",
					name, (int)(nlen - 1), name);
				free(name);
				return val_u64((ut64)hv);
			}
		}
	}
	// The host could not resolve this identifier. The legacy
	// rz_num_get() treats an unknown symbol as 0 but also records
	// an error (its error() bumps nc.errors), which is how callers
	// like the seek command tell that `s main` did not resolve and
	// must not move. Mirror that: fold to 0 so the rest of a larger
	// expression (e.g. `sym + 4`) still evaluates as before, but
	// flag the failure through nc so those callers can react.
	if (c->num) {
		c->num->nc.errors = 1;
	}
	free(name);
	return val_u64(0);
}

static RzNumValue eval_special_variable(EvalCtx *c, TSNode n) {
	// The text node includes the leading '$'; pass it through to the
	// callback verbatim so the callback can dispatch on the canonical
	// name (e.g. "$$", "$F", "$SS").
	char *name = node_text(n, c->src);
	if (!name) {
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
		return val_u64(0);
	}
	int ok = 0;
	ut64 v = 0;
	if (c->num && c->num->callback) {
		// Pass the host's opaque userptr, not the RzNum (see
		// eval_variable for why).
		v = c->num->callback(c->num->userptr, name, &ok);
	}
	if (!ok) {
		// Special variables that the host does not know about
		// resolve to 0 with a diagnostic. Unlike plain variables,
		// these are a closed namespace per the grammar, so a typo
		// like "$F" vs "$Ff" is meaningful to report.
		set_err_code(c, RZ_NUM_ERR_UNDEFINED_VAR, "unknown special variable: %s", name);
		v = 0;
	}
	free(name);
	return val_u64(v);
}

// Built-in function table

// Forward declaration: big_cmp is defined further down, alongside
// the other bignum helpers used by eval_binop.
static int big_cmp(const RzNumValue *lv, const RzNumValue *rv);

// Collect a comma-separated argument list from a `function` node. The
// caller passes a maximum count; we stop early if more arguments are
// present and the caller can flag that as an error.
//
// AST shape: function -> [function_name, argument_list].
// argument_list contains the arguments as its named children.
static int eval_function_args(EvalCtx *c, TSNode n, RzNumValue *out, int max) {
	int count = 0;
	uint32_t nc = ts_node_named_child_count(n);
	if (nc < 2) {
		return 0;
	}
	TSNode args_list = ts_node_named_child(n, 1);
	uint32_t an = ts_node_named_child_count(args_list);
	for (uint32_t i = 0; i < an && count < max; i++) {
		out[count++] = eval_node(c, ts_node_named_child(args_list, i));
	}
	return count;
}

// Number of argument nodes in a call, used to size the argument
// buffer so a function can take an arbitrary number of arguments.
static uint32_t function_arg_count(TSNode n) {
	if (ts_node_named_child_count(n) < 2) {
		return 0;
	}
	return ts_node_named_child_count(ts_node_named_child(n, 1));
}

// Built-in function entry: name + dispatcher. The dispatcher receives
// the already-evaluated args (with their kinds preserved) and an
// EvalCtx that it can populate with set_err_code on failure.
typedef RzNumValue (*builtin_fn)(EvalCtx *c, RzNumValue *args, int n);

typedef struct {
	const char *name; ///< canonical UTF-8 name; aliases go in their own row
	int arity; ///< exact argument count, or -1 for variadic
	builtin_fn fn;
} BuiltinEntry;

static RzNumValue builtin_min(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 2) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "min expects 2 arguments, got %d", n);
		return val_u64(0);
	}
	// Comparison promotes to the more general kind so we get an
	// answer that reflects the true ordering rather than a lossy
	// projection. Then return the original chosen operand so the
	// kind is preserved.
	if (value_is_float_like(&a[0]) || value_is_float_like(&a[1])) {
		return to_double(&a[0]) < to_double(&a[1])
			? a[0]
			: a[1];
	}
	if (a[0].kind == RZ_NUM_KIND_BIG || a[1].kind == RZ_NUM_KIND_BIG) {
		return big_cmp(&a[0], &a[1]) < 0 ? a[0] : a[1];
	}
	return a[0].val.n < a[1].val.n ? a[0] : a[1];
}

static RzNumValue builtin_max(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 2) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "max expects 2 arguments, got %d", n);
		return val_u64(0);
	}
	if (value_is_float_like(&a[0]) || value_is_float_like(&a[1])) {
		return to_double(&a[0]) > to_double(&a[1])
			? a[0]
			: a[1];
	}
	if (a[0].kind == RZ_NUM_KIND_BIG || a[1].kind == RZ_NUM_KIND_BIG) {
		return big_cmp(&a[0], &a[1]) > 0 ? a[0] : a[1];
	}
	return a[0].val.n > a[1].val.n ? a[0] : a[1];
}

static RzNumValue builtin_abs(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "abs expects 1 argument, got %d", n);
		return val_u64(0);
	}
	if (a[0].kind == RZ_NUM_KIND_FLOAT) {
		return val_f64(fabs(a[0].val.d));
	}
	if (a[0].kind == RZ_NUM_KIND_BIGDECIMAL && a[0].val.bigdec) {
		RzBigDecimal *zero = rz_big_decimal_new_from_int(0);
		bool neg = zero && rz_big_decimal_cmp(a[0].val.bigdec, zero) < 0;
		rz_big_decimal_free(zero);
		RzBigDecimal *r = neg ? rz_big_decimal_neg(a[0].val.bigdec)
				      : rz_big_decimal_dup(a[0].val.bigdec);
		return r ? val_bigdecimal(r) : val_u64(0);
	}
	if (a[0].kind == RZ_NUM_KIND_UT64) {
		st64 s = (st64)a[0].val.n;
		return val_u64(s < 0 ? (ut64)(-s) : (ut64)s);
	}
	// Bignum / bitvector: no width-independent sign interpretation
	// is meaningful, so just project to ut64 absolute value.
	st64 s = (st64)to_u64(&a[0]);
	return val_u64(s < 0 ? (ut64)(-s) : (ut64)s);
}

static RzNumValue builtin_popcount(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "popcount expects 1 argument, got %d", n);
		return val_u64(0);
	}
	// popcount on a bignum walks the hex form's nibbles. That's
	// well-defined regardless of underlying representation.
	if (a[0].kind == RZ_NUM_KIND_BIG) {
		char *hex = rz_big_to_hexstr(a[0].val.big);
		ut64 total = 0;
		if (hex) {
			const char *p = hex;
			size_t prefix_len = 0;
			if (rz_num_base_prefix(p, NULL, &prefix_len) == RZ_NUM_BASE_PREFIX_HEX) {
				p += prefix_len;
			}
			for (; *p; p++) {
				ut8 v = 0;
				if (!rz_hex_to_byte(&v, (ut8)*p)) {
					total += rz_bits_count_ones_ut8(v & 0xf);
				}
			}
			free(hex);
		}
		return val_u64(total);
	}
	return val_u64(rz_bits_count_ones_ut64(to_u64(&a[0])));
}

// len(x): the length of the operand.
//   - bit-vector  -> its width in BITS (a string-bytes literal such
//                    as "ABCD" is a bit-vector of 8 * byte-count, so
//                    len("ABCD") is 32 and len("ABCD") / 8 is the
//                    byte count);
//   - big number  -> its significant bit width;
//   - ut64        -> its significant bit width (0 for 0).
// This gives a single, well-defined notion of "length" across the
// integer-ish kinds, keyed on bits, with bytes one division away.
static RzNumValue builtin_len(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "len expects 1 argument, got %d", n);
		return val_u64(0);
	}
	if (a[0].kind == RZ_NUM_KIND_BITVECTOR && a[0].val.bv) {
		return val_u64(rz_bv_len(a[0].val.bv));
	}
	if (a[0].kind == RZ_NUM_KIND_BIG) {
		// Exact significant bit width: take the hex form, drop the
		// optional sign and "0x", then count 4 bits per full hex
		// digit minus the leading zeros of the top digit.
		char *hex = rz_big_to_hexstr(a[0].val.big);
		if (!hex) {
			set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
			return val_u64(0);
		}
		const char *p = hex;
		if (p[0] == '-') {
			p++;
		}
		size_t prefix_len = 0;
		if (rz_num_base_prefix(p, NULL, &prefix_len) == RZ_NUM_BASE_PREFIX_HEX) {
			p += prefix_len;
		}
		// Skip leading zero digits.
		while (p[0] == '0' && p[1] != '\0') {
			p++;
		}
		ut64 bits = 0;
		if (!(p[0] == '0' && p[1] == '\0')) {
			size_t ndigits = strlen(p);
			int top = 0;
			char ch = p[0];
			if (ch >= '0' && ch <= '9')
				top = ch - '0';
			else if (ch >= 'a' && ch <= 'f')
				top = ch - 'a' + 10;
			else if (ch >= 'A' && ch <= 'F')
				top = ch - 'A' + 10;
			int top_bits = 0;
			while (top) {
				top_bits++;
				top >>= 1;
			}
			bits = (ut64)(ndigits - 1) * 4 + top_bits;
		}
		free(hex);
		return val_u64(bits);
	}
	if (value_is_float_like(&a[0])) {
		// A float / decimal has no bit-length notion here; report rather
		// than silently returning a misleading number.
		set_err_code(c, RZ_NUM_ERR_TYPE_MISMATCH, "len is not defined on floats");
		return val_u64(0);
	}
	return val_u64(rz_bits_ut64_width(a[0].val.n));
}

// Domain-relevant math and bit functions. The transcendental ones
// return FLOAT (only the float kind can carry an irrational result);
// floor/ceil/round hand back a ut64 when the integer fits the 64-bit
// two's-complement range (the common case for address/offset math)
// and otherwise stay float; the bit-counting ones project to ut64.
// All are registered in builtin_table below with no grammar change,
// since `name(args)` already parses as a function call.

// floor/ceil/round produce a mathematical integer: return it as ut64
// when representable, else keep it float so nothing is silently lost.
static RzNumValue float_to_int_kind(double d) {
	if (d >= 0.0 && d < 18446744073709551616.0) { // [0, 2^64)
		return val_u64((ut64)d);
	}
	if (d < 0.0 && d >= -9223372036854775808.0) { // [-2^63, 0)
		return val_u64((ut64)(st64)d);
	}
	return val_f64(d);
}

static RzNumValue builtin_log_natural(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "log expects 1 argument, got %d", n);
		return val_u64(0);
	}
	double x = to_double(&a[0]);
	if (!(x > 0.0)) {
		set_err_code(c, RZ_NUM_ERR_UNCOMPUTABLE, "log is undefined for arguments <= 0");
		return val_f64(0.0);
	}
	return val_f64(log(x));
}

static RzNumValue builtin_log2(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "log2 expects 1 argument, got %d", n);
		return val_u64(0);
	}
	double x = to_double(&a[0]);
	if (!(x > 0.0)) {
		set_err_code(c, RZ_NUM_ERR_UNCOMPUTABLE, "log2 is undefined for arguments <= 0");
		return val_f64(0.0);
	}
	return val_f64(log2(x));
}

static RzNumValue builtin_log10(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "log10 expects 1 argument, got %d", n);
		return val_u64(0);
	}
	double x = to_double(&a[0]);
	if (!(x > 0.0)) {
		set_err_code(c, RZ_NUM_ERR_UNCOMPUTABLE, "log10 is undefined for arguments <= 0");
		return val_f64(0.0);
	}
	return val_f64(log10(x));
}

static RzNumValue builtin_sqrt(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "sqrt expects 1 argument, got %d", n);
		return val_u64(0);
	}
	double x = to_double(&a[0]);
	if (x < 0.0) {
		set_err_code(c, RZ_NUM_ERR_UNCOMPUTABLE, "sqrt is undefined for negative arguments");
		return val_f64(0.0);
	}
	return val_f64(sqrt(x));
}

static RzNumValue builtin_floor(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "floor expects 1 argument, got %d", n);
		return val_u64(0);
	}
	// Integer kinds already are their own floor; pass them through so
	// floor(big) keeps full precision instead of going through double.
	if (!value_is_float_like(&a[0])) {
		return a[0];
	}
	return float_to_int_kind(floor(to_double(&a[0])));
}

static RzNumValue builtin_ceil(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "ceil expects 1 argument, got %d", n);
		return val_u64(0);
	}
	if (!value_is_float_like(&a[0])) {
		return a[0];
	}
	return float_to_int_kind(ceil(to_double(&a[0])));
}

static RzNumValue builtin_round(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "round expects 1 argument, got %d", n);
		return val_u64(0);
	}
	if (!value_is_float_like(&a[0])) {
		return a[0];
	}
	// C round() rounds halves away from zero (round(2.5) == 3,
	// round(-2.5) == -3), which is the least surprising rule here.
	return float_to_int_kind(round(to_double(&a[0])));
}

static RzNumValue builtin_gcd(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 2) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "gcd expects 2 arguments, got %d", n);
		return val_u64(0);
	}
	ut64 x = to_u64(&a[0]), y = to_u64(&a[1]);
	while (y) {
		ut64 t = x % y;
		x = y;
		y = t;
	}
	return val_u64(x);
}

static RzNumValue builtin_clz(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "clz expects 1 argument, got %d", n);
		return val_u64(0);
	}
	// Count leading zero bits of the 64-bit projection; 0 has all 64.
	ut64 x = to_u64(&a[0]);
	if (x == 0) {
		return val_u64(64);
	}
	ut64 count = 0;
	while (!(x & (1ULL << 63))) {
		count++;
		x <<= 1;
	}
	return val_u64(count);
}

static RzNumValue builtin_ctz(EvalCtx *c, RzNumValue *a, int n) {
	if (n != 1) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "ctz expects 1 argument, got %d", n);
		return val_u64(0);
	}
	ut64 x = to_u64(&a[0]);
	if (x == 0) {
		return val_u64(64);
	}
	ut64 count = 0;
	while (!(x & 1)) {
		count++;
		x >>= 1;
	}
	return val_u64(count);
}

// Built-in registry. The unicode-named entries are demonstrations of
// the grammar's identifier handling: the `variable` and `function`
// rules accept any sequence of identifier characters per Unicode's
// XID_Start / XID_Continue (per tree-sitter's word handling), so
// non-ASCII names work for free at the parser level. The mapping
// table here is what makes them actually evaluate.
//
// New entries land here without grammar changes.
static const BuiltinEntry builtin_table[] = {
	// English-named primitives.
	{ "min", 2, builtin_min },
	{ "max", 2, builtin_max },
	{ "abs", 1, builtin_abs },
	{ "popcount", 1, builtin_popcount },
	{ "len", 1, builtin_len },
	// Math and bit functions. log() is the natural logarithm (ln is
	// an explicit alias); the base-b logarithm is the `b log x`
	// operator. log2/clz/ctz are the bit-oriented ones most useful
	// for binary analysis (widths, alignment, bit scanning).
	{ "log", 1, builtin_log_natural },
	{ "ln", 1, builtin_log_natural },
	{ "log2", 1, builtin_log2 },
	{ "log10", 1, builtin_log10 },
	{ "sqrt", 1, builtin_sqrt },
	{ "floor", 1, builtin_floor },
	{ "ceil", 1, builtin_ceil },
	{ "round", 1, builtin_round },
	{ "gcd", 2, builtin_gcd },
	{ "clz", 1, builtin_clz },
	{ "ctz", 1, builtin_ctz },
	// Unicode-named aliases. Demonstrate that the parser does the
	// right thing on non-ASCII identifiers across writing systems;
	// each is functionally identical to its English counterpart
	// above. (The escapes keep this source ASCII-clean; the comments
	// give the script and meaning.)
	{ "\xd0\xbc\xd0\xb8\xd0\xbd\xd0\xb8\xd0\xbc\xd1\x83\xd0\xbc", // "минимум" (Cyrillic: minimum)
		2, builtin_min },
	{ "\xd0\xbc\xd0\xb0\xd0\xba\xd1\x81\xd0\xb8\xd0\xbc\xd1\x83\xd0\xbc", // "максимум" (Cyrillic: maximum)
		2, builtin_max },
	{ "\xe6\x9c\x80\xe5\xb0\x8f", // "最小" (Chinese/Japanese: minimum)
		2, builtin_min },
	{ "\xe6\x9c\x80\xe5\xa4\xa7", // "最大" (Chinese/Japanese: maximum)
		2, builtin_max },
	{ "\xd8\xaf\xd8\xa7\xd9\x84\xd8\xa9", // "دالة" (Arabic: function) -> abs
		1, builtin_abs },
	{ "\xce\xa3", // "Σ" (Greek capital sigma) -> popcount, as a
		// math-symbol-named alias
		1, builtin_popcount },
	{ NULL, 0, NULL },
};

static RzNumValue eval_function(EvalCtx *c, TSNode n) {
	char *name = node_text(ts_node_named_child(n, 0), c->src);
	if (!name) {
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
		return val_u64(0);
	}

	// User-registered functions take precedence over the built-in
	// table, so a host (e.g. RzCore) can shadow or extend the set.
	const RzNumFuncEntry *user_entry = func_registry_find(c->funcs, name);
	if (user_entry) {
		// Size the buffer to the actual argument count so a
		// registered function may take any number of arguments. A
		// small inline buffer covers the common case without a heap
		// allocation; larger calls fall back to malloc.
		RzNumValue inline_args[8];
		uint32_t nargs = function_arg_count(n);
		RzNumValue *args = inline_args;
		if (nargs > RZ_ARRAY_SIZE(inline_args)) {
			args = RZ_NEWS0(RzNumValue, nargs);
			if (!args) {
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
				free(name);
				return val_u64(0);
			}
		}
		int got = eval_function_args(c, n, args, (int)nargs);
		RzNumValue out;
		if (user_entry->arity >= 0 && got != user_entry->arity) {
			set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED,
				"%s expects %d argument%s, got %d",
				name, user_entry->arity,
				user_entry->arity == 1 ? "" : "s", got);
			out = val_u64(0);
		} else {
			RzNumCallbackResult res = { 0 };
			user_entry->fn(user_entry->user, args, got, &res);
			if (!res.ok) {
				set_err_code(c, RZ_NUM_ERR_UNCOMPUTABLE,
					"function %s failed", name);
				out = val_u64(0);
			} else {
				out = value_from_callback_result(&res);
				// Defensive: a well-behaved callback returns a
				// freshly-allocated owning payload, but if it
				// returned one of its argument slots verbatim
				// (aliasing an arg's BIG / BITVECTOR pointer), the
				// arg-cleanup loop below would free the payload the
				// result points at. Disown the matching slot, same
				// as the built-in min/max path does.
				if (out.kind == RZ_NUM_KIND_BIG || out.kind == RZ_NUM_KIND_BITVECTOR) {
					for (int i = 0; i < got; i++) {
						if (args[i].kind == out.kind &&
							args[i].val.big == out.val.big) {
							rz_num_value_init(&args[i]);
							break;
						}
					}
				}
			}
		}
		for (int i = 0; i < got; i++) {
			rz_num_value_fini(&args[i]);
		}
		if (args != inline_args) {
			free(args);
		}
		free(name);
		return out;
	}

	// Look the function up in the built-in table.
	const BuiltinEntry *entry = NULL;
	for (const BuiltinEntry *e = builtin_table; e->name; e++) {
		if (!strcmp(e->name, name)) {
			entry = e;
			break;
		}
	}
	if (!entry) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "unknown function: %s", name);
		free(name);
		return val_u64(0);
	}
	free(name);
	// Size the buffer to the actual argument count. A small inline
	// buffer covers the common case; larger calls (e.g. a variadic
	// built-in) fall back to malloc.
	RzNumValue inline_args[8];
	uint32_t nargs = function_arg_count(n);
	RzNumValue *args = inline_args;
	if (nargs > RZ_ARRAY_SIZE(inline_args)) {
		args = RZ_NEWS0(RzNumValue, nargs);
		if (!args) {
			set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
			return val_u64(0);
		}
	}
	int got = eval_function_args(c, n, args, (int)nargs);
	RzNumValue out;
	if (entry->arity >= 0 && got != entry->arity) {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED,
			"%s expects %d argument%s, got %d",
			entry->name, entry->arity,
			entry->arity == 1 ? "" : "s", got);
		out = val_u64(0);
	} else {
		out = entry->fn(c, args, got);
	}
	// `min` and `max` return one of the input slots verbatim; we
	// need to make sure we don't double-free that slot in the
	// cleanup loop below. Since RzNumBig and RzBitVector are
	// owning pointers, take ownership of the returned value's
	// payload by stealing it from the matching arg slot.
	if (out.kind == RZ_NUM_KIND_BIG || out.kind == RZ_NUM_KIND_BITVECTOR ||
		out.kind == RZ_NUM_KIND_BIGDECIMAL) {
		for (int i = 0; i < got; i++) {
			if (args[i].kind == out.kind && args[i].val.big == out.val.big) {
				// Disown - prevent the cleanup loop from freeing
				// the payload the result is pointing at.
				rz_num_value_init(&args[i]);
				break;
			}
		}
	}
	for (int i = 0; i < got; i++) {
		rz_num_value_fini(&args[i]);
	}
	if (args != inline_args) {
		free(args);
	}
	return out;
}

// Bignum helper: run a 2-arg bignum operation `fn` on the promoted
// versions of lv and rv, wrapping the result in a BIG-kind value and
// then demoting back to UT64 if it now fits. Returns val_u64(0) on
// OOM (rare). The caller is responsible for setting an error if the
// operation has additional preconditions (e.g. nonzero divisor).
typedef void (*big_binop_fn)(RzNumBig *c, RzNumBig *a, RzNumBig *b);

static RzNumValue do_big_binop(EvalCtx *c, const RzNumValue *lv,
	const RzNumValue *rv, big_binop_fn fn) {
	RzNumBig *a = value_to_big(lv);
	RzNumBig *b = value_to_big(rv);
	RzNumBig *r = rz_big_new();
	if (!a || !b || !r) {
		rz_big_free(a);
		rz_big_free(b);
		rz_big_free(r);
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory in bignum operation");
		return val_u64(0);
	}
	fn(r, a, b);
	rz_big_free(a);
	rz_big_free(b);
	RzNumValue out = val_big(r);
	demote_big_if_fits(&out);
	return out;
}

static int big_cmp(const RzNumValue *lv, const RzNumValue *rv) {
	RzNumBig *a = value_to_big(lv);
	RzNumBig *b = value_to_big(rv);
	int r = 0;
	if (a && b) {
		r = rz_big_cmp(a, b);
	}
	rz_big_free(a);
	rz_big_free(b);
	return r;
}

// Exact decimal arithmetic for + - * /. Both operands are converted to
// RzBigDecimal (integers included); + - * are exact and / is bounded to
// RZ_BIG_DECIMAL_DEFAULT_PREC significant digits. A zero divisor is
// reported the same way the other dispatch paths report it.
static RzNumValue do_decimal_binop(EvalCtx *c, const RzNumValue *lv,
	const RzNumValue *rv, char op) {
	RzBigDecimal *a = value_to_bigdecimal(lv);
	RzBigDecimal *b = value_to_bigdecimal(rv);
	if (!a || !b) {
		rz_big_decimal_free(a);
		rz_big_decimal_free(b);
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory in decimal operation");
		return val_u64(0);
	}
	RzNumValue out;
	if (op == '/' && rz_big_decimal_is_zero(b)) {
		if (c->num) {
			c->num->dbz = 1;
		}
		set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "division by zero");
		rz_big_decimal_free(a);
		rz_big_decimal_free(b);
		return val_bigdecimal(rz_big_decimal_new_from_int(0));
	}
	RzBigDecimal *res = NULL;
	switch (op) {
	case '+': res = rz_big_decimal_add(a, b); break;
	case '-': res = rz_big_decimal_sub(a, b); break;
	case '*': res = rz_big_decimal_mul(a, b); break;
	case '/': res = rz_big_decimal_div(a, b, RZ_BIG_DECIMAL_DEFAULT_PREC); break;
	default: break;
	}
	rz_big_decimal_free(a);
	rz_big_decimal_free(b);
	if (!res) {
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory in decimal operation");
		return val_u64(0);
	}
	out = val_bigdecimal(res);
	return out;
}

// Wrap an owned RzBitVector in a value, or report OOM.
static RzNumValue val_bv(EvalCtx *c, RzBitVector *bv) {
	if (!bv) {
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory in bitvector operation");
		return val_u64(0);
	}
	RzNumValue v = { .kind = RZ_NUM_KIND_BITVECTOR, .err = RZ_NUM_ERR_OK };
	v.val.bv = bv;
	return v;
}

// Evaluate a binary operation where at least one operand is a
// bit-vector. Both operands are coerced to the combined width; the
// result is a bit-vector for arithmetic/bitwise ops and a ut64 0/1
// for comparisons. Comparisons use unsigned bit-vector ordering.
static RzNumValue eval_bv_binop(EvalCtx *c, const RzNumValue *lv,
	const RzNumValue *rv, const char *op) {
	ut32 w = combined_bv_width(lv, rv);
	RzBitVector *a = value_to_bv_width(lv, w);
	RzBitVector *b = value_to_bv_width(rv, w);
	if (!a || !b) {
		rz_bv_free(a);
		rz_bv_free(b);
		set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory in bitvector operation");
		return val_u64(0);
	}

	RzNumValue out;
	if (!strcmp(op, "+")) {
		out = val_bv(c, rz_bv_add(a, b, NULL));
	} else if (!strcmp(op, "-")) {
		out = val_bv(c, rz_bv_sub(a, b, NULL));
	} else if (!strcmp(op, "*")) {
		out = val_bv(c, rz_bv_mul(a, b));
	} else if (!strcmp(op, "/")) {
		if (rz_bv_is_zero_vector(b)) {
			set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "division by zero");
			out = val_u64(0);
		} else {
			out = val_bv(c, rz_bv_div(a, b));
		}
	} else if (!strcmp(op, "%")) {
		if (rz_bv_is_zero_vector(b)) {
			set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "modulo by zero");
			out = val_u64(0);
		} else {
			out = val_bv(c, rz_bv_mod(a, b));
		}
	} else if (!strcmp(op, "&")) {
		out = val_bv(c, rz_bv_and(a, b));
	} else if (!strcmp(op, "|")) {
		out = val_bv(c, rz_bv_or(a, b));
	} else if (!strcmp(op, "^")) {
		out = val_bv(c, rz_bv_xor(a, b));
	} else if (!strcmp(op, "<<") || !strcmp(op, ">>")) {
		// Shift amount is the low bits of the right operand as a
		// plain integer; the bit-vector shift is in-place on a copy.
		RzBitVector *res = rz_bv_dup(a);
		if (res) {
			ut32 amount = (ut32)rz_bv_to_ut64(b);
			if (op[0] == '<') {
				rz_bv_lshift(res, amount);
			} else {
				rz_bv_rshift(res, amount);
			}
		}
		out = val_bv(c, res);
	} else if (!strcmp(op, "==")) {
		out = val_u64(rz_bv_eq(a, b) ? 1 : 0);
	} else if (!strcmp(op, "!=")) {
		out = val_u64(rz_bv_eq(a, b) ? 0 : 1);
	} else if (!strcmp(op, "<")) {
		out = val_u64(rz_bv_ule(a, b) && !rz_bv_eq(a, b) ? 1 : 0);
	} else if (!strcmp(op, "<=")) {
		out = val_u64(rz_bv_ule(a, b) ? 1 : 0);
	} else if (!strcmp(op, ">")) {
		out = val_u64(rz_bv_ule(b, a) && !rz_bv_eq(a, b) ? 1 : 0);
	} else if (!strcmp(op, ">=")) {
		out = val_u64(rz_bv_ule(b, a) ? 1 : 0);
	} else if (!strcmp(op, "sdiv")) {
		if (rz_bv_is_zero_vector(b)) {
			set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "division by zero");
			out = val_u64(0);
		} else {
			out = val_bv(c, rz_bv_sdiv(a, b));
		}
	} else if (!strcmp(op, "smod")) {
		if (rz_bv_is_zero_vector(b)) {
			set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "modulo by zero");
			out = val_u64(0);
		} else {
			out = val_bv(c, rz_bv_smod(a, b));
		}
	} else if (!strcmp(op, "sar")) {
		RzBitVector *res = rz_bv_dup(a);
		if (res) {
			ut32 amount = (ut32)rz_bv_to_ut64(b);
			rz_bv_arshift(res, amount);
		}
		out = val_bv(c, res);
	} else if (!strcmp(op, "<<<") || !strcmp(op, ">>>")) {
		// Rotate within the operand width: bits that fall off one end
		// wrap to the other. The shift amount is taken modulo W so a
		// rotate by k full widths is the identity.
		RzBitVector *res = rz_bv_dup(a);
		if (res) {
			ut32 amount = (ut32)(rz_bv_to_ut64(b) % w);
			if (amount > 0) {
				RzBitVector *other = rz_bv_dup(a);
				if (other) {
					if (op[0] == '<') {
						// rol(x, n) = (x << n) | (x >> (W - n))
						rz_bv_lshift(res, amount);
						rz_bv_rshift(other, w - amount);
					} else {
						// ror(x, n) = (x >> n) | (x << (W - n))
						rz_bv_rshift(res, amount);
						rz_bv_lshift(other, w - amount);
					}
					RzBitVector *combined = rz_bv_or(res, other);
					rz_bv_free(res);
					rz_bv_free(other);
					res = combined;
				}
			}
		}
		out = val_bv(c, res);
	} else if (!strcmp(op, "**")) {
		// Power with bit-vector base / exponent, computed at the
		// combined width, all arithmetic modular at W bits. Iterative
		// exponentiation by squaring: this is O(log e) multiplications
		// and stays exact within the width without ever projecting to
		// ut64, so it works correctly for the base. The exponent has
		// to fit a ut64 (so the squaring loop terminates in O(64)
		// steps); a wider exponent is rejected rather than silently
		// truncated.
		if (w > 64) {
			// Check that the high bits of the exponent are all zero.
			RzBitVector *e_dup = rz_bv_dup(b);
			if (e_dup) {
				rz_bv_rshift(e_dup, 64);
				bool too_wide = !rz_bv_is_zero_vector(e_dup);
				rz_bv_free(e_dup);
				if (too_wide) {
					set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED,
						"** exponent does not fit a 64-bit value");
					rz_bv_free(a);
					rz_bv_free(b);
					return val_u64(0);
				}
			}
		}
		ut64 e = rz_bv_to_ut64(b);
		RzBitVector *result = rz_bv_new(w);
		RzBitVector *base = rz_bv_dup(a);
		if (!result || !base) {
			rz_bv_free(result);
			rz_bv_free(base);
			set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
			out = val_u64(0);
		} else {
			rz_bv_set(result, 0, true); // result = 1
			while (e > 0) {
				if (e & 1) {
					RzBitVector *t = rz_bv_mul(result, base);
					rz_bv_free(result);
					result = t;
				}
				e >>= 1;
				if (e) {
					RzBitVector *t = rz_bv_mul(base, base);
					rz_bv_free(base);
					base = t;
				}
			}
			rz_bv_free(base);
			out = val_bv(c, result);
		}
	} else if (!strcmp(op, "log")) {
		// Match the scalar log semantic: log_base(value) = log(value)/
		// log(base), computed in double and reduced back to a
		// bit-vector at the combined width. Loses precision when the
		// width exceeds the mantissa, but stays consistent with the
		// ut64/big paths so a mixed-kind expression behaves
		// predictably.
		double base = (double)rz_bv_to_ut64(a);
		double value = (double)rz_bv_to_ut64(b);
		ut64 r = 0;
		if (base > 1.0 && value > 0.0) {
			double lr = log(value) / log(base);
			if (lr >= 0.0 && lr < (double)UT64_MAX) {
				r = (ut64)lr;
			}
		}
		out = val_bv(c, rz_bv_new_from_ut64(w, r));
	} else {
		// Operations without a natural fixed-width bit-vector meaning
		// (anything not listed above) are reported rather than
		// silently projected to a different kind.
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED,
			"operator '%s' is not defined on bit-vectors", op);
		out = val_u64(0);
	}

	rz_bv_free(a);
	rz_bv_free(b);
	return out;
}

static RzNumValue eval_binop(EvalCtx *c, TSNode n, const char *op) {
	TSNode l = ts_node_child_by_field_name(n, "left", 4);
	TSNode r = ts_node_child_by_field_name(n, "right", 5);
	if (ts_node_is_null(l) || ts_node_is_null(r)) {
		// exponent / logarithm use base/exponent instead
		l = ts_node_child_by_field_name(n, "base", 4);
		r = ts_node_child_by_field_name(n, "exponent", 8);
	}
	RzNumValue lv = eval_node(c, l);
	// For + and -, expose the left operand through the legacy calc
	// state before evaluating the right one. The host callback resolves
	// a `.label` (function-local flag) relative to the value that
	// precedes the operator - e.g. `main + .foo` is main plus the delta
	// of label foo in the function at main. The new evaluator otherwise
	// leaves nc untouched; this just hands the callback the base it
	// expects, matching the legacy left-to-right behaviour.
	if (c->num && op[0] && op[1] == '\0' && (op[0] == '+' || op[0] == '-')) {
		c->num->nc.number_value.n = to_u64(&lv);
		c->num->nc.curr_tok = op[0];
	}
	RzNumValue rv = eval_node(c, r);
	RzNumValue out = val_u64(0);

	// Operator dispatch. Float dominates: if either operand is
	// RZ_NUM_KIND_FLOAT, both are projected to double and the
	// result is float. Otherwise, if either operand is
	// RZ_NUM_KIND_BIG, we route through the bignum API for
	// operations where that makes sense (no overflow loss) and
	// demote back to ut64 if the result fits. Plain ut64 paths
	// match the legacy behaviour bit-for-bit.
	bool float_mode = any_float(&lv, &rv);
	// Exact decimal arithmetic applies when a decimal operand is present
	// and no raw double is mixed in; otherwise the float path projects to
	// double (math-function results, typed float reads, etc.).
	bool decimal_mode = any_bigdecimal(&lv, &rv) && !any_real_float(&lv, &rv);
	bool big_mode = !float_mode && any_big(&lv, &rv);
	bool bv_mode = !float_mode && !big_mode && any_bitvector(&lv, &rv);

	// Bit-vector operands have their own fixed-width semantics
	// (modular at the operand width), so they are handled first and
	// short-circuit the ut64/big/float dispatch below.
	if (bv_mode) {
		out = eval_bv_binop(c, &lv, &rv, op);
		rz_num_value_fini(&lv);
		rz_num_value_fini(&rv);
		return out;
	}

	if (!strcmp(op, "+")) {
		if (decimal_mode) {
			out = do_decimal_binop(c, &lv, &rv, '+');
		} else if (float_mode) {
			out = val_f64(to_double(&lv) + to_double(&rv));
		} else if (big_mode) {
			out = do_big_binop(c, &lv, &rv, rz_big_add);
		} else {
			out = val_u64(lv.val.n + rv.val.n);
		}
	} else if (!strcmp(op, "-")) {
		if (decimal_mode) {
			out = do_decimal_binop(c, &lv, &rv, '-');
		} else if (float_mode) {
			out = val_f64(to_double(&lv) - to_double(&rv));
		} else if (big_mode) {
			out = do_big_binop(c, &lv, &rv, rz_big_sub);
		} else {
			out = val_u64(lv.val.n - rv.val.n);
		}
	} else if (!strcmp(op, "*")) {
		if (decimal_mode) {
			out = do_decimal_binop(c, &lv, &rv, '*');
		} else if (float_mode) {
			out = val_f64(to_double(&lv) * to_double(&rv));
		} else if (big_mode) {
			out = do_big_binop(c, &lv, &rv, rz_big_mul);
		} else {
			out = val_u64(lv.val.n * rv.val.n);
		}
	} else if (!strcmp(op, "/")) {
		if (decimal_mode) {
			out = do_decimal_binop(c, &lv, &rv, '/');
		} else if (float_mode) {
			double rd = to_double(&rv);
			if (rd == 0.0) {
				if (c->num) {
					c->num->dbz = 1;
				}
				set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "division by zero");
				out = val_f64(0.0);
			} else {
				out = val_f64(to_double(&lv) / rd);
			}
		} else if (big_mode) {
			// Zero divisor: bignum API does not define behaviour,
			// so guard here.
			if (rv.kind == RZ_NUM_KIND_UT64 && rv.val.n == 0) {
				if (c->num) {
					c->num->dbz = 1;
				}
				set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "division by zero");
				out = val_u64(0);
			} else {
				out = do_big_binop(c, &lv, &rv, rz_big_div);
			}
		} else if (rv.val.n == 0) {
			if (c->num) {
				c->num->dbz = 1;
			}
			set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "division by zero");
			out = val_u64(0);
		} else {
			out = val_u64(lv.val.n / rv.val.n);
		}
	} else if (!strcmp(op, "%")) {
		if (float_mode) {
			double rd = to_double(&rv);
			if (rd == 0.0) {
				set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "modulo by zero");
				out = val_f64(0.0);
			} else {
				out = val_f64(fmod(to_double(&lv), rd));
			}
		} else if (big_mode) {
			if (rv.kind == RZ_NUM_KIND_UT64 && rv.val.n == 0) {
				set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "modulo by zero");
				out = val_u64(0);
			} else {
				out = do_big_binop(c, &lv, &rv, rz_big_mod);
			}
		} else if (rv.val.n == 0) {
			set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "modulo by zero");
			out = val_u64(0);
		} else {
			out = val_u64(lv.val.n % rv.val.n);
		}
	} else if (!strcmp(op, "sdiv")) {
		// Signed (two's-complement) division. Operands are taken as
		// st64; the result is stored back as ut64 (its bit pattern).
		// Bignum / float operands are not supported for the signed
		// word operators - they project to st64 first.
		st64 a = (st64)to_u64(&lv);
		st64 b = (st64)to_u64(&rv);
		if (b == 0) {
			if (c->num) {
				c->num->dbz = 1;
			}
			set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "division by zero");
			out = val_u64(0);
		} else if (a == INT64_MIN && b == -1) {
			// INT64_MIN / -1 overflows st64; the wrapped two's
			// complement result is INT64_MIN again.
			out = val_u64((ut64)INT64_MIN);
		} else {
			out = val_u64((ut64)(a / b));
		}
	} else if (!strcmp(op, "smod")) {
		st64 a = (st64)to_u64(&lv);
		st64 b = (st64)to_u64(&rv);
		if (b == 0) {
			set_err_code(c, RZ_NUM_ERR_DIV_ZERO, "modulo by zero");
			out = val_u64(0);
		} else if (a == INT64_MIN && b == -1) {
			out = val_u64(0); // remainder of the overflowing division
		} else {
			out = val_u64((ut64)(a % b));
		}
	} else if (!strcmp(op, "sar")) {
		// Arithmetic shift right: sign-propagating. The shift amount
		// is the low 6 bits of the RHS (matching << / >> semantics);
		// a shift of 64 or more saturates to the sign bit.
		st64 a = (st64)to_u64(&lv);
		ut64 sh = to_u64(&rv);
		if (sh >= 64) {
			out = val_u64((ut64)(a >> 63)); // all sign bits
		} else {
			out = val_u64((ut64)(a >> sh));
		}
	} else if (!strcmp(op, "**")) {
		// Power. Both operands are read as signed, the same way a
		// leading '-' is negation everywhere else in the language:
		// -76 ** 2 is (-76)^2 == 5776, not (2^64-76)^2.
		//
		// The result is an exact integer (promoting to a bignum) when
		// both operands are integer-kind AND the exponent is a
		// non-negative integer of bounded size; rz_big_pow squares and
		// multiplies through a signed bignum, so a negative base with
		// an odd exponent stays negative ((-25)^3 == -15625).
		//
		// A negative exponent makes the result fractional (x^-n is
		// 1/x^n), and a float operand makes it inexact, so both take
		// the double-precision pow() path with signed operands. The
		// exponent bound (4096) keeps a hostile 2 ** 1000000 from
		// materialising a megabit-wide bignum; past it we defer to the
		// (lossy but bounded) double path.
		bool lv_int = (lv.kind == RZ_NUM_KIND_UT64 || lv.kind == RZ_NUM_KIND_BIG);
		bool rv_int = (rv.kind == RZ_NUM_KIND_UT64 || rv.kind == RZ_NUM_KIND_BIG);

		// Exponent magnitude for the exact path. exp_ok is set only for
		// a non-negative integer exponent; a negative one falls through
		// to the double path below.
		bool exp_ok = false;
		ut64 exp = 0;
		if (rv_int && !value_int_is_negative(&rv)) {
			if (rv.kind == RZ_NUM_KIND_UT64) {
				exp = rv.val.n;
				exp_ok = true;
			} else {
				// Non-negative BIG exponent. rz_big_to_int saturates
				// past st64, which the magnitude check below rejects.
				st64 e = rz_big_to_int(rv.val.big);
				if (e >= 0) {
					exp = (ut64)e;
					exp_ok = true;
				}
			}
		}
		// The exact bignum path is only safe if the result actually
		// fits the fixed bignum width. |base| ** exp needs about
		// magnitude_bit_width(base) * exp bits; if that reaches the
		// bignum ceiling, rz_big_pow would silently overflow (e.g.
		// 2 ** 4096 is 4097 bits wide), so defer to the double path.
		bool result_fits = false;
		if (lv_int && exp_ok && exp <= 4096) {
			ut32 base_bits = value_int_bit_width(&lv); // of |base|
			if (base_bits <= 1) {
				// base is 0 or +-1: result is 0 or +-1, always fits.
				result_fits = true;
			} else {
				// The result has ceil(exp * log2(|base|)) bits, and
				// log2(|base|) lies in (base_bits - 1, base_bits]. The
				// bound exp * (base_bits - 1) + 1 is exact when |base|
				// is a power of two and an upper bound otherwise, so it
				// neither rejects values that fit (e.g. 2 ** 4095, which
				// is 4096 bits) nor accepts one that would overflow.
				ut64 result_bits = (ut64)exp * (base_bits - 1) + 1;
				result_fits = (result_bits <= RZ_BIG_MAX_BITS);
			}
		}
		if (result_fits) {
			RzNumBig *base = value_to_big_signed(&lv);
			RzNumBig *e = big_from_u64(exp);
			RzNumBig *r = rz_big_new();
			if (!base || !e || !r) {
				rz_big_free(base);
				rz_big_free(e);
				rz_big_free(r);
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY,
					"out of memory in bignum power");
				out = val_u64(0);
			} else {
				rz_big_pow(r, base, e);
				rz_big_free(base);
				rz_big_free(e);
				out = val_big(r);
				demote_big_if_fits(&out);
			}
		} else {
			// Negative exponent, an oversized exact result, or a float
			// operand: evaluate in double precision with signed
			// operands. pow() gives the right value for a negative base
			// with an integer exponent (e.g. (-2) ** -1 == -0.5) and
			// NaN for a negative base with a fractional one, which is
			// the correct real-valued answer.
			out = val_f64(pow(to_double_signed(&lv), to_double_signed(&rv)));
		}
	} else if (!strcmp(op, "log")) {
		double base = to_double(&lv);
		double arg = to_double(&rv);
		if (base <= 0.0 || base == 1.0 || arg <= 0.0) {
			set_err_code(c, RZ_NUM_ERR_UNCOMPUTABLE, "invalid argument to log");
			out = val_f64(0.0);
		} else {
			out = val_f64(log(arg) / log(base));
		}
	} else if (!strcmp(op, "&")) {
		if (big_mode) {
			out = do_big_binop(c, &lv, &rv, rz_big_and);
		} else {
			out = val_u64(to_u64(&lv) & to_u64(&rv));
		}
	} else if (!strcmp(op, "|")) {
		if (big_mode) {
			out = do_big_binop(c, &lv, &rv, rz_big_or);
		} else {
			out = val_u64(to_u64(&lv) | to_u64(&rv));
		}
	} else if (!strcmp(op, "^")) {
		if (big_mode) {
			out = do_big_binop(c, &lv, &rv, rz_big_xor);
		} else {
			out = val_u64(to_u64(&lv) ^ to_u64(&rv));
		}
	} else if (!strcmp(op, "<<")) {
		// Shifts on big operands route through rz_big_lshift which
		// accepts an arbitrary shift count. Plain ut64 shifts mask
		// to 6 bits to match the legacy parser.
		if (big_mode) {
			size_t s = (size_t)to_u64(&rv);
			RzNumBig *a = value_to_big(&lv);
			RzNumBig *rr = rz_big_new();
			if (!a || !rr) {
				rz_big_free(a);
				rz_big_free(rr);
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory in bignum shift");
				out = val_u64(0);
			} else {
				rz_big_lshift(rr, a, s);
				rz_big_free(a);
				out = val_big(rr);
				demote_big_if_fits(&out);
			}
		} else {
			ut64 s = to_u64(&rv) & 63;
			out = val_u64(to_u64(&lv) << s);
		}
	} else if (!strcmp(op, ">>")) {
		if (big_mode) {
			size_t s = (size_t)to_u64(&rv);
			RzNumBig *a = value_to_big(&lv);
			RzNumBig *rr = rz_big_new();
			if (!a || !rr) {
				rz_big_free(a);
				rz_big_free(rr);
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory in bignum shift");
				out = val_u64(0);
			} else {
				rz_big_rshift(rr, a, s);
				rz_big_free(a);
				out = val_big(rr);
				demote_big_if_fits(&out);
			}
		} else {
			ut64 s = to_u64(&rv) & 63;
			out = val_u64(to_u64(&lv) >> s);
		}
	} else if (!strcmp(op, "<<<")) {
		// Rotations have no obvious bignum semantics (they require a
		// fixed bit-width), so always evaluate them on the ut64
		// projection of the operands.
		ut64 v = to_u64(&lv);
		ut64 s = to_u64(&rv) & 63;
		out = val_u64(s ? (v << s) | (v >> (64 - s)) : v);
	} else if (!strcmp(op, ">>>")) {
		ut64 v = to_u64(&lv);
		ut64 s = to_u64(&rv) & 63;
		out = val_u64(s ? (v >> s) | (v << (64 - s)) : v);
	} else if (!strcmp(op, "<")) {
		if (float_mode) {
			out = val_u64(to_double(&lv) < to_double(&rv) ? 1 : 0);
		} else if (big_mode) {
			out = val_u64(big_cmp(&lv, &rv) < 0 ? 1 : 0);
		} else {
			out = val_u64(lv.val.n < rv.val.n ? 1 : 0);
		}
	} else if (!strcmp(op, "<=")) {
		if (float_mode) {
			out = val_u64(to_double(&lv) <= to_double(&rv) ? 1 : 0);
		} else if (big_mode) {
			out = val_u64(big_cmp(&lv, &rv) <= 0 ? 1 : 0);
		} else {
			out = val_u64(lv.val.n <= rv.val.n ? 1 : 0);
		}
	} else if (!strcmp(op, ">")) {
		if (float_mode) {
			out = val_u64(to_double(&lv) > to_double(&rv) ? 1 : 0);
		} else if (big_mode) {
			out = val_u64(big_cmp(&lv, &rv) > 0 ? 1 : 0);
		} else {
			out = val_u64(lv.val.n > rv.val.n ? 1 : 0);
		}
	} else if (!strcmp(op, ">=")) {
		if (float_mode) {
			out = val_u64(to_double(&lv) >= to_double(&rv) ? 1 : 0);
		} else if (big_mode) {
			out = val_u64(big_cmp(&lv, &rv) >= 0 ? 1 : 0);
		} else {
			out = val_u64(lv.val.n >= rv.val.n ? 1 : 0);
		}
	} else if (!strcmp(op, "==")) {
		if (float_mode) {
			out = val_u64(to_double(&lv) == to_double(&rv) ? 1 : 0);
		} else if (big_mode) {
			out = val_u64(big_cmp(&lv, &rv) == 0 ? 1 : 0);
		} else {
			out = val_u64(lv.val.n == rv.val.n ? 1 : 0);
		}
	} else if (!strcmp(op, "!=")) {
		if (float_mode) {
			out = val_u64(to_double(&lv) != to_double(&rv) ? 1 : 0);
		} else if (big_mode) {
			out = val_u64(big_cmp(&lv, &rv) != 0 ? 1 : 0);
		} else {
			out = val_u64(lv.val.n != rv.val.n ? 1 : 0);
		}
	} else {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "unhandled operator: %s", op);
	}
	rz_num_value_fini(&lv);
	rz_num_value_fini(&rv);
	return out;
}

static RzNumValue eval_unop_right(EvalCtx *c, TSNode n, const char *op) {
	TSNode r = ts_node_child_by_field_name(n, "right", 5);
	RzNumValue rv = eval_node(c, r);
	RzNumValue out;
	if (!strcmp(op, "~")) {
		// Bitwise NOT has no width-independent meaning on a bignum;
		// project to ut64 here. This matches the legacy behaviour
		// and is documented as a known asymmetry: ~ on a bignum
		// gives a ut64 result, while + - * etc. preserve bignum.
		out = val_u64(~to_u64(&rv));
	} else if (!strcmp(op, "!")) {
		// Logical not: 1 for a falsy value, 0 otherwise. A zero of any
		// kind (including float -0 and an exact decimal zero) is falsy.
		out = val_u64(value_is_truthy(&rv) ? 0 : 1);
	} else if (!strcmp(op, "++")) {
		if (rv.kind == RZ_NUM_KIND_FLOAT) {
			out = val_f64(rv.val.d + 1.0);
		} else if (rv.kind == RZ_NUM_KIND_BIGDECIMAL) {
			RzBigDecimal *one = rz_big_decimal_new_from_int(1);
			RzBigDecimal *res = one ? rz_big_decimal_add(rv.val.bigdec, one) : NULL;
			rz_big_decimal_free(one);
			out = res ? val_bigdecimal(res) : val_u64(0);
		} else if (rv.kind == RZ_NUM_KIND_BIG) {
			RzNumBig *nb = rz_big_new();
			if (!nb) {
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
				out = val_u64(0);
			} else {
				rz_big_assign(nb, rv.val.big);
				rz_big_inc(nb);
				out = val_big(nb);
				demote_big_if_fits(&out);
			}
		} else {
			out = val_u64(to_u64(&rv) + 1);
		}
	} else if (!strcmp(op, "--")) {
		if (rv.kind == RZ_NUM_KIND_FLOAT) {
			out = val_f64(rv.val.d - 1.0);
		} else if (rv.kind == RZ_NUM_KIND_BIGDECIMAL) {
			RzBigDecimal *one = rz_big_decimal_new_from_int(1);
			RzBigDecimal *res = one ? rz_big_decimal_sub(rv.val.bigdec, one) : NULL;
			rz_big_decimal_free(one);
			out = res ? val_bigdecimal(res) : val_u64(0);
		} else if (rv.kind == RZ_NUM_KIND_BIG) {
			RzNumBig *nb = rz_big_new();
			if (!nb) {
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
				out = val_u64(0);
			} else {
				rz_big_assign(nb, rv.val.big);
				rz_big_dec(nb);
				out = val_big(nb);
				demote_big_if_fits(&out);
			}
		} else {
			out = val_u64(to_u64(&rv) - 1);
		}
	} else if (!strcmp(op, "u+")) {
		// Unary plus: identity, preserves kind.
		if (rv.kind == RZ_NUM_KIND_FLOAT) {
			out = val_f64(rv.val.d);
		} else if (rv.kind == RZ_NUM_KIND_BIGDECIMAL) {
			RzBigDecimal *res = rv.val.bigdec ? rz_big_decimal_dup(rv.val.bigdec) : NULL;
			out = res ? val_bigdecimal(res) : val_u64(0);
		} else if (rv.kind == RZ_NUM_KIND_BIG) {
			RzNumBig *nb = rz_big_new();
			if (!nb) {
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
				out = val_u64(0);
			} else {
				rz_big_assign(nb, rv.val.big);
				out = val_big(nb);
				demote_big_if_fits(&out);
			}
		} else {
			out = val_u64(to_u64(&rv));
		}
	} else if (!strcmp(op, "u-")) {
		// Unary minus.
		if (rv.kind == RZ_NUM_KIND_FLOAT) {
			out = val_f64(-rv.val.d);
		} else if (rv.kind == RZ_NUM_KIND_BIGDECIMAL) {
			RzBigDecimal *res = rv.val.bigdec ? rz_big_decimal_neg(rv.val.bigdec) : NULL;
			out = res ? val_bigdecimal(res) : val_u64(0);
		} else if (rv.kind == RZ_NUM_KIND_BIG) {
			// rz_big has no dedicated negate; compute it as
			// `zero - x`.
			RzNumBig *zero = rz_big_new();
			RzNumBig *nb = rz_big_new();
			if (!zero || !nb) {
				rz_big_free(zero);
				rz_big_free(nb);
				set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
				out = val_u64(0);
			} else {
				rz_big_from_int(zero, 0);
				rz_big_sub(nb, zero, rv.val.big);
				rz_big_free(zero);
				out = val_big(nb);
				demote_big_if_fits(&out);
			}
		} else {
			out = val_u64((ut64)(-(st64)to_u64(&rv)));
		}
	} else {
		set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "unhandled unary operator: %s", op);
		out = val_u64(0);
	}
	rz_num_value_fini(&rv);
	return out;
}

// The depth-guarded recursive body; eval_node() below wraps it.
static RzNumValue eval_node_inner(EvalCtx *c, TSNode n);

// Cap on the tree-walk recursion depth. eval_node() recurses once per
// nesting level, and a left-associative chain such as "1+1+...+1" nests
// one binary_expression per term, so a few thousand terms would exhaust
// a small thread stack (Windows defaults to 1 MB) and crash the process.
// Report a clean error past the cap instead of overflowing. 256 is far
// beyond any realistic hand-written expression yet stays well within the
// smallest stack we run on.
#define RZ_NUM_MAX_EVAL_DEPTH 256

static RzNumValue eval_node(EvalCtx *c, TSNode n) {
	if (c->depth >= RZ_NUM_MAX_EVAL_DEPTH) {
		// Pin the first error; an already-recorded one (e.g. a timeout)
		// keeps priority and the short-circuit below unwinds the stack.
		if (!c->err) {
			set_err_code(c, RZ_NUM_ERR_DEPTH,
				"expression nesting exceeds the evaluator depth limit");
		}
		return val_u64(0);
	}
	c->depth++;
	RzNumValue v = eval_node_inner(c, n);
	c->depth--;
	return v;
}

static RzNumValue eval_node_inner(EvalCtx *c, TSNode n) {
	// Cheap-amortised deadline check. Calling rz_time_now_mono() on
	// every node would be measurable overhead for small expressions;
	// we only check every 256 nodes plus on entry. The mask is a
	// power of two so the predicate compiles down to an AND. The
	// outer check on deadline_us also skips the increment + AND in
	// the common case of no timeout configured.
	if (c->deadline_us != 0 && (c->node_count++ & 0xff) == 0) {
		if (rz_time_now_mono() >= c->deadline_us) {
			set_err_code(c, RZ_NUM_ERR_TIMEOUT,
				"evaluation exceeded the configured timeout");
			return val_u64(0);
		}
	}
	// Once an error has been recorded, short-circuit further work.
	// This both makes timeout failure terminate promptly and keeps
	// the diagnostic pinned to the first issue rather than a
	// cascade of follow-on errors from operating on bad values.
	if (c->err) {
		return val_u64(0);
	}
	// A top-level `expression` may be a ';'-separated sequence: one or
	// more sub-expressions whose value is that of the last. Evaluate
	// each in order (so bindings established by earlier statements are
	// visible to later ones) and return the final value. A single
	// sub-expression falls through to skip_wrappers as before.
	if (ts_node_symbol(n) == g_sym.sym_expression &&
		ts_node_named_child_count(n) > 1) {
		uint32_t count = ts_node_named_child_count(n);
		RzNumValue last = val_u64(0);
		for (uint32_t i = 0; i < count; i++) {
			rz_num_value_fini(&last);
			last = eval_node(c, ts_node_named_child(n, i));
			if (c->err) {
				return last;
			}
		}
		return last;
	}
	n = skip_wrappers(n);
	// Dispatch on TSSymbol rather than ts_node_type() string. The
	// cache is populated lazily once per process; see the comment
	// at SymCache above for the thread-safety reasoning.
	TSSymbol s = ts_node_symbol(n);
	if (s == g_sym.sym_number)
		return eval_number(c, n);
	if (s == g_sym.sym_variable)
		return eval_variable(c, n);
	if (s == g_sym.sym_special_variable)
		return eval_special_variable(c, n);
	if (s == g_sym.sym_address_typed)
		return eval_address_typed(c, n);
	if (s == g_sym.sym_string_bytes)
		return eval_string_bytes(c, n);
	if (s == g_sym.sym_function)
		return eval_function(c, n);
	if (s == g_sym.sym_sum)
		return eval_binop(c, n, "+");
	if (s == g_sym.sym_subtraction)
		return eval_binop(c, n, "-");
	if (s == g_sym.sym_product)
		return eval_binop(c, n, "*");
	if (s == g_sym.sym_division)
		return eval_binop(c, n, "/");
	if (s == g_sym.sym_signed_division)
		return eval_binop(c, n, "sdiv");
	if (s == g_sym.sym_modulo)
		return eval_binop(c, n, "%");
	if (s == g_sym.sym_signed_modulo)
		return eval_binop(c, n, "smod");
	if (s == g_sym.sym_exponent)
		return eval_binop(c, n, "**");
	if (s == g_sym.sym_logarithm)
		return eval_binop(c, n, "log");
	if (s == g_sym.sym_logical_and)
		return eval_binop(c, n, "&");
	if (s == g_sym.sym_logical_or)
		return eval_binop(c, n, "|");
	if (s == g_sym.sym_logical_xor)
		return eval_binop(c, n, "^");
	if (s == g_sym.sym_logical_shl)
		return eval_binop(c, n, "<<");
	if (s == g_sym.sym_logical_shr)
		return eval_binop(c, n, ">>");
	if (s == g_sym.sym_arith_shr)
		return eval_binop(c, n, "sar");
	if (s == g_sym.sym_logical_rol)
		return eval_binop(c, n, "<<<");
	if (s == g_sym.sym_logical_ror)
		return eval_binop(c, n, ">>>");
	if (s == g_sym.sym_less_than)
		return eval_binop(c, n, "<");
	if (s == g_sym.sym_less_equal)
		return eval_binop(c, n, "<=");
	if (s == g_sym.sym_greater_than)
		return eval_binop(c, n, ">");
	if (s == g_sym.sym_greater_equal)
		return eval_binop(c, n, ">=");
	if (s == g_sym.sym_equal)
		return eval_binop(c, n, "==");
	if (s == g_sym.sym_not_equal)
		return eval_binop(c, n, "!=");
	if (s == g_sym.sym_logical_negation)
		return eval_unop_right(c, n, "~");
	if (s == g_sym.sym_logical_not)
		return eval_unop_right(c, n, "!");
	if (s == g_sym.sym_increment)
		return eval_unop_right(c, n, "++");
	if (s == g_sym.sym_decrement)
		return eval_unop_right(c, n, "--");
	if (s == g_sym.sym_unary_plus)
		return eval_unop_right(c, n, "u+");
	if (s == g_sym.sym_unary_minus)
		return eval_unop_right(c, n, "u-");
	if (s == g_sym.sym_conditional) {
		// Ternary: evaluate the condition, then evaluate ONLY the
		// taken branch. Short-circuiting matters for correctness as
		// well as cost: `b != 0 ? a / b : 0` must not evaluate the
		// division when b is zero.
		TSNode cond = ts_node_child_by_field_name(n, "condition", 9);
		RzNumValue cv = eval_node(c, cond);
		if (c->err) {
			return cv;
		}
		bool take = value_is_truthy(&cv);
		rz_num_value_fini(&cv);
		TSNode branch = take
			? ts_node_child_by_field_name(n, "consequence", 11)
			: ts_node_child_by_field_name(n, "alternative", 11);
		return eval_node(c, branch);
	}
	if (s == g_sym.sym_assignment || s == g_sym.sym_let_assignment) {
		// Evaluate the RHS, bind it to the LHS variable name in the
		// local store, and return the value. The binding persists
		// for the remainder of this evaluation, so a later
		// sub-expression (or a chained `;`-free compound, once the
		// grammar grows one) can read it back. The store is created
		// lazily on first assignment.
		TSNode l = ts_node_child_by_field_name(n, "left", 4);
		TSNode r = ts_node_child_by_field_name(n, "right", 5);
		RzNumValue rhs = eval_node(c, r);
		if (c->err) {
			return rhs;
		}
		char *name = node_text(l, c->src);
		if (!name) {
			set_err_code(c, RZ_NUM_ERR_OUT_OF_MEMORY, "out of memory");
			return rhs;
		}
		if (is_reserved_word(name)) {
			set_err_code(c, RZ_NUM_ERR_RESERVED_WORD,
				"reserved word '%s' cannot be assigned", name);
			free(name);
			return rhs;
		}
		if (!c->vars) {
			c->vars = ht_sp_new(HT_STR_DUP, NULL, value_store_free);
			c->vars_owned = true;
		}
		if (c->vars) {
			RzNumValue *stored = value_dup_heap(&rhs);
			if (stored) {
				// ht_sp_update replaces an existing binding, freeing
				// the old value via value_store_free.
				ht_sp_update(c->vars, name, stored);
			}
		}
		free(name);
		return rhs;
	}
	set_err_code(c, RZ_NUM_ERR_NOT_IMPLEMENTED, "unhandled node type: %s",
		ts_node_type(n));
	return val_u64(0);
}

// Public entry point

/**
 * \brief Evaluate a numerical expression with full type awareness.
 *
 * Unlike rz_num_math_ut64() this entry point reports the kind of the
 * result (ut64 / float / bit-vector / big number). Out-of-band errors
 * are reported through \p error_msg.
 *
 * \param num         RzNum instance used for the variable resolution
 *                    callback.
 * \param expr        The expression to evaluate.
 * \param out_value   Out-parameter receiving the evaluated value.
 *                    The caller must finalise it with
 *                    rz_num_value_fini() once done.
 * \param error_msg   Set to a diagnostic string on a parse or
 *                    evaluation error.
 * \return true on success, false on parse or evaluation error.
 */
RZ_API bool rz_num_math_value(RZ_NULLABLE RzNum *num, RZ_NONNULL const char *expr,
	RZ_OUT RZ_NONNULL RzNumValue *out_value, RZ_OUT RZ_NULLABLE char **error_msg) {
	return rz_num_math_value_ex(num, expr, NULL, out_value, error_msg);
}

/**
 * \brief Same as rz_num_math_value() but accepts an options struct.
 *
 * Use this entry point when you need to set a wall-clock evaluation
 * timeout. Passing NULL for \p options is equivalent to calling
 * rz_num_math_value().
 */
RZ_API bool rz_num_math_value_ex(RZ_NULLABLE RzNum *num, RZ_NONNULL const char *expr,
	RZ_NULLABLE const RzNumMathOptions *options,
	RZ_OUT RZ_NONNULL RzNumValue *out_value, RZ_OUT RZ_NULLABLE char **error_msg) {
	rz_return_val_if_fail(expr && out_value, false);
	rz_num_value_init(out_value);

	RzNumParseResult *pr = rz_num_parse(expr);
	if (!pr) {
		out_value->err = RZ_NUM_ERR_OUT_OF_MEMORY;
		if (error_msg) {
			*error_msg = rz_str_dup("rz_num_parse: out of memory");
		}
		return false;
	}
	if (pr->has_error) {
		// Distinguish empty-input from a real syntax error so
		// callers (in particular rz_num_math_ut64()'s legacy
		// fall-through path) can give the empty case the silent
		// treatment.
		const char *msg = pr->error_msg ? pr->error_msg : "parse error";
		out_value->err = strstr(msg, "empty expression")
			? RZ_NUM_ERR_EMPTY
			: RZ_NUM_ERR_PARSE;
		if (error_msg) {
			*error_msg = rz_str_dup(msg);
		}
		rz_num_parse_result_free(pr);
		return false;
	}

	TSNode root = rz_num_parse_root(pr);
	// Warm the shared grammar symbol cache before the evaluation loop
	// (lazily populated on first use; see rz_num_parse_syms()).
	(void)rz_num_parse_syms();
	ut64 deadline = 0;
	if (options && options->timeout_ms > 0) {
		deadline = rz_time_now_mono() + options->timeout_ms * 1000;
	}
	EvalCtx ctx = {
		.num = num,
		.src = rz_num_parse_source(pr),
		.err = NULL,
		.err_code = RZ_NUM_ERR_OK,
		.deadline_us = deadline,
		.node_count = 0,
		.depth = 0,
		.funcs = options ? options->funcs : NULL,
		.io_read = options ? options->io_read : NULL,
		.io_read_user = options ? options->io_read_user : NULL,
		// If the caller supplied a persistent store, use it directly
		// (bindings survive across calls) and do not free it here.
		// Otherwise bindings live in a per-evaluation store created
		// lazily on first assignment and freed below.
		.vars = options ? options->vars : NULL,
		.vars_owned = false,
	};
	RzNumValue v = eval_node(&ctx, root);
	bool ok = ctx.err == NULL;
	if (!ok) {
		// Evaluation failed. Stamp the category onto the output
		// value and surface the textual diagnostic. The numeric
		// payload (kind / val) carries the partial result; tests
		// can inspect it but most callers should treat the value
		// as undefined when out_value->err != RZ_NUM_ERR_OK.
		rz_num_value_fini(&v);
		out_value->err = ctx.err_code;
		if (error_msg) {
			*error_msg = ctx.err;
		} else {
			free(ctx.err);
		}
	} else {
		*out_value = v;
		out_value->err = RZ_NUM_ERR_OK;
	}
	if (ctx.vars_owned) {
		ht_sp_free(ctx.vars);
	}
	rz_num_parse_result_free(pr);
	return ok;
}
// Persistent variable store

/**
 * \brief Create a persistent variable store for rz_num_math_value_ex().
 *
 * Pass the returned handle via RzNumMathOptions.vars to make variable
 * bindings (`x = expr`, `let x = expr`) survive across evaluations.
 * Free it with rz_num_value_store_free(). Returns NULL on allocation
 * failure.
 */
RZ_API RZ_OWN HtSP *rz_num_value_store_new(void) {
	// String key (duplicated) -> heap RzNumValue* (freed on removal).
	// Matches the per-evaluation store the evaluator builds lazily, so
	// a caller-supplied store is interchangeable with it.
	return ht_sp_new(HT_STR_DUP, NULL, value_store_free);
}

/**
 * \brief Free a variable store created by rz_num_value_store_new().
 */
RZ_API void rz_num_value_store_free(RZ_NULLABLE HtSP *store) {
	ht_sp_free(store);
}
