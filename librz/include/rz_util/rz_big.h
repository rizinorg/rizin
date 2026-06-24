#ifndef RZ_BIG_H
#define RZ_BIG_H

#include "../rz_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if HAVE_LIB_GMP
/* Use GMP's data struct */
#define RzNumBig mpz_t
#elif HAVE_LIB_SSL
#define RzNumBig BIGNUM
#else
/* Use default impl */
#define RZ_BIG_WORD_SIZE          4
/* Let's support 4096-bit big number */
#define RZ_BIG_ARRAY_SIZE         (512 / RZ_BIG_WORD_SIZE)
/* RZ_BIG_WORD_SIZE == 4, 32 bits long */
#define RZ_BIG_DTYPE              ut32
#define RZ_BIG_DTYPE_TMP          ut64
#define RZ_BIG_SPRINTF_FORMAT_STR "%.08x"
#define RZ_BIG_FORMAT_STR_LEN     9
#define RZ_BIG_SSCANF_FORMAT_STR  "%8x"
#define RZ_BIG_MAX_VAL            (RZ_BIG_DTYPE_TMP) UT32_MAX

typedef struct rz_num_big_t {
	RZ_BIG_DTYPE array[RZ_BIG_ARRAY_SIZE];
	int sign;
} RzNumBig;
#endif

RZ_API RzNumBig *rz_big_new(void);
RZ_API void rz_big_free(RzNumBig *b);
RZ_API void rz_big_init(RzNumBig *b);
RZ_API void rz_big_fini(RzNumBig *b);

/* Assignment operations */
RZ_API void rz_big_from_int(RzNumBig *b, st64 v);
RZ_API st64 rz_big_to_int(RzNumBig *b);
RZ_API void rz_big_from_hexstr(RzNumBig *b, const char *str);
RZ_API char *rz_big_to_hexstr(RzNumBig *b);
RZ_API RZ_OWN char *rz_big_to_decstr(RZ_NONNULL RzNumBig *b); /* Lossless base-10 string */
RZ_API void rz_big_assign(RzNumBig *dst, RzNumBig *src);

/* Basic arithmetic operations */
RZ_API void rz_big_add(RzNumBig *c, RzNumBig *a, RzNumBig *b); /* c = a + b */
RZ_API void rz_big_sub(RzNumBig *c, RzNumBig *a, RzNumBig *b); /* c = a - b */
RZ_API void rz_big_mul(RzNumBig *c, RzNumBig *a, RzNumBig *b); /* c = a * b */
RZ_API void rz_big_div(RzNumBig *c, RzNumBig *a, RzNumBig *b); /* c = a / b */
RZ_API void rz_big_mod(RzNumBig *c, RzNumBig *a, RzNumBig *b); /* c = a % b */
RZ_API void rz_big_divmod(RzNumBig *c, RzNumBig *d, RzNumBig *a, RzNumBig *b); /* c = a/b, d = a%b */

/* Bitwise operations(for >= 0) */
RZ_API void rz_big_and(RzNumBig *c, RzNumBig *a, RzNumBig *b); /* c = a & b */
RZ_API void rz_big_or(RzNumBig *c, RzNumBig *a, RzNumBig *b); /* c = a | b */
RZ_API void rz_big_xor(RzNumBig *c, RzNumBig *a, RzNumBig *b); /* c = a ^ b */
RZ_API void rz_big_lshift(RzNumBig *c, RzNumBig *a, size_t nbits); /* c = a << nbits */
RZ_API void rz_big_rshift(RzNumBig *c, RzNumBig *a, size_t nbits); /* c = a >> nbits */

/* Special operators and comparison */
RZ_API int rz_big_cmp(RzNumBig *a, RzNumBig *b); /* Return 1 if a>b, -1 if a<b, else 0 */
RZ_API int rz_big_is_zero(RzNumBig *a); /* For comparison with zero */
RZ_API void rz_big_inc(RzNumBig *a); /* Increment: add one to n */
RZ_API void rz_big_dec(RzNumBig *a); /* Decrement: subtract one from n */
RZ_API void rz_big_powm(RzNumBig *c, RzNumBig *a, RzNumBig *b, RzNumBig *m); /* Calculate a^b -- e.g. 2^10 => 1024 */
RZ_API void rz_big_pow(RZ_NONNULL RzNumBig *c, RZ_NONNULL RzNumBig *a, RZ_NONNULL RzNumBig *b); /* Non-modular c = a^b */
RZ_API void rz_big_isqrt(RzNumBig *c, RzNumBig *a); /* Integer square root -- e.g. isqrt(5) => 2*/

/* ------------------------------------------------------------------ */
/* Arbitrary-precision base-10 decimal.                                */
/* ------------------------------------------------------------------ */

/**
 * \brief Arbitrary-precision decimal: value == mantissa * 10^(-scale).
 *
 * The sign lives in the mantissa and \p scale is always >= 0, so the
 * value 3.14 is { mantissa = 314, scale = 2 }. Addition, subtraction and
 * multiplication are exact; division is bounded to a caller-chosen number
 * of significant digits (a base-10 decimal cannot represent e.g. 1/3
 * exactly). This is the representation RzNum's value-returning evaluation
 * uses for decimals so that a result keeps full precision instead of
 * collapsing to a double.
 */
typedef struct rz_big_decimal_t {
	RzNumBig *mantissa; ///< signed integer significand (owned)
	st32 scale; ///< number of base-10 fractional digits, always >= 0
} RzBigDecimal;

/** \brief Significant digits kept when dividing (IEEE decimal128 width). */
#define RZ_BIG_DECIMAL_DEFAULT_PREC 34

RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_new_from_str(RZ_NONNULL const char *str);
RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_new_from_int(st64 v);
RZ_API void rz_big_decimal_free(RZ_NULLABLE RzBigDecimal *d);
RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_dup(RZ_NONNULL const RzBigDecimal *d);

RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_add(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b);
RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_sub(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b);
RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_mul(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b);
/** \brief a / b to \p precision significant digits; NULL if b is zero. */
RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_div(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b, ut32 precision);
RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_neg(RZ_NONNULL const RzBigDecimal *a);

RZ_API int rz_big_decimal_cmp(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b);
RZ_API bool rz_big_decimal_is_zero(RZ_NONNULL const RzBigDecimal *d);

RZ_API RZ_OWN char *rz_big_decimal_to_str(RZ_NONNULL const RzBigDecimal *d);
RZ_API ut64 rz_big_decimal_to_ut64(RZ_NONNULL const RzBigDecimal *d);
RZ_API double rz_big_decimal_to_double(RZ_NONNULL const RzBigDecimal *d);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BIG_H
