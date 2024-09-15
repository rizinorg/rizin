#ifndef RZ_BIG_H
#define RZ_BIG_H

#include "<rz_types.h>"

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
RZ_API void rz_big_isqrt(RzNumBig *c, RzNumBig *a); /* Integer square root -- e.g. isqrt(5) => 2*/

#ifdef __cplusplus
}
#endif

#endif //  RZ_BIG_H
