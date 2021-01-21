#ifndef RZ_BIG_H
#define RZ_BIG_H

#include "../rz_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if HAVE_LIB_GMP
/* Use GMP's data struct */
#define RNumBig mpz_t
#elif HAVE_LIB_SSL
#define RNumBig BIGNUM
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
} RNumBig;
#endif

RZ_API RNumBig *rz_big_new(void);
RZ_API void rz_big_free(RNumBig *b);
RZ_API void rz_big_init(RNumBig *b);
RZ_API void rz_big_fini(RNumBig *b);

/* Assignment operations */
RZ_API void rz_big_from_int(RNumBig *b, st64 v);
RZ_API st64 rz_big_to_int(RNumBig *b);
RZ_API void rz_big_from_hexstr(RNumBig *b, const char *str);
RZ_API char *rz_big_to_hexstr(RNumBig *b);
RZ_API void rz_big_assign(RNumBig *dst, RNumBig *src);

/* Basic arithmetic operations */
RZ_API void rz_big_add(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a + b */
RZ_API void rz_big_sub(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a - b */
RZ_API void rz_big_mul(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a * b */
RZ_API void rz_big_div(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a / b */
RZ_API void rz_big_mod(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a % b */
RZ_API void rz_big_divmod(RNumBig *c, RNumBig *d, RNumBig *a, RNumBig *b); /* c = a/b, d = a%b */

/* Bitwise operations(for >= 0) */
RZ_API void rz_big_and(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a & b */
RZ_API void rz_big_or(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a | b */
RZ_API void rz_big_xor(RNumBig *c, RNumBig *a, RNumBig *b); /* c = a ^ b */
RZ_API void rz_big_lshift(RNumBig *c, RNumBig *a, size_t nbits); /* c = a << nbits */
RZ_API void rz_big_rshift(RNumBig *c, RNumBig *a, size_t nbits); /* c = a >> nbits */

/* Special operators and comparison */
RZ_API int rz_big_cmp(RNumBig *a, RNumBig *b); /* Return 1 if a>b, -1 if a<b, else 0 */
RZ_API int rz_big_is_zero(RNumBig *a); /* For comparison with zero */
RZ_API void rz_big_inc(RNumBig *a); /* Increment: add one to n */
RZ_API void rz_big_dec(RNumBig *a); /* Decrement: subtract one from n */
RZ_API void rz_big_powm(RNumBig *c, RNumBig *a, RNumBig *b, RNumBig *m); /* Calculate a^b -- e.g. 2^10 => 1024 */
RZ_API void rz_big_isqrt(RNumBig *c, RNumBig *a); /* Integer square root -- e.g. isqrt(5) => 2*/

#ifdef __cplusplus
}
#endif

#endif //  RZ_BIG_H
