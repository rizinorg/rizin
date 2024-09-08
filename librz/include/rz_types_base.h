#ifndef RZ_TYPES_BASE_H
#define RZ_TYPES_BASE_H

#include <ctype.h>
#include <sys/types.h>
#include <limits.h>

#if defined(_MSC_VER)
// required to forbid the declaration
// of __ucrt_int_to_float which is
// included from 10.0.25182.0, where
// `math.h` includes `corecrt_math.h`
#define __midl
#endif
#include <math.h>
#if defined(_MSC_VER)
// remove __midl
#undef __midl
#endif

#define cut8  const unsigned char
#define ut64  unsigned long long
#define st64  long long
#define ut32  unsigned int
#define st32  int
#define ut16  unsigned short
#define st16  short
#define ut8   unsigned char
#define st8   signed char
#define boolt int

#if defined(_MSC_VER)
typedef intptr_t ssize_t;
#endif

#if defined(_MSC_VER)
#define RZ_ALIGNED(x) __declspec(align(x))
#else
#define RZ_ALIGNED(x) __attribute__((aligned(x)))
#endif

typedef struct _ut80 {
	ut64 Low;
	ut16 High;
} ut80;
typedef struct _ut96 {
	ut64 Low;
	ut32 High;
} ut96;
typedef struct _ut128 {
	ut64 Low;
	ut64 High;
} ut128;
typedef struct _ut256 {
	ut128 Low;
	ut128 High;
} ut256;
typedef struct _utX {
	ut80 v80;
	ut96 v96;
	ut128 v128;
	ut256 v256;
} utX;

#include <stdbool.h>

#define RZ_EMPTY \
	{ 0 }
#define RZ_EMPTY2 \
	{ \
		{ 0 } \
	}

/* limits */
#undef UT64_MAX
#undef UT64_GT0
#undef UT64_LT0
#undef UT64_MIN
#undef UT32_MAX
#undef UT32_MIN
#undef UT16_MIN
#undef UT8_MIN
#define ST64_MAX  ((st64)0x7FFFFFFFFFFFFFFFULL)
#define ST64_MIN  ((st64)(-ST64_MAX - 1))
#define UT64_MAX  0xFFFFFFFFFFFFFFFFULL
#define UT64_GT0  0x8000000000000000ULL
#define UT64_LT0  0x7FFFFFFFFFFFFFFFULL
#define UT64_MIN  0ULL
#define UT64_32U  0xFFFFFFFF00000000ULL
#define UT64_16U  0xFFFFFFFFFFFF0000ULL
#define UT64_8U   0xFFFFFFFFFFFFFF00ULL
#define UT32_MIN  0U
#define UT16_MIN  0U
#define UT32_GT0  0x80000000U
#define UT32_LT0  0x7FFFFFFFU
#define ST32_MAX  0x7FFFFFFF
#define ST32_MIN  (-ST32_MAX - 1)
#define UT32_MAX  0xFFFFFFFFU
#define ST16_MAX  0x7FFF
#define ST16_MIN  (-ST16_MAX - 1)
#define UT16_GT0  0x8000U
#define UT16_MAX  0xFFFFU
#define ST8_MAX   0x7F
#define ST8_MIN   (-ST8_MAX - 1)
#define UT8_GT0   0x80U
#define UT8_MAX   0xFFU
#define UT8_MIN   0x00U
#define ASCII_MIN 32
#define ASCII_MAX 127

#if SSIZE_MAX == ST32_MAX
#define SZT_MAX  UT32_MAX
#define SZT_MIN  UT32_MIN
#define SSZT_MAX ST32_MAX
#define SSZT_MIN ST32_MIN
#else
#define SZT_MAX  UT64_MAX
#define SZT_MIN  UT64_MIN
#define SSZT_MAX ST64_MAX
#define SSZT_MIN ST64_MIN
#endif

#define UT64_ALIGN(x) (x + (x - (x % sizeof(ut64))))
#define UT32_ALIGN(x) (x + (x - (x % sizeof(ut32))))
#define UT16_ALIGN(x) (x + (x - (x % sizeof(ut16))))

#define UT32_LO(x) ((ut32)((x)&UT32_MAX))
#define UT32_HI(x) ((ut32)(((ut64)(x)) >> 32) & UT32_MAX)

#define RZ_BETWEEN(x, y, z) (((y) >= (x)) && ((y) <= (z)))
#define RZ_ROUND(x, y)      ((x) % (y)) ? (x) + ((y) - ((x) % (y))) : (x)
#define RZ_DIM(x, y, z)     (((x) < (y)) ? (y) : ((x) > (z)) ? (z) \
							     : (x))
#ifndef RZ_MAX_DEFINED
#define RZ_MAX(x, y) (((x) > (y)) ? (x) : (y))
#define RZ_MAX_DEFINED
#endif
#ifndef RZ_MIN_DEFINED
#define RZ_MIN(x, y) (((x) > (y)) ? (y) : (x))
#define RZ_MIN_DEFINED
#endif
#define RZ_ABS(x)       (((x) < 0) ? -(x) : (x))
#define RZ_BTW(x, y, z) (((x) >= (y)) && ((y) <= (z))) ? y : x

#include "rz_types_overflow.h"

/* copied from bithacks.h */
#define B_IS_SET(x, n) (((x) & (1ULL << (n))) ? 1 : 0)
#define B_SET(x, n)    ((x) |= (1ULL << (n)))
#define B_EVEN(x)      (((x)&1) == 0)
#define B_ODD(x)       (!B_EVEN((x)))
#define B_UNSET(x, n)  ((x) &= ~(1ULL << (n)))
#define B_TOGGLE(x, n) ((x) ^= (1ULL << (n)))

#define B11111 31
#define B11110 30
#define B11101 29
#define B11100 28
#define B11011 27
#define B11010 26
#define B11001 25
#define B11000 24
#define B10111 23
#define B10110 22
#define B10101 21
#define B10100 20
#define B10011 19
#define B10010 18
#define B10001 17
#define B10000 16
#define B1111  15
#define B1110  14
#define B1101  13
#define B1100  12
#define B1011  11
#define B1010  10
#define B1001  9
#define B1000  8
#define B0111  7
#define B0110  6
#define B0101  5
#define B0100  4
#define B0011  3
#define B0010  2
#define B0001  1
#define B0000  0
#undef B
#define B4(a, b, c, d) ((a << 12) | (b << 8) | (c << 4) | (d))

/* portable non-c99 inf/nan types */
#if !defined(INFINITY)
#define INFINITY (1.0f / 0.0f)
#endif

#if !defined(NAN)
#define NAN (0.0f / 0.0f)
#endif

/* A workaround against libc headers redefinition of __attribute__:
 * Standard include has lines like
 * #if (GCC_VERSION < 2007)
 * # define __attribute__(x)
 * #endif
 * So we have do remove this define for TinyCC compiler
 */
#if defined(__TINYC__) && (GCC_VERSION < 2007)
#undef __attribute__
#endif

#ifdef _MSC_VER
#define RZ_PACKED(__Declaration__) __pragma(pack(push, 1)) __Declaration__ __pragma(pack(pop))
#undef INFINITY
#undef NAN
#elif defined(__GNUC__) || defined(__TINYC__)
#define RZ_PACKED(__Declaration__) __Declaration__ __attribute__((__packed__))
#endif

#if APPLE_SDK_IPHONESIMULATOR
#undef DEBUGGER
#define DEBUGGER 0
#endif

#define HEAPTYPE(x) \
	static x *x##_new(x n) { \
		x *m = malloc(sizeof(x)); \
		return m ? *m = n, m : m; \
	}

#define RZ_STR_DEF(s) RZ_STR(s)
#define RZ_STR(s)     #s

#endif // RZ_TYPES_BASE_H
