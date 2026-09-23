#ifndef RZ_TYPES_OVERFLOW_H
#define RZ_TYPES_OVERFLOW_H

#include <rz_types.h>

// Probed here rather than at configure time: this header is installed and is
// regularly consumed by a different compiler than the one Rizin was built with,
// so a cached HAVE_* value would be a lie. Only the non-_p builtins are used,
// Clang does not implement the _p variants at all.
#if defined(__has_builtin)
#if __has_builtin(__builtin_add_overflow) && __has_builtin(__builtin_sub_overflow) && __has_builtin(__builtin_mul_overflow)
#define RZ_HAVE_OVERFLOW_BUILTINS 1
#endif
#elif defined(__GNUC__) && __GNUC__ >= 5
#define RZ_HAVE_OVERFLOW_BUILTINS 1
#endif

#ifdef RZ_HAVE_OVERFLOW_BUILTINS

// Operands stay 64 bit so that arguments outside the checked type are still
// reported, exactly as the fallback macros do. The width is decided by the type
// of the result, never by the promoted type of the operands.
#define RZ_OVFCHK_UNSIGNED(name, type, op) \
	static inline bool name(ut64 a, ut64 b) { \
		type res; \
		return __builtin_##op##_overflow(a, b, &res); \
	}
#define RZ_OVFCHK_SIGNED(name, type, op) \
	static inline bool name(st64 a, st64 b) { \
		type res; \
		return __builtin_##op##_overflow(a, b, &res); \
	}

RZ_OVFCHK_UNSIGNED(SZT_ADD_OVFCHK, size_t, add)
RZ_OVFCHK_UNSIGNED(UT64_ADD_OVFCHK, ut64, add)
RZ_OVFCHK_UNSIGNED(UT32_ADD_OVFCHK, ut32, add)
RZ_OVFCHK_UNSIGNED(UT16_ADD_OVFCHK, ut16, add)
RZ_OVFCHK_UNSIGNED(UT8_ADD_OVFCHK, ut8, add)
RZ_OVFCHK_SIGNED(ST64_ADD_OVFCHK, st64, add)
RZ_OVFCHK_SIGNED(ST32_ADD_OVFCHK, st32, add)
RZ_OVFCHK_SIGNED(ST16_ADD_OVFCHK, st16, add)
RZ_OVFCHK_SIGNED(ST8_ADD_OVFCHK, st8, add)

RZ_OVFCHK_UNSIGNED(SZT_SUB_OVFCHK, size_t, sub)
RZ_OVFCHK_UNSIGNED(UT64_SUB_OVFCHK, ut64, sub)
RZ_OVFCHK_UNSIGNED(UT32_SUB_OVFCHK, ut32, sub)
RZ_OVFCHK_UNSIGNED(UT16_SUB_OVFCHK, ut16, sub)
RZ_OVFCHK_UNSIGNED(UT8_SUB_OVFCHK, ut8, sub)
RZ_OVFCHK_SIGNED(ST64_SUB_OVFCHK, st64, sub)
RZ_OVFCHK_SIGNED(ST32_SUB_OVFCHK, st32, sub)
RZ_OVFCHK_SIGNED(ST16_SUB_OVFCHK, st16, sub)
RZ_OVFCHK_SIGNED(ST8_SUB_OVFCHK, st8, sub)

RZ_OVFCHK_UNSIGNED(SZT_MUL_OVFCHK, size_t, mul)
RZ_OVFCHK_UNSIGNED(UT64_MUL_OVFCHK, ut64, mul)
RZ_OVFCHK_UNSIGNED(UT32_MUL_OVFCHK, ut32, mul)
RZ_OVFCHK_UNSIGNED(UT16_MUL_OVFCHK, ut16, mul)
RZ_OVFCHK_UNSIGNED(UT8_MUL_OVFCHK, ut8, mul)
RZ_OVFCHK_SIGNED(ST64_MUL_OVFCHK, st64, mul)
RZ_OVFCHK_SIGNED(ST32_MUL_OVFCHK, st32, mul)
RZ_OVFCHK_SIGNED(ST16_MUL_OVFCHK, st16, mul)
RZ_OVFCHK_SIGNED(ST8_MUL_OVFCHK, st8, mul)

// ssize_t is absent on Windows, so these stay lazy macros as before.
#define SSZT_ADD_OVFCHK(a, x) ((((x) > 0) && ((a) > SSIZE_MAX - (x))) || (((x) < 0) && (a) < SSIZE_MIN - (x)))
#define SSZT_SUB_OVFCHK(a, b) SSZT_ADD_OVFCHK(a, -(b))

#else

// ADD
// if ((x > 0) && (a > INT_MAX - x)) /* `a + x` would overflow */;
// if ((x < 0) && (a < INT_MIN - x)) /* `a + x` would underflow */;
#define SZT_ADD_OVFCHK(x, y)  ((SIZE_MAX - (x)) < (y))
#define SSZT_ADD_OVFCHK(a, x) ((((x) > 0) && ((a) > SSIZE_MAX - (x))) || (((x) < 0) && (a) < SSIZE_MIN - (x)))
#define UT64_ADD_OVFCHK(x, y) ((UT64_MAX - (x)) < (y))
#define ST64_ADD_OVFCHK(a, x) ((((x) > 0) && ((a) > ST64_MAX - (x))) || (((x) < 0) && (a) < ST64_MIN - (x)))
#define UT32_ADD_OVFCHK(x, y) ((UT32_MAX - (x)) < (y))
#define ST32_ADD_OVFCHK(a, x) ((((x) > 0) && ((a) > ST32_MAX - (x))) || (((x) < 0) && (a) < ST32_MIN - (x)))
#define UT16_ADD_OVFCHK(x, y) ((UT16_MAX - (x)) < (y))
#define ST16_ADD_OVFCHK(a, b) ((((b) > 0) && ((a) > ST16_MAX - (b))) || (((b) < 0) && ((a) < ST16_MIN - (b))))
#define UT8_ADD_OVFCHK(x, y)  ((UT8_MAX - (x)) < (y))
#define ST8_ADD_OVFCHK(a, x)  ((((x) > 0) && ((a) > ST8_MAX - (x))) || ((x) < 0 && (a) < ST8_MIN - (x)))

// SUB
// if ((x < 0) && (a > INT_MAX + x)) /* `a - x` would overflow */;
// if ((x > 0) && (a < INT_MIN + x)) /* `a - x` would underflow */;
#define SZT_SUB_OVFCHK(a, b)  SZT_ADD_OVFCHK(a, -(b))
#define SSZT_SUB_OVFCHK(a, b) SSZT_ADD_OVFCHK(a, -(b))
#define UT64_SUB_OVFCHK(a, b) UT64_ADD_OVFCHK(a, -(b))
#define ST64_SUB_OVFCHK(a, b) ST64_ADD_OVFCHK(a, -(b))
#define UT32_SUB_OVFCHK(a, b) UT32_ADD_OVFCHK(a, -(b))
#define ST32_SUB_OVFCHK(a, b) ST32_ADD_OVFCHK(a, -(b))
#define UT16_SUB_OVFCHK(a, b) UT16_ADD_OVFCHK(a, -(b))
#define ST16_SUB_OVFCHK(a, b) ST16_ADD_OVFCHK(a, -(b))
#define UT8_SUB_OVFCHK(a, b)  UT8_ADD_OVFCHK(a, -(b))
#define ST8_SUB_OVFCHK(a, b)  ST8_ADD_OVFCHK(a, -(b))

// MUL
#define UNSIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		return (a > 0 && b > 0 && a > type_max / b); \
	}

#define SIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		if (a > 0) { \
			if (b > 0) { \
				return a > type_max / b; \
			} \
			return b < type_min / a; \
		} \
		if (b > 0) { \
			return a < type_min / b; \
		} \
		return a && b < type_max / a; \
	}

// TODO: Windows doesn't have ssize_t, and we don't need this check yet
// SIGNED_MUL_OVERFLOW_CHECK(SSZT_MUL_OVFCHK, ssize_t, SSZT_MIN, SSZT_MAX)
SIGNED_MUL_OVERFLOW_CHECK(ST8_MUL_OVFCHK, st8, ST8_MIN, ST8_MAX)
SIGNED_MUL_OVERFLOW_CHECK(ST16_MUL_OVFCHK, st16, ST16_MIN, ST16_MAX)
SIGNED_MUL_OVERFLOW_CHECK(ST32_MUL_OVFCHK, st32, ST32_MIN, ST32_MAX)
SIGNED_MUL_OVERFLOW_CHECK(ST64_MUL_OVFCHK, st64, ST64_MIN, ST64_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(SZT_MUL_OVFCHK, size_t, SZT_MIN, SZT_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(UT8_MUL_OVFCHK, ut8, UT8_MIN, UT8_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(UT16_MUL_OVFCHK, ut16, UT16_MIN, UT16_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(UT32_MUL_OVFCHK, ut32, UT32_MIN, UT32_MAX)
UNSIGNED_MUL_OVERFLOW_CHECK(UT64_MUL_OVFCHK, ut64, UT64_MIN, UT64_MAX)

#endif /* RZ_HAVE_OVERFLOW_BUILTINS */

// No compiler builtin exists for division.
#define SIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_mid, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		return (!b || (a == type_mid && b == type_max)); \
	}
#define UNSIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		(void)a; \
		return !b; \
	}

SIGNED_DIV_OVERFLOW_CHECK(ST8_DIV_OVFCHK, ut8, UT8_GT0, UT8_MAX)
SIGNED_DIV_OVERFLOW_CHECK(ST16_DIV_OVFCHK, ut16, UT16_GT0, UT16_MAX)
SIGNED_DIV_OVERFLOW_CHECK(ST32_DIV_OVFCHK, ut32, UT32_GT0, UT32_MAX)
SIGNED_DIV_OVERFLOW_CHECK(ST64_DIV_OVFCHK, ut64, UT64_GT0, UT64_MAX)
UNSIGNED_DIV_OVERFLOW_CHECK(UT8_DIV_OVFCHK, ut8, UT8_MIN, UT8_MAX)
UNSIGNED_DIV_OVERFLOW_CHECK(UT16_DIV_OVFCHK, ut16, UT16_MIN, UT16_MAX)
UNSIGNED_DIV_OVERFLOW_CHECK(UT32_DIV_OVFCHK, ut32, UT32_MIN, UT32_MAX)
UNSIGNED_DIV_OVERFLOW_CHECK(UT64_DIV_OVFCHK, ut64, UT64_MIN, UT64_MAX)

#endif
