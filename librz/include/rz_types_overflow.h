#ifndef RZ_TYPES_OVERFLOW_H
#define RZ_TYPES_OVERFLOW_H

#include <rz_types.h>
#include <rz_userconf.h>

// Using compiler builtins when available

// ADD
#if HAVE___BUILTIN_ADD_OVERFLOW
#define SZT_ADD_OVFCHK(x, y)  __builtin_add_overflow_p (x, y, (__typeof__ ((x) + (y))) 0)
#define SZT_ADD_OVFCHK(x, y)  __builtin_add_overflow_p (x, y, (__typeof__ ((x) + (y))) 0)
#define SSZT_ADD_OVFCHK(a, x) __builtin_add_overflow_p (a, x, (__typeof__ ((a) + (x))) 0)
#define UT64_ADD_OVFCHK(x, y) __builtin_add_overflow_p (x, y, (__typeof__ ((x) + (y))) 0)
#define ST64_ADD_OVFCHK(a, x) __builtin_add_overflow_p (a, x, (__typeof__ ((a) + (x))) 0)
#define UT32_ADD_OVFCHK(x, y) __builtin_add_overflow_p (x, y, (__typeof__ ((x) + (y))) 0)
#define ST32_ADD_OVFCHK(a, x) __builtin_add_overflow_p (a, x, (__typeof__ ((a) + (x))) 0)
#define UT16_ADD_OVFCHK(x, y) __builtin_add_overflow_p (x, y, (__typeof__ ((x) + (y))) 0)
#define ST16_ADD_OVFCHK(a, b) __builtin_add_overflow_p (a, b, (__typeof__ ((a) + (b))) 0)
#define UT8_ADD_OVFCHK(x, y)  __builtin_add_overflow_p (x, y, (__typeof__ ((x) + (y))) 0)
#define ST8_ADD_OVFCHK(a, x)  __builtin_add_overflow_p (a, x, (__typeof__ ((a) + (x))) 0)
#else
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
#endif

// SUB
#if HAVE___BUILTIN_SUB_OVERFLOW
#define SZT_SUB_OVFCHK(a, b)  __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#define SSZT_SUB_OVFCHK(a, b) __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#define UT64_SUB_OVFCHK(a, b) __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#define ST64_SUB_OVFCHK(a, b) __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#define UT32_SUB_OVFCHK(a, b) __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#define ST32_SUB_OVFCHK(a, b) __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#define UT16_SUB_OVFCHK(a, b) __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#define ST16_SUB_OVFCHK(a, b) __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#define UT8_SUB_OVFCHK(a, b)  __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#define ST8_SUB_OVFCHK(a, b)  __builtin_sub_overflow_p (a, b, (__typeof__ ((a) - (b))) 0)
#else
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
#endif

// MUL
#define UNSIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		return (a > 0 && b > 0 && a > type_max / b); \
	}


#if HAVE___BUILTIN_MUL_OVERFLOW
#define SIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
	static inline bool overflow_name(type_base a, type_base b) { \
		return __builtin_mul_overflow_p(a, b, (__typeof__ ((a) * (b))) 0); \
	}
#else
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
#endif

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

#endif
