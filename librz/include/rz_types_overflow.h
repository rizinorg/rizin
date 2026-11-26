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

#else

// Operands stay 64 bit so fallback behavior matches the builtin path above
// without macro double-evaluation or signed negation UB.

static inline bool UT64_ADD_OVFCHK(ut64 a, ut64 b) {
	return (UT64_MAX - a) < b;
}

static inline bool UT64_SUB_OVFCHK(ut64 a, ut64 b) {
	return a < b;
}

static inline bool ST64_ADD_OVFCHK(st64 a, st64 b) {
	return (b > 0 && a > ST64_MAX - b) || (b < 0 && a < ST64_MIN - b);
}

static inline bool ST64_SUB_OVFCHK(st64 a, st64 b) {
	return (b < 0 && a > ST64_MAX + b) || (b > 0 && a < ST64_MIN + b);
}

#define RZ_OVFCHK_UNSIGNED_ADD(name, type_max) \
	static inline bool name(ut64 a, ut64 b) { \
		const ut64 max = (ut64)(type_max); \
		return a > max || b > max - a; \
	}

#define RZ_OVFCHK_UNSIGNED_SUB(name, type_max) \
	static inline bool name(ut64 a, ut64 b) { \
		const ut64 max = (ut64)(type_max); \
		return a < b || (a - b) > max; \
	}

#define RZ_OVFCHK_SIGNED_ADD(name, type_min, type_max) \
	static inline bool name(st64 a, st64 b) { \
		if (ST64_ADD_OVFCHK(a, b)) { \
			return true; \
		} \
		const st64 res = a + b; \
		return res < (st64)(type_min) || res > (st64)(type_max); \
	}

#define RZ_OVFCHK_SIGNED_SUB(name, type_min, type_max) \
	static inline bool name(st64 a, st64 b) { \
		if (ST64_SUB_OVFCHK(a, b)) { \
			return true; \
		} \
		const st64 res = a - b; \
		return res < (st64)(type_min) || res > (st64)(type_max); \
	}

#define RZ_OVFCHK_UNSIGNED_MUL(name, type_max) \
	static inline bool name(ut64 a, ut64 b) { \
		return a > 0 && b > 0 && a > (ut64)(type_max) / b; \
	}

#define RZ_OVFCHK_SIGNED_MUL(name, type_min, type_max) \
	static inline bool name(st64 a, st64 b) { \
		if (!a || !b) { \
			return false; \
		} \
		if (a > 0) { \
			if (b > 0) { \
				return a > (st64)(type_max) / b; \
			} \
			return b < (st64)(type_min) / a; \
		} \
		if (b > 0) { \
			return a < (st64)(type_min) / b; \
		} \
		return a < (st64)(type_max) / b; \
	}

// ADD
RZ_OVFCHK_UNSIGNED_ADD(SZT_ADD_OVFCHK, SIZE_MAX)
RZ_OVFCHK_UNSIGNED_ADD(UT32_ADD_OVFCHK, UT32_MAX)
RZ_OVFCHK_UNSIGNED_ADD(UT16_ADD_OVFCHK, UT16_MAX)
RZ_OVFCHK_UNSIGNED_ADD(UT8_ADD_OVFCHK, UT8_MAX)
RZ_OVFCHK_SIGNED_ADD(ST32_ADD_OVFCHK, ST32_MIN, ST32_MAX)
RZ_OVFCHK_SIGNED_ADD(ST16_ADD_OVFCHK, ST16_MIN, ST16_MAX)
RZ_OVFCHK_SIGNED_ADD(ST8_ADD_OVFCHK, ST8_MIN, ST8_MAX)

// SUB
RZ_OVFCHK_UNSIGNED_SUB(SZT_SUB_OVFCHK, SIZE_MAX)
RZ_OVFCHK_UNSIGNED_SUB(UT32_SUB_OVFCHK, UT32_MAX)
RZ_OVFCHK_UNSIGNED_SUB(UT16_SUB_OVFCHK, UT16_MAX)
RZ_OVFCHK_UNSIGNED_SUB(UT8_SUB_OVFCHK, UT8_MAX)
RZ_OVFCHK_SIGNED_SUB(ST32_SUB_OVFCHK, ST32_MIN, ST32_MAX)
RZ_OVFCHK_SIGNED_SUB(ST16_SUB_OVFCHK, ST16_MIN, ST16_MAX)
RZ_OVFCHK_SIGNED_SUB(ST8_SUB_OVFCHK, ST8_MIN, ST8_MAX)

// MUL
// TODO: Windows doesn't have ssize_t, and we don't need this check yet
// RZ_OVFCHK_SIGNED_MUL(SSZT_MUL_OVFCHK, SSZT_MIN, SSZT_MAX)
RZ_OVFCHK_SIGNED_MUL(ST8_MUL_OVFCHK, ST8_MIN, ST8_MAX)
RZ_OVFCHK_SIGNED_MUL(ST16_MUL_OVFCHK, ST16_MIN, ST16_MAX)
RZ_OVFCHK_SIGNED_MUL(ST32_MUL_OVFCHK, ST32_MIN, ST32_MAX)
RZ_OVFCHK_SIGNED_MUL(ST64_MUL_OVFCHK, ST64_MIN, ST64_MAX)
RZ_OVFCHK_UNSIGNED_MUL(SZT_MUL_OVFCHK, SIZE_MAX)
RZ_OVFCHK_UNSIGNED_MUL(UT8_MUL_OVFCHK, UT8_MAX)
RZ_OVFCHK_UNSIGNED_MUL(UT16_MUL_OVFCHK, UT16_MAX)
RZ_OVFCHK_UNSIGNED_MUL(UT32_MUL_OVFCHK, UT32_MAX)
RZ_OVFCHK_UNSIGNED_MUL(UT64_MUL_OVFCHK, UT64_MAX)

#endif /* RZ_HAVE_OVERFLOW_BUILTINS */

// ssize_t is absent on Windows, so these stay lazy macros as before.
#define SSZT_ADD_OVFCHK(a, x) ((((x) > 0) && ((a) > SSIZE_MAX - (x))) || (((x) < 0) && ((a) < SSIZE_MIN - (x))))
#define SSZT_SUB_OVFCHK(a, b) ((((b) < 0) && ((a) > SSIZE_MAX + (b))) || (((b) > 0) && ((a) < SSIZE_MIN + (b))))

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
