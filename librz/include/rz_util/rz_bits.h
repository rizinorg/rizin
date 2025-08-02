// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only//

#ifndef RIZIN_RZ_BITS_H
#define RIZIN_RZ_BITS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_util/rz_assert.h>
#include <rz_types_base.h>

/**
 * \brief Count number of 1s in the given value.
 * Reference: https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetParallel
 *
 * \param v The value to count the set bits in.
 *
 * \return Number of set bits in \p v.
 */
#define DEFINE_COUNT_ONES(T) \
	static inline size_t rz_bits_count_ones_##T(T v) { \
		v = v - ((v >> 1) & (T) ~(T)0 / 3); \
		v = (v & (T) ~(T)0 / 15 * 3) + ((v >> 2) & (T) ~(T)0 / 15 * 3); \
		v = (v + (v >> 4)) & (T) ~(T)0 / 255 * 15; \
		size_t c = (T)(v * ((T) ~(T)0 / 255)) >> (sizeof(T) - 1) * CHAR_BIT; \
		return c; \
	}

DEFINE_COUNT_ONES(ut64);
DEFINE_COUNT_ONES(ut32);
DEFINE_COUNT_ONES(ut16);
DEFINE_COUNT_ONES(ut8);

/**
 * \brief Get the number of leading zeros of a 64-bit integer in binary representation.
 * \param x the 64-bit integer
 * \return the number of leading zeros
 */
static inline int rz_bits_leading_zeros(ut64 x) {
#if HAS___BUILTIN_CLZLL
	return __builtin_clzll(x);
#else
	int n = 0;
	if (x == 0)
		return 64;

	if (x <= 0x00000000FFFFFFFFULL) {
		n = n + 32;
		x = x << 32;
	}
	if (x <= 0x0000FFFFFFFFFFFFULL) {
		n = n + 16;
		x = x << 16;
	}
	if (x <= 0x00FFFFFFFFFFFFFFULL) {
		n = n + 8;
		x = x << 8;
	}
	if (x <= 0x0FFFFFFFFFFFFFFFULL) {
		n = n + 4;
		x = x << 4;
	}
	if (x <= 0x3FFFFFFFFFFFFFFFULL) {
		n = n + 2;
		x = x << 2;
	}
	if (x <= 0x7FFFFFFFFFFFFFFFULL) {
		n = n + 1;
	}

	return n;
#endif
}

/**
 * \brief Sign-extends a value from a specified bit-width to full width of type.
 *
 * This macro defines an inline function that performs sign extension on an
 * unsigned integer value of `bits` significant bits, extending it to a signed
 * integer of full bit-width `B`. It works for 8, 16, 32, and 64-bit integers.
 *
 * The function shifts the value left to discard higher bits, then arithmetically
 * shifts it back right, preserving the sign.
 *
 * \param value The input unsigned integer of type ut##B.
 * \param bits The number of significant bits in `value` (must be less than or equal to B).
 * \return The sign-extended signed integer of type st##B.
 */
#define SIGN_EXT_IMPL(B) \
	static inline st##B rz_bits_sign_ext##B(ut##B value, ut##B bits) { \
		return (st##B)(value << (B - bits)) >> (B - bits); \
	}

SIGN_EXT_IMPL(8);
SIGN_EXT_IMPL(16);
SIGN_EXT_IMPL(32);
SIGN_EXT_IMPL(64);

#ifdef __cplusplus
}
#endif
#endif // RIZIN_RZ_BITS_H
