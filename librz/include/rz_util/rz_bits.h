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
 * \brief Count trailing zeros of \p v.
 * If v == 0 it returns 64.
 *
 * \param v The value to count the trailing zeros for.
 *
 * \return The number of trailing zeros.
 */
static inline size_t rz_bits_trailing_zeros(ut64 v) {
	if (v == 0) {
		return 64;
	}
#if HAVE___BUILTIN_CTZLL
	return __builtin_ctzll(v);
#else
	// src: https://graphics.stanford.edu/~seander/bithacks.html#ZerosOnRightBinSearch
	size_t c;
	if (v & 0x1) {
		// special case for odd v (assumed to happen half of the time)
		return 0;
	}
	c = 1;
	if ((v & 0xffffffff) == 0) {
		v >>= 32;
		c += 32;
	}
	if ((v & 0xffff) == 0) {
		v >>= 16;
		c += 16;
	}
	if ((v & 0xff) == 0) {
		v >>= 8;
		c += 8;
	}
	if ((v & 0xf) == 0) {
		v >>= 4;
		c += 4;
	}
	if ((v & 0x3) == 0) {
		v >>= 2;
		c += 2;
	}
	c -= v & 0x1;
	return c;
#endif
}

/**
 * \brief Get the number of leading zeros of a 64-bit integer in binary representation.
 * \param x the 64-bit integer
 * \return the number of leading zeros
 */
static inline int rz_bits_leading_zeros(ut64 x) {
	if (x == 0) {
		return 64;
	}
#if HAVE___BUILTIN_CLZLL
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
 * \brief Copies a bit range from \p src to \p dst at specified positions
 * \param src 64-bit unsigned integer to copy bits from
 * \param src_pos bit position related to \p src
 * \param dst 64-bit unsigned integer to copy bits to
 * \param dst_pos bit position related to \p dst
 * \param size number of bits to copy (needs to be <= 64)
 * \return a new 64-bit unsigned integer with the specified bit range replaced
 */
static inline ut64 rz_bits_copy_ut64(ut64 src, ut8 src_pos, ut64 dst, ut8 dst_pos, ut8 size) {
	if (size >= 64) {
		return src;
	}

	ut64 mask = ((1ull) << size) - 1;
	return (dst & ~(mask << dst_pos)) | (src >> src_pos & mask) << dst_pos;
}

/**
 * \brief Similar to rz_bits_copy_ut64() but for 8-bit unsigned integers
 */
static inline ut8 rz_bits_copy_ut8(ut8 src, ut8 src_pos, ut8 dst, ut8 dst_pos, ut8 size) {
	if (size >= 8) {
		return src;
	}

	ut8 mask = ((1u) << size) - 1;
	return (dst & ~(mask << dst_pos)) | (src >> src_pos & mask) << dst_pos;
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

RZ_API ut64 rz_bits_spread(const ut64 mask, const ut64 value);

#ifdef __cplusplus
}
#endif
#endif // RIZIN_RZ_BITS_H
