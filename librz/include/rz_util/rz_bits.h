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

#ifdef __cplusplus
}
#endif
#endif // RIZIN_RZ_BITS_H
