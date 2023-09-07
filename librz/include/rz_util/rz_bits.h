// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only//

#ifndef RIZIN_RZ_BITS_H
#define RIZIN_RZ_BITS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_util/rz_assert.h>
#include <rz_types_base.h>

typedef ut64 RzBitmap64;
typedef ut32 RzBitmap32;

/**
 * \brief Init the 64bit bitmap \p map.
 *
 * \param map The bitmap to edit.
 */
static inline void rz_bits_map_init_64(RZ_OUT RzBitmap64 *map) {
	rz_return_if_fail(map);
	*map = 0;
}

/**
 * \brief Init the 32bit bitmap \p map.
 *
 * \param map The bitmap to edit.
 */
static inline void rz_bits_map_init_32(RZ_OUT RzBitmap32 *map) {
	rz_return_if_fail(map);
	*map = 0;
}

/**
 * \brief Set the bit at \p pos in the 64bit bitmap \p map.
 *
 * \param map The bitmap to edit.
 * \param pos Bit index to set.
 */
static inline void rz_bits_map_set_64(RZ_OUT RzBitmap64 *map, ut32 pos) {
	rz_return_if_fail(map && pos < 64);
	*map = *map | ((1ULL) << pos);
}

/**
 * \brief Set the bit at \p pos in the 32bit bitmap \p map.
 *
 * \param map The bitmap to edit.
 * \param pos Bit index to set.
 */
static inline void rz_bits_map_set_32(RZ_OUT RzBitmap32 *map, ut32 pos) {
	rz_return_if_fail(map && pos < 32);
	*map = *map | ((1UL) << pos);
}

/**
 * \brief Unset the bit at \p pos in the 64bit bitmap \p map.
 *
 * \param map The bitmap to edit.
 * \param pos Bit index to unset.
 */
static inline void rz_bits_map_unset_64(RZ_OUT RzBitmap64 *map, ut32 pos) {
	rz_return_if_fail(map && pos < 64);
	*map = *map & ~((ut64)(1ULL) << pos);
}

/**
 * \brief Unset the bit at \p pos in the 32bit bitmap \p map.
 *
 * \param map The bitmap to edit.
 * \param pos Bit index to unset.
 */
static inline void rz_bits_map_unset_32(RZ_OUT RzBitmap32 *map, ut32 pos) {
	rz_return_if_fail(map && pos < 32);
	*map = *map & ~((ut32)(1UL) << pos);
}

/**
 * \brief Get the bit at \p pos in the 64bit bitmap \p map.
 *
 * \param map The bitmap to check.
 * \param pos Bit index to check.
 *
 * \return true If bit is set.
 * \return false If bit is unset.
 */
static inline bool rz_bits_map_get_64(const RzBitmap64 *map, ut32 pos) {
	rz_return_val_if_fail(map && pos < 64, false);
	return (*map & ((1ULL) << pos)) != 0;
}

/**
 * \brief Get the bit at \p pos in the 32bit bitmap \p map.
 *
 * \param map The bitmap to check.
 * \param pos Bit index to check.
 *
 * \return true If bit is set.
 * \return false If bit is unset.
 */
static inline bool rz_bits_map_get_32(const RzBitmap32 *map, ut32 pos) {
	rz_return_val_if_fail(map && pos < 32, false);
	return (*map & ((1UL) << pos)) != 0;
}

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
