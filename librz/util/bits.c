// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util.h"

/**
 * \brief Spreads the value bits according to the bitmask and returns the result.
 *
 * The \p mask indicates which bits of the result the \p value bits are copied into.
 * If it has n bits set, value[n:0] are copied to the result at the bit positions
 * given in \p mask.
 *
 * Example:
 * mask = 0x0301003f
 * value = 0x000000fe
 * result = 0x0201003e
 *
 * \param mask The bitmask which indicates where the value bits should be placed.
 * \param value The value to spread.
 * \return The result of setting the \p value bits to the bit positions of \p mask.
 */
RZ_API ut64 rz_bits_spread(const ut64 mask, const ut64 value) {
	ut64 result = 0;
	ut64 off = 0;

	for (ut64 bit = 0; bit != 64; ++bit) {
		ut64 val_bit = (value >> off) & 1;
		ut64 mask_bit = (mask >> bit) & 1;
		if (mask_bit) {
			result |= (val_bit << bit);
			++off;
		}
	}
	return result;
}
