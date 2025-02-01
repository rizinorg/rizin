// SPDX-FileCopyrightText: 2017 kazarmy <kazarmy@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

/**
 * \brief Decode bytes from the buffer \p buf into a code point.
 *
 * \param buf The buffer to read from.
 * \param buf_len The buffer size in bytes.
 * \param ch The code point to write the value to.
 * \param big_endian If the buffer bytes have big endian order.
 *
 * \return The number of bytes converted. For UTF-32 this is always 0 or 4.
 */
RZ_API size_t rz_utf32_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool big_endian) {
	rz_return_val_if_fail(buf, 0);
	if (buf_len < 4) {
		return 0;
	}
	if (!ch) {
		return 4;
	}
	*ch = rz_read_ble32(buf, big_endian);
	return 4;
}

/* Convert an UTF-32LE buf into a unicode RzRune */
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch) {
	return rz_utf32_decode(ptr, ptrlen, ch, false);
}

/* Convert an UTF-32BE buf into a unicode RzRune */
RZ_API int rz_utf32be_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch) {
	return rz_utf32_decode(ptr, ptrlen, ch, true);
}
