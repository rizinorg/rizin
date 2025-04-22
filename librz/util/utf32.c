// SPDX-FileCopyrightText: 2017 kazarmy <kazarmy@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

/**
 * \brief Decode bytes from the buffer \p buf into a code point.
 *
 * \param buf The buffer to read from.
 * \param buf_len The buffer size in bytes.
 * \param ch The decoded code point. It is only written if a valid
 * Unicode code point was decoded.
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
	RzCodePoint cp = rz_read_ble32(buf, big_endian);
	if (!rz_unicode_code_point_is_legal_decode(cp)) {
		return 0;
	}
	*ch = cp;
	return 4;
}

/* Convert an UTF-32LE buf into a unicode RzCodePoint */
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch) {
	return rz_utf32_decode(ptr, ptrlen, ch, false);
}

/* Convert an UTF-32BE buf into a unicode RzCodePoint */
RZ_API int rz_utf32be_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch) {
	return rz_utf32_decode(ptr, ptrlen, ch, true);
}

/**
 * \brief Checks if there are valid UTF-32 code points at \p buf.
 * This function does not check if the code points are defined.
 * It just checks they are in a valid range according to RFC 3629.
 *
 * \param buf The buffer to check the bytes from.
 * \param buf_len The buffer length.
 * \param big_endian Should be set if the bytes in the buffer are in big endian order.
 * \param lookahead Number of code points to check.
 * Note: if the buffer can't cover all \p lookahead code points, this returns false.
 *
 * \return True if the buffer has \p lookahead valid UTF-32 code points.
 * \return False otherwise.
 */
RZ_API bool rz_utf32_valid_code_point(RZ_NONNULL const ut8 *buf, size_t buf_len, bool big_endian, size_t lookahead) {
	rz_return_val_if_fail(buf && buf_len > 0, false);
	// At least 4 bytes must be given.
	// Buffer must cover all look aheads.
	if (buf_len < 4 || buf_len < (lookahead * 4) || lookahead == 0) {
		return false;
	}
	size_t offset = 0;
	while (lookahead > 0) {
		RzCodePoint cp = rz_read_ble32(buf + offset, big_endian);
		// UTF-16 surrogates are forbitten code points as of RFC 3629.
		bool is_utf16_surregate = cp >= 0xd800 && cp <= 0xdfff;
		// Largest Unicode code point is 0x10ffff, also limited in RFC 3629.
		bool above_max_code_point = cp > RZ_UNICODE_LAST_CODE_POINT;
		if (is_utf16_surregate || above_max_code_point) {
			return false;
		}
		lookahead--;
		offset += 4;
	}
	return true;
}
