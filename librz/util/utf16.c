// SPDX-FileCopyrightText: 2017 kazarmy <kazarmy@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

// For high: Only d8-db
// For low: Only dc-df
static bool is_valid_surrogate_pair(ut8 high_byte_surrogate, ut8 low_byte_surrogate) {
	bool high_ok = high_byte_surrogate >= 0xd8 && high_byte_surrogate <= 0xdb;
	bool low_ok = low_byte_surrogate >= 0xdc && low_byte_surrogate <= 0xdf;
	return high_ok && low_ok;
}

static RzCodePoint utf16_surrogate_to_codepoint(ut16 high_surrogate, ut16 low_surrogate) {
	ut32 high = (high_surrogate - 0xd800) * 0x400;
	ut32 low = (low_surrogate - 0xdc00);
	RzCodePoint codepoint = high + low;
	RzCodePoint codepoint1 = 0x10000 + codepoint;
	return codepoint1;
}

/**
 * \brief Decode UTF-16 bytes to Unicode code point.
 *
 * \param buf       The buffer to read the bytes from.
 * \param buf_len   The buffer length.
 * \param codepoint The decoded code point.
 * \param bigendian Flag if the \p buf holds UTF-16 bytes in big endian.
 *
 * \return Number of bytes decoded.
 */
RZ_API size_t rz_utf16_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NONNULL RZ_OUT RzCodePoint *ch, bool bigendian) {
	rz_return_val_if_fail(buf && ch, 0);
	if (buf_len <= 1) {
		return 0;
	}
	int high = bigendian ? 0 : 1;
	int low = bigendian ? 1 : 0;
	if (buf_len > 3 && is_valid_surrogate_pair(buf[high], buf[high + 2])) {
		*ch = utf16_surrogate_to_codepoint((buf[high] << 8 | buf[low]), (buf[high + 2] << 8) | buf[low + 2]);
		return 4;
	}
	if (buf[high]) {
		*ch = buf[high] << 8 | buf[low];
		return 2;
	}
	*ch = (ut32)buf[low];
	return 1;
}

/**
 * \brief Decode UTF-16 bytes in little endian to the Unicode code point.
 *
 * \param buf       The buffer to read the bytes from.
 * \param buf_len   The buffer length.
 * \param codepoint The decoded code point.
 *
 * \return Number of bytes decoded.
 */
RZ_API size_t rz_utf16le_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NONNULL RZ_OUT RzCodePoint *codepoint) {
	rz_return_val_if_fail(buf && codepoint, 0);
	return rz_utf16_decode(buf, buf_len, codepoint, false);
}

/**
 * \brief Decode UTF-16 bytes in big endian to the Unicode code point.
 *
 * \param buf       The buffer to read the bytes from.
 * \param buf_len   The buffer length.
 * \param codepoint The decoded code point.
 *
 * \return Number of bytes decoded.
 */
RZ_API size_t rz_utf16be_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NONNULL RZ_OUT RzCodePoint *codepoint) {
	rz_return_val_if_fail(buf && codepoint, 0);
	return rz_utf16_decode(buf, buf_len, codepoint, true);
}

/**
 * \brief Encodes a Unicode code point to little endian UTF16 bytes.
 *
 * \param buf       The buffer to write the bytes to. Must be at least 4 bytes.
 * \param codepoint The code point to encode.
 *
 * \return Number of bytes encoded.
 */
RZ_API size_t rz_utf16le_encode(RZ_NONNULL RZ_OUT ut8 *buf, RzCodePoint codepoint) {
	rz_return_val_if_fail(buf, 0);
	if (codepoint < 0x10000) {
		buf[0] = codepoint & 0xff;
		buf[1] = codepoint >> 8 & 0xff;
		return 2;
	}
	if (codepoint > 0x10FFFF) {
		return 0;
	}
	codepoint -= 0x10000;
	RzCodePoint high = 0xd800 + ((codepoint >> 10) & 0x3ff);
	RzCodePoint low = 0xdc00 + (codepoint & 0x3ff);
	buf[0] = high & 0xff;
	buf[1] = high >> 8 & 0xff;
	buf[2] = low & 0xff;
	buf[3] = low >> 8 & 0xff;
	return 4;
}
