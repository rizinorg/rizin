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
 * \param codepoint (Optional) The decoded code point.
 * \param check_is_def If true, checks the code point against the defined
 *        Unicode table. It will not write \p cp and return 0 if the decoded code
 *        point is undefined.
 *        If false, it won't perform any checks and just decode.
 *        Be aware, the check has a runtime of O(log n).
 *        Where n: number of undefined Unicode ranges.
 * \param bigendian Flag if the \p buf holds UTF-16 bytes in big endian.
 *
 * \return Number of bytes decoded.
 */
RZ_API size_t rz_utf16_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *codepoint, bool check_is_def, bool bigendian) {
	rz_return_val_if_fail(buf, 0);
	if (buf_len <= 1) {
		return 0;
	}
	RzCodePoint cp;
	size_t bytes_used = 0;
	int high = bigendian ? 0 : 1;
	int low = bigendian ? 1 : 0;
	if (buf_len > 3 && is_valid_surrogate_pair(buf[high], buf[high + 2])) {
		cp = utf16_surrogate_to_codepoint((buf[high] << 8 | buf[low]), (buf[high + 2] << 8) | buf[low + 2]);
		bytes_used = 4;
		goto check_assign;
	}
	if (buf[high]) {
		cp = buf[high] << 8 | buf[low];
		bytes_used = 2;
		goto check_assign;
	}
	cp = (RzCodePoint)buf[low];
	bytes_used = 2;

check_assign:
	if (rz_unicode_code_point_is_surrogate(cp) || (check_is_def && !rz_unicode_code_point_is_defined(cp))) {
		return 0;
	}
	if (codepoint) {
		*codepoint = cp;
	}
	return bytes_used;
}

/**
 * \brief Decode UTF-16 bytes in little endian to the Unicode code point.
 *
 * \param buf       The buffer to read the bytes from.
 * \param buf_len   The buffer length.
 * \param codepoint (Optional) The decoded code point.
 * \param check_is_def If true, checks the code point against the defined
 *        Unicode table. It will not write \p cp and return 0 if the decoded code
 *        point is undefined.
 *        If false, it won't perform any checks and just decode.
 *        Be aware, the check has a runtime of O(log n).
 *        Where n: number of undefined Unicode ranges.
 *
 * \return Number of bytes decoded.
 */
RZ_API size_t rz_utf16le_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *codepoint, bool check_is_def) {
	rz_return_val_if_fail(buf, 0);
	return rz_utf16_decode(buf, buf_len, codepoint, check_is_def, false);
}

/**
 * \brief Decode UTF-16 bytes in big endian to the Unicode code point.
 *
 * \param buf       The buffer to read the bytes from.
 * \param buf_len   The buffer length.
 * \param codepoint (Optional) The decoded code point.
 * \param check_is_def If true, checks the code point against the defined
 *        Unicode table. It will not write \p cp and return 0 if the decoded code
 *        point is undefined.
 *        If false, it won't perform any checks and just decode.
 *        Be aware, the check has a runtime of O(log n).
 *        Where n: number of undefined Unicode ranges.
 *
 * \return Number of bytes decoded.
 */
RZ_API size_t rz_utf16be_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *codepoint, bool check_is_def) {
	rz_return_val_if_fail(buf, 0);
	return rz_utf16_decode(buf, buf_len, codepoint, check_is_def, true);
}

/**
 * \brief Encodes a Unicode code point to little endian UTF16 bytes.
 *
 * \param buf        The buffer to write the bytes to. Must be at least 4 bytes.
 * \param codepoint  The code point to encode.
 * \param big_endian Encodes in big endian order if set.
 *
 * \return Number of bytes encoded.
 */
RZ_API size_t rz_utf16_encode(RZ_NONNULL RZ_OUT ut8 *buf, RzCodePoint codepoint, bool big_endian) {
	rz_return_val_if_fail(buf, 0);
	if (big_endian) {
		if (codepoint < 0x10000) {
			buf[1] = codepoint & 0xff;
			buf[0] = codepoint >> 8 & 0xff;
			return 2;
		}
		if (codepoint > 0x10FFFF) {
			return 0;
		}
		codepoint -= 0x10000;
		RzCodePoint high = 0xd800 + ((codepoint >> 10) & 0x3ff);
		RzCodePoint low = 0xdc00 + (codepoint & 0x3ff);
		buf[1] = high & 0xff;
		buf[0] = high >> 8 & 0xff;
		buf[3] = low & 0xff;
		buf[2] = low >> 8 & 0xff;
		return 4;
	}
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

/**
 * \brief Checks if there are \p lookahead number of printable UTF-16 code points in \p buf.
 *
 * NOTE: Any byte sequence >=2 bytes can be a valid UTF-16 code point.
 * Hence this function checks if each code point is also printable.
 *
 * This takes O(lookahead * log(|Unicode Code Points|)) steps.
 * It is advisable to first check for other encodings for this reason.
 *
 * \param buf The buffer to check the bytes from.
 * \param buf_len The buffer length.
 * \param big_endian Should be set if the bytes in the buffer are in big endian order.
 * \param lookahead Number of code points to check.
 *        NOTE: if the buffer can't cover all \p lookahead code points, this returns false.
 *
 * \return True if the buffer has \p lookahead number of printable UTF-16 characters.
 * \return False otherwise.
 */
RZ_API bool rz_utf16_is_printable_code_point(RZ_NONNULL const ut8 *buf, size_t buf_len, bool big_endian, size_t lookahead) {
	rz_return_val_if_fail(buf && buf_len > 0, false);
	// At least 2 bytes must be given.
	// Buffer must cover all look aheads.
	if (buf_len < 2 || buf_len < (lookahead * 2) || lookahead == 0) {
		return false;
	}
	size_t offset = 0;
	RzCodePoint cp = 0;
	while (lookahead > 0) {
		size_t dec_bytes = rz_utf16_decode(buf + offset, buf_len - offset, &cp, true, big_endian);
		if (!rz_unicode_code_point_is_printable(cp) || dec_bytes == 0) {
			return false;
		}
		lookahead--;
		offset += dec_bytes;
		if (offset >= buf_len && lookahead > 0) {
			return false;
		}
	}
	return true;
}

/**
 * \brief Converts the \p utf16_str into an UTF-8 string.
 * The conversion will stop if there are any encoding or decoding issues
 * (e.g. any code point is larger than RZ_UNICODE_LAST_CODE_POINT or a surrogate).
 *
 * \param utf16_str The UTF-16 string to convert to UTF-8. It must be at least
 * 2 bytes long.
 * \param len The len of \p utf16_str in bytes.
 * \param big_endian Flag if \p ut16_str is encoded in big endian.
 *
 * \return The restulting UTF-8 string or NULL in case of failure.
 */
RZ_API RZ_OWN ut8 *rz_str_utf16_to_utf8(RZ_NONNULL const ut8 *utf16_str, size_t len, bool big_endian) {
	rz_return_val_if_fail(utf16_str && len > 1, NULL);
	// Worst case each 2 bytes UTF-16 character requires 3 bytes in UTF-8.
	// Each 4 bytes UTF-16 character also needs 4 bytes in UTF-8.
	size_t len_dst = len * 2;
	ut8 *dst = RZ_NEWS0(ut8, len_dst);

	size_t k = 0;
	for (size_t i = 0; i < len;) {
		RzCodePoint ucp;
		size_t x = rz_utf16_decode(utf16_str + i, len - i, &ucp, false, big_endian);
		if (!x) {
			// Failed to decode.
			goto return_dst;
		}
		i += x;
		size_t utf8_bytes = rz_utf8_encode(dst + k, ucp);
		if (!utf8_bytes) {
			// Code point is larger than the last Unicode code point.
			goto return_dst;
		}
		k += utf8_bytes;
	}

return_dst:
	return dst;
}
