// SPDX-FileCopyrightText: 2017 kazarmy <kazarmy@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

/**
 * \brief Decode bytes from the buffer \p buf into a code point.
 *
 * \param buf The buffer to read from.
 * \param buf_len The buffer size in bytes.
 * \param cp The decoded code point.
 * \param check_is_def If true, checks the code point against the defined
 *        Unicode table. It will not write \p cp and return 0 if the decoded code
 *        point is undefined.
 *        If false, it won't perform any checks and just decode.
 *        Be aware, the check has a runtime of O(log n).
 *        Where n: number of undefined Unicode ranges.
 * \param big_endian If the buffer bytes have big endian order.
 *
 * \return The number of bytes converted. For UTF-32 this is always 0 or 4.
 */
RZ_API size_t rz_utf32_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool check_is_def, bool big_endian) {
	rz_return_val_if_fail(buf, 0);
	if (buf_len < 4) {
		return 0;
	}
	if (!ch) {
		return 4;
	}
	RzCodePoint cp = rz_read_ble32(buf, big_endian);
	if (rz_unicode_code_point_is_surrogate(cp) || (check_is_def && !rz_unicode_code_point_is_defined(cp))) {
		return 0;
	}
	*ch = cp;
	return 4;
}

/* Convert an UTF-32LE buf into a unicode RzCodePoint */
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool check_is_def) {
	return rz_utf32_decode(ptr, ptrlen, ch, check_is_def, false);
}

/* Convert an UTF-32BE buf into a unicode RzCodePoint */
RZ_API int rz_utf32be_decode(const ut8 *ptr, int ptrlen, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool check_is_def) {
	return rz_utf32_decode(ptr, ptrlen, ch, check_is_def, true);
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
 *        NOTE: if the buffer can't cover all \p lookahead code points, this returns false.
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

/**
 * \brief Encodes the Unicode code point \p ucp into \p buf.
 *
 * \param buf The buffer to write the UTF-32 character into.
 *        The buffer must be at least 4 bytes in size.
 * \param ucp The Unicode code point to encode.
 * \param big_endian If true it will encode \p ucp as a big endian character. If false, as little endian.
 *
 * \return Number of bytes written into \p buf. 0 in case of failure, 4 otherwise.
 */
RZ_API size_t rz_utf32_encode(RZ_NONNULL RZ_OUT ut8 *buf, RzCodePoint ucp, bool big_endian) {
	if (ucp > RZ_UNICODE_LAST_CODE_POINT || rz_unicode_code_point_is_surrogate(ucp)) {
		return 0;
	}
	if (big_endian) {
		buf[3] = ucp & 0xff;
		buf[2] = (ucp >> 8) & 0xff;
		buf[1] = (ucp >> 16) & 0xff;
		buf[0] = (ucp >> 24) & 0xff;
		return 4;
	}
	buf[0] = ucp & 0xff;
	buf[1] = (ucp >> 8) & 0xff;
	buf[2] = (ucp >> 16) & 0xff;
	buf[3] = (ucp >> 24) & 0xff;
	return 4;
}

/**
 * \brief Converts the \p utf32_str into an UTF-8 string.
 * The conversion will stop if there are any encoding or decoding issues
 * (e.g. any code point is larger than RZ_UNICODE_LAST_CODE_POINT or a surrogate).
 *
 * \param utf32_str The UTF-32 string to convert to UTF-8. It must be at least
 * 4 bytes long.
 * \param len The len of \p utf32_str in bytes.
 * \param big_endian Flag if \p ut32_str is encoded in big endian.
 *
 * \return The resulting UTF-8 string or NULL in case of failure.
 */
RZ_API RZ_OWN ut8 *rz_str_utf32_to_utf8(RZ_NONNULL const ut8 *utf32_str, size_t len, bool big_endian) {
	rz_return_val_if_fail(utf32_str && len > 3, NULL);
	// Worst case each character is also 4 bytes in UTF-8.
	size_t len_dst = len + 1;
	ut8 *dst = RZ_NEWS0(ut8, len_dst);

	size_t k = 0;
	for (size_t i = 0; i < len; i += 4) {
		RzCodePoint ucp;
		if (!rz_utf32_decode(utf32_str + i, len - i, &ucp, false, big_endian)) {
			// Failed to decode.
			goto return_dst;
		}
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
