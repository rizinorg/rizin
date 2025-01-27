// SPDX-FileCopyrightText: 2017 kazarmy <kazarmy@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

/* Convert an UTF-32 buf into a unicode RzRune */
RZ_API int rz_utf32_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch, bool bigendian) {
	if (ptrlen < 1) {
		return 0;
	}
	int low = 0;
	int high = 3;
	if (bigendian) {
		low = 3;
		high = 0;
	}
	if (ptrlen > 3) {
		int sign = bigendian ? -1 : 1;
		if (ch) {
			int i;
			*ch = (ut32)ptr[low];
			for (i = 1; i < 4; i++) {
				*ch |= (ut32)ptr[3 - high + i * sign] << 8 * i;
			}
		}
		if (ptr[high] || ptr[high - 1 * sign]) {
			return 4;
		}
		if (ptr[low + 1 * sign]) {
			return 2;
		}
		return 1;
	}
	return 0;
}

/* Convert an UTF-32LE buf into a unicode RzRune */
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch) {
	return rz_utf32_decode(ptr, ptrlen, ch, false);
}

/* Convert an UTF-32BE buf into a unicode RzRune */
RZ_API int rz_utf32be_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch) {
	return rz_utf32_decode(ptr, ptrlen, ch, true);
}

/**
 * \brief Checks if there is a valid UTF-32 code point at \p buf.
 * This function does not check if the code point is defined.
 * It just checks it is in a valid range according to RFC 3629.
 *
 * \param buf The buffer to check the bytes from.
 * \param buf_len The buffer length.
 * \param big_endian Should be set if the bytes in the buffer are in big endian order.
 *
 * \return True if the first four bytes are in the valid UTF-32 code point range.
 * \return False otherwise.
 */
RZ_API bool rz_utf32_valid_cp(const ut8 *buf, size_t buf_len, bool big_endian) {
	// At least 4 bytes must be given.
	if (buf_len < 4) {
		return false;
	}
	RzCodePoint cp = rz_read_ble32(buf, big_endian);
	// UTF-16 surrogates are forbitten code points as of RFC 3629.
	bool is_utf16_surregate = cp >= 0xd800 && cp <= 0xdfff;
	// Largest Unicode code point is 0x10ffff, also limited in RFC 3629.
	bool above_max_code_point = cp > 0x10ffff;
	return !is_utf16_surregate && !above_max_code_point;
}
