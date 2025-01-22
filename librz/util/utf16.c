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

static RzRune utf16_surrogate_to_codepoint(ut16 high_surrogate, ut16 low_surrogate) {
	ut32 high = (high_surrogate - 0xd800) * 0x400;
	ut32 low = (low_surrogate - 0xdc00);
	RzRune codepoint = high + low;
	RzRune codepoint1 = 0x10000 + codepoint;
	return codepoint1;
}

/* Convert an UTF-16 buf into a unicode RzRune */
RZ_API int rz_utf16_decode(const ut8 *ptr, int ptrlen, RzRune *ch, bool bigendian) {
	if (ptrlen < 1) {
		return 0;
	}
	int high = bigendian ? 0 : 1;
	int low = bigendian ? 1 : 0;
	if (ptrlen > 3) {
		if (!is_valid_surrogate_pair(ptr[high], ptr[high + 2])) {
			return 0;
		}
		if (ch) {
			*ch = utf16_surrogate_to_codepoint((ptr[high] << 8 | ptr[low]), (ptr[high + 2] << 8) | ptr[low + 2]);
		}
		return 4;
	}
	if (ptrlen > 1 && ptr[high]) {
		if (ch) {
			*ch = ptr[high] << 8 | ptr[low];
		}
		return 2;
	}
	if (ptrlen > 1) {
		if (ch) {
			*ch = (ut32)ptr[low];
		}
		return 1;
	}
	return 0;
}

/* Convert an UTF-16LE buf into a unicode RzRune */
RZ_API int rz_utf16le_decode(const ut8 *ptr, int ptrlen, RzRune *ch) {
	return rz_utf16_decode(ptr, ptrlen, ch, false);
}

/* Convert an UTF-16BE buf into a unicode RzRune */
RZ_API int rz_utf16be_decode(const ut8 *ptr, int ptrlen, RzRune *ch) {
	return rz_utf16_decode(ptr, ptrlen, ch, true);
}

/* Convert a unicode RzRune into a UTF-16LE buf */
RZ_API int rz_utf16le_encode(ut8 *ptr, RzRune ch) {
	if (ch < 0x10000) {
		ptr[0] = ch & 0xff;
		ptr[1] = ch >> 8 & 0xff;
		return 2;
	}
	if (ch < 0x110000) {
		ch -= 0x10000;
		RzRune high = 0xd800 + (ch >> 10 & 0x3ff);
		RzRune low = 0xdc00 + (ch & 0x3ff);
		ptr[0] = high & 0xff;
		ptr[1] = high >> 8 & 0xff;
		ptr[2] = low & 0xff;
		ptr[3] = low >> 8 & 0xff;
		return 4;
	}
	return 0;
}
