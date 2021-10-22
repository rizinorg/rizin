// SPDX-FileCopyrightText: 2021 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_ebcdic.h"
#include "rz_util/rz_assert.h"

/**
 *  \file ebcdic.c
 * Support charsets:
 * 1. IBM037
 * 2. IBM290
 * 3. EBCDIC-UK
 * 4. EBCDIC-US
 * 5. EBCDIC-ES
 * 
 * see:
 *  - https://www.ibm.com/docs/en/zos/2.3.0?topic=sets-coded-character-sorted-by-ccsid
 *  - https://www.compart.com/en/unicode/search?q=EBCDIC#char-sets
 * 
 */

/**
 * \name IBM037
 * see https://www.compart.com/en/unicode/charsets/IBM037
 */
/// @{

/**
 * \brief Convert an ibm037 char into an unicode RzRune
 * 
 * \param src ibm037 char
 * \param dst unicode RzRune
 * \retval 0 if \p dst is null
 * \retval 1 if convert successful
 */
RZ_API int rz_str_ibm037_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzRune *dst) {
	rz_return_val_if_fail(dst, 0);
	*dst = ibm037_to_uni[src];
	return 1;
}

/**
 * \brief Convert an unicode RzRune into an ibm037 char
 * 
 * \param dst ibm037 char
 * \param src unicode RzRune
 */
RZ_API int rz_str_ibm037_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzRune src) {
	rz_return_val_if_fail(dst, 0);
	if (src <= 0xff) {
		*dst = ibm037_from_uni[src];
		return 1;
	}
	return 0;
}

/**
 * \brief Convert an ibm037 char into an ascii char
 * 
 * \param dst ibm037 char
 * \param src ascii char
 */
RZ_API int rz_str_ibm037_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst) {
	rz_return_val_if_fail(dst, 0);
	ut8 c = ibm037_to_uni[src];
	if (c < 0x80) {
		*dst = c;
		return 1;
	}
	return 0;
}

/**
 * \brief Convert an ascii char into an ibm037 char
 * 
 * \param dst ibm037 char
 * \param src ascii char
 */
RZ_API int rz_str_ibm037_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src) {
	rz_return_val_if_fail(dst, 0);
	*dst = ibm037_from_uni[src];
	return 1;
}

/// @}

/**
 * \name IBM290
 * see https://www.compart.com/en/unicode/charsets/IBM290
 */

/// @{

/// Convert an ibm290 char into an unicode RzRune
RZ_API int rz_str_ibm290_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzRune *dst) {
	rz_return_val_if_fail(dst, 0);
	*dst = ibm290_to_uni[src];
	return 1;
}

/// Convert an unicode RzRune into an ibm290 char
RZ_API int rz_str_ibm290_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzRune src) {
	rz_return_val_if_fail(dst, 0);
	if (src <= 0xff) {
		*dst = ibm290_page00[src];
		return 1;
	} else if (src >= 0x3000 && src <= 0x30ff) {
		*dst = ibm290_page30[src & 0xff];
		return 1;
	}
	return 0;
}

/// Convert an ibm290 char into an ascii char
RZ_API int rz_str_ibm290_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst) {
	rz_return_val_if_fail(dst, 0);
	ut8 c = ibm290_to_uni[src];
	if (c < 0x80) {
		*dst = c;
		return 1;
	}
	return 0;
}

/// Convert an ascii char into an ibm290 char
RZ_API int rz_str_ibm290_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src) {
	rz_return_val_if_fail(dst, 0);
	*dst = ibm290_page00[src];
	return 1;
}

/// @}

/**
 * \name EBCDIC-UK
 * see https://www.compart.com/en/unicode/charsets/EBCDIC-UK
 */

/// @{

/// Convert an ebcdic_uk char into an unicode RzRune
RZ_API int rz_str_ebcdic_uk_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzRune *dst) {
	rz_return_val_if_fail(dst, 0);
	*dst = ebcdic_uk_to_uni[src];
	return 1;
}

/// Convert an unicode RzRune into an ebcdic_uk char
RZ_API int rz_str_ebcdic_uk_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzRune src) {
	rz_return_val_if_fail(dst, 0);
	if (src <= 0xff) {
		*dst = ebcdic_uk_from_uni[src];
		return 1;
	}
	return 0;
}

/// Convert an ebcdic_uk char into an ascii char
RZ_API int rz_str_ebcdic_uk_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst) {
	rz_return_val_if_fail(dst, 0);
	ut8 c = ebcdic_uk_to_uni[src];
	if (c < 0x80) {
		*dst = c;
		return 1;
	}
	return 0;
}

/// Convert an ascii char into an ebcdic_uk char
RZ_API int rz_str_ebcdic_uk_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src) {
	rz_return_val_if_fail(dst, 0);
	*dst = ebcdic_uk_from_uni[src];
	return 1;
}

/// @}

/**
 * \name EBCDIC-US
 * see https://www.compart.com/en/unicode/charsets/EBCDIC-US
 */

/// @{

/// Convert an ebcdic_us char into an unicode RzRune
RZ_API int rz_str_ebcdic_us_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzRune *dst) {
	rz_return_val_if_fail(dst, 0);
	*dst = ebcdic_us_to_uni[src];
	return 1;
}

/// Convert an unicode RzRune into an ebcdic_us char
RZ_API int rz_str_ebcdic_us_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzRune src) {
	rz_return_val_if_fail(dst, 0);
	if (src <= 0xff) {
		*dst = ebcdic_us_from_uni[src];
		return 1;
	}
	return 0;
}

/// Convert an ebcdic_us char into an ascii char
RZ_API int rz_str_ebcdic_us_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst) {
	rz_return_val_if_fail(dst, 0);
	ut8 c = ebcdic_us_to_uni[src];
	if (c < 0x80) {
		*dst = c;
		return 1;
	}
	return 0;
}

/// Convert an ascii char into an ebcdic_us char
RZ_API int rz_str_ebcdic_us_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src) {
	rz_return_val_if_fail(dst, 0);
	*dst = ebcdic_us_from_uni[src];
	return 1;
}

/// @}

/**
 * \name EBCDIC-ES
 * see https://www.compart.com/en/unicode/charsets/EBCDIC-ES
 */
/// @{

/// Convert an ebcdic_es char into an unicode RzRune
RZ_API int rz_str_ebcdic_es_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzRune *dst) {
	rz_return_val_if_fail(dst, 0);
	*dst = ebcdic_es_to_uni[src];
	return 1;
}

/// Convert an unicode RzRune into an ebcdic_es char
RZ_API int rz_str_ebcdic_es_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzRune src) {
	rz_return_val_if_fail(dst, 0);
	if (src <= 0xff) {
		*dst = ebcdic_es_page00[src];
		return 1;
	} else if (src >= 0x2000 && src <= 0x20ff) {
		*dst = ebcdic_es_page20[src & 0xff];
		return 1;
	}
	return 0;
}

/// Convert an ebcdic_es char into an ascii char
RZ_API int rz_str_ebcdic_es_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst) {
	rz_return_val_if_fail(dst, 0);
	ut8 c = ebcdic_es_to_uni[src];
	if (c < 0x80) {
		*dst = c;
		return 1;
	}
	return 0;
}

/// Convert an ascii char into an ebcdic char
RZ_API int rz_str_ebcdic_es_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src) {
	rz_return_val_if_fail(dst, 0);
	*dst = ebcdic_es_page00[src];
	return 1;
}

/// @}
