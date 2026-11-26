// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include "rz_util/rz_assert.h"
#include "rz_util/rz_str.h"
#include "rz_util/rz_unicode.h"

/**
 * Include auto-generated Unicode tables
 */
#include "unicode_tables.inc"
#include "undefined_ranges_bitmap.inc"

/**
 * Note: undefined if `index` exceeds `undefined_ranges_bitmap` size. Caller should do proper checks.
 */
static inline bool undefined_ranges_bitmap_at(RzCodePoint index) {
	const ut32 bits_per_element = sizeof(undefined_ranges_bitmap[0]) * 8;
	return (undefined_ranges_bitmap[index / bits_per_element] & (1ull << (index % bits_per_element))) != 0;
}

static bool bin_search_range(RzCodePoint cp, const RzUnicodeRangeTable table, size_t table_size) {
	size_t low = 0;
	size_t hi = table_size - 1;

	do {
		size_t mid = (low + hi) >> 1;
		if (cp >= table[mid].from && cp <= table[mid].to) {
			return true;
		}
		if (low == hi) {
			break;
		}
		if (mid < table_size && cp > table[mid].to) {
			low = mid + 1;
		}
		if (mid < table_size && cp < table[mid].from) {
			hi = mid - 1;
		}
	} while (low <= hi);

	return false;
}

/**
 * \brief Returns true when the RzCodePoint is a defined Unicode code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is defined, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_defined(const RzCodePoint c) {
	if (c > RZ_UNICODE_LAST_CODE_POINT) {
		return false;
	}
	const ut32 undefined_ranges_bitmap_size = RZ_ARRAY_SIZE(undefined_ranges_bitmap) * sizeof(undefined_ranges_bitmap[0]) * 8;
	if (c < undefined_ranges_bitmap_size) {
		return !undefined_ranges_bitmap_at(c);
	}
	return !bin_search_range(c, undefined_ranges + undefined_ranges_skip_entries, RZ_ARRAY_SIZE(undefined_ranges) - undefined_ranges_skip_entries);
}

/**
 * \brief Returns true when the RzCodePoint is a defined Unicode code point and not a surrogate.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is defined and not a surrogate, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_legal_decode(const RzCodePoint c) {
	return rz_unicode_code_point_is_defined(c) && !rz_unicode_code_point_is_surrogate(c);
}

/**
 * \brief Returns true when the RzCodePoint is a Unicode control code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is a control code point, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_control(const RzCodePoint c) {
	return (c >= control_ranges[0].from && c <= control_ranges[0].to) ||
		(c >= control_ranges[1].from && c <= control_ranges[1].to);
}

/**
 * \brief Returns true when the RzCodePoint is a Unicode surrogate code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is a surrogate code point, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_surrogate(const RzCodePoint c) {
	return c >= surrogate_ranges[0].from && c <= surrogate_ranges[0].to;
}

/**
 * \brief Returns true when the RzCodePoint is a Unicode private code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is a private code point, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_private(const RzCodePoint c) {
	return bin_search_range(c, private_ranges, RZ_ARRAY_SIZE(private_ranges));
}

/**
 * \brief Returns true when the RzCodePoint is a Unicode format code point.
 *
 * \param c RzCodePoint value to test.
 *
 * \return True if the code point is a format code point, false otherwise.
 */
RZ_API bool rz_unicode_code_point_is_format(const RzCodePoint c) {
	return bin_search_range(c, format_ranges, RZ_ARRAY_SIZE(format_ranges));
}

/**
 * \brief Returns true when the RzCodePoint is a printable symbol.
 * Printable means:
 * - Is defined Unicode code point.
 * - Outside of the control plain.
 * - Not a surrogate.
 * - Not from the private range.
 * - Not a format character.
 *
 * NOTE: This means \n, \t, \r etc. are considered not printable!
 * NOTE: Be careful when passing char values to it. On some platforms
 * they might get sign extended and the result is an invalid code point.
 *
 * \param  c RzCodePoint value to test.
 *
 * \return   true if the code point is printable, otherwise false.
 */
RZ_API bool rz_unicode_code_point_is_printable(const RzCodePoint c) {
	// RzCodePoints are most commonly single bytes.
	// We can early out with this common case.
	if (c <= RZ_UNICODE_LAST_ASCII) {
		// Check for control plain of ASCII here, because they are so common.
		return IS_PRINTABLE(c);
	}
	return !rz_unicode_code_point_is_control(c) &&
		rz_unicode_code_point_is_defined(c) &&
		!rz_unicode_code_point_is_surrogate(c) &&
		!rz_unicode_code_point_is_format(c) &&
		!rz_unicode_code_point_is_private(c);
}

static RzUnicodeCaseMapping bin_search_case_mapping(const RzUnicodeCaseMap map, size_t n, RzCodePoint key) {
	size_t lo = 0, hi = n;
	while (lo < hi) {
		size_t mid = lo + ((hi - lo) >> 1);
		RzCodePoint k = map[mid].key;
		if (k == key) {
			return map[mid];
		}
		if (k < key) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	return rz_unicode_case_mapping_default(key);
}

RZ_API RzUnicodeCaseMapping rz_unicode_case_mapping_default(RzCodePoint key) {
	RzUnicodeCaseMapping um = { key, { 0 } };
	return um;
}

RZ_API bool rz_unicode_case_mapping_is_empty(RZ_NULLABLE const RzUnicodeCaseMapping *um) {
	return !um || !um->val[0];
}

RZ_API RzUnicodeCaseMapping rz_unicode_code_point_find_lower(RzCodePoint c) {
	return bin_search_case_mapping(lowercase_mapping, RZ_ARRAY_SIZE(lowercase_mapping), c);
}

RZ_API RzUnicodeCaseMapping rz_unicode_code_point_find_upper(RzCodePoint c) {
	return bin_search_case_mapping(uppercase_mapping, RZ_ARRAY_SIZE(uppercase_mapping), c);
}

RZ_API RzStrEnc rz_unicode_bom_encoding(const ut8 *ptr, size_t ptrlen) {
	rz_return_val_if_fail(ptr, RZ_STRING_ENC_GUESS);
	if (ptrlen > 3) {
		if (ptr[0] == 0xff && ptr[1] == 0xfe && !ptr[2] && !ptr[3]) {
			return RZ_STRING_ENC_UTF32LE;
		}
		if (!ptr[0] && !ptr[1] && ptr[2] == 0xfe && ptr[3] == 0xff) {
			return RZ_STRING_ENC_UTF32BE;
		}
	}
	if (ptrlen > 2) {
		if (ptr[0] == 0xef && ptr[1] == 0xbb && ptr[2] == 0xbf) {
			return RZ_STRING_ENC_UTF8;
		}
	}
	if (ptrlen > 1) {
		if (ptr[0] == 0xff && ptr[1] == 0xfe) {
			return RZ_STRING_ENC_UTF16LE;
		}
		if (ptr[0] == 0xfe && ptr[1] == 0xff) {
			return RZ_STRING_ENC_UTF16BE;
		}
	}
	return RZ_STRING_ENC_GUESS;
}

static bool short_escape(RzCodePoint code_point, char **dst, const RzStrEscOptions *opt) {
	char *q = *dst;
	switch (code_point) {
	case '\n':
		*q++ = '\\';
		*q++ = opt->dot_nl ? 'l' : 'n';
		break;
	case '\r':
		*q++ = '\\';
		*q++ = 'r';
		break;
	case '\\':
		if (opt->esc_bslash) {
			*q++ = '\\';
		}
		*q++ = '\\';
		break;
	case '\t':
		*q++ = '\\';
		*q++ = 't';
		break;
	case '"':
		if (opt->esc_double_quotes) {
			*q++ = '\\';
		}
		*q++ = '"';
		break;
	case '\f':
		*q++ = '\\';
		*q++ = 'f';
		break;
	case '\b':
		*q++ = '\\';
		*q++ = 'b';
		break;
	case '\v':
		*q++ = '\\';
		*q++ = 'v';
		break;
	case '\a':
		*q++ = '\\';
		*q++ = 'a';
		break;
	case '\x1b':
		*q++ = '\\';
		*q++ = 'e';
		break;
	default:
		return false;
	}
	*dst = q;
	return true;
}

/**
 * \brief Converts an unicode characters to the \U00hhhhhh backslash representation.
 * Common control characters like (new line, tab etc.) are escaped
 * to their short form ('\n', '\r', '\t' etc.).
 *
 * NOTE: The \p dst pointer is incremented up to 10 bytes (if \U00hhhhhh is copied into it).
 * NOTE: This function _ignores_ opt->keep_printable.
 *
 * \param code_point The code point to escape.
 * \param dst String pointer to write the escaped code point into.
 * It must have at least a length of 11 (10 + '\0'). It gets incremented by the amount of bytes copied into it.
 * \param opt The encoding options structure.
 **/
RZ_API void rz_unicode_code_point_escape(RzCodePoint code_point, RZ_NONNULL RZ_OUT char **dst, RZ_NONNULL const RzStrEscOptions *opt) {
	rz_return_if_fail(dst && opt);

	char *q = *dst;
	if (opt->show_asciidot && !IS_PRINTABLE(code_point)) {
		*q++ = '.';
		goto assign_return;
	} else if (short_escape(code_point, &q, opt)) {
		goto assign_return;
	} else {
		rz_snprintf(q, RZ_UNICODE_ESCAPED_STR_WIDTH + 1, "\\U00%06" PFMT32x, code_point);
		q += RZ_UNICODE_ESCAPED_STR_WIDTH;
	}
assign_return:
	*dst = q;
}

/**
 * \brief Escapes an unprintable character to C-like backslash representation '\xhh'.
 * Common control characters like (new line, tab etc.) are escaped
 * to their short form ('\n', '\r', '\t' etc.).
 *
 * NOTE: The \p dst pointer is incremented by 2 to 4 bytes.
 * NOTE: This function _ignores_ opt->keep_printable.
 *
 * \param ch The character to escape.
 * \param dst pointer where pointer to the resulting characters sequence is put.
 * \param opt pointer to encoding options structure.
 **/
RZ_API void rz_unicode_byte_escape(char ch, RZ_NONNULL RZ_OUT char **dst, RZ_NONNULL const RzStrEscOptions *opt) {
	rz_return_if_fail(dst && opt);
	char *q = *dst;
	if (opt->show_asciidot && !IS_PRINTABLE(ch)) {
		*q++ = '.';
		goto assign_return;
	} else if (short_escape(ch, &q, opt)) {
		goto assign_return;
	} else {
		*q++ = '\\';
		*q++ = 'x';
		*q++ = "0123456789abcdef"[ch >> 4 & 0xf];
		*q++ = "0123456789abcdef"[ch & 0xf];
	}
assign_return:
	*dst = q;
}
