// SPDX-FileCopyrightText: 2021 borzacchiello <lucaborza@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_assert.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_buf.h>
#include <rz_util/rz_regex.h>
#include <rz_util/ht_uu.h>
#include <rz_util/rz_str_search.h>
#include <rz_util/rz_utf8.h>
#include <rz_util/rz_utf16.h>
#include <rz_util/rz_utf32.h>
#include <rz_util/rz_ebcdic.h>

/**
 * Free a RzDetectedString
 */
RZ_API void rz_detected_string_free(RzDetectedString *str) {
	if (!str) {
		return;
	}
	free(str->string);
	rz_regex_free(str->regex);
	free(str);
}

static inline bool is_c_escape_sequence(char ch) {
	return strchr("\b\v\f\n\r\t\a\033\\", ch);
}

static ut64 adjust_offset(RzStrEnc str_type, const ut8 *buf, const ut64 str_start) {
	switch (str_type) {
	case RZ_STRING_ENC_UTF16LE:
		if (str_start > 1) {
			const ut8 *p = buf + str_start - 2;
			if (p[0] == 0xff && p[1] == 0xfe) {
				return 2; // \xff\xfe
			}
		}
		break;
	case RZ_STRING_ENC_UTF16BE:
		if (str_start > 1) {
			const ut8 *p = buf + str_start - 2;
			if (p[0] == 0xfe && p[1] == 0xff) {
				return 2; // \xfe\xff
			}
		}
		break;
	case RZ_STRING_ENC_UTF32LE:
		if (str_start > 3) {
			const ut8 *p = buf + str_start - 4;
			if (p[0] == 0xff && p[1] == 0xfe && !p[2] && !p[3]) {
				return 4; // \xff\xfe\x00\x00
			}
		}
		break;
	case RZ_STRING_ENC_UTF32BE:
		if (str_start > 3) {
			const ut8 *p = buf + str_start - 4;
			if (!p[0] && !p[1] && p[2] == 0xfe && p[3] == 0xff) {
				return 4; // \x00\x00\xfe\xff
			}
		}
		break;
	default:
		break;
	}

	return 0;
}

static inline size_t buf_look_ahead(const RzUtilStrScanOptions *opt, RzStrEnc enc) {
	if (opt->buf_size < opt->min_str_length) {
		return 0;
	}
	switch (enc) {
	case RZ_STRING_ENC_8BIT:
		return 1;
	case RZ_STRING_ENC_UTF16BE:
	case RZ_STRING_ENC_UTF16LE:
		return 2;
	case RZ_STRING_ENC_UTF32BE:
	case RZ_STRING_ENC_UTF32LE:
	default:
		return 4;
	}
}

static RzDetectedString *process_one_string(const ut8 *buf, const ut64 from, ut64 needle, const ut64 to,
	RzStrEnc str_type, const RzUtilStrScanOptions *opt, ut64 str_list_idx) {
	rz_return_val_if_fail(str_type != RZ_STRING_ENC_GUESS, NULL);
	size_t look_ahead = buf_look_ahead(opt, str_type);
	if (look_ahead == 0) {
		return NULL;
	}

	ut8 *strbuf = RZ_NEWS0(ut8, opt->buf_size);
	if (!strbuf) {
		goto error;
	}

	if (str_type == RZ_STRING_ENC_UTF8) {
		// Below it will be reset to UTF-8 if any non-ascii character
		// was decoded.
		str_type = RZ_STRING_ENC_8BIT;
	}

	ut64 str_addr = needle;
	int rc = 0, i = 0, runes = 0;

	/* Eat a whole C string */
	for (i = 0; i < opt->buf_size - look_ahead && needle < to; i += rc) {
		RzCodePoint r = 0;

		switch (str_type) {
		case RZ_STRING_ENC_UTF32LE:
			rc = rz_utf32le_decode(buf + needle - from, to - needle, &r);
			break;
		case RZ_STRING_ENC_UTF16LE:
			rc = rz_utf16le_decode(buf + needle - from, to - needle, &r);
			break;
		case RZ_STRING_ENC_UTF32BE:
			rc = rz_utf32be_decode(buf + needle - from, to - needle, &r);
			break;
		case RZ_STRING_ENC_UTF16BE:
			rc = rz_utf16be_decode(buf + needle - from, to - needle, &r);
			break;
		case RZ_STRING_ENC_IBM037:
			rc = rz_str_ibm037_to_unicode(*(buf + needle - from), &r);
			break;
		case RZ_STRING_ENC_IBM290:
			rc = rz_str_ibm290_to_unicode(*(buf + needle - from), &r);
			break;
		case RZ_STRING_ENC_EBCDIC_ES:
			rc = rz_str_ebcdic_es_to_unicode(*(buf + needle - from), &r);
			break;
		case RZ_STRING_ENC_EBCDIC_UK:
			rc = rz_str_ebcdic_uk_to_unicode(*(buf + needle - from), &r);
			break;
		case RZ_STRING_ENC_EBCDIC_US:
			rc = rz_str_ebcdic_us_to_unicode(*(buf + needle - from), &r);
			break;
		case RZ_STRING_ENC_SETTINGS:
		case RZ_STRING_ENC_GUESS:
		case RZ_STRING_ENC_MUTF8:
		case RZ_STRING_ENC_BASE64:
			rz_warn_if_reached();
			RZ_LOG_ERROR("Illegal state reached. '%s' encoding is not a valid value here.\n", rz_str_enc_as_string(str_type));
			return NULL;
		case RZ_STRING_ENC_UTF8:
		case RZ_STRING_ENC_8BIT:
			rc = rz_utf8_decode(buf + needle - from, to - needle, &r);
			if (r > 0x7f) {
				str_type = RZ_STRING_ENC_UTF8;
			}
			break;
		}

		/* Invalid sequence detected */
		if (!rc) {
			needle++;
			break;
		}

		if (opt->utf8_to_mem_offset_map && !rz_string_enc_is_utf8_compatible(str_type)) {
			ut64 offset_id = ((str_list_idx) << 32) | i;
			ht_uu_insert(opt->utf8_to_mem_offset_map, offset_id, needle);
		}

		needle += rc;

		if (rz_code_point_is_printable(r) && r != '\\') {
			rc = rz_utf8_encode(strbuf + i, r);
			runes++;
		} else if (r && r < 0x100 && is_c_escape_sequence((char)r)) {
			if ((i + 32) < opt->buf_size && r < 93) {
				rc = rz_utf8_encode(strbuf + i, r);
			} else {
				// String too long
				break;
			}
			runes++;
		} else {
			/* \0 marks the end of C-strings */
			break;
		}
	}

	int strbuf_size = i;
	if (runes >= opt->min_str_length) {
		RzDetectedString *ds = RZ_NEW0(RzDetectedString);
		if (!ds) {
			goto error;
		}
		ds->type = str_type;
		ds->length = runes;
		ds->size = needle - str_addr;
		ds->addr = str_addr;

		ut64 off_adj = adjust_offset(str_type, buf, ds->addr - from);
		ds->addr -= off_adj;
		ds->size += off_adj;

		ds->string = rz_str_ndup((const char *)strbuf, strbuf_size);
		free(strbuf);
		return ds;
	}

error:
	free(strbuf);
	return NULL;
}

/**
 * \brief Look for strings in a byte array, but returns only the first result.
 *
 * \param buf     Pointer to a raw buffer to scan
 * \param opt     Pointer to a RzUtilStrScanOptions that specifies search parameters
 * \param type    Type of strings to search
 * \param output  Pointer to a RzDetectedString where to store the result.
 *
 * \return On success returns true, otherwise false.
 */
RZ_API bool rz_scan_strings_single_raw(RZ_NONNULL const ut8 *buf, ut64 size, RZ_NONNULL const RzUtilStrScanOptions *opt, RzStrEnc type, RZ_NONNULL RzDetectedString **output) {
	rz_return_val_if_fail(buf && opt && output, false);

	RzList *list = rz_list_newf((RzListFree)rz_detected_string_free);
	if (!list) {
		return false;
	} else if (rz_scan_strings_raw(buf, list, opt, 0, size, type) > 0) {
		*output = rz_list_pop_head(list);
	}

	rz_list_free(list);
	return *output != NULL;
}

/**
 * \brief Look for strings in a byte array.
 *
 * \param buf   Pointer to a raw buffer to scan.
 * \param list  Pointer to a list that will be populated with the found strings.
 * \param opt   Pointer to an RzUtilStrScanOptions that specifies search parameters.
 * \param from  Minimum address to scan.
 * \param to    Maximum address to scan.
 * \param type  Type of strings to search.
 *
 * \return Number of strings found. Or -1 in case of failure.
 *
 * Used to look for strings in a give RzBuffer. The function can also automatically detect string types.
 */
RZ_API int rz_scan_strings_raw(RZ_NONNULL const ut8 *buf, RZ_NONNULL RzList /*<RzDetectedString *>*/ *list, RZ_NONNULL const RzUtilStrScanOptions *opt,
	const ut64 from, const ut64 to, RzStrEnc type) {
	rz_return_val_if_fail(opt && list && buf, -1);

	if (from == to) {
		return 0;
	} else if (from > to) {
		RZ_LOG_ERROR("rz_scan_strings: Invalid range to find strings 0x%" PFMT64x " .. 0x%" PFMT64x "\n", from, to);
		return -1;
	}

	RzStrEncStats *stats = NULL;
	if (type == RZ_STRING_ENC_SETTINGS || type == RZ_STRING_ENC_BASE64) {
		rz_warn_if_reached();
		return 0;
	}
	if (type != RZ_STRING_ENC_GUESS) {
		ut64 needle = from;
		while (needle < to) {
			RzDetectedString *ds = process_one_string(buf, from, needle, to, type, opt, rz_list_length(list));
			if (!ds) {
				needle++;
				continue;
			}
			rz_list_append(list, ds);
			needle += ds->size;
		}
		return rz_list_length(list);
	}

	// We have to guess the string encoding
	size_t length = to - from;
	RzStrEnc bom = rz_utf_bom_encoding(buf + from, length);

	RzStrEncStatsBiases biases = opt->prefer_big_endian ? rz_str_enc_stats_get_big_endian_biases() : rz_str_enc_stats_get_default_biases();
	stats = rz_str_enc_stats_new(length, opt->min_str_length, bom, &biases);
	if (!stats) {
		return 0;
	}
	rz_str_enc_stats_run(stats, buf + from, length);
	RzVector *pois = rz_str_enc_stats_get_pois(stats);

	RzStrEncPOI *poi;
	rz_vector_foreach (pois, poi) {
		RzDetectedString *ds = process_one_string(buf, from, poi->buf_offset + from, to, poi->candidate.enc, opt, rz_list_length(list));
		if (ds) {
			rz_list_append(list, ds);
		}
	}

	rz_vector_free(pois);
	rz_str_enc_stats_free(stats);
	return rz_list_length(list);
}

/**
 * \brief Look for strings in an RzBuffer.
 * \param buf_to_scan Pointer to a RzBuffer to scan.
 * \param list Pointer to a list that will be populated with the found strings.
 * \param opt Pointer to a RzUtilStrScanOptions that specifies search parameters.
 * \param from Minimum address to scan.
 * \param to Maximum address to scan.
 * \param type Type of strings to search.
 * \return Number of strings found.
 *
 * Used to look for strings in a give RzBuffer. The function can also automatically detect string types.
 */
RZ_API int rz_scan_strings(RZ_NONNULL RzBuffer *buf_to_scan, RZ_NONNULL RzList /*<RzDetectedString *>*/ *list, RZ_NONNULL const RzUtilStrScanOptions *opt,
	const ut64 from, const ut64 to, RzStrEnc type) {
	rz_return_val_if_fail(opt && list && buf_to_scan, -1);

	if (from == to) {
		return 0;
	} else if (from > to) {
		RZ_LOG_ERROR("rz_scan_strings: Invalid range to find strings 0x%" PFMT64x " .. 0x%" PFMT64x "\n", from, to);
		return -1;
	} else if (type == RZ_STRING_ENC_MUTF8 || type == RZ_STRING_ENC_BASE64) {
		RZ_LOG_ERROR("rz_scan_strings: %s search type is not supported.\n", rz_str_enc_as_string(type));
		return -1;
	}

	ut64 len = to - from;
	ut8 *buf = calloc(len, 1);
	if (!buf) {
		return -1;
	}

	rz_buf_read_at(buf_to_scan, from, buf, len);

	int count = rz_scan_strings_raw(buf, list, opt, from, to, type);

	free(buf);
	return count;
}

/**
 * \brief Look for strings in an RzBuffer. The whole buffer is scanned.
 * This function is suited for usage on hot paths.
 *
 * \param buf_to_scan Pointer to an RzBuffer to scan.
 * \param list Pointer to a list that will be populated with the found strings. The strings are always cinverted as UTF-8.
 * \param opt Pointer to an RzUtilStrScanOptions that specifies search parameters.
 * \param type Type of strings to search.
 *
 * \return Number of strings found or -1 in case of failure.
 */
RZ_API int rz_scan_strings_whole_buf(RZ_NONNULL const RzBuffer *buf_to_scan, RZ_NONNULL RzList /*<RzDetectedString *>*/ *list, RZ_NONNULL const RzUtilStrScanOptions *opt, RzStrEnc type) {
	rz_return_val_if_fail(opt && list && buf_to_scan, -1);
	if (type == RZ_STRING_ENC_MUTF8 || type == RZ_STRING_ENC_BASE64) {
		RZ_LOG_ERROR("rz_scan_strings_whole_buf: '%s' search type is not supported.\n", rz_str_enc_as_string(type));
		return -1;
	}

	ut64 size;
	const ut8 *raw_buf = rz_buf_get_whole_hot_paths((RzBuffer *)buf_to_scan, &size);
	if (!raw_buf) {
		RZ_LOG_ERROR("Failed to get whole buffer.");
		return -1;
	}
	int count = rz_scan_strings_raw(raw_buf, list, opt, 0, size, type);
	return count;
}
