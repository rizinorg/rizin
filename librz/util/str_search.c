// SPDX-FileCopyrightText: 2021 borzacchiello <lucaborza@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_str_search.h>
#include <rz_util/rz_utf8.h>
#include <rz_util/rz_utf16.h>
#include <rz_util/rz_utf32.h>
#include <rz_util/rz_ebcdic.h>

typedef enum {
	SKIP_STRING,
	RETRY_ASCII,
	STRING_OK,
} FalsePositiveResult;

typedef struct {
	int num_ascii;
	int num_ascii_extended;
	int num_chars;
} UTF8StringInfo;

// clang-format off
static const ut8 LATIN1_CLASS[256] = {
  0,0,0,0,0,0,0,0, 0,1,1,0,0,1,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
  1,6,6,6,6,6,6,6, 6,6,6,6,6,6,6,6, 2,2,2,2,2,2,2,2, 2,2,6,6,6,6,6,6,
  6,3,3,3,3,3,3,3, 3,3,3,3,3,3,3,3, 3,3,3,3,3,3,3,3, 3,3,3,6,6,6,6,6,
  6,4,4,4,4,4,4,4, 4,4,4,4,4,4,4,4, 4,4,4,4,4,4,4,4, 4,4,4,6,6,6,6,0,

  0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
  1,6,6,6,6,6,6,6, 6,6,6,6,6,6,6,6, 6,6,6,6,6,6,6,6, 6,6,6,6,6,6,6,6,
  5,5,5,5,5,5,5,5, 5,5,5,5,5,5,5,5, 5,5,5,5,5,5,5,5, 5,5,5,5,5,5,5,6,
  5,5,5,5,5,5,5,5, 5,5,5,5,5,5,5,5, 5,5,5,5,5,5,5,6, 5,5,5,5,5,5,5,5,
};
static const ut8 LATIN1[49] = {
	0,0,0,0,0,0,0,
	0,1,6,6,6,1,3,
	0,6,12,6,6,1,3,
	0,6,6,18,9,1,3,
	0,6,6,9,18,1,3,
	0,1,1,1,1,1,1,
	0,3,3,3,3,1,3,
};
// clang-format on

static inline int compute_index(ut8 x, ut8 y) {
	return (x * 7 + y);
}

static st64 score(RzCodePoint *buff, const int len) {
	int score = 0;
	for (RzCodePoint *src = buff, *end = buff + len - 1; src < end; ++src) {
		RzCodePoint b1 = src[0], b2 = src[1];
		ut8 c1 = LATIN1_CLASS[b1], c2 = LATIN1_CLASS[b2];
		if (b1 > 0x7f) {
			score -= 6;
		}

		ut8 i = compute_index(c1, c2);
		rz_return_val_if_fail(i < 49, ST64_MIN);
		ut8 y = LATIN1[i];
		if (y == 0) {
			score += -100;
		} else {
			score += y;
		}
	}
	return score;
}

/**
 * Free a RzDetectedString
 */
RZ_API void rz_detected_string_free(RzDetectedString *str) {
	if (!str) {
		return;
	}
	free(str->string);
	free(str);
}

static inline bool is_c_escape_sequence(char ch) {
	return strchr("\b\v\f\n\r\t\a\033\\", ch);
}

static UTF8StringInfo calculate_utf8_string_info(ut8 *str, int size) {
	UTF8StringInfo res = {
		.num_ascii = 0,
		.num_ascii_extended = 0,
		.num_chars = 0
	};

	const ut8 *str_ptr = str;
	const ut8 *str_end = str + size;
	RzCodePoint ch = 0;
	while (str_ptr < str_end) {
		int ch_bytes = rz_utf8_decode(str_ptr, str_end - str_ptr, &ch);
		if (!ch_bytes) {
			break;
		}

		res.num_chars += 1;
		if (ch < 0x80u) {
			res.num_ascii += 1;
		}
		if (ch < 0x100u) {
			res.num_ascii_extended += 1;
		}

		str_ptr += ch_bytes;
	}

	return res;
}

static FalsePositiveResult reduce_false_positives(const RzUtilStrScanOptions *opt, ut8 *str, int size, RzStrEnc str_type) {

	switch (str_type) {
	case RZ_STRING_ENC_8BIT: {
		for (int i = 0; i < size; i++) {
			char ch = str[i];
			if (!is_c_escape_sequence(ch)) {
				if (!IS_PRINTABLE(str[i])) {
					return SKIP_STRING;
				}
			}
		}
		break;
	}
	case RZ_STRING_ENC_UTF8:
	case RZ_STRING_ENC_UTF16LE:
	case RZ_STRING_ENC_UTF32LE:
	case RZ_STRING_ENC_UTF16BE:
	case RZ_STRING_ENC_UTF32BE: {
		int num_blocks = 0;
		int *block_list = rz_utf_block_list((const ut8 *)str, size - 1, NULL);
		if (block_list) {
			for (int i = 0; block_list[i] != -1; i++) {
				num_blocks++;
			}
		}
		free(block_list);

		UTF8StringInfo str_info = calculate_utf8_string_info(str, size);
		if (str_info.num_ascii_extended == str_info.num_chars) {
			return STRING_OK;
		}

		int expected_ascii = num_blocks ? str_info.num_chars / num_blocks : 0;
		if (opt->check_ascii_freq && str_info.num_ascii > expected_ascii) {
			return RETRY_ASCII;
		}

		if (num_blocks > opt->max_uni_blocks) {
			return SKIP_STRING;
		}
		break;
	}
	default:
		break;
	}

	return STRING_OK;
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

static RzDetectedString *process_one_string(const ut8 *buf, const ut64 from, ut64 needle, const ut64 to,
	RzStrEnc str_type, bool ascii_only, const RzUtilStrScanOptions *opt, ut8 *strbuf) {

	rz_return_val_if_fail(str_type != RZ_STRING_ENC_GUESS, NULL);

	ut64 str_addr = needle;
	int rc = 0, i = 0, runes = 0;

	/* Eat a whole C string */
	for (i = 0; i < opt->buf_size - 4 && needle < to; i += rc) {
		RzCodePoint r = 0;

		if (str_type == RZ_STRING_ENC_UTF32LE) {
			rc = rz_utf32le_decode(buf + needle - from, to - needle, &r);
			if (rc) {
				rc = 4;
			}
		} else if (str_type == RZ_STRING_ENC_UTF16LE) {
			rc = rz_utf16le_decode(buf + needle - from, to - needle, &r);
			if (rc == 1) {
				rc = 2;
			}
		} else if (str_type == RZ_STRING_ENC_UTF32BE) {
			rc = rz_utf32be_decode(buf + needle - from, to - needle, &r);
			if (rc) {
				rc = 4;
			}
		} else if (str_type == RZ_STRING_ENC_UTF16BE) {
			rc = rz_utf16be_decode(buf + needle - from, to - needle, &r);
			if (rc == 1) {
				rc = 2;
			}
		} else if (str_type == RZ_STRING_ENC_IBM037) {
			rc = rz_str_ibm037_to_unicode(*(buf + needle - from), &r);
		} else if (str_type == RZ_STRING_ENC_IBM290) {
			rc = rz_str_ibm290_to_unicode(*(buf + needle - from), &r);
		} else if (str_type == RZ_STRING_ENC_EBCDIC_ES) {
			rc = rz_str_ebcdic_es_to_unicode(*(buf + needle - from), &r);
		} else if (str_type == RZ_STRING_ENC_EBCDIC_UK) {
			rc = rz_str_ebcdic_uk_to_unicode(*(buf + needle - from), &r);
		} else if (str_type == RZ_STRING_ENC_EBCDIC_US) {
			rc = rz_str_ebcdic_us_to_unicode(*(buf + needle - from), &r);
		} else {
			rc = rz_utf8_decode(buf + needle - from, to - needle, &r);
			if (rc > 1) {
				str_type = RZ_STRING_ENC_UTF8;
			}
		}

		/* Invalid sequence detected */
		if (!rc || (ascii_only && r > 0x7f)) {
			needle++;
			break;
		}

		needle += rc;

		if (rz_code_point_is_printable(r) && r != '\\') {
			if (str_type == RZ_STRING_ENC_UTF32LE || str_type == RZ_STRING_ENC_UTF32BE) {
				if (r == 0xff) {
					r = 0;
				}
			}
			rc = rz_utf8_encode(strbuf + i, r);
			runes++;
		} else if (r && r < 0x100 && is_c_escape_sequence((char)r)) {
			if ((i + 32) < opt->buf_size && r < 93) {
				rc = rz_utf8_encode(strbuf + i, r);
			} else {
				// string too long
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
		FalsePositiveResult false_positive_result = reduce_false_positives(opt, strbuf, strbuf_size, str_type);
		if (false_positive_result == SKIP_STRING) {
			return NULL;
		} else if (false_positive_result == RETRY_ASCII) {
			return process_one_string(buf, from, str_addr, to, str_type, true, opt, strbuf);
		}

		RzDetectedString *ds = RZ_NEW0(RzDetectedString);
		if (!ds) {
			return NULL;
		}
		ds->type = str_type;
		ds->length = runes;
		ds->size = needle - str_addr;
		ds->addr = str_addr;

		ut64 off_adj = adjust_offset(str_type, buf, ds->addr - from);
		ds->addr -= off_adj;
		ds->size += off_adj;

		ds->string = rz_str_ndup((const char *)strbuf, strbuf_size);
		return ds;
	}

	return NULL;
}

static inline bool can_be_utf16_le(const ut8 *buf, ut64 size) {
	int rc = rz_utf8_decode(buf, size, NULL);
	if (!rc || (size - rc) < 5) {
		return false;
	}
	char *w = (char *)buf + rc;
	return !w[0] && w[1] && !w[2] && w[3] && !w[4];
}

static inline bool can_be_utf16_be(const ut8 *buf, ut64 size) {
	if (size < 7) {
		return false;
	}
	return !buf[0] && buf[1] && !buf[2] && buf[3] && !buf[4] && buf[5] && !buf[6];
}

static inline bool can_be_utf32_le(const ut8 *buf, ut64 size) {
	int rc = rz_utf8_decode(buf, size, NULL);
	if (!rc || (size - rc) < 5) {
		return false;
	}
	char *w = (char *)buf + rc;
	return !w[0] && !w[1] && !w[2] && w[3] && !w[4];
}

static inline bool can_be_utf32_be(const ut8 *buf, ut64 size) {
	if (size < 7) {
		return false;
	}
	return !buf[0] && !buf[1] && !buf[2] && buf[3] && !buf[4] && !buf[5] && !buf[6];
}

static inline bool can_be_ebcdic(const ut8 *buf, ut64 size) {
	return buf[0] < 0x20 || buf[0] > 0x3f;
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
 * \param buf   Pointer to a raw buffer to scan
 * \param list  Pointer to a list that will be populated with the found strings
 * \param opt   Pointer to a RzUtilStrScanOptions that specifies search parameters
 * \param from  Minimum address to scan
 * \param to    Maximum address to scan
 * \param type  Type of strings to search
 *
 * \return Number of strings found
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

	ut64 needle = 0;
	int count = 0;
	RzStrEnc str_type = type;

	ut8 *strbuf = calloc(opt->buf_size, 1);
	if (!strbuf) {
		return -1;
	}

	needle = from;
	const ut8 *ptr = NULL;
	ut64 size = 0;
	int skip_ibm037 = 0;
	while (needle < to) {
		ptr = buf + needle - from;
		size = to - needle;
		--skip_ibm037;
		if (type == RZ_STRING_ENC_GUESS) {
			if (can_be_utf32_le(ptr, size)) {
				str_type = RZ_STRING_ENC_UTF32LE;
			} else if (can_be_utf16_le(ptr, size)) {
				str_type = RZ_STRING_ENC_UTF16LE;
			} else if (can_be_utf32_be(ptr, size)) {
				if (to - needle > 3 && can_be_utf32_le(ptr + 3, size - 3)) {
					// The string can be either utf32-le or utf32-be
					RzDetectedString *ds_le = process_one_string(buf, from, needle + 3, to, RZ_STRING_ENC_UTF32LE, false, opt, strbuf);
					RzDetectedString *ds_be = process_one_string(buf, from, needle, to, RZ_STRING_ENC_UTF32BE, false, opt, strbuf);

					RzDetectedString *to_add = NULL;
					RzDetectedString *to_delete = NULL;
					ut64 needle_offset = 0;

					if (!ds_le && !ds_be) {
						needle++;
						continue;
					} else if (!ds_be) {
						to_add = ds_le;
						needle_offset = ds_le->size + 3;
					} else if (!ds_le) {
						to_add = ds_be;
						needle_offset = ds_be->size;
					} else if (!opt->prefer_big_endian) {
						to_add = ds_le;
						to_delete = ds_be;
						needle_offset = ds_le->size + 3;
					} else {
						to_add = ds_be;
						to_delete = ds_le;
						needle_offset = ds_le->size;
					}

					count++;
					needle += needle_offset;
					rz_list_append(list, to_add);
					rz_detected_string_free(to_delete);
					continue;
				}
				str_type = RZ_STRING_ENC_UTF32BE;
			} else if (can_be_utf16_be(ptr, size)) {
				if (to - needle > 1 && can_be_utf16_le(ptr + 1, size - 1)) {
					// The string can be either utf16-le or utf16-be
					RzDetectedString *ds_le = process_one_string(buf, from, needle + 1, to, RZ_STRING_ENC_UTF16LE, false, opt, strbuf);
					RzDetectedString *ds_be = process_one_string(buf, from, needle, to, RZ_STRING_ENC_UTF16BE, false, opt, strbuf);

					RzDetectedString *to_add = NULL;
					RzDetectedString *to_delete = NULL;
					ut64 needle_offset = 0;

					if (!ds_le && !ds_be) {
						needle++;
						continue;
					} else if (!ds_be) {
						to_add = ds_le;
						needle_offset = ds_le->size + 1;
					} else if (!ds_le) {
						to_add = ds_be;
						needle_offset = ds_be->size;
					} else if (!opt->prefer_big_endian) {
						to_add = ds_le;
						to_delete = ds_be;
						needle_offset = ds_le->size + 1;
					} else {
						to_add = ds_be;
						to_delete = ds_le;
						needle_offset = ds_le->size;
					}

					count++;
					needle += needle_offset;
					rz_list_append(list, to_add);
					rz_detected_string_free(to_delete);
					continue;
				}
				str_type = RZ_STRING_ENC_UTF16BE;
			} else if (can_be_ebcdic(ptr, size) && skip_ibm037 < 0) {
				ut8 sz = RZ_MIN(size, 15);
				RzCodePoint code_points[15] = { 0 };
				int i = 0;
				for (; i < sz; i++) {
					rz_str_ibm037_to_unicode(ptr[i], &code_points[i]);
					if (!rz_code_point_is_printable(code_points[i])) {
						break;
					}
				}
				int s = score(code_points, i);
				if (s >= 36) {
					str_type = RZ_STRING_ENC_IBM037;
				} else {
					skip_ibm037 = i + 1;
					continue;
				}
			} else {
				int rc = rz_utf8_decode(ptr, size, NULL);
				if (!rc) {
					needle++;
					continue;
				} else {
					str_type = RZ_STRING_ENC_8BIT;
				}
			}
		} else if (type == RZ_STRING_ENC_UTF8) {
			str_type = RZ_STRING_ENC_8BIT; // initial assumption
		}

		RzDetectedString *ds = process_one_string(buf, from, needle, to, str_type, false, opt, strbuf);
		if (!ds) {
			needle++;
			continue;
		}
		if (str_type == RZ_STRING_ENC_IBM037) {
			skip_ibm037 = 0;
		}

		count++;
		rz_list_append(list, ds);
		needle += ds->size;
	}
	free(strbuf);
	return count;
}
/**
 * \brief Look for strings in an RzBuffer.
 * \param buf_to_scan Pointer to a RzBuffer to scan
 * \param list Pointer to a list that will be populated with the found strings
 * \param opt Pointer to a RzUtilStrScanOptions that specifies search parameters
 * \param from Minimum address to scan
 * \param to Maximum address to scan
 * \param type Type of strings to search
 * \return Number of strings found
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
