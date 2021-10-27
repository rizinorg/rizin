// SPDX-FileCopyrightText: 2021 borzacchiello <lucaborza@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_str_search.h>
#include <rz_util/rz_utf8.h>
#include <rz_util/rz_utf16.h>
#include <rz_util/rz_utf32.h>

typedef enum {
	SKIP_STRING,
	RETRY_ASCII,
	STRING_OK,
} FalsePositiveResult;

/**
 * Free a RzDetectedString
 */
RZ_API void rz_detected_string_free(RzDetectedString *str) {
	if (str) {
		free(str->string);
		free(str);
	}
}

static FalsePositiveResult reduce_false_positives(const RzUtilStrScanOptions *opt, ut8 *str, int size, RzStrEnc str_type) {
	int i, num_blocks, *block_list;
	int *freq_list = NULL, expected_ascii, actual_ascii, num_chars;

	switch (str_type) {
	case RZ_STRING_ENC_LATIN1: {
		for (i = 0; i < size; i++) {
			char ch = str[i];
			if (ch != '\n' && ch != '\r' && ch != '\t') {
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
		num_blocks = 0;
		block_list = rz_utf_block_list((const ut8 *)str, size - 1,
			str_type == RZ_STRING_ENC_UTF16LE ? &freq_list : NULL);
		if (block_list) {
			for (i = 0; block_list[i] != -1; i++) {
				num_blocks++;
			}
		}
		if (freq_list) {
			num_chars = 0;
			actual_ascii = 0;
			for (i = 0; freq_list[i] != -1; i++) {
				num_chars += freq_list[i];
				if (!block_list[i]) { // ASCII
					actual_ascii = freq_list[i];
				}
			}
			free(freq_list);
			expected_ascii = num_blocks ? num_chars / num_blocks : 0;
			if (actual_ascii > expected_ascii) {
				free(block_list);
				return RETRY_ASCII;
			}
		}
		free(block_list);
		if (num_blocks > opt->max_uni_blocks) {
			return SKIP_STRING;
		}
		break;
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
	RzStrEnc str_type, bool ascii_only, const RzUtilStrScanOptions *opt) {

	rz_return_val_if_fail(str_type != RZ_STRING_ENC_GUESS, NULL);

	ut8 *tmp = malloc(opt->buf_size);
	if (!tmp) {
		return NULL;
	}
	ut64 str_addr = needle;
	int rc, i, runes;

	/* Eat a whole C string */
	runes = 0;
	rc = 0;
	for (i = 0; i < opt->buf_size - 4 && needle < to; i += rc) {
		RzRune r = { 0 };

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

		if (rz_isprint(r) && r != '\\') {
			if (str_type == RZ_STRING_ENC_UTF32LE || str_type == RZ_STRING_ENC_UTF32BE) {
				if (r == 0xff) {
					r = 0;
				}
			}
			rc = rz_utf8_encode(tmp + i, r);
			runes++;
		} else if (r && r < 0x100 && strchr("\b\v\f\n\r\t\a\033\\", (char)r)) {
			if ((i + 32) < opt->buf_size && r < 93) {
				tmp[i + 0] = '\\';
				tmp[i + 1] = "       abtnvfr             e  "
					     "                              "
					     "                              "
					     "  \\"[r];
			} else {
				// string too long
				break;
			}
			rc = 2;
			runes++;
		} else {
			/* \0 marks the end of C-strings */
			break;
		}
	}

	tmp[i++] = '\0';

	if (runes >= opt->min_str_length) {
		FalsePositiveResult false_positive_result = reduce_false_positives(opt, tmp, i - 1, str_type);
		if (false_positive_result == SKIP_STRING) {
			free(tmp);
			return NULL;
		} else if (false_positive_result == RETRY_ASCII) {
			free(tmp);
			return process_one_string(buf, from, str_addr, to, str_type, true, opt);
		}

		RzDetectedString *ds = RZ_NEW0(RzDetectedString);
		if (!ds) {
			free(tmp);
			return NULL;
		}
		ds->type = str_type;
		ds->length = runes;
		ds->size = needle - str_addr;
		ds->addr = str_addr;

		ut64 off_adj = adjust_offset(str_type, buf, ds->addr - from);
		ds->addr -= off_adj;
		ds->size += off_adj;

		ds->string = rz_str_ndup((const char *)tmp, i);
		free(tmp);
		return ds;
	}

	free(tmp);
	return NULL;
}

static inline bool can_be_utf16_le(ut8 *buf, ut64 size) {
	int rc = rz_utf8_decode(buf, size, NULL);
	if (!rc) {
		return false;
	}

	if (size - rc < 5) {
		return false;
	}
	char *w = (char *)buf + rc;
	return !w[0] && w[1] && !w[2] && w[3] && !w[4];
}

static inline bool can_be_utf16_be(ut8 *buf, ut64 size) {
	if (size < 7) {
		return false;
	}
	return !buf[0] && buf[1] && !buf[2] && buf[3] && !buf[4] && buf[5] && !buf[6];
}

static inline bool can_be_utf32_le(ut8 *buf, ut64 size) {
	int rc = rz_utf8_decode(buf, size, NULL);
	if (!rc) {
		return false;
	}

	if (size - rc < 5) {
		return false;
	}
	char *w = (char *)buf + rc;
	return !w[0] && !w[1] && !w[2] && w[3] && !w[4];
}

static inline bool can_be_utf32_be(ut8 *buf, ut64 size) {
	if (size < 7) {
		return false;
	}
	return !buf[0] && !buf[1] && !buf[2] && buf[3] && !buf[4] && !buf[5] && !buf[6];
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
RZ_API int rz_scan_strings(RzBuffer *buf_to_scan, RzList *list, const RzUtilStrScanOptions *opt,
	const ut64 from, const ut64 to, RzStrEnc type) {

	rz_return_val_if_fail(opt, -1);
	rz_return_val_if_fail(list, -1);
	rz_return_val_if_fail(buf_to_scan, -1);

	if (from == to) {
		return 0;
	}
	if (from > to) {
		RZ_LOG_ERROR("Invalid range to find strings 0x%" PFMT64x " .. 0x%" PFMT64x "\n", from, to);
		return -1;
	}

	ut64 needle;
	int count = 0;
	RzStrEnc str_type = type;

	int len = to - from;
	ut8 *buf = calloc(len, 1);
	if (!buf) {
		return -1;
	}

	rz_buf_read_at(buf_to_scan, from, buf, len);

	needle = from;
	while (needle < to) {
		if (type == RZ_STRING_ENC_GUESS) {
			if (can_be_utf32_le(buf + needle - from, to - needle)) {
				str_type = RZ_STRING_ENC_UTF32LE;
			} else if (can_be_utf16_le(buf + needle - from, to - needle)) {
				str_type = RZ_STRING_ENC_UTF16LE;
			} else if (can_be_utf32_be(buf + needle - from, to - needle)) {
				if (to - needle > 3 && can_be_utf32_le(buf + needle - from + 3, to - needle - 3)) {
					// The string can be either utf32-le or utf32-be
					RzDetectedString *ds_le = process_one_string(buf, from, needle + 3, to, RZ_STRING_ENC_UTF32LE, false, opt);
					RzDetectedString *ds_be = process_one_string(buf, from, needle, to, RZ_STRING_ENC_UTF32BE, false, opt);

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
			} else if (can_be_utf16_be(buf + needle - from, to - needle)) {
				if (to - needle > 1 && can_be_utf16_le(buf + needle - from + 1, to - needle - 1)) {
					// The string can be either utf16-le or utf16-be
					RzDetectedString *ds_le = process_one_string(buf, from, needle + 1, to, RZ_STRING_ENC_UTF16LE, false, opt);
					RzDetectedString *ds_be = process_one_string(buf, from, needle, to, RZ_STRING_ENC_UTF16BE, false, opt);

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
			} else {
				int rc = rz_utf8_decode(buf + needle - from, to - needle, NULL);
				if (!rc) {
					needle++;
					continue;
				}
				str_type = RZ_STRING_ENC_LATIN1;
			}
		} else if (type == RZ_STRING_ENC_UTF8) {
			str_type = RZ_STRING_ENC_LATIN1; // initial assumption
		}

		RzDetectedString *ds = process_one_string(buf, from, needle, to, str_type, false, opt);
		if (!ds) {
			needle++;
			continue;
		}

		count++;
		rz_list_append(list, ds);
		needle += ds->size;
	}
	free(buf);
	return count;
}
