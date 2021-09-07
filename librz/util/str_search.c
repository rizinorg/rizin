#include <rz_util/rz_str_search.h>
#include <rz_util/rz_utf8.h>
#include <rz_util/rz_utf16.h>
#include <rz_util/rz_utf32.h>

typedef enum {
	SKIP_STRING,
	RETRY_ASCII,
	STRING_OK,
} FalsePositiveResult;

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
		return STRING_OK;
	}

	return STRING_OK;
}

static ut64 adjust_offset(RzStrEnc str_type, ut8 *buf, const ut64 str_start) {
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

	ut8 tmp[opt->buf_size];
	ut64 str_start, needle = from;
	int count = 0, i, rc, runes;
	RzStrEnc str_type = RZ_STRING_ENC_GUESS;

	int len = to - from;
	ut8 *buf = calloc(len, 1);
	if (!buf) {
		free(buf);
		return -1;
	}

	bool ascii_only = false;

	rz_buf_read_at(buf_to_scan, from, buf, len);
	// may oobread
	while (needle < to) {
		ut64 original_needle = needle;
		bool is_wide_be_str = false;

		char ch = *(buf + needle - from);
		if (ch == 0 && type == RZ_STRING_ENC_GUESS) {
			char *w = (char *)buf + needle + 1 - from;
			if ((to - needle) > 5 + 1) {
				bool is_wide32_be = !w[0] && !w[1] && w[2] && !w[3] && !w[4];
				bool is_wide_be = w[0] && !w[1] && w[2] && !w[3] && w[4];
				if (is_wide32_be) {
					is_wide_be_str = true;
					str_type = RZ_STRING_ENC_UTF32BE;
					rc = 4;
				} else if (is_wide_be) {
					is_wide_be_str = true;
					str_type = RZ_STRING_ENC_UTF16BE;
					rc = 2;
				}
			}
		}

		if (!is_wide_be_str) {
			rc = rz_utf8_decode(buf + needle - from, to - needle, NULL);
			if (!rc) {
				needle++;
				continue;
			}

			if (type == RZ_STRING_ENC_GUESS) {
				char *w = (char *)buf + needle + rc - from;
				if ((to - needle) > 5 + rc) {
					bool is_wide32_le = !w[0] && !w[1] && !w[2] && w[3] && !w[4];
					bool is_wide_le = !w[0] && w[1] && !w[2] && w[3] && !w[4];

					if (is_wide32_le) {
						str_type = RZ_STRING_ENC_UTF32LE;
					} else if (is_wide_le) {
						str_type = RZ_STRING_ENC_UTF16LE;
					} else {
						str_type = RZ_STRING_ENC_LATIN1;
					}
				} else {
					str_type = RZ_STRING_ENC_LATIN1;
				}
			} else if (type == RZ_STRING_ENC_UTF8) {
				str_type = RZ_STRING_ENC_LATIN1; // initial assumption
			} else {
				str_type = type;
			}
		}

		runes = 0;
		str_start = needle;

		/* Eat a whole C string */
		for (i = 0; i < sizeof(tmp) - 4 && needle < to; i += rc) {
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
				if ((i + 32) < sizeof(tmp) && r < 93) {
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

		if (runes < opt->min_str_length && runes >= 2 && str_type == RZ_STRING_ENC_LATIN1 && needle < to) {
			// back up past the \0 to the last char just in case it starts a wide string
			needle -= 2;
		}
		if (runes >= opt->min_str_length) {
			FalsePositiveResult false_positive_result = reduce_false_positives(opt, tmp, i - 1, str_type);
			if (false_positive_result == SKIP_STRING) {
				needle = original_needle + 1;
				continue;
			} else if (false_positive_result == RETRY_ASCII) {
				ascii_only = true;
				needle = str_start;
				continue;
			}

			RzDetectedString *ds = RZ_NEW0(RzDetectedString);
			if (!ds) {
				break;
			}
			ds->type = str_type;
			ds->length = runes;
			ds->size = needle - str_start;

			count++;

			str_start -= adjust_offset(str_type, buf, str_start - from);
			ds->addr = str_start;
			ds->string = rz_str_ndup((const char *)tmp, i);
			rz_list_append(list, ds);
		} else {
			needle = original_needle + 1;
		}
		ascii_only = false;
	}
	free(buf);
	return count;
}
