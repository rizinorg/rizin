#include <rz_bin.h>
#include <rz_util/rz_assert.h>

// maybe too big sometimes? 2KB of stack eaten here..
#define RZ_STRING_SCAN_BUFFER_SIZE 2048
#define RZ_STRING_MAX_UNI_BLOCKS   4

RZ_API int rz_scan_strings(RzList *list, RzBuffer *buf_to_scan,
	const ut64 from, const ut64 to, int min_str_length, int type) {

	ut8 tmp[RZ_STRING_SCAN_BUFFER_SIZE];
	ut64 str_start, needle = from;
	int count = 0, i, rc, runes;
	int str_type = RZ_STRING_TYPE_DETECT;

	// list cannot be NULL
	rz_return_val_if_fail(list, -1);

	// buf_to_scan cannot be NULL
	rz_return_val_if_fail(buf_to_scan, -1);

	if (type == -1) {
		type = RZ_STRING_TYPE_DETECT;
	}
	if (from == to) {
		return 0;
	}
	if (from > to) {
		eprintf("Invalid range to find strings 0x%" PFMT64x " .. 0x%" PFMT64x "\n", from, to);
		return -1;
	}
	int len = to - from;
	ut8 *buf = calloc(len, 1);
	if (!buf || !min_str_length) {
		free(buf);
		return -1;
	}

	bool ascii_only = false;

	rz_buf_read_at(buf_to_scan, from, buf, len);
	// may oobread
	while (needle < to) {
		rc = rz_utf8_decode(buf + needle - from, to - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}

		if (type == RZ_STRING_TYPE_DETECT) {
			char *w = (char *)buf + needle + rc - from;
			if ((to - needle) > 5 + rc) {
				bool is_wide32 = (needle + rc + 2 < to) && (!w[0] && !w[1] && !w[2] && w[3] && !w[4]);
				if (is_wide32) {
					str_type = RZ_STRING_TYPE_WIDE32;
				} else {
					bool is_wide = needle + rc + 4 < to && !w[0] && w[1] && !w[2] && w[3] && !w[4];
					str_type = is_wide ? RZ_STRING_TYPE_WIDE : RZ_STRING_TYPE_ASCII;
				}
			} else {
				str_type = RZ_STRING_TYPE_ASCII;
			}
		} else if (type == RZ_STRING_TYPE_UTF8) {
			str_type = RZ_STRING_TYPE_ASCII; // initial assumption
		} else {
			str_type = type;
		}
		runes = 0;
		str_start = needle;

		/* Eat a whole C string */
		for (i = 0; i < sizeof(tmp) - 4 && needle < to; i += rc) {
			RzRune r = { 0 };

			if (str_type == RZ_STRING_TYPE_WIDE32) {
				rc = rz_utf32le_decode(buf + needle - from, to - needle, &r);
				if (rc) {
					rc = 4;
				}
			} else if (str_type == RZ_STRING_TYPE_WIDE) {
				rc = rz_utf16le_decode(buf + needle - from, to - needle, &r);
				if (rc == 1) {
					rc = 2;
				}
			} else {
				rc = rz_utf8_decode(buf + needle - from, to - needle, &r);
				if (rc > 1) {
					str_type = RZ_STRING_TYPE_UTF8;
				}
			}

			/* Invalid sequence detected */
			if (!rc || (ascii_only && r > 0x7f)) {
				needle++;
				break;
			}

			needle += rc;

			if (rz_isprint(r) && r != '\\') {
				if (str_type == RZ_STRING_TYPE_WIDE32) {
					if (r == 0xff) {
						r = 0;
					}
				}
				rc = rz_utf8_encode(tmp + i, r);
				runes++;
				/* Print the escape code */
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

		if (runes < min_str_length && runes >= 2 && str_type == RZ_STRING_TYPE_ASCII && needle < to) {
			// back up past the \0 to the last char just in case it starts a wide string
			needle -= 2;
		}
		if (runes >= min_str_length) {
			// reduce false positives
			int j, num_blocks, *block_list;
			int *freq_list = NULL, expected_ascii, actual_ascii, num_chars;
			if (str_type == RZ_STRING_TYPE_ASCII) {
				for (j = 0; j < i; j++) {
					char ch = tmp[j];
					if (ch != '\n' && ch != '\r' && ch != '\t') {
						if (!IS_PRINTABLE(tmp[j])) {
							continue;
						}
					}
				}
			}
			switch (str_type) {
			case RZ_STRING_TYPE_UTF8:
			case RZ_STRING_TYPE_WIDE:
			case RZ_STRING_TYPE_WIDE32:
				num_blocks = 0;
				block_list = rz_utf_block_list((const ut8 *)tmp, i - 1,
					str_type == RZ_STRING_TYPE_WIDE ? &freq_list : NULL);
				if (block_list) {
					for (j = 0; block_list[j] != -1; j++) {
						num_blocks++;
					}
				}
				if (freq_list) {
					num_chars = 0;
					actual_ascii = 0;
					for (j = 0; freq_list[j] != -1; j++) {
						num_chars += freq_list[j];
						if (!block_list[j]) { // ASCII
							actual_ascii = freq_list[j];
						}
					}
					free(freq_list);
					expected_ascii = num_blocks ? num_chars / num_blocks : 0;
					if (actual_ascii > expected_ascii) {
						ascii_only = true;
						needle = str_start;
						free(block_list);
						continue;
					}
				}
				free(block_list);
				if (num_blocks > RZ_STRING_MAX_UNI_BLOCKS) {
					continue;
				}
			}
			RzBinString *bs = RZ_NEW0(RzBinString);
			if (!bs) {
				break;
			}
			bs->type = str_type;
			bs->length = runes;
			bs->size = needle - str_start;
			bs->ordinal = count++;
			// TODO: move into adjust_offset
			switch (str_type) {
			case RZ_STRING_TYPE_WIDE:
				if (str_start - from > 1) {
					const ut8 *p = buf + str_start - 2 - from;
					if (p[0] == 0xff && p[1] == 0xfe) {
						str_start -= 2; // \xff\xfe
					}
				}
				break;
			case RZ_STRING_TYPE_WIDE32:
				if (str_start - from > 3) {
					const ut8 *p = buf + str_start - 4 - from;
					if (p[0] == 0xff && p[1] == 0xfe) {
						str_start -= 4; // \xff\xfe\x00\x00
					}
				}
				break;
			}
			bs->paddr = str_start;
			bs->vaddr = str_start;
			bs->string = rz_str_ndup((const char *)tmp, i);
			rz_list_append(list, bs);
		}
		ascii_only = false;
	}
	free(buf);
	return count;
}
