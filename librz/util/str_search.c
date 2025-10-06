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
	free(str->byte_mem_map);
	rz_regex_free_multi(str->regex);
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
		int ch_bytes = rz_utf8_decode(str_ptr, str_end - str_ptr, &ch, true);
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

		// If the string has characters of more then 4 blocks, it is
		// considered invalid. I think at least. This was a funny metric
		// to reduce false positives. But basically useless, because not
		// documented. Also way too ineffecient. Because this whole thing iterates
		// twice over the string. Leave it here to prevent regressions.
		if (num_blocks > 4) {
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

static inline size_t buf_look_ahead(const RzUtilStrScanOptions *opt, RzStrEnc enc) {
	if (opt->max_str_length < opt->min_str_length) {
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
		return RZ_UNICODE_MAX_BYTES_PER_CHAR;
	}
}

/**
 * \brief Number of characters to store on the stack during scanning.
 * If the scanned string has more characters than this or is valid
 * it is copied to the heap.
 * Used to save unnecessary memory allocations.
 */
#define SCANNING_STACK_BUF_CHARS 16
#define SCANNING_STACK_BUF_SIZE  (RZ_UNICODE_MAX_BYTES_PER_CHAR * SCANNING_STACK_BUF_CHARS)

static void add_byte_mem_mapping(ut64 **byte_mem_map, size_t *byte_mem_map_size, size_t utf8_char_offset, size_t mem_offset) {
	size_t size = *byte_mem_map_size;
	if (!*byte_mem_map) {
		*byte_mem_map = RZ_NEWS0(ut64, SCANNING_STACK_BUF_SIZE);
		*byte_mem_map_size += SCANNING_STACK_BUF_SIZE;
	} else if (utf8_char_offset >= size) {
		*byte_mem_map = realloc(*byte_mem_map, (size + SCANNING_STACK_BUF_SIZE) * sizeof(ut64));
		*byte_mem_map_size += SCANNING_STACK_BUF_SIZE;
	}
	if (utf8_char_offset >= *byte_mem_map_size) {
		// Invalid string
		return;
	}
	(*byte_mem_map)[utf8_char_offset] = mem_offset;
}

static RzDetectedString *process_one_string(const ut8 *buf, const ut64 from, ut64 needle, const ut64 to,
	RzStrEnc str_type, bool ascii_only, const RzUtilStrScanOptions *opt, bool test_false_positives) {
	rz_return_val_if_fail(str_type != RZ_STRING_ENC_GUESS, NULL);
	size_t look_ahead = buf_look_ahead(opt, str_type);
	if (look_ahead == 0) {
		return NULL;
	}

	// Most calls to this function never produce a valid string (e.g. because they are too short).
	// To save allocations and frees, we first decode the first few code points onto the stack.
	// Then, if the stack buffer is full, we move it to the heap.
	ut8 stack_alloc[SCANNING_STACK_BUF_SIZE] = { 0 };
	// Gets only set if the stack buffer is full.
	ut8 *heap_alloc = NULL;
	ut8 *output_buf = stack_alloc;
	ut64 *byte_mem_map = NULL;
	size_t byte_mem_map_size = 0;

	ut64 str_addr = needle;
	// Bytes of a decoded/encoded character/code point.
	int char_bytes = 0;
	// Counter of correctly decoded characters/code points.
	int char_count = 0;
	int i = 0;
	bool stopped_with_undef_cp = false;

	/* Eat a whole C string */
	for (i = 0; i < opt->max_str_length - look_ahead && needle < to; i += char_bytes) {
		// Decoded Unicode code point
		RzCodePoint ucp = 0;

		switch (str_type) {
		case RZ_STRING_ENC_UTF32LE:
			char_bytes = rz_utf32le_decode(buf + needle - from, to - needle, &ucp, false);
			break;
		case RZ_STRING_ENC_UTF16LE:
			char_bytes = rz_utf16le_decode(buf + needle - from, to - needle, &ucp, false);
			break;
		case RZ_STRING_ENC_UTF32BE:
			char_bytes = rz_utf32be_decode(buf + needle - from, to - needle, &ucp, false);
			break;
		case RZ_STRING_ENC_UTF16BE:
			char_bytes = rz_utf16be_decode(buf + needle - from, to - needle, &ucp, false);
			break;
		case RZ_STRING_ENC_IBM037:
			char_bytes = rz_str_ibm037_to_unicode(*(buf + needle - from), &ucp);
			break;
		case RZ_STRING_ENC_IBM290:
			char_bytes = rz_str_ibm290_to_unicode(*(buf + needle - from), &ucp);
			break;
		case RZ_STRING_ENC_EBCDIC_ES:
			char_bytes = rz_str_ebcdic_es_to_unicode(*(buf + needle - from), &ucp);
			break;
		case RZ_STRING_ENC_EBCDIC_UK:
			char_bytes = rz_str_ebcdic_uk_to_unicode(*(buf + needle - from), &ucp);
			break;
		case RZ_STRING_ENC_EBCDIC_US:
			char_bytes = rz_str_ebcdic_us_to_unicode(*(buf + needle - from), &ucp);
			break;
		case RZ_STRING_ENC_SETTINGS:
			rz_warn_if_reached();
			RZ_LOG_ERROR("Illegal state reached. 'settings' encoding is not a valid value here.\n");
			return NULL;
		default:
			char_bytes = rz_utf8_decode(buf + needle - from, to - needle, &ucp, false);
			if (char_bytes > 1) {
				str_type = RZ_STRING_ENC_UTF8;
				look_ahead = buf_look_ahead(opt, RZ_STRING_ENC_UTF8);
			}
			break;
		}

		/* Invalid sequence detected */
		if (!char_bytes || (ascii_only && ucp > RZ_UNICODE_LAST_ASCII)) {
			// Either an invalid code point decoded or a non-ASCII character.
			break;
		}

		if (!rz_string_enc_same_char_width_as_utf8(str_type)) {
			add_byte_mem_mapping(&byte_mem_map, &byte_mem_map_size, i, needle);
		}

		needle += char_bytes;

		if (i + RZ_UNICODE_MAX_BYTES_PER_CHAR > sizeof(stack_alloc) && !heap_alloc) {
			// The decoded string now gets larger than the space on the stack.
			// Allocate on the heap and move the string decoded so far.
			heap_alloc = RZ_NEWS(ut8, opt->max_str_length + 1);
			if (!heap_alloc) {
				goto error;
			}
			rz_mem_copy(heap_alloc, opt->max_str_length + 1, stack_alloc, sizeof(stack_alloc));
			output_buf = heap_alloc;
		}

		if (rz_unicode_code_point_is_printable(ucp) && ucp != '\\') {
			char_bytes = rz_utf8_encode(output_buf + i, ucp);
			char_count++;
		} else if (ucp && ucp < 0x100 && is_c_escape_sequence((char)ucp)) {
			if ((i + 32) < opt->max_str_length && ucp < 93) {
				char_bytes = rz_utf8_encode(output_buf + i, ucp);
			} else {
				// String too long
				break;
			}
			char_count++;
		} else {
			/* \0 or undefined code point marks the end of C-strings */
			stopped_with_undef_cp = ucp != 0;
			break;
		}
	}
	add_byte_mem_mapping(&byte_mem_map, &byte_mem_map_size, i, needle);

	int strbuf_size = i;
	if (char_count >= opt->min_str_length && char_count <= opt->max_str_length) {
		if (test_false_positives) {
			FalsePositiveResult false_positive_result = reduce_false_positives(opt, output_buf, strbuf_size, str_type);
			if (false_positive_result == SKIP_STRING) {
				goto error;
			} else if (false_positive_result == RETRY_ASCII) {
				free(heap_alloc);
				free(byte_mem_map);
				return process_one_string(buf, from, str_addr, to, str_type, true, opt, false);
			}
		}

		RzDetectedString *ds = RZ_NEW0(RzDetectedString);
		if (!ds) {
			goto error;
		}
		ds->encoding = str_type;
		ds->length = char_count;
		ds->size = needle - str_addr;
		if (stopped_with_undef_cp) {
			// The decoding stops if a byte sequence is an undefined unicode code point.
			// This last undefined code point still increments needle by its code point width.
			// Subtract it again, so we don't have it in the string length.
			ds->size -= char_bytes;
		}
		ds->addr = str_addr;
		ds->byte_mem_map = byte_mem_map;

		ut64 off_adj = adjust_offset(str_type, buf, ds->addr - from);
		ds->addr -= off_adj;
		ds->size += off_adj;
		output_buf[strbuf_size] = '\0';
		ds->string = heap_alloc ? (char *)output_buf : rz_str_ndup((char *)stack_alloc, sizeof(stack_alloc));
		return ds;
	}

error:
	free(byte_mem_map);
	free(heap_alloc);
	return NULL;
}

static inline bool can_be_utf16_le(const ut8 *buf, ut64 size) {
	int rc = rz_utf8_decode(buf, size, NULL, true);
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
	int rc = rz_utf8_decode(buf, size, NULL, true);
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

	ut64 needle = 0;
	int count = 0;
	RzStrEnc str_type = type;

	bool test_false_positives = false;
	needle = from;
	const ut8 *ptr = NULL;
	ut64 size = 0;
	int skip_ibm037 = 0;
	while (needle < to) {
		ptr = buf + needle - from;
		size = to - needle;
		--skip_ibm037;
		if (type == RZ_STRING_ENC_GUESS) {
			test_false_positives = true;
			if (can_be_utf32_le(ptr, size)) {
				str_type = RZ_STRING_ENC_UTF32LE;
			} else if (can_be_utf16_le(ptr, size)) {
				str_type = RZ_STRING_ENC_UTF16LE;
			} else if (can_be_utf32_be(ptr, size)) {
				if (to - needle > 3 && can_be_utf32_le(ptr + 3, size - 3)) {
					// The string can be either utf32-le or utf32-be
					RzDetectedString *ds_le = process_one_string(buf, from, needle + 3, to, RZ_STRING_ENC_UTF32LE, false, opt, false);
					RzDetectedString *ds_be = process_one_string(buf, from, needle, to, RZ_STRING_ENC_UTF32BE, false, opt, false);

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
					RzDetectedString *ds_le = process_one_string(buf, from, needle + 1, to, RZ_STRING_ENC_UTF16LE, false, opt, false);
					RzDetectedString *ds_be = process_one_string(buf, from, needle, to, RZ_STRING_ENC_UTF16BE, false, opt, false);

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
					if (!rz_unicode_code_point_is_printable(code_points[i])) {
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
				int rc = rz_utf8_decode(ptr, size, NULL, false);
				if (!rc) {
					needle++;
					continue;
				} else {
					str_type = RZ_STRING_ENC_8BIT;
				}
			}
		}

		RzDetectedString *ds = process_one_string(buf, from, needle, to, str_type, false, opt, test_false_positives);
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
	return count;
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
	} else if (type == RZ_STRING_ENC_MUTF8) {
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
	if (type == RZ_STRING_ENC_MUTF8) {
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
