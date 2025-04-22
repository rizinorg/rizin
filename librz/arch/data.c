// SPDX-FileCopyrightText: 2012-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>

static bool get_string(const ut8 *buf, int size, RzDetectedString **dstr, RzStrEnc encoding, bool big_endian) {
	if (!buf || size < 1) {
		return false;
	}

	RzUtilStrScanOptions opt = {
		.max_str_length = size,
		.min_str_length = 4,
		.prefer_big_endian = big_endian,
		.check_ascii_freq = false,
	};

	if (rz_scan_strings_single_raw(buf, size, &opt, encoding, dstr) && (*dstr)->addr) {
		rz_detected_string_free(*dstr);
		*dstr = NULL;
	}
	return *dstr;
}

static int is_number(const ut8 *buf, int size) {
	ut64 n = rz_mem_get_num(buf, size);
	return (n < UT32_MAX) ? (int)n : 0;
}

static int is_null(const ut8 *buf, int size) {
	const char zero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	return (!memcmp(buf, &zero, size)) ? 1 : 0;
}

static int is_invalid(const ut8 *buf, int size) {
	if (size < 1) {
		return 1;
	}
	if (size > 8) {
		size = 8;
	}
	return (!memcmp(buf, "\xff\xff\xff\xff\xff\xff\xff\xff", size)) ? 1 : 0;
}

static ut64 is_pointer(RzAnalysis *analysis, const ut8 *buf, int size) {
	ut64 n;
	ut8 buf2[32];
	RzIOBind *iob = &analysis->iob;
	if (size > sizeof(buf2)) {
		size = sizeof(buf2);
	}
	n = rz_mem_get_num(buf, size);
	if (!n) {
		return 1; // null pointer
	}
	int r = iob->is_valid_offset(iob->io, n, 0);
	return r ? n : 0LL;
}

static bool is_bin(const ut8 *buf, int size) {
	// TODO: add more magic signatures heres
	if ((size >= 4 && !memcmp(buf, "\xcf\xfa\xed\xfe", 4))) {
		return true;
	}
	if ((size >= 4 && !memcmp(buf, "\x7f\x45\x4c\x46", 4))) { // \x7fELF
		return true;
	}
	if ((size >= 2 && !memcmp(buf, "MZ", 2))) {
		return true;
	}
	return false;
}

// TODO: add is_flag, is comment?

RZ_API char *rz_analysis_data_to_string(RzAnalysisData *d, RzConsPrintablePalette *pal) {
	int i = 0, len = 0, mallocsz = 1024;
	ut32 n32 = 0;

	if (!d) {
		return NULL;
	}

	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	if (!rz_strbuf_reserve(sb, mallocsz)) {
		RZ_LOG_ERROR("Cannot allocate %d byte(s)\n", mallocsz);
		rz_strbuf_free(sb);
		return NULL;
	}
	if (pal) {
		const char *k = pal->offset;
		rz_strbuf_appendf(sb, "%s0x%08" PFMT64x Color_RESET "  ", k, d->addr);
	} else {
		rz_strbuf_appendf(sb, "0x%08" PFMT64x "  ", d->addr);
	}
	n32 = (ut32)d->ptr;
	len = RZ_MIN(d->len, 8);
	for (i = 0; i < len; i++) {
		rz_strbuf_appendf(sb, "%02x", d->buf[i]);
	}
	if (i > 0 && d->len > len) {
		rz_strbuf_append(sb, "..");
	}
	rz_strbuf_append(sb, "  ");
	switch (d->type) {
	case RZ_ANALYSIS_DATA_INFO_TYPE_STRING:
		if (pal) {
			rz_strbuf_appendf(sb, "%sstring \"%s\"" Color_RESET, pal->comment, d->str);
		} else {
			rz_strbuf_appendf(sb, "string \"%s\"", d->str);
		}
		break;
	case RZ_ANALYSIS_DATA_INFO_TYPE_NUMBER:
		if (pal) {
			const char *k = pal->num;
			if (n32 == d->ptr) {
				rz_strbuf_appendf(sb, "%snumber %d (0x%x)" Color_RESET, k, n32, n32);
			} else {
				rz_strbuf_appendf(sb, "%snumber %" PFMT64d " (0x%" PFMT64x ")" Color_RESET,
					k, d->ptr, d->ptr);
			}
		} else {
			if (n32 == d->ptr) {
				rz_strbuf_appendf(sb, "number %d 0x%x", n32, n32);
			} else {
				rz_strbuf_appendf(sb, "number %" PFMT64d " 0x%" PFMT64x,
					d->ptr, d->ptr);
			}
		}
		break;
	case RZ_ANALYSIS_DATA_INFO_TYPE_POINTER:
		rz_strbuf_append(sb, "pointer ");
		if (pal) {
			const char *k = pal->offset;
			rz_strbuf_appendf(sb, " %s0x%08" PFMT64x, k, d->ptr);
		} else {
			rz_strbuf_appendf(sb, " 0x%08" PFMT64x, d->ptr);
		}
		break;
	case RZ_ANALYSIS_DATA_INFO_TYPE_INVALID:
		if (pal) {
			rz_strbuf_appendf(sb, "%sinvalid" Color_RESET, pal->invalid);
		} else {
			rz_strbuf_append(sb, "invalid");
		}
		break;
	case RZ_ANALYSIS_DATA_INFO_TYPE_HEADER:
		rz_strbuf_append(sb, "header");
		break;
	case RZ_ANALYSIS_DATA_INFO_TYPE_SEQUENCE:
		rz_strbuf_append(sb, "sequence");
		break;
	case RZ_ANALYSIS_DATA_INFO_TYPE_PATTERN:
		rz_strbuf_append(sb, "pattern");
		break;
	case RZ_ANALYSIS_DATA_INFO_TYPE_UNKNOWN:
		if (pal) {
			rz_strbuf_appendf(sb, "%sunknown" Color_RESET, pal->invalid);
		} else {
			rz_strbuf_append(sb, "unknown");
		}
		break;
	default:
		if (pal) {
			rz_strbuf_appendf(sb, "%s(null)" Color_RESET, pal->b0x00);
		} else {
			rz_strbuf_append(sb, "(null)");
		}
		break;
	}
	return rz_strbuf_drain(sb);
}

static RzAnalysisData *rz_analysis_data_new_string(ut64 addr, const ut8 *buf, RzDetectedString *dstr) {
	RzAnalysisData *ad = RZ_NEW0(RzAnalysisData);
	if (!ad) {
		return NULL;
	}
	ad->addr = addr;
	ad->type = RZ_ANALYSIS_DATA_INFO_TYPE_STRING;
	ad->buf = malloc(dstr->size);
	if (!ad->buf) {
		rz_analysis_data_free(ad);
		RZ_LOG_ERROR("Cannot allocate %d byte(s)\n", dstr->size);
		return NULL;
	}
	memcpy(ad->buf, buf, dstr->size);
	RZ_PTR_MOVE(ad->str, dstr->string);
	ad->len = dstr->size;
	return ad;
}

RZ_API RzAnalysisData *rz_analysis_data_new(ut64 addr, RzAnalysisDataInfoType type, ut64 n, const ut8 *buf, int len) {
	RzAnalysisData *ad = RZ_NEW0(RzAnalysisData);
	int l = RZ_MIN(len, 8);
	if (!ad) {
		return NULL;
	}
	ad->buf = (ut8 *)&(ad->sbuf);
	memset(ad->buf, 0, 8);
	if (l < 1) {
		rz_analysis_data_free(ad);
		return NULL;
	}
	if (buf) {
		memcpy(ad->buf, buf, l);
	}
	ad->addr = addr;
	ad->type = type;
	ad->str = NULL;
	switch (type) {
	case RZ_ANALYSIS_DATA_INFO_TYPE_PATTERN:
	case RZ_ANALYSIS_DATA_INFO_TYPE_SEQUENCE:
		ad->len = len;
		break;
	default:
		ad->len = l;
	}
	ad->ptr = n;
	return ad;
}

RZ_API void rz_analysis_data_free(RZ_NULLABLE RzAnalysisData *d) {
	if (!d) {
		return;
	}
	if (d->buf != (ut8 *)&(d->sbuf)) {
		free(d->buf);
	}
	free(d->str);
	free(d);
}

/**
 * \brief      Tries to detect the type of data in a give buffer.
 *
 * \param      analysis  The RzAnalysis structure to use
 * \param[in]  addr      The address at which the buffer is located
 * \param[in]  buf       The buffer to analyze
 * \param[in]  size      The size of the buffer (requires to be at least 4 bytes)
 * \param[in]  wordsize  The word size (when 0 it will be set to arch bits/8)
 *
 * \return     On success a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzAnalysisData *rz_analysis_data(RZ_NONNULL RzAnalysis *analysis, ut64 addr, RZ_NONNULL const ut8 *buf, size_t size, int wordsize) {
	rz_return_val_if_fail(analysis && buf, NULL);

	ut64 dst = 0;
	RzDetectedString *dstr = NULL;
	bool big_endian = analysis->big_endian;
	RzStrEnc encoding = analysis->core ? analysis->coreb.cfggeti(analysis->core, "str.encoding") : RZ_STRING_ENC_GUESS;
	int n = 0;
	int bits = analysis->bits;
	int word = wordsize > 0 ? wordsize : RZ_MIN(8, bits / 8);

	if (analysis->binb.bin) {
		encoding = analysis->binb.bin->str_search_cfg.string_encoding;
	}

	if (size < 4) {
		return NULL;
	} else if (size >= word && is_invalid(buf, word)) {
		return rz_analysis_data_new(addr, RZ_ANALYSIS_DATA_INFO_TYPE_INVALID, -1, buf, word);
	}
	{
		size_t len = RZ_MIN(size, 64);
		int is_pattern = 0;
		int is_sequence = 0;
		char ch = buf[0];
		char ch2 = ch + 1;
		for (size_t i = 1; i < len; i++) {
			if (ch2 == buf[i]) {
				ch2++;
				is_sequence++;
			} else {
				is_sequence = 0;
			}
			if (ch == buf[i]) {
				is_pattern++;
			}
		}
		if (is_sequence > len - 2) {
			return rz_analysis_data_new(addr, RZ_ANALYSIS_DATA_INFO_TYPE_SEQUENCE, -1,
				buf, is_sequence);
		}
		if (is_pattern > len - 2) {
			return rz_analysis_data_new(addr, RZ_ANALYSIS_DATA_INFO_TYPE_PATTERN, -1,
				buf, is_pattern);
		}
	}
	if (size >= word && is_null(buf, word)) {
		return rz_analysis_data_new(addr, RZ_ANALYSIS_DATA_INFO_TYPE_NULL, -1, buf, word);
	}
	if (is_bin(buf, size)) {
		return rz_analysis_data_new(addr, RZ_ANALYSIS_DATA_INFO_TYPE_HEADER, -1, buf, word);
	}
	if (size >= word) {
		dst = is_pointer(analysis, buf, word);
		if (dst) {
			return rz_analysis_data_new(addr, RZ_ANALYSIS_DATA_INFO_TYPE_POINTER, dst, buf, word);
		}
	}
	if (get_string(buf, size, &dstr, encoding, big_endian)) {
		RzAnalysisData *ad = rz_analysis_data_new_string(addr, buf, dstr);
		rz_detected_string_free(dstr);
		return ad;
	}
	if (size >= word) {
		n = is_number(buf, word);
		if (n) {
			return rz_analysis_data_new(addr, RZ_ANALYSIS_DATA_INFO_TYPE_NUMBER, n, buf, word);
		}
	}
	return rz_analysis_data_new(addr, RZ_ANALYSIS_DATA_INFO_TYPE_UNKNOWN, dst, buf, RZ_MIN(word, size));
}

/**
 * \brief      Describes the type of data hold by the given buffer
 *
 * \param      a     The RzAnalysis structure to use
 * \param[in]  addr  The address at which the buffer is located
 * \param[in]  buf   The buffer to analyze
 * \param[in]  len   The length of the buffer
 *
 * \return     The data kind.
 */
RZ_API RzAnalysisDataKind rz_analysis_data_kind(RZ_NONNULL RzAnalysis *a, ut64 addr, RZ_NONNULL const ut8 *buf, size_t len) {
	rz_return_val_if_fail(a && buf, RZ_ANALYSIS_DATA_KIND_UNKNOWN);

	size_t inv = 0;
	size_t unk = 0;
	size_t str = 0;
	size_t num = 0;
	size_t j = 0;
	size_t word = a->bits / 8;
	for (size_t i = 0; i < len; j++) {
		if (str && !buf[i]) {
			str++;
		}
		RzAnalysisData *data = rz_analysis_data(a, addr + i, buf + i, len - i, 0);
		if (!data) {
			i += word;
			continue;
		}
		switch (data->type) {
		case RZ_ANALYSIS_DATA_INFO_TYPE_INVALID:
			inv++;
			i += word;
			break;
		case RZ_ANALYSIS_DATA_INFO_TYPE_NUMBER:
			if (data->ptr > 1000) {
				num++;
			}
			i += word;
			break;
		case RZ_ANALYSIS_DATA_INFO_TYPE_UNKNOWN:
			unk++;
			i += word;
			break;
		case RZ_ANALYSIS_DATA_INFO_TYPE_STRING:
			i += data->len;
			str++;
			break;
		default:
			i += word;
		}
		rz_analysis_data_free(data);
	}
	if (j < 1) {
		return RZ_ANALYSIS_DATA_KIND_UNKNOWN;
	} else if ((inv * 100 / j) > 60) {
		return RZ_ANALYSIS_DATA_KIND_INVALID;
	} else if ((unk * 100 / j) > 60 || (num * 100 / j) > 60) {
		return RZ_ANALYSIS_DATA_KIND_CODE;
	} else if ((str * 100 / j) > 40) {
		return RZ_ANALYSIS_DATA_KIND_STRING;
	}
	return RZ_ANALYSIS_DATA_KIND_DATA;
}

RZ_API const char *rz_analysis_datatype_to_string(RzAnalysisDataType t) {
	switch (t) {
	case RZ_ANALYSIS_DATATYPE_NULL:
		return NULL;
	case RZ_ANALYSIS_DATATYPE_ARRAY:
		return "array";
	case RZ_ANALYSIS_DATATYPE_OBJECT: // instance
		return "object";
	case RZ_ANALYSIS_DATATYPE_STRING:
		return "string";
	case RZ_ANALYSIS_DATATYPE_CLASS:
		return "class";
	case RZ_ANALYSIS_DATATYPE_BOOLEAN:
		return "boolean";
	case RZ_ANALYSIS_DATATYPE_INT16:
		return "int16";
	case RZ_ANALYSIS_DATATYPE_INT32:
		return "int32";
	case RZ_ANALYSIS_DATATYPE_INT64:
		return "int64";
	case RZ_ANALYSIS_DATATYPE_FLOAT:
		return "float";
	}
	return NULL;
}
