// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser_string.c
 * \brief String/encoding spec parsing and reading for the pf engine.
 *
 * Covers the `z` (inline NUL-terminated), `s` (pointer-to-string), and
 * legacy `Z` (UTF-16LE) specifiers, the full set of supported encodings
 * (UTF-8/16/32, EBCDIC/IBM code pages, GUESS), the `[N]`/`[Nb]` length-
 * prefix form, and pointer dereference of string targets.
 *
 * Cross-TU entry points are declared in pf_internal.h with the pf_
 * prefix; the file-local scanners stay static.
 */

#include <rz_endian.h>
#include <rz_util.h>
#include <rz_util/rz_ebcdic.h>
#include <string.h>
#include <stdlib.h>

#include "pf_parser.h"
#include "pf_internal.h"

static int scan_null_term(const ut8 *buf, int max, int unit) {
	for (int i = 0; i + unit <= max; i += unit) {
		bool nul = true;
		for (int j = 0; j < unit; j++) {
			if (buf[i + j]) {
				nul = false;
				break;
			}
		}
		if (nul) {
			return i;
		}
	}
	return max;
}

static RzCodePoint ebcdic_byte_to_codepoint(ut8 byte, RzStrEnc enc) {
	RzCodePoint ch = 0;
	switch (enc) {
	case RZ_STRING_ENC_IBM037:
		(void)rz_str_ibm037_to_unicode(byte, &ch);
		break;
	case RZ_STRING_ENC_IBM290:
		(void)rz_str_ibm290_to_unicode(byte, &ch);
		break;
	case RZ_STRING_ENC_EBCDIC_ES:
		(void)rz_str_ebcdic_es_to_unicode(byte, &ch);
		break;
	case RZ_STRING_ENC_EBCDIC_UK:
		(void)rz_str_ebcdic_uk_to_unicode(byte, &ch);
		break;
	case RZ_STRING_ENC_EBCDIC_US:
		(void)rz_str_ebcdic_us_to_unicode(byte, &ch);
		break;
	default:
		break;
	}
	return ch;
}

char *pf_decode_string(const ut8 *raw, int raw_len,
	RzStrEnc enc) {
	if (!raw || raw_len <= 0) {
		return strdup("");
	}
	switch (enc) {
	case RZ_STRING_ENC_8BIT:
	case RZ_STRING_ENC_UTF8:
	case RZ_STRING_ENC_MUTF8:
		return rz_str_ndup((const char *)raw, raw_len);

	case RZ_STRING_ENC_UTF16LE:
	case RZ_STRING_ENC_UTF16BE:
	case RZ_STRING_ENC_UTF32LE:
	case RZ_STRING_ENC_UTF32BE: {
		RzStrBuf *sb = rz_strbuf_new("");
		if (!sb) {
			return strdup("");
		}
		int pos = 0;
		// Note, we force checking string encoding validity
		while (pos < raw_len) {
			RzCodePoint ch = 0;
			int c = 0;
			switch (enc) {
			case RZ_STRING_ENC_UTF16LE:
				c = rz_utf16le_decode(raw + pos,
					raw_len - pos, &ch, true);
				break;
			case RZ_STRING_ENC_UTF16BE:
				c = rz_utf16be_decode(raw + pos,
					raw_len - pos, &ch, true);
				break;
			case RZ_STRING_ENC_UTF32LE:
				c = rz_utf32le_decode(raw + pos,
					raw_len - pos, &ch, true);
				break;
			case RZ_STRING_ENC_UTF32BE:
				c = rz_utf32be_decode(raw + pos,
					raw_len - pos, &ch, true);
				break;
			default: break;
			}
			if (c <= 0) {
				break;
			}
			ut8 u8[8];
			int u8l = rz_utf8_encode(u8, ch);
			if (u8l > 0) {
				rz_strbuf_append_n(sb,
					(const char *)u8, u8l);
			}
			pos += c;
		}
		return rz_strbuf_drain(sb);
	}

	case RZ_STRING_ENC_IBM037:
	case RZ_STRING_ENC_IBM290:
	case RZ_STRING_ENC_EBCDIC_ES:
	case RZ_STRING_ENC_EBCDIC_UK:
	case RZ_STRING_ENC_EBCDIC_US: {
		RzStrBuf *sb = rz_strbuf_new("");
		if (!sb) {
			return strdup("");
		}
		for (int i = 0; i < raw_len; i++) {
			RzCodePoint ch = ebcdic_byte_to_codepoint(raw[i], enc);
			ut8 u8[8];
			int u8l = rz_utf8_encode(u8, ch);
			if (u8l > 0) {
				rz_strbuf_append_n(sb,
					(const char *)u8, u8l);
			}
		}
		return rz_strbuf_drain(sb);
	}

	case RZ_STRING_ENC_GUESS: {
		RzStrEnc det = rz_str_guess_encoding_from_buffer(
			raw, raw_len);
		if (det == RZ_STRING_ENC_GUESS) {
			det = RZ_STRING_ENC_UTF8;
		}
		return pf_decode_string(raw, raw_len, det);
	}

	default:
		return rz_str_ndup((const char *)raw, raw_len);
	}
}

/* Read an inline NUL-terminated string out of `buf[off..buf_len]`.
 * If a NUL is not found before the buffer end, `*out_overflow` is set
 * to true and the caller may emit an `ovf "..."` indicator. The
 * returned string is the printable prefix found before either the
 * NUL or the first non-printable byte (so noisy `\xff` tails from
 * `io.unalloc=true` reads do not leak into the rendered output).
 */
int pf_read_inline_string(const ut8 *buf, int off, int buf_len,
	RzStrEnc enc, char **out_str, bool *out_overflow) {
	int avail = buf_len - off;
	if (avail <= 0) {
		*out_str = strdup("");
		if (out_overflow) {
			*out_overflow = true;
		}
		return 0;
	}
	int unit = rz_pf_enc_null_unit_size(enc);
	int raw_len = scan_null_term(buf + off, avail, unit);
	bool overflow = (raw_len >= avail);
	if (overflow) {
		/* No terminator inside the buffer. Truncate the printable
		 * prefix at the first non-printable byte to avoid spilling
		 * the (often `\xff`) tail of unmapped memory into output. */
		int printable = 0;
		while (printable < raw_len) {
			ut8 b = buf[off + printable];
			if (b < 0x20 || b > 0x7e) {
				break;
			}
			printable++;
		}
		raw_len = printable;
	}
	*out_str = pf_decode_string(buf + off, raw_len, enc);
	if (out_overflow) {
		*out_overflow = overflow;
	}
	return RZ_MIN(raw_len + unit, avail);
}

char *pf_deref_string(const RzPfCtx *ctx, ut64 addr,
	RzStrEnc enc) {
	if (!ctx || !ctx->read_at || addr == 0 || addr == UT64_MAX) {
		return strdup("");
	}
	ut8 tmp[1024];
	memset(tmp, 0, sizeof(tmp));
	int n = ctx->read_at(ctx->read_at_user, addr, tmp, sizeof(tmp));
	if (n <= 0) {
		return strdup("");
	}
	int unit = rz_pf_enc_null_unit_size(enc);
	int raw_len = scan_null_term(tmp, n, unit);
	return pf_decode_string(tmp, raw_len, enc);
}

// String:  z / s  with optional (encoding) and optional trailing
// length prefix [N] or [Nb] (bytes-unit suffix). The trailing form
// can only appear immediately after the spec (and optional
// (encoding)); a separate leading [N] before z/s still means
// "array of strings", which is parsed at field level.
int pf_parse_string_spec(const char *p, const char *end,
	RzPfField *fld) {
	fld->type = (p[0] == 'z') ? RZ_PF_ZSTRING : RZ_PF_STRPTR;
	fld->encoding = RZ_STRING_ENC_UTF8;
	fld->endian = RZ_PF_ENDIAN_CTX;
	fld->str_len_prefix = 0;
	fld->str_len_in_bytes = false;
	int consumed = 1;
	if (p[consumed] == '(') {
		char *enc_name = NULL;
		int pl = pf_parse_paren_annotation(p + consumed, end, &enc_name);
		if (enc_name) {
			RzStrEnc enc = rz_str_enc_string_as_type(enc_name);
			/* rz_str_enc_string_as_type falls back to GUESS on
			 * unknown names. If the user spelled something
			 * other than "guess" and we got GUESS back, that's
			 * a typo -- emit a parse-time diagnostic. */
			if (enc == RZ_STRING_ENC_GUESS && strncmp(enc_name, "guess", 5) != 0) {
				PF_DIAG(RZ_PF_ERR_WARN,
					RZ_PF_ERRC_SEMANTIC, p,
					"pf: unknown string encoding '%s', defaulting to guess\n",
					enc_name);
			}
			fld->encoding = enc;
			free(enc_name);
			consumed += pl;
		}
	}
	/* Optional trailing length prefix [N] / [Nb]. We only treat the
	 * brackets as a prefix marker if N is one of {1,2,4,8}; anything
	 * else is left for the outer field-array parser. Skip entirely
	 * when the field already has a fixed-length `[N]z` prefix --
	 * the next bracket belongs to the next field's array prefix. */
	if (p[consumed] == '[' && fld->str_fixed_len == 0) {
		const char *cl = strchr(p + consumed, ']');
		if (cl && (!end || cl < end)) {
			int inner = cl - (p + consumed + 1);
			if (inner >= 1 && inner <= 3) {
				char buf[4] = { 0 };
				memcpy(buf, p + consumed + 1, inner);
				bool in_bytes = false;
				if (buf[inner - 1] == 'b') {
					in_bytes = true;
					buf[inner - 1] = 0;
				}
				int n = atoi(buf);
				if (n == 1 || n == 2 || n == 4 || n == 8) {
					fld->str_len_prefix = n;
					fld->str_len_in_bytes = in_bytes;
					consumed += (cl - (p + consumed)) + 1;
				}
			}
		}
	}
	return consumed;
}

/* Read a string with a length prefix. Returns the total bytes
 * consumed (prefix + payload). Output is decoded into UTF-8. */
int pf_read_lenprefix_string(const ut8 *buf, int off, int avail,
	RzStrEnc enc, int prefix_size, bool len_in_bytes,
	bool be, char **out_str) {
	if (avail < prefix_size) {
		*out_str = strdup("");
		return 0;
	}
	ut64 raw_len = 0;
	switch (prefix_size) {
	case 1: raw_len = buf[off]; break;
	case 2: raw_len = rz_read_ble16(buf + off, be); break;
	case 4: raw_len = rz_read_ble32(buf + off, be); break;
	case 8: raw_len = rz_read_ble64(buf + off, be); break;
	default:
		*out_str = strdup("");
		return 0;
	}
	int unit = rz_pf_enc_null_unit_size(enc);
	int byte_count = len_in_bytes ? (int)raw_len : (int)(raw_len * unit);
	if (byte_count < 0)
		byte_count = 0;
	int max_avail = avail - prefix_size;
	if (byte_count > max_avail) {
		byte_count = max_avail;
	}
	*out_str = pf_decode_string(buf + off + prefix_size, byte_count, enc);
	return prefix_size + byte_count;
}
