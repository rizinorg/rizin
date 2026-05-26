// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser.c
 * \brief Implementation of the pf format parser, reader, and renderers.
 *
 * The pipeline is split into three stages:
 *   1. parse  -- turn a pf format string into an RzPfFormat
 *      (field descriptors plus repeat/union metadata).
 *   2. read   -- walk the parsed format over a byte buffer and produce
 *      an array of RzPfValue, one per top-level field, with nested
 *      children for struct fields.
 *   3. render -- emit the parsed values in one of the modes (text,
 *      JSON, C struct, quiet).
 *
 * All three stages are exposed as public RZ_API entry points so that
 * callers that already have a parsed format or values can skip the
 * earlier stages, and there is also a single-shot rz_pf_format()
 * convenience that runs the whole pipeline.
 *
 * Timestamp formats are owned by pf_parser_time.c. The legacy bridge
 * rz_type_format_data() lives at the bottom of this file so that older
 * call sites keep working until they are migrated to the new API.
 */

#include <rz_endian.h>
#include <rz_util.h>
#include <rz_util/rz_ebcdic.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <ctype.h>

#include "pf_parser.h"
#include "pf_parser_time.h"

/* Portable replacement for vasprintf() -- which is a glibc extension
 * not provided by MSVC. The contract matches vasprintf(3) on success:
 * the caller owns *out and must free() it. On failure *out is set to
 * NULL and -1 is returned. ap is consumed in either case. */
static int pf_vasprintf(char **out, const char *fmt, va_list ap) {
	va_list ap2;
	va_copy(ap2, ap);
	int n = vsnprintf(NULL, 0, fmt, ap2);
	va_end(ap2);
	if (n < 0) {
		*out = NULL;
		return -1;
	}
	char *buf = malloc((size_t)n + 1);
	if (!buf) {
		*out = NULL;
		return -1;
	}
	int n2 = vsnprintf(buf, (size_t)n + 1, fmt, ap);
	if (n2 < 0) {
		free(buf);
		*out = NULL;
		return -1;
	}
	*out = buf;
	return n2;
}

/**
 * Resolve per-field endianness to a concrete bool (true = big).
 * RZ_PF_ENDIAN_CTX falls back to the context default.
 */
static inline bool resolve_endian(RzPfEndian field_endian,
	const RzPfCtx *ctx) {
	switch (field_endian) {
	case RZ_PF_ENDIAN_LE: return false;
	case RZ_PF_ENDIAN_BE: return true;
	default:
		return ctx ? ctx->big_endian : false;
	}
}

static const char *endian_str(RzPfEndian e) {
	switch (e) {
	case RZ_PF_ENDIAN_LE: return "little";
	case RZ_PF_ENDIAN_BE: return "big";
	default: return "context";
	}
}

static inline float read_ble_float(const void *s, bool be) {
	return be ? rz_read_be_float(s) : rz_read_le_float(s);
}

static inline double read_ble_double(const void *s, bool be) {
	return be ? rz_read_be_double(s) : rz_read_le_double(s);
}

// IEEE 754 half-precision (binary16) -> float.
//
// The NaN/Infinity return paths build the result via bit manipulation
// and memcpy rather than going through the <math.h> NAN/INFINITY
// macros, because those macros are not exposed by MSVC's <math.h>.
// The bit patterns used:
//   exp=31, man!=0  -> quiet NaN  (sign-preserving, 0x7fc00000 | sign)
//   exp=31, man==0  -> +/-Infinity (0x7f800000 | sign)
static float half_to_float(ut16 h) {
	ut32 sign = (ut32)(h >> 15) << 31;
	ut32 exp = (h >> 10) & 0x1F;
	ut32 man = h & 0x3FF;

	if (exp == 0) {
		if (man == 0) {
			ut32 bits = sign;
			float f;
			memcpy(&f, &bits, 4);
			return f;
		}
		float val = ldexpf((float)man, -24);
		return sign ? -val : val;
	}
	if (exp == 31) {
		ut32 bits = sign | (man ? 0x7fc00000u : 0x7f800000u);
		float f;
		memcpy(&f, &bits, 4);
		return f;
	}
	ut32 f_exp = (exp - 15 + 127) << 23;
	ut32 f_man = man << 13;
	ut32 bits = sign | f_exp | f_man;
	float f;
	memcpy(&f, &bits, 4);
	return f;
}

static float read_ble_half(const void *s, bool be) {
	ut16 raw = be ? rz_read_be16(s) : rz_read_le16(s);
	return half_to_float(raw);
}

// ULEB128
static int decode_uleb128(const ut8 *buf, int max, ut64 *out) {
	ut64 r = 0;
	int sh = 0, i = 0;
	while (i < max && sh < 64) {
		ut8 byte = buf[i++];
		r |= (ut64)(byte & 0x7f) << sh;
		sh += 7;
		if (!(byte & 0x80)) {
			break;
		}
	}
	*out = r;
	return i;
}

// SLEB128
static int decode_sleb128(const ut8 *buf, int max, st64 *out) {
	st64 r = 0;
	int sh = 0, i = 0;
	ut8 byte = 0;
	while (i < max && sh < 64) {
		byte = buf[i++];
		r |= (st64)(byte & 0x7f) << sh;
		sh += 7;
		if (!(byte & 0x80)) {
			break;
		}
	}
	if (sh < 64 && (byte & 0x40)) {
		r |= -(1LL << sh);
	}
	*out = r;
	return i;
}

// Pointer helpers (always use ctx->big_endian)

static int ctx_ptr_size(const RzPfCtx *ctx) {
	if (!ctx) {
		return 8;
	}
	switch (ctx->bits) {
	case 16: return 2;
	case 32: return 4;
	default: return 8;
	}
}

static ut64 read_ptr(const ut8 *buf, int off, int avail,
	const RzPfCtx *ctx) {
	bool be = ctx ? ctx->big_endian : false;
	int psz = ctx_ptr_size(ctx);
	if (avail < psz) {
		return 0;
	}
	switch (psz) {
	case 2: return rz_read_ble16(buf + off, be);
	case 4: return rz_read_ble32(buf + off, be);
	default: return rz_read_ble64(buf + off, be);
	}
}

// String encoding handling
/**
 * \brief Size in bytes of a single NUL terminator code unit for the
 *        given string encoding.
 *
 * For UTF-32 this is 4, for UTF-16 it is 2, for everything else 1.
 * Used by string-scanning code to know how many zero bytes to look for
 * when searching for the end of an inline string.
 */
RZ_API int rz_pf_enc_null_unit_size(RzStrEnc enc) {
	switch (enc) {
	case RZ_STRING_ENC_UTF32LE:
	case RZ_STRING_ENC_UTF32BE:
		return 4;
	case RZ_STRING_ENC_UTF16LE:
	case RZ_STRING_ENC_UTF16BE:
		return 2;
	default:
		return 1;
	}
}

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

static char *pf_decode_string(const ut8 *raw, int raw_len,
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
static int read_inline_string(const ut8 *buf, int off, int buf_len,
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

static char *deref_string(const RzPfCtx *ctx, ut64 addr,
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

// Timestamp support is implemented in pf_parser_time.c.

// PF Parsing Context

/**
 * \brief Allocate a fresh RzPfCtx with safe defaults.
 *
 * Default bit width is 64 and recursion bound is 32. The typedb and
 * read_at callback are left NULL; populate them with
 * rz_pf_ctx_setup() before passing to rz_pf_read() if you intend to
 * resolve named formats or dereference pointers.
 */
RZ_API RZ_OWN RzPfCtx *rz_pf_ctx_new(void) {
	RzPfCtx *ctx = RZ_NEW0(RzPfCtx);
	if (ctx) {
		ctx->bits = 64;
		ctx->max_depth = 32;
	}
	return ctx;
}

/**
 * \brief Populate an existing RzPfCtx.
 *
 * \param ctx Context to configure. Must not be NULL.
 * \param typedb Type database for resolving struct/enum/bitfield
 *               names; may be NULL.
 * \param big_endian Default endianness when a field's spec does not
 *                   carry case-derived per-field endianness.
 * \param bits Pointer width in bits. Coerced to 16, 32, or 64;
 *             any other value is treated as 64.
 * \param read_at Optional pointer-dereference callback; may be NULL.
 * \param user Opaque pointer passed unchanged to \p read_at.
 */
RZ_API void rz_pf_ctx_setup(RZ_BORROW RzPfCtx *ctx,
	RZ_NULLABLE RzTypeDB *typedb, bool big_endian, int bits,
	RZ_NULLABLE RzPfReadAtCb read_at,
	RZ_NULLABLE void *user) {
	rz_return_if_fail(ctx);
	ctx->typedb = typedb;
	ctx->big_endian = big_endian;
	ctx->bits = (bits == 16 || bits == 32) ? bits : 64;
	ctx->read_at = read_at;
	ctx->read_at_user = user;
}

/**
 * \brief Release a context. Safe to call with NULL.
 */
RZ_API void rz_pf_ctx_free(RZ_NULLABLE RzPfCtx *ctx) {
	free(ctx);
}

// PF Utilities

/**
 * \brief Fixed byte size for a field type, or -1 if the type's width
 *        is variable (timestamps, raw, leb128, bits, align, TLV).
 *
 * For timestamps, callers should consult rz_pf_timefmt_size() with
 * the field's RzPfTimeFmt to get the actual wire size.
 */
RZ_API int rz_pf_field_size(RzPfFieldType type) {
	switch (type) {
	case RZ_PF_HEX8:
	case RZ_PF_DEC_S8:
	case RZ_PF_DEC_U8:
	case RZ_PF_OCT8:
	case RZ_PF_BIN8:
	case RZ_PF_CHAR:
	case RZ_PF_SKIP:
		return 1;
	case RZ_PF_HEX16:
	case RZ_PF_DEC_S16:
	case RZ_PF_DEC_U16:
	case RZ_PF_OCT16:
	case RZ_PF_BIN16:
	case RZ_PF_FLOAT16:
		return 2;
	case RZ_PF_HEX32:
	case RZ_PF_DEC_S32:
	case RZ_PF_DEC_U32:
	case RZ_PF_OCT32:
	case RZ_PF_BIN32:
	case RZ_PF_FLOAT32:
	case RZ_PF_ENUM:
	case RZ_PF_BITFIELD:
		return 4;
	case RZ_PF_HEX64:
	case RZ_PF_DEC_S64:
	case RZ_PF_DEC_U64:
	case RZ_PF_OCT64:
	case RZ_PF_BIN64:
	case RZ_PF_FLOAT64:
		return 8;
	case RZ_PF_UINT128:
	case RZ_PF_GUID:
		return 16;
	case RZ_PF_TIMESTAMP:
		return -1; /* use rz_pf_timefmt_size() */
	default:
		return -1; /* variable / bit / align / TLV */
	}
}

/**
 * \brief C-language type spelling for a field type.
 *
 * Used by the cstruct renderer to emit a `struct { ... }` declaration
 * that mirrors the binary layout. Returns a stable string literal;
 * callers must not free it.
 */
RZ_API const char *rz_pf_field_ctype(RzPfFieldType type) {
	switch (type) {
	case RZ_PF_HEX8:
	case RZ_PF_DEC_U8:
	case RZ_PF_OCT8:
	case RZ_PF_BIN8:
		return "uint8_t";
	case RZ_PF_DEC_S8:
	case RZ_PF_CHAR:
		return "int8_t";
	case RZ_PF_HEX16:
	case RZ_PF_DEC_U16:
	case RZ_PF_OCT16:
	case RZ_PF_BIN16:
		return "uint16_t";
	case RZ_PF_DEC_S16:
		return "int16_t";
	case RZ_PF_HEX32:
	case RZ_PF_DEC_U32:
	case RZ_PF_OCT32:
	case RZ_PF_BIN32:
		return "uint32_t";
	case RZ_PF_DEC_S32:
		return "int32_t";
	case RZ_PF_HEX64:
	case RZ_PF_DEC_U64:
	case RZ_PF_OCT64:
	case RZ_PF_BIN64:
		return "uint64_t";
	case RZ_PF_DEC_S64:
		return "int64_t";
	case RZ_PF_UINT128:
		return "uint128_t";
	case RZ_PF_FLOAT16:
		return "_Float16";
	case RZ_PF_FLOAT32:
		return "float";
	case RZ_PF_FLOAT64:
		return "double";
	case RZ_PF_ZSTRING:
	case RZ_PF_STRPTR:
		return "char*";
	case RZ_PF_POINTER:
		return "void*";
	case RZ_PF_HEXDUMP:
		return "uint8_t[]";
	case RZ_PF_ULEB128:
	case RZ_PF_SLEB128:
		return "leb128_t";
	case RZ_PF_ENUM:
		return "enum";
	case RZ_PF_BITFIELD:
		return "bitfield";
	case RZ_PF_GUID:
		return "uuid_t";
	case RZ_PF_BITS:
		return "uint64_t /* bits */";
	case RZ_PF_TLV:
		return "tlv_t";
	case RZ_PF_ALIGN:
		return "/* padding */";
	default:
		return "unknown";
	}
}

static const char *type_repr_name(RzPfFieldType type) {
	switch (type) {
	case RZ_PF_HEX8:
	case RZ_PF_HEX16:
	case RZ_PF_HEX32:
	case RZ_PF_HEX64:
		return "hex";
	case RZ_PF_DEC_S8:
	case RZ_PF_DEC_S16:
	case RZ_PF_DEC_S32:
	case RZ_PF_DEC_S64:
		return "signed";
	case RZ_PF_DEC_U8:
	case RZ_PF_DEC_U16:
	case RZ_PF_DEC_U32:
	case RZ_PF_DEC_U64:
		return "unsigned";
	case RZ_PF_OCT8:
	case RZ_PF_OCT16:
	case RZ_PF_OCT32:
	case RZ_PF_OCT64:
		return "octal";
	case RZ_PF_BIN8:
	case RZ_PF_BIN16:
	case RZ_PF_BIN32:
	case RZ_PF_BIN64:
		return "binary";
	case RZ_PF_FLOAT16: return "float16";
	case RZ_PF_FLOAT32: return "float32";
	case RZ_PF_FLOAT64: return "float64";
	case RZ_PF_TIMESTAMP: return "timestamp";
	case RZ_PF_HEXDUMP: return "raw";
	case RZ_PF_GUID: return "guid";
	case RZ_PF_BITS: return "bits";
	case RZ_PF_TLV: return "tlv";
	case RZ_PF_ALIGN: return "align";
	default:
		return rz_pf_field_ctype(type);
	}
}

// PF Parser implementation

/* Per-parse current format pointer. Set on entry to rz_pf_parse(),
 * cleared on exit. Allows the leaf parse helpers (`parse_bits_spec`,
 * `parse_sized_int`, etc.) to record positioned diagnostics without
 * threading the format pointer through every helper signature.
 *
 * A thread-local would be safer in principle, but rz_pf_parse() is
 * not re-entrant within a single thread (no nested parse -> parse
 * calls) and concurrent parses in different threads are not a
 * supported configuration today. */
static RzPfFormat *g_current_fmt = NULL;
static const char *g_current_src = NULL;

/* Compute the 0-based position into the source string from a char
 * pointer that must lie within the source. Returns -1 if outside. */
static int pf_pos_of(const char *p) {
	if (!g_current_src || !p) {
		return -1;
	}
	if (p < g_current_src) {
		return -1;
	}
	return (int)(p - g_current_src);
}

/* Append a diagnostic to a format. The format takes ownership of the
 * formatted message.
 *
 * Visibility: extern (not RZ_API) so the TLV parser in pf_parser_tlv.c
 * can emit diagnostics into the same format object without needing to
 * pass the pointer through every call. */
void pf_emit_error(RzPfFormat *fmt, RzPfErrSeverity sev,
	RzPfErrCategory cat, int pos, const char *fmt_str, ...) {
	if (!fmt) {
		return;
	}
	int new_cap = fmt->nerrors + 1;
	RzPfError *grow = realloc(fmt->errors,
		new_cap * sizeof(RzPfError));
	if (!grow) {
		return;
	}
	fmt->errors = grow;
	RzPfError *e = &fmt->errors[fmt->nerrors];
	e->severity = sev;
	e->category = cat;
	e->pos = pos;

	va_list ap;
	va_start(ap, fmt_str);
	if (pf_vasprintf(&e->message, fmt_str, ap) < 0) {
		e->message = NULL;
	}
	va_end(ap);
	fmt->nerrors++;
}

/* Accessor for cross-file emitters (TLV). */
RzPfFormat *pf_current_fmt(void) {
	return g_current_fmt;
}
const char *pf_current_src(void) {
	return g_current_src;
}

/* Free a single error's owned fields. */
static void pf_error_fini(RzPfError *e) {
	free(e->message);
}

/* Position-aware diagnostic from any parse helper. The position is
 * resolved from the source pointer (set by rz_pf_parse), the message
 * is also forwarded to RZ_LOG_WARN so existing log scrapes keep
 * working unchanged. */
#define PF_DIAG(sev, cat, src_ptr, ...) \
	do { \
		int _pos = pf_pos_of(src_ptr); \
		if (g_current_fmt) { \
			pf_emit_error(g_current_fmt, (sev), (cat), _pos, __VA_ARGS__); \
		} \
		RZ_LOG_WARN(__VA_ARGS__); \
	} while (0)

static char **split_names(const char *s, int *out_n) {
	*out_n = 0;
	if (RZ_STR_ISEMPTY(s)) {
		return NULL;
	}
	int cap = 8, n = 0;
	char **arr = RZ_NEWS0(char *, cap);
	if (!arr) {
		return NULL;
	}
	const char *p = s;
	while (*p) {
		while (*p == ' ') {
			p++;
		}
		if (!*p) {
			break;
		}
		const char *start = p;
		while (*p && *p != ' ') {
			p++;
		}
		if (n >= cap) {
			cap *= 2;
			char **tmp = realloc(arr, cap * sizeof(char *));
			if (!tmp) {
				break;
			}
			arr = tmp;
		}
		arr[n++] = rz_str_ndup(start, p - start);
	}
	*out_n = n;
	return arr;
}

static void parse_annotated_name(const char *raw,
	char **out_type, char **out_name) {
	*out_type = NULL;
	*out_name = NULL;
	if (!raw) {
		return;
	}
	if (raw[0] == '(') {
		const char *cl = strchr(raw, ')');
		if (cl) {
			*out_type = rz_str_ndup(raw + 1, cl - raw - 1);
			*out_name = strdup(cl + 1);
			return;
		}
	}
	*out_name = strdup(raw);
}

static int parse_paren_annotation(const char *p, const char *end,
	char **out_str) {
	*out_str = NULL;
	if (p[0] != '(') {
		return 0;
	}
	const char *cl = strchr(p + 1, ')');
	if (!cl || (end && cl >= end)) {
		return 0;
	}
	*out_str = rz_str_ndup(p + 1, cl - (p + 1));
	return (int)(cl - p) + 1;
}

/**
 * Two-char sized integer:  {x,d,u,o,b,X,D,U,O,B}{1,2,4,8}
 * Lower-case = LE, upper-case = BE.
 */
static int parse_sized_int(char repr, char sz,
	RzPfFieldType *out, RzPfEndian *endian) {
	int col;
	switch (sz) {
	case '1': col = 0; break;
	case '2': col = 1; break;
	case '4': col = 2; break;
	case '8': col = 3; break;
	default: return 0;
	}
	char low = (char)tolower((ut8)repr);
	int row;
	switch (low) {
	case 'x': row = 0; break;
	case 'd': row = 1; break;
	case 'u': row = 2; break;
	case 'o': row = 3; break;
	case 'b': row = 4; break;
	default: return 0;
	}
	static const RzPfFieldType tbl[5][4] = {
		{ RZ_PF_HEX8, RZ_PF_HEX16, RZ_PF_HEX32, RZ_PF_HEX64 },
		{ RZ_PF_DEC_S8, RZ_PF_DEC_S16, RZ_PF_DEC_S32, RZ_PF_DEC_S64 },
		{ RZ_PF_DEC_U8, RZ_PF_DEC_U16, RZ_PF_DEC_U32, RZ_PF_DEC_U64 },
		{ RZ_PF_OCT8, RZ_PF_OCT16, RZ_PF_OCT32, RZ_PF_OCT64 },
		{ RZ_PF_BIN8, RZ_PF_BIN16, RZ_PF_BIN32, RZ_PF_BIN64 },
	};
	*out = tbl[row][col];
	*endian = isupper((ut8)repr) ? RZ_PF_ENDIAN_BE : RZ_PF_ENDIAN_LE;
	return 2;
}

/**
 * Two-char sized float:  {f,F}{2,4,8}
 * Lower = LE, upper = BE.
 */
static int parse_sized_float(char leader, char sz,
	RzPfFieldType *out, RzPfEndian *endian) {
	switch (sz) {
	case '2': *out = RZ_PF_FLOAT16; break;
	case '4': *out = RZ_PF_FLOAT32; break;
	case '8': *out = RZ_PF_FLOAT64; break;
	default: return 0;
	}
	*endian = (leader == 'F') ? RZ_PF_ENDIAN_BE : RZ_PF_ENDIAN_LE;
	return 2;
}

// Timestamp:  t(...) / T(...)  +  deprecated t4 t8 T4 T8 t T
static int parse_timestamp_spec(const char *p, const char *end,
	RzPfField *fld) {
	char ldr = p[0]; /* 't' or 'T' */
	fld->type = RZ_PF_TIMESTAMP;
	fld->endian = (ldr == 'T') ? RZ_PF_ENDIAN_BE : RZ_PF_ENDIAN_LE;

	if (p[1] == '(') {
		char *name = NULL;
		int c = 1 + parse_paren_annotation(p + 1, end, &name);
		if (name) {
			fld->timefmt = rz_pf_timefmt_from_string(name);
			/* If the lookup fell back to UNIX32 and the spelled
			 * name wasn't an explicit "unix32", surface the
			 * mismatch as a parse-time warning so callers get
			 * a positioned diagnostic, not just a log line. */
			if (fld->timefmt == RZ_PF_TIMEFMT_UNIX32 && rz_str_casecmp(name, "unix32") != 0) {
				PF_DIAG(RZ_PF_ERR_WARN,
					RZ_PF_ERRC_SEMANTIC, p,
					"pf: unknown timestamp format '%s', defaulting to unix32\n",
					name);
			}
			free(name);
			return c;
		}
	}
	if (p[1] == '4') {
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: '%c4' deprecated, use '%c(unix32)'\n", ldr, ldr);
		fld->timefmt = RZ_PF_TIMEFMT_UNIX32;
		return 2;
	}
	if (p[1] == '8') {
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: '%c8' deprecated, use '%c(unix64)'\n", ldr, ldr);
		fld->timefmt = RZ_PF_TIMEFMT_UNIX64;
		return 2;
	}
	PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
		"pf: bare '%c' deprecated, use '%c(unix32)'\n", ldr, ldr);
	fld->timefmt = RZ_PF_TIMEFMT_UNIX32;
	return 1;
}

// String:  z / s  with optional (encoding) and optional trailing
// length prefix [N] or [Nb] (bytes-unit suffix). The trailing form
// can only appear immediately after the spec (and optional
// (encoding)); a separate leading [N] before z/s still means
// "array of strings", which is parsed at field level.
static int parse_string_spec(const char *p, const char *end,
	RzPfField *fld) {
	fld->type = (p[0] == 'z') ? RZ_PF_ZSTRING : RZ_PF_STRPTR;
	fld->encoding = RZ_STRING_ENC_UTF8;
	fld->endian = RZ_PF_ENDIAN_CTX;
	fld->str_len_prefix = 0;
	fld->str_len_in_bytes = false;
	int consumed = 1;
	if (p[consumed] == '(') {
		char *enc_name = NULL;
		int pl = parse_paren_annotation(p + consumed, end, &enc_name);
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

// Parse a comma-separated list of NAME=VALUE entries inside parens.
// VALUE accepts decimal, 0x... hex, or 0b... binary. Returns the
// number of entries appended; caller passes a growable array.
static int parse_bitflag_list(const char *body,
	RzPfBitflag **out_arr, int *out_count) {
	int cap = 8, n = 0;
	RzPfBitflag *arr = RZ_NEWS0(RzPfBitflag, cap);
	if (!arr) {
		return 0;
	}
	const char *p = body;
	while (*p) {
		while (*p == ',' || isspace((ut8)*p)) {
			p++;
		}
		if (!*p) {
			break;
		}
		const char *nm = p;
		while (*p && *p != '=' && *p != ',') {
			p++;
		}
		if (*p != '=') {
			/* Bad entry -- skip to next comma. */
			PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, nm,
				"pf: bitfield entry without '=' (expected NAME=VALUE), skipping\n");
			while (*p && *p != ',') {
				p++;
			}
			continue;
		}
		int nm_len = p - nm;
		while (nm_len > 0 && isspace((ut8)nm[nm_len - 1])) {
			nm_len--;
		}
		p++; /* eat '=' */
		while (isspace((ut8)*p)) {
			p++;
		}
		const char *vs = p;
		while (*p && *p != ',') {
			p++;
		}
		int vlen = p - vs;
		while (vlen > 0 && isspace((ut8)vs[vlen - 1])) {
			vlen--;
		}
		if (nm_len <= 0 || vlen <= 0) {
			PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, nm,
				"pf: bitfield entry has empty name or value, skipping\n");
			continue;
		}

		char *vstr = rz_str_ndup(vs, vlen);
		if (!vstr) {
			continue;
		}
		ut64 val = 0;
		if (vstr[0] == '0' && (vstr[1] == 'x' || vstr[1] == 'X')) {
			val = strtoull(vstr + 2, NULL, 16);
		} else if (vstr[0] == '0' && (vstr[1] == 'b' || vstr[1] == 'B')) {
			val = strtoull(vstr + 2, NULL, 2);
		} else {
			val = strtoull(vstr, NULL, 10);
		}
		free(vstr);

		if (n >= cap) {
			cap *= 2;
			RzPfBitflag *tmp = realloc(arr, cap * sizeof(RzPfBitflag));
			if (!tmp) {
				break;
			}
			arr = tmp;
		}
		arr[n].name = rz_str_ndup(nm, nm_len);
		arr[n].value = val;
		n++;
	}
	*out_arr = arr;
	*out_count = n;
	return n;
}

// Inline-bitfield re-interpretation: convert a parsed BIN field to
// BITFIELD when the immediately following parens contains '='.
// Returns extra bytes consumed (length of "(...)") or 0 if no.
static int maybe_inline_bitfield(const char *p_after_spec,
	const char *spec_end, RzPfField *fld, int size_bytes) {
	if (p_after_spec[0] != '(') {
		return 0;
	}
	const char *cl = strchr(p_after_spec + 1, ')');
	if (!cl || (spec_end && cl >= spec_end)) {
		return 0;
	}
	/* Discriminate: presence of '=' inside parens marks an inline
	 * bitflag map; otherwise leave the parens alone (it's a typedb
	 * name annotation, handled at field-name level). */
	const char *eq = memchr(p_after_spec + 1, '=', cl - (p_after_spec + 1));
	if (!eq) {
		return 0;
	}
	char *body = rz_str_ndup(p_after_spec + 1, cl - (p_after_spec + 1));
	if (!body) {
		return 0;
	}
	fld->type = RZ_PF_BITFIELD;
	fld->bitfield_size = size_bytes;
	parse_bitflag_list(body, &fld->bitflags, &fld->bitflag_count);
	free(body);
	return (cl - p_after_spec) + 1;
}

// GUID:  G  with optional (le|be|ms). Default is MS layout.
static int parse_guid_spec(const char *p, const char *end, RzPfField *fld) {
	fld->type = RZ_PF_GUID;
	fld->endian = RZ_PF_ENDIAN_CTX;
	fld->guid_layout = RZ_PF_GUID_MS;
	int consumed = 1;
	if (p[1] == '(') {
		char *name = NULL;
		int pl = parse_paren_annotation(p + 1, end, &name);
		if (name) {
			if (!rz_str_casecmp(name, "le")) {
				fld->guid_layout = RZ_PF_GUID_LE;
			} else if (!rz_str_casecmp(name, "be")) {
				fld->guid_layout = RZ_PF_GUID_BE;
			} else if (!rz_str_casecmp(name, "ms")) {
				fld->guid_layout = RZ_PF_GUID_MS;
			} else {
				PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_SEMANTIC, p + 1,
					"pf: G: unknown layout '%s', "
					"using ms (mixed-endian)\n",
					name);
			}
			free(name);
			consumed += pl;
		}
	}
	return consumed;
}

// Bit field:  :N with optional <  (LSB-first) or >  (MSB-first) suffix.
// Width 1..64. Default order is MSB-first.
static int parse_bits_spec(const char *p, RzPfField *fld) {
	int consumed = 1; /* the ':' */
	if (!isdigit((ut8)p[consumed])) {
		PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, p,
			"pf: ':' bit spec missing width (use ':N' "
			"with N in 1..64), skipping\n");
		return 1;
	}
	int n = 0;
	while (isdigit((ut8)p[consumed]) && n < 1000) {
		n = n * 10 + (p[consumed] - '0');
		consumed++;
	}
	if (n < 1 || n > 64) {
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_RANGE, p,
			"pf: bit width %d out of range, clamped to 1..64\n", n);
		if (n < 1)
			n = 1;
		if (n > 64)
			n = 64;
	}
	fld->type = RZ_PF_BITS;
	fld->bit_width = n;
	fld->bit_order = RZ_PF_BITORDER_MSB;
	if (p[consumed] == '<') {
		fld->bit_order = RZ_PF_BITORDER_LSB;
		consumed++;
	} else if (p[consumed] == '>') {
		fld->bit_order = RZ_PF_BITORDER_MSB;
		consumed++;
	}
	return consumed;
}

// Alignment:  @N where N >= 1.
static int parse_align_spec(const char *p, RzPfField *fld) {
	int consumed = 1; /* the '@' */
	if (!isdigit((ut8)p[consumed])) {
		PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, p,
			"pf: '@' alignment missing N (use '@N' with N>=1), "
			"skipping\n");
		return 1;
	}
	int n = 0;
	while (isdigit((ut8)p[consumed]) && n < 1000000) {
		n = n * 10 + (p[consumed] - '0');
		consumed++;
	}
	if (n < 1) {
		PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_RANGE, p,
			"pf: '@%d' alignment must be >= 1, clamping to 1\n", n);
		n = 1;
	}
	fld->type = RZ_PF_ALIGN;
	fld->align_to = n;
	return consumed;
}

/* Forward decl: parse a TLV V(t=...,l=...,d=...,h=...,e=...) spec.
 * The implementation lives in pf_parser_tlv.c so the TLV semantics
 * are isolated from the core parser. */
extern int pf_parse_tlv_spec(const char *p, const char *end,
	RzPfField *fld);

// Main type-specifier dispatcher.
/* The four BIN sizes paired with their wire width. Used to recover
 * the size when parse_sized_int has matched a `B{1,2,4,8}` prefix
 * and we may need to reinterpret the field as an inline bitfield. */
static int bin_type_width(RzPfFieldType bin) {
	switch (bin) {
	case RZ_PF_BIN8: return 1;
	case RZ_PF_BIN16: return 2;
	case RZ_PF_BIN32: return 4;
	case RZ_PF_BIN64: return 8;
	default: return 0;
	}
}

/* Parse a single type specifier starting at p (bounded by spec_end).
 *
 * Returns the number of source bytes consumed. The dispatch order is:
 *   1. Multi-char prefixes with their own parsers: timestamp (t/T),
 *      string (z/s), float (f/F), inline bitfield reinterpretation
 *      of B{1,2,4,8}, alignment (@), bits (:), GUID (G), TLV (V).
 *   2. Two-char sized integers: {x,d,u,o,b,X,D,U,O,B}{1,2,4,8}.
 *   3. Single-char endian-context specifiers: c, p, Q, r, U, L, E,
 *      B, ?, '.'.
 *   4. Deprecated single-char legacy specifiers: Z, w, X, D, O.
 *
 * A return value of 0 means the byte at `p` is not a recognised
 * specifier; the caller emits an "unknown specifier" warning and
 * advances past it. */
static int parse_type_spec(const char *p, const char *spec_end,
	RzPfField *fld) {

	/* -- Timestamp: t/T -- */
	if (p[0] == 't' || p[0] == 'T') {
		return parse_timestamp_spec(p, spec_end, fld);
	}

	/* -- String: z / s -- */
	if (p[0] == 'z' || p[0] == 's') {
		return parse_string_spec(p, spec_end, fld);
	}

	/* -- Float: f/F  (try sized first, then bare) -- */
	if (p[0] == 'f' || p[0] == 'F') {
		if (p[1]) {
			RzPfFieldType ft;
			RzPfEndian en;
			int r = parse_sized_float(p[0], p[1], &ft, &en);
			if (r) {
				fld->type = ft;
				fld->endian = en;
				return r;
			}
		}
		/* bare f / F -- deprecated */
		if (p[0] == 'f') {
			PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
				"pf: bare 'f' deprecated, use 'f4'\n");
			fld->type = RZ_PF_FLOAT32;
			fld->endian = RZ_PF_ENDIAN_LE;
		} else {
			PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
				"pf: bare 'F' deprecated, use 'F8'\n");
			fld->type = RZ_PF_FLOAT64;
			fld->endian = RZ_PF_ENDIAN_BE;
		}
		return 1;
	}

	/* -- Sized integers: {x,d,u,o,b,X,D,U,O,B}{1,2,4,8} -- */
	if (p[0] && p[1]) {
		RzPfFieldType it;
		RzPfEndian en;
		int r = parse_sized_int(p[0], p[1], &it, &en);
		if (r) {
			fld->type = it;
			fld->endian = en;
			/* Inline-bitfield reinterpretation: parse_sized_int
			 * matches `B{1,2,4,8}` as the BIN row, but if a
			 * parenthesised flag-list follows we want the field
			 * to be an inline bitfield of the same width. */
			if (p[0] == 'B' && p[r] == '(') {
				int sz = bin_type_width(it);
				if (sz) {
					int extra = maybe_inline_bitfield(p + r,
						spec_end, fld, sz);
					if (extra) {
						return r + extra;
					}
				}
			}
			return r;
		}
	}

	/* -- Context-endian sized integer: n{1,2,4,8} (unsigned hex)
	 *    Endianness follows the surrounding context (ctx->big_endian).
	 *    This is the replacement for the legacy `N{1,2,4,8}` codes
	 *    that bin/format/elf and friends used for headers whose
	 *    endianness depends on the file's data byte. */
	if (p[0] == 'n' && p[1]) {
		RzPfFieldType ct = RZ_PF_HEX8;
		bool match = true;
		switch (p[1]) {
		case '1': ct = RZ_PF_HEX8; break;
		case '2': ct = RZ_PF_HEX16; break;
		case '4': ct = RZ_PF_HEX32; break;
		case '8': ct = RZ_PF_HEX64; break;
		default: match = false; break;
		}
		if (match) {
			fld->type = ct;
			fld->endian = RZ_PF_ENDIAN_CTX;
			return 2;
		}
	}

	/* -- DSL extensions: @N, :N, G, V(...) -- */
	if (p[0] == '@') {
		return parse_align_spec(p, fld);
	}
	if (p[0] == ':') {
		return parse_bits_spec(p, fld);
	}
	if (p[0] == 'G') {
		return parse_guid_spec(p, spec_end, fld);
	}
	if (p[0] == 'V') {
		return pf_parse_tlv_spec(p, spec_end, fld);
	}

	/* -- Single-char (context-endian or endian-neutral) --
	 * These leave fld->endian = RZ_PF_ENDIAN_CTX so the reader can
	 * fall back to the RzPfCtx's big_endian flag. */
	switch (p[0]) {
	case 'c':
		fld->type = RZ_PF_CHAR;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case 'p':
		fld->type = RZ_PF_POINTER;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case 'Q':
		fld->type = RZ_PF_UINT128;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case 'r':
		fld->type = RZ_PF_HEXDUMP;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case 'U':
		fld->type = RZ_PF_ULEB128;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case 'L':
		fld->type = RZ_PF_SLEB128;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case 'E':
		fld->type = RZ_PF_ENUM;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case 'B':
		/* Bare B (not B{1,2,4,8} -- that was caught above) */
		fld->type = RZ_PF_BITFIELD;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case '?':
		fld->type = RZ_PF_STRUCT;
		fld->endian = RZ_PF_ENDIAN_CTX;
		/* Optional inline `(typename)`. Canonical form:
		 * `?(inner) fieldname`. The annotation binds to the
		 * field's type_name; if absent here, the typename can
		 * still be supplied later via the `(typename)fieldname`
		 * annotation in the names list. */
		if (p[1] == '(') {
			char *tn = NULL;
			int annot = parse_paren_annotation(p + 1, spec_end, &tn);
			if (annot > 0 && tn) {
				free(fld->type_name);
				fld->type_name = tn;
				return 1 + annot;
			}
			free(tn);
		}
		return 1;
	case '.':
		fld->type = RZ_PF_SKIP;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;

	/* -- Deprecated single-char (kept for back-compat) -- */
	case 'b':
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: bare 'b' deprecated, use 'b1'\n");
		fld->type = RZ_PF_BIN8;
		fld->endian = RZ_PF_ENDIAN_LE;
		return 1;
	case 'd':
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: bare 'd' deprecated, use 'd4'\n");
		fld->type = RZ_PF_DEC_S32;
		fld->endian = RZ_PF_ENDIAN_LE;
		return 1;
	case 'o':
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: bare 'o' deprecated, use 'o4'\n");
		fld->type = RZ_PF_OCT32;
		fld->endian = RZ_PF_ENDIAN_LE;
		return 1;
	case 'q':
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: bare 'q' deprecated, use 'x8'\n");
		fld->type = RZ_PF_HEX64;
		fld->endian = RZ_PF_ENDIAN_LE;
		return 1;
	case 'u':
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: bare 'u' deprecated, use 'u4'\n");
		fld->type = RZ_PF_DEC_U32;
		fld->endian = RZ_PF_ENDIAN_LE;
		return 1;
	case 'x':
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: bare 'x' deprecated, use 'x4'\n");
		fld->type = RZ_PF_HEX32;
		fld->endian = RZ_PF_ENDIAN_LE;
		return 1;
	case 'i':
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: bare 'i' deprecated, use 'd4'\n");
		fld->type = RZ_PF_DEC_S32;
		fld->endian = RZ_PF_ENDIAN_LE;
		return 1;
	case 'Z':
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: 'Z' deprecated, use 'z(utf16le)'\n");
		fld->type = RZ_PF_ZSTRING;
		fld->encoding = RZ_STRING_ENC_UTF16LE;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case 'w':
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: 'w' deprecated, use 'x2'\n");
		fld->type = RZ_PF_HEX16;
		fld->endian = RZ_PF_ENDIAN_LE;
		return 1;
	case 'X':
		/* Bare X -- legacy hexdump. Sized X{1,2,4,8} matches
		 * the BE-hex row of parse_sized_int above. */
		PF_DIAG(RZ_PF_ERR_WARN, RZ_PF_ERRC_DEPRECATED, p,
			"pf: bare 'X' (hexdump) deprecated, use 'r'\n");
		fld->type = RZ_PF_HEXDUMP;
		fld->endian = RZ_PF_ENDIAN_CTX;
		return 1;
	case 'D':
	case 'O':
		/* Bare D / O have no legacy meaning -- always paired
		 * with a width. */
		PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, p,
			"pf: bare '%c' is not valid, did you mean '%c4'?\n",
			p[0], p[0]);
		return 1; /* skip */

	default:
		return 0;
	}
}

/* Parse an optional `{N}` repeat count at p. Returns the number of
 * bytes consumed (0 if no brace at p) and writes the repeat count
 * to *out (default 1 on parse failure). */
static int parse_brace_repeat(const char *p, int *out) {
	if (*p != '{') {
		return 0;
	}
	const char *close = strchr(p, '}');
	if (!close) {
		return 0;
	}
	char *body = rz_str_ndup(p + 1, close - p - 1);
	int n = 1;
	if (body) {
		n = atoi(body);
		if (n < 1) {
			n = 1;
		}
		free(body);
	}
	*out = n;
	return (int)(close - p) + 1;
}

/* Locate the boundary between the specifier region and the names
 * list. The specifier region runs from `start` to the first
 * top-level (paren-depth 0, bracket-depth 0) space; the names list
 * is everything after that space. If there is no separator the
 * spec region runs to end-of-string and there are no names. */
static void locate_spec_names_split(const char *start,
	const char **spec_end_out, const char **names_start_out) {

	int depth = 0;
	for (const char *s = start; *s; s++) {
		if (*s == '[' || *s == '(') {
			depth++;
		} else if (*s == ']' || *s == ')') {
			depth--;
		} else if (*s == ' ' && depth == 0) {
			*spec_end_out = s;
			*names_start_out = s + 1;
			return;
		}
	}
	*spec_end_out = start + strlen(start);
	*names_start_out = NULL;
}

/* Legacy-to-new DSL converter.
 *
 * The new pf parser requires explicit sizes (`x4`, `d2`, `u8`, ...)
 * and uses `u`/`U` for explicit-endian unsigned, `t(kind)` for time,
 * `z(enc)` for encoded strings, `@N` for alignment, `:N<` / `:N>` for
 * bit fields. The legacy DSL allowed bare-letter specifiers with
 * implicit sizes:
 *
 *   x  -> x4 LE      X  -> X4 BE (uppercase = BE)
 *   d  -> d4 LE      D  -> d4 LE (legacy "explicit" decimal)
 *   o  -> o4 LE      O  -> o4 LE
 *   u  -> u4 LE
 *   b  -> b1 LE      (single-byte binary)
 *   w  -> x2 LE      (16-bit word)
 *   q  -> x8 LE      (64-bit quad)
 *   i  -> d4 LE      (legacy "integer")
 *   nN -> uN LE      (N=1,2,4,8: little-endian explicit-width)
 *   NN -> UN BE      (N=1,2,4,8: big-endian explicit-width)
 *
 * Strings inside parenthesised annotations like `(name)`, `t(kind)`,
 * `z(enc)`, `B4(flag=val,...)`, and `V(t=...,l=...)` are passed
 * through untouched. The specifier block ends at the first unescaped
 * space (which separates spec from names).
 *
 * This converter is the only place where legacy syntax is handled.
 * Once all callers of `pf` migrate to the new DSL (the on-disk
 * `librz/bin/d/*` files and the C-coded `librz/bin/format/*.c`
 * setters), this function can be deleted. */
static char *convert_legacy_to_new_dsl(const char *src, RzPfFormat *fmt) {
	if (!src) {
		return NULL;
	}
	size_t in_len = strlen(src);
	/* Generous upper bound: each input byte may turn into 2 output
	 * bytes (bare `x` -> `x4`). Plus a few bytes of slack. */
	char *out = malloc(in_len * 2 + 16);
	if (!out) {
		return NULL;
	}
	size_t oi = 0;
	const char *p = src;
	int paren_depth = 0;
	int bracket_depth = 0;
	int in_specs = 1;
	/* Emit one deprecation warning per converted spec character.
	 * Position is the offset into the original source. */
#define WARN_LEGACY(letter, repl) \
	do { \
		if (fmt) { \
			pf_emit_error(fmt, RZ_PF_ERR_WARN, \
				RZ_PF_ERRC_DEPRECATED, \
				(int)(p - src), \
				"pf: legacy '%c' deprecated, use '%s'", \
				(letter), (repl)); \
		} \
	} while (0)
	while (*p) {
		char c = *p;
		if (in_specs && paren_depth == 0 && (c == ' ' || c == '\t')) {
			in_specs = 0;
		}
		if (!in_specs) {
			out[oi++] = c;
			p++;
			continue;
		}
		if (c == '(') {
			paren_depth++;
			out[oi++] = c;
			p++;
			continue;
		}
		if (c == ')') {
			if (paren_depth > 0) {
				paren_depth--;
			}
			out[oi++] = c;
			p++;
			continue;
		}
		if (c == '[') {
			bracket_depth++;
			out[oi++] = c;
			p++;
			continue;
		}
		if (c == ']') {
			if (bracket_depth > 0) {
				bracket_depth--;
			}
			out[oi++] = c;
			p++;
			continue;
		}
		if (paren_depth > 0 || bracket_depth > 0) {
			out[oi++] = c;
			p++;
			continue;
		}
		/* In specifier territory at top level. Look at the next
		 * char to decide whether this is a sized form (already
		 * new DSL: `x4`, `d2`, ...) or a bare legacy form. */
		char nx = p[1];
		int already_sized = (nx == '1' || nx == '2' || nx == '4' || nx == '8');
		/* Avoid converting tokens that look like bare specifiers
		 * but are actually new-DSL prefixes: `t(`, `z(`, `s(`,
		 * `T(`, `Z(`, `S(`, `G(`, `V(`, `B(`. */
		int has_paren_arg = (nx == '(');
		switch (c) {
		case 't':
		case 'T':
		case 'z':
		case 'Z':
		case 's':
		case 'S':
		case 'G':
		case 'V':
			if (has_paren_arg || already_sized) {
				out[oi++] = c;
				p++;
				continue;
			}
			/* Bare 't' / 'T' / 'z' / 's' are themselves
			 * legacy forms; the new parser handles them with
			 * a deprecation warning. Pass through. */
			out[oi++] = c;
			p++;
			continue;
		case 'B':
			if (has_paren_arg || already_sized) {
				out[oi++] = c;
				p++;
				continue;
			}
			out[oi++] = c;
			p++;
			continue;
		case 'f':
		case 'F':
			out[oi++] = c;
			p++;
			continue;
		case 'x':
			if (already_sized) {
				out[oi++] = c;
				p++;
				continue;
			}
			WARN_LEGACY('x', "x4");
			out[oi++] = 'x';
			out[oi++] = '4';
			p++;
			continue;
		case 'X':
			/* Bare X means legacy hex dump (RZ_PF_HEXDUMP) and
			 * goes to the in-parser case. Only sized X{1,2,4,8}
			 * is a big-endian hex int. Don't touch either. */
			out[oi++] = c;
			p++;
			continue;
		case 'd':
			if (already_sized) {
				out[oi++] = c;
				p++;
				continue;
			}
			WARN_LEGACY('d', "d4");
			out[oi++] = 'd';
			out[oi++] = '4';
			p++;
			continue;
		case 'D':
			if (already_sized) {
				out[oi++] = c;
				p++;
				continue;
			}
			WARN_LEGACY('D', "d4");
			out[oi++] = 'd';
			out[oi++] = '4';
			p++;
			continue;
		case 'o':
			if (already_sized) {
				out[oi++] = c;
				p++;
				continue;
			}
			WARN_LEGACY('o', "o4");
			out[oi++] = 'o';
			out[oi++] = '4';
			p++;
			continue;
		case 'O':
			if (already_sized) {
				out[oi++] = c;
				p++;
				continue;
			}
			WARN_LEGACY('O', "o4");
			out[oi++] = 'o';
			out[oi++] = '4';
			p++;
			continue;
		case 'u':
			if (already_sized) {
				out[oi++] = c;
				p++;
				continue;
			}
			WARN_LEGACY('u', "u4");
			out[oi++] = 'u';
			out[oi++] = '4';
			p++;
			continue;
		case 'b':
			if (already_sized) {
				out[oi++] = c;
				p++;
				continue;
			}
			WARN_LEGACY('b', "b1");
			out[oi++] = 'b';
			out[oi++] = '1';
			p++;
			continue;
		case 'w':
			WARN_LEGACY('w', "x2");
			out[oi++] = 'x';
			out[oi++] = '2';
			p++;
			continue;
		case 'q':
			WARN_LEGACY('q', "x8");
			out[oi++] = 'x';
			out[oi++] = '8';
			p++;
			continue;
		case 'i':
			WARN_LEGACY('i', "d4");
			out[oi++] = 'd';
			out[oi++] = '4';
			p++;
			continue;
		case 'n':
		case 'N':
			if (nx == '1' || nx == '2' || nx == '4' || nx == '8') {
				char tmp[4] = { (c == 'n') ? 'u' : 'U',
					nx, 0, 0 };
				WARN_LEGACY(c, tmp);
				out[oi++] = tmp[0];
				out[oi++] = nx;
				p += 2;
				continue;
			}
			out[oi++] = c;
			p++;
			continue;
		default:
			out[oi++] = c;
			p++;
			continue;
		}
	}
	out[oi] = '\0';
	return out;
}

/**
 * \brief Parse a pf format string into an RzPfFormat tree.
 *
 * \param fmt_str Format string in the new pf DSL (see cmd print help
 *                or the file-level comment of pf_parser.c for the
 *                grammar). Must be non-empty.
 * \return Newly-allocated RzPfFormat on success; NULL on parse or
 *         allocation failure. Caller frees with rz_pf_format_free().
 *
 * Parsing is structural -- it does not resolve type names through the
 * typedb. Use rz_pf_read() to actually decode bytes, passing an
 * RzPfCtx populated with a typedb if your format references named
 * structs, enums, or bitfields.
 */

RZ_API RZ_OWN RzPfFormat *rz_pf_parse(const char *fmt_str) {
	if (!fmt_str) {
		return NULL;
	}
	RzPfFormat *fmt = RZ_NEW0(RzPfFormat);
	if (!fmt) {
		return NULL;
	}
	fmt->repeat = 1;
	fmt->source = strdup(fmt_str);
	if (!*fmt_str) {
		/* Empty input is a valid no-op format: zero fields, zero
		 * diagnostics. Returning NULL here would force every
		 * caller to special-case the empty string. */
		return fmt;
	}
	/* Apply the legacy-to-new DSL conversion. The owned `source`
	 * still reflects what the caller passed (for round-trip), but
	 * the parser walks the converted string. The converter is a
	 * narrow compatibility shim that exists to keep the on-disk
	 * format files (`librz/bin/d/*`) and a few C-coded format
	 * setters (`librz/bin/format/*.c`) working until they are
	 * migrated to the new DSL. */
	char *converted = convert_legacy_to_new_dsl(fmt_str, fmt);
	const char *parse_src = converted ? converted : fmt_str;

	/* Establish the per-parse diagnostic context. Saved across the
	 * call so that rz_pf_parse() remains safe to invoke recursively
	 * from helpers (e.g. read_nested_struct() reparses a child
	 * format string by name). */
	RzPfFormat *saved_fmt = g_current_fmt;
	const char *saved_src = g_current_src;
	g_current_fmt = fmt;
	g_current_src = parse_src;

	const char *p = parse_src;
	while (*p && isspace((ut8)*p)) {
		p++;
	}

	/* Optional leading repeat count */
	if (isdigit((ut8)*p) && *p != '0') {
		fmt->repeat = (int)strtol(p, (char **)&p, 10);
		if (fmt->repeat < 1) {
			fmt->repeat = 1;
		} else if (fmt->repeat > 4096) {
			fmt->repeat = 4096;
		}
	}

	/* Allow whitespace between the leading repeat and the rest. */
	while (*p && isspace((ut8)*p)) {
		p++;
	}

	/* Optional {N} repeat */
	{
		int brace_n;
		int consumed = parse_brace_repeat(p, &brace_n);
		if (consumed) {
			if (brace_n > 4096) {
				brace_n = 4096;
			}
			fmt->repeat = brace_n;
			p += consumed;
		}
	}

	while (*p && isspace((ut8)*p)) {
		p++;
	}

	/* Union flag */
	if (*p == '0') {
		fmt->is_union = true;
		p++;
	}

	/* Separate specifier region from names */
	const char *spec_start = p;
	const char *names_start = NULL;
	const char *spec_end = NULL;
	locate_spec_names_split(p, &spec_end, &names_start);

	int name_count = 0;
	char **names = split_names(names_start, &name_count);

	int cap = 16;
	fmt->fields = RZ_NEWS0(RzPfField, cap);
	if (!fmt->fields) {
		for (int i = 0; i < name_count; i++) {
			free(names[i]);
		}
		free(names);
		g_current_fmt = saved_fmt;
		g_current_src = saved_src;
		free(fmt->source);
		free(fmt);
		free(converted);
		return NULL;
	}

	int name_idx = 0;
	p = spec_start;

	while (p < spec_end && *p) {
		if (fmt->nfields >= cap) {
			cap *= 2;
			RzPfField *tmp = realloc(fmt->fields,
				cap * sizeof(RzPfField));
			if (!tmp) {
				break;
			}
			fmt->fields = tmp;
			memset(tmp + fmt->nfields, 0,
				(cap - fmt->nfields) * sizeof(RzPfField));
		}

		RzPfField *fld = &fmt->fields[fmt->nfields];
		memset(fld, 0, sizeof(RzPfField));
		fld->array_count = -1;
		fld->encoding = RZ_STRING_ENC_UTF8;
		fld->endian = RZ_PF_ENDIAN_CTX;

		/* Pointer prefix */
		if (*p == '*') {
			fld->is_pointer = true;
			p++;
		}

		/* Array prefix [N] (literal) or [@field-name] (lookup).
		 *
		 * Width-form special cases: the bracketed integer is the
		 * BYTE WIDTH of the underlying scalar (legacy semantics),
		 * not an array count, when the next specifier is bare
		 * `E`, `B`, `z`, or `s` -- because those carry no built-in
		 * width. The width is stashed in fld->bit_width (E/B) or
		 * fld->str_fixed_len (z/s) for the reader to honour.
		 * `[N]?` keeps the array-count meaning (N repetitions of
		 * the nested struct). */
		if (*p == '[') {
			const char *cl = strchr(p, ']');
			if (cl && cl < spec_end) {
				const char *inner = p + 1;
				int inner_len = cl - inner;
				bool eb_width = (cl[1] == 'E' || cl[1] == 'B');
				bool zs_width = (cl[1] == 'z' || cl[1] == 's');
				if (inner_len > 1 && inner[0] == '@') {
					/* [@name] -- array count comes from
					 * a previously-parsed scalar field. */
					fld->length_ref = rz_str_ndup(
						inner + 1, inner_len - 1);
					fld->array_count = -1;
				} else {
					char *tmp = rz_str_ndup(inner, inner_len);
					if (tmp) {
						int n = atoi(tmp);
						if (eb_width) {
							if (n < 1 || n > 8) {
								PF_DIAG(RZ_PF_ERR_ERROR,
									RZ_PF_ERRC_RANGE, p,
									"pf: [%s] enum/bitfield width must be 1..8, defaulting to 4\n",
									tmp);
								n = 4;
							}
							fld->bit_width = n;
							fld->array_count = -1;
						} else if (zs_width) {
							if (n < 1) {
								PF_DIAG(RZ_PF_ERR_ERROR,
									RZ_PF_ERRC_RANGE, p,
									"pf: [%s] string width must be >= 1, clamping to 1\n",
									tmp);
								n = 1;
							}
							fld->str_fixed_len = n;
							fld->array_count = -1;
						} else {
							fld->array_count = n;
							if (fld->array_count < 1) {
								PF_DIAG(RZ_PF_ERR_ERROR,
									RZ_PF_ERRC_RANGE, p,
									"pf: [%s] array count must be >= 1, clamping to 1\n",
									tmp);
								fld->array_count = 1;
							} else if (fld->array_count > 4096) {
								PF_DIAG(RZ_PF_ERR_ERROR,
									RZ_PF_ERRC_RANGE, p,
									"pf: [%s] array count exceeds maximum 4096, clamping\n",
									tmp);
								fld->array_count = 4096;
							}
						}
						free(tmp);
					}
				}
				p = cl + 1;
			}
		}

		int consumed = parse_type_spec(p, spec_end, fld);
		if (consumed == 0) {
			PF_DIAG(RZ_PF_ERR_ERROR, RZ_PF_ERRC_SYNTAX, p,
				"pf: unknown specifier '%c' at position %d, "
				"skipping\n",
				*p, (int)(p - spec_start));
			p++;
			continue;
		}
		p += consumed;

		/* Assign name. SKIP and ALIGN are positional padding,
		 * not user-visible values, so they do not consume from
		 * the names list. */
		bool wants_name = (fld->type != RZ_PF_SKIP && fld->type != RZ_PF_ALIGN);
		if (wants_name && name_idx < name_count) {
			char *tn = NULL, *fn = NULL;
			parse_annotated_name(names[name_idx], &tn, &fn);
			/* A `(typename)fieldname` annotation on a sized binary
			 * field promotes it to BITFIELD with the underlying
			 * scalar size preserved. This lets users write
			 * `B4 (perm) flags` to look up a bitfield by name in
			 * the typedb. Other sized types are not promoted --
			 * `i (color) c` still renders as a decimal integer
			 * because the existing pre-rewrite tests rely on it. */
			if (tn) {
				switch (fld->type) {
				case RZ_PF_BIN8:
				case RZ_PF_BIN16:
				case RZ_PF_BIN32:
				case RZ_PF_BIN64:
					fld->bitfield_size =
						rz_pf_field_size(fld->type);
					fld->type = RZ_PF_BITFIELD;
					break;
				default:
					break;
				}
			}
			if (fld->type == RZ_PF_STRUCT || fld->type == RZ_PF_ENUM || fld->type == RZ_PF_BITFIELD) {
				/* If the spec already established the typedb name
				 * (e.g. `?(inner) field`), don't clobber it with a
				 * NULL from the names side. */
				if (tn) {
					free(fld->type_name);
					fld->type_name = tn;
				}
				fld->name = fn;
			} else {
				fld->name = fn;
				free(tn);
			}
			name_idx++;
		}

		fmt->nfields++;
	}

	for (int i = 0; i < name_count; i++) {
		free(names[i]);
	}
	free(names);

	g_current_fmt = saved_fmt;
	g_current_src = saved_src;
	free(converted);
	return fmt;
}

/**
 * \brief Release an RzPfFormat tree and all owned strings.
 *
 * Walks every field and frees its name, type_name, length_ref,
 * bitflag entries, and TLV spec. Safe to call with NULL.
 */
RZ_API void rz_pf_format_free(RZ_NULLABLE RzPfFormat *fmt) {
	if (!fmt) {
		return;
	}
	for (int i = 0; i < fmt->nfields; i++) {
		RzPfField *f = &fmt->fields[i];
		free(f->name);
		free(f->type_name);
		free(f->length_ref);
		if (f->bitflags) {
			for (int k = 0; k < f->bitflag_count; k++) {
				free(f->bitflags[k].name);
			}
			free(f->bitflags);
		}
		if (f->tlv_spec) {
			free(f->tlv_spec->dispatch_name);
			free(f->tlv_spec);
		}
	}
	free(fmt->fields);
	for (int i = 0; i < fmt->nerrors; i++) {
		pf_error_fini(&fmt->errors[i]);
	}
	free(fmt->errors);
	free(fmt->source);
	free(fmt);
}

/* Tag used when prefixing a diagnostic line: "[warn]" / "[error]". */
static const char *severity_tag(RzPfErrSeverity s) {
	return (s == RZ_PF_ERR_ERROR) ? "error" : "warn";
}

/* Tag used when prefixing the category: syntax / semantic / range /
 * deprecated / data / depth. */
static const char *category_tag(RzPfErrCategory c) {
	switch (c) {
	case RZ_PF_ERRC_SYNTAX: return "syntax";
	case RZ_PF_ERRC_SEMANTIC: return "semantic";
	case RZ_PF_ERRC_RANGE: return "range";
	case RZ_PF_ERRC_DEPRECATED: return "deprecated";
	case RZ_PF_ERRC_DATA: return "data";
	case RZ_PF_ERRC_DEPTH: return "depth";
	}
	return "?";
}

/**
 * \brief Render every diagnostic on \p fmt as a printable string.
 *
 * Each entry produces three lines: a header `[sev category @pos]
 * message`, the source format string, and a caret line that points
 * at the offending column. Returns NULL when \p fmt has no errors.
 */
RZ_API RZ_OWN char *rz_pf_format_errors_to_string(
	RZ_BORROW const RzPfFormat *fmt) {
	if (!fmt || fmt->nerrors == 0) {
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return NULL;
	}
	for (int i = 0; i < fmt->nerrors; i++) {
		const RzPfError *e = &fmt->errors[i];
		rz_strbuf_appendf(sb, "[%s %s @%d] %s",
			severity_tag(e->severity),
			category_tag(e->category), e->pos,
			e->message ? e->message : "");
		/* Most messages already carry a trailing newline. */
		size_t mlen = e->message ? strlen(e->message) : 0;
		if (mlen == 0 || e->message[mlen - 1] != '\n') {
			rz_strbuf_append(sb, "\n");
		}
		if (fmt->source && e->pos >= 0 && (size_t)e->pos <= strlen(fmt->source)) {
			rz_strbuf_appendf(sb, "  %s\n", fmt->source);
			rz_strbuf_append(sb, "  ");
			for (int k = 0; k < e->pos; k++) {
				rz_strbuf_append(sb, " ");
			}
			rz_strbuf_append(sb, "^\n");
		}
	}
	return rz_strbuf_drain(sb);
}

/**
 * \brief Parse a format and log every diagnostic via RZ_LOG.
 *
 * Equivalent to rz_pf_parse() followed by walking fmt->errors and
 * emitting each one. Useful for callers that want to surface
 * positioned errors at the boundary between user input and the
 * parser without having to handle the error array themselves.
 */
RZ_API RZ_OWN RzPfFormat *rz_pf_parse_verbose(const char *fmt_str) {
	RzPfFormat *fmt = rz_pf_parse(fmt_str);
	if (!fmt) {
		return NULL;
	}
	if (fmt->nerrors > 0) {
		char *out = rz_pf_format_errors_to_string(fmt);
		if (out) {
			RZ_LOG_WARN("pf parse diagnostics:\n%s", out);
			free(out);
		}
	}
	return fmt;
}

/**
 * \brief Resolve a named format from the typedb's `formats` hash.
 *
 * \param typedb Type database; may be NULL.
 * \param name Format key (e.g. "_ELF32_HEADER"); may be NULL/empty.
 * \return Borrowed pointer to the stored format string or NULL when
 *         the typedb is missing, the name is empty, or there is no
 *         such entry. The returned pointer is owned by the typedb;
 *         callers must not free it.
 */
RZ_API RZ_BORROW const char *rz_pf_resolve_name(
	RZ_BORROW const RzTypeDB *typedb, const char *name) {
	if (!typedb || RZ_STR_ISEMPTY(name)) {
		return NULL;
	}
	const char *direct = rz_type_db_format_get(typedb, name);
	if (direct) {
		return direct;
	}
	/* Not in the formats hash. Synthesise the format string from
	 * the RzType tree (covers `td "union poo {...}"` and other
	 * declarations that register the type but never call
	 * rz_type_db_format_set). The generated string is registered
	 * into the formats hash so the returned BORROWED pointer stays
	 * valid for the typedb's lifetime and subsequent lookups are
	 * O(1). */
	char *generated = rz_type_format((RzTypeDB *)typedb, name);
	if (RZ_STR_ISEMPTY(generated)) {
		free(generated);
		return NULL;
	}
	rz_type_db_format_set((RzTypeDB *)typedb, name, generated);
	free(generated);
	return rz_type_db_format_get(typedb, name);
}

// Reader functions

static void read_scalar(const ut8 *buf, int off, int avail,
	RzPfFieldType type, bool be, RzPfScalar *out) {
	memset(out, 0, sizeof(*out));
	const ut8 *p = buf + off;

	switch (type) {
	case RZ_PF_HEX8:
	case RZ_PF_DEC_U8:
	case RZ_PF_OCT8:
	case RZ_PF_BIN8:
	case RZ_PF_CHAR:
		if (avail >= 1) {
			out->v_u8 = p[0];
		}
		break;
	case RZ_PF_DEC_S8:
		if (avail >= 1) {
			out->v_s8 = (st8)p[0];
		}
		break;
	case RZ_PF_HEX16:
	case RZ_PF_DEC_U16:
	case RZ_PF_OCT16:
	case RZ_PF_BIN16:
		if (avail >= 2) {
			out->v_u16 = rz_read_ble16(p, be);
		}
		break;
	case RZ_PF_DEC_S16:
		if (avail >= 2) {
			out->v_s16 = (st16)rz_read_ble16(p, be);
		}
		break;
	case RZ_PF_FLOAT16:
		if (avail >= 2) {
			out->v_f32 = read_ble_half(p, be);
		}
		break;
	case RZ_PF_HEX32:
	case RZ_PF_DEC_U32:
	case RZ_PF_OCT32:
	case RZ_PF_BIN32:
	case RZ_PF_ENUM:
	case RZ_PF_BITFIELD:
		if (avail >= 4) {
			out->v_u32 = rz_read_ble32(p, be);
		}
		break;
	case RZ_PF_DEC_S32:
		if (avail >= 4) {
			out->v_s32 = (st32)rz_read_ble32(p, be);
		}
		break;
	case RZ_PF_FLOAT32:
		if (avail >= 4) {
			out->v_f32 = read_ble_float(p, be);
		}
		break;
	case RZ_PF_HEX64:
	case RZ_PF_DEC_U64:
	case RZ_PF_OCT64:
	case RZ_PF_BIN64:
		if (avail >= 8) {
			out->v_u64 = rz_read_ble64(p, be);
		}
		break;
	case RZ_PF_DEC_S64:
		if (avail >= 8) {
			out->v_s64 = (st64)rz_read_ble64(p, be);
		}
		break;
	case RZ_PF_FLOAT64:
		if (avail >= 8) {
			out->v_f64 = read_ble_double(p, be);
		}
		break;
	default:
		break;
	}
}

/* Per-format reading state. Used to thread the bit cursor through
 * consecutive :N fields and to let [@name] fields look back at
 * previously-parsed siblings in the same format scope. */
typedef struct {
	int bit_cursor; //<< 0..7, bit position within the
			//   current byte for :N fields.
	const RzPfValue *siblings; //<< borrowed array of values already
				   //   parsed in this scope (for [@name]).
	int n_siblings;
} ReadState;

/* Look up the most-recent same-name scalar in the sibling array. */
static ut64 lookup_sibling_value(const ReadState *st, const char *name) {
	if (!st || !name) {
		return 0;
	}
	for (int i = st->n_siblings - 1; i >= 0; i--) {
		const RzPfValue *v = &st->siblings[i];
		if (!v->name || strcmp(v->name, name)) {
			continue;
		}
		if (v->count < 1 || !v->scalars) {
			continue;
		}
		const RzPfScalar *s = &v->scalars[0];
		/* Match by field type -> pick the right slot. */
		switch (v->type) {
		case RZ_PF_HEX8:
		case RZ_PF_DEC_U8:
		case RZ_PF_OCT8:
		case RZ_PF_BIN8:
		case RZ_PF_CHAR:
			return s->v_u8;
		case RZ_PF_DEC_S8: return (ut64)(st64)s->v_s8;
		case RZ_PF_HEX16:
		case RZ_PF_DEC_U16:
		case RZ_PF_OCT16:
		case RZ_PF_BIN16:
			return s->v_u16;
		case RZ_PF_DEC_S16: return (ut64)(st64)s->v_s16;
		case RZ_PF_HEX32:
		case RZ_PF_DEC_U32:
		case RZ_PF_OCT32:
		case RZ_PF_BIN32:
		case RZ_PF_ENUM:
		case RZ_PF_BITFIELD:
			return s->v_u32;
		case RZ_PF_DEC_S32: return (ut64)(st64)s->v_s32;
		case RZ_PF_HEX64:
		case RZ_PF_DEC_U64:
		case RZ_PF_OCT64:
		case RZ_PF_BIN64:
		case RZ_PF_POINTER:
		case RZ_PF_ULEB128:
		case RZ_PF_BITS:
			return s->v_u64;
		case RZ_PF_DEC_S64:
		case RZ_PF_SLEB128:
			return (ut64)s->v_s64;
		default:
			return 0;
		}
	}
	RZ_LOG_WARN("pf: [@%s] no earlier field with that name\n", name);
	return 0;
}

/* Resolve the effective array count for a field, honoring [@name]. */
static int resolve_array_count(const RzPfField *fld, const ReadState *st) {
	if (fld->length_ref) {
		ut64 v = lookup_sibling_value(st, fld->length_ref);
		if (v > INT32_MAX) {
			RZ_LOG_WARN("pf: [@%s] count %" PFMT64u
				    " too large, clamping\n",
				fld->length_ref, v);
			v = INT32_MAX;
		}
		return (int)v;
	}
	return (fld->array_count > 0) ? fld->array_count : 1;
}

/* Read a string with a length prefix. Returns the total bytes
 * consumed (prefix + payload). Output is decoded into UTF-8. */
static int read_lenprefix_string(const ut8 *buf, int off, int avail,
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

/* GUID layout decoders. The buffer is always 16 bytes long. The MS
 * layout (default) follows the Microsoft "GUID" struct: D1=u32 LE,
 * D2=u16 LE, D3=u16 LE, D4=8 raw bytes in display order. The BE
 * layout treats all 16 bytes in network order. The LE layout reverses
 * each of the first three components. The raw 16 bytes are stored in
 * v_raw, the layout is stored in val->guid_layout, and rendering uses
 * the canonical xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx form. */
static int read_guid_field(const RzPfField *fld, const ut8 *buf,
	int off, int avail, RzPfValue *val) {
	val->count = 1;
	val->scalars = RZ_NEWS0(RzPfScalar, 1);
	if (!val->scalars) {
		return 0;
	}
	val->scalars[0].v_raw = RZ_NEWS0(ut8, 16);
	val->guid_layout = fld->guid_layout;
	if (avail >= 16 && val->scalars[0].v_raw) {
		memcpy(val->scalars[0].v_raw, buf + off, 16);
	}
	val->raw_len = RZ_MIN(16, avail);
	return RZ_MIN(16, avail);
}

/* Read bit_width bits from buf starting at byte off, bit st->bit_cursor.
 * Updates the bit cursor. Returns the number of *bytes* consumed (0 if
 * the field finishes within the current byte). When the bit cursor wraps
 * past 8, the byte advance is reported. */
static int read_bits_field(const RzPfField *fld, const ut8 *buf,
	int off, int avail, ReadState *st, RzPfValue *val) {
	int width = fld->bit_width;
	if (width < 1)
		width = 1;
	if (width > 64)
		width = 64;
	val->bit_width = width;
	val->bit_offset = st ? st->bit_cursor : 0;
	val->count = 1;
	val->scalars = RZ_NEWS0(RzPfScalar, 1);
	if (!val->scalars) {
		return 0;
	}

	int cursor = st ? st->bit_cursor : 0;
	int total_bits_needed = width + cursor;
	int bytes_needed = (total_bits_needed + 7) / 8;
	if (avail < bytes_needed) {
		bytes_needed = avail;
	}

	ut64 v = 0;
	if (fld->bit_order == RZ_PF_BITORDER_MSB) {
		/* MSB-first: bit 0 is the most-significant bit of byte 0. */
		int bit_idx = cursor;
		for (int i = 0; i < width; i++) {
			int byte_pos = bit_idx / 8;
			int byte_bit = 7 - (bit_idx & 7);
			if (byte_pos >= bytes_needed)
				break;
			ut64 b = (buf[off + byte_pos] >> byte_bit) & 1ULL;
			v = (v << 1) | b;
			bit_idx++;
		}
	} else {
		/* LSB-first: bit 0 is the least-significant bit of byte 0. */
		int bit_idx = cursor;
		for (int i = 0; i < width; i++) {
			int byte_pos = bit_idx / 8;
			int byte_bit = bit_idx & 7;
			if (byte_pos >= bytes_needed)
				break;
			ut64 b = (buf[off + byte_pos] >> byte_bit) & 1ULL;
			v |= (b << i);
			bit_idx++;
		}
	}
	val->scalars[0].v_u64 = v;

	int new_cursor = cursor + width;
	int bytes_consumed = new_cursor / 8;
	if (st) {
		st->bit_cursor = new_cursor & 7;
	}
	return bytes_consumed;
}

static int read_field(const RzPfField *fld, const ut8 *buf, int off,
	int buf_len, ut64 base_addr, const RzPfCtx *ctx, int depth,
	ReadState *st, RzPfValue *val);

static int read_nested_struct(const RzPfField *fld, const ut8 *buf,
	int off, int buf_len, ut64 base_addr,
	const RzPfCtx *ctx, int depth, RzPfValue *val) {
	if (!ctx || !ctx->typedb || !fld->type_name) {
		return 0;
	}
	if (depth >= ctx->max_depth) {
		RZ_LOG_WARN("pf: max depth for '%s'\n", fld->type_name);
		return 0;
	}
	const char *sub_str = rz_pf_resolve_name(
		ctx->typedb, fld->type_name);
	if (RZ_STR_ISEMPTY(sub_str)) {
		RZ_LOG_WARN("pf: unknown format '%s'\n", fld->type_name);
		return 0;
	}
	RzPfFormat *sub = rz_pf_parse(sub_str);
	if (!sub) {
		return 0;
	}

	int repeat = (fld->array_count > 0)
		? fld->array_count
		: sub->repeat;
	int child_cap = sub->nfields * repeat;
	val->children = RZ_NEWS0(RzPfValue, child_cap);
	val->nchildren = 0;
	/* Record the array length so filter-path navigators (e.g.
	 * `name.field[N]`) can slice the flat children list into a
	 * per-iteration window of `nchildren / count` entries. For a
	 * scalar struct field (no array prefix) `repeat` is 1, which
	 * matches the default. */
	val->count = repeat;

	int total = 0;
	for (int r = 0; r < repeat && off + total < buf_len; r++) {
		int soff = 0, max_soff = 0;
		/* Fresh per-iteration read state: bit cursor and sibling
		 * lookup are scoped to this struct instance. */
		ReadState sub_st = { 0 };
		sub_st.siblings = val->children;
		for (int fi = 0; fi < sub->nfields; fi++) {
			if (sub->is_union) {
				soff = 0;
			}
			if (val->nchildren >= child_cap) {
				child_cap *= 2;
				val->children = realloc(val->children,
					child_cap * sizeof(RzPfValue));
				sub_st.siblings = val->children;
			}
			sub_st.n_siblings = val->nchildren;
			int c = read_field(&sub->fields[fi], buf,
				off + total + soff, buf_len,
				base_addr, ctx, depth + 1,
				&sub_st,
				&val->children[val->nchildren]);
			val->nchildren++;
			if (sub->is_union) {
				max_soff = RZ_MAX(max_soff, c);
			} else {
				soff += c;
			}
		}
		total += sub->is_union ? max_soff : soff;
	}
	rz_pf_format_free(sub);
	return total;
}

/* Forward decl for the TLV reader, defined in pf_parser_tlv.c. */
extern int pf_tlv_read(const RzPfField *fld, const ut8 *buf,
	int off, int buf_len, ut64 base_addr, const RzPfCtx *ctx,
	int depth, RzPfValue *val);

static int read_field(const RzPfField *fld, const ut8 *buf, int off,
	int buf_len, ut64 base_addr, const RzPfCtx *ctx,
	int depth, ReadState *st, RzPfValue *val) {
	memset(val, 0, sizeof(*val));
	val->type = fld->type;
	val->endian = fld->endian;
	val->name = fld->name ? strdup(fld->name) : NULL;
	val->type_name = fld->type_name ? strdup(fld->type_name) : NULL;
	val->encoding = fld->encoding;
	val->timefmt = fld->timefmt;
	val->offset = base_addr + off;
	val->is_pointer = fld->is_pointer;
	val->guid_layout = fld->guid_layout;
	val->bitflags = fld->bitflags;
	val->bitflag_count = fld->bitflag_count;

	/* Snap-flush rule: any non-BITS field starting mid-byte rounds
	 * the bit cursor up to the next byte boundary, advancing the
	 * read offset by one. The cursor stays per-format, not per-field. */
	int snap_advance = 0;
	if (st && st->bit_cursor != 0 && fld->type != RZ_PF_BITS) {
		snap_advance = 1;
		st->bit_cursor = 0;
		off += 1;
	}

	bool be = resolve_endian(fld->endian, ctx);
	int avail = buf_len - off;
	if (avail <= 0) {
		/* Avail check after snap-advance -- caller already saw avail>0,
		 * but the byte we burned may have exhausted it. Still return
		 * the snap-advance count so the outer cursor moves. */
		return snap_advance;
	}

	/* Alignment field -- no value, no name consumed, only adjusts off. */
	if (fld->type == RZ_PF_ALIGN) {
		int rem = off % fld->align_to;
		if (rem == 0) {
			return snap_advance;
		}
		int pad = fld->align_to - rem;
		if (pad > avail) {
			pad = avail;
		}
		return snap_advance + pad;
	}

	/* Pointer dereference ('*' prefix) -- always ctx endian.
	 * For pointer-to-string (`*z`), additionally follow the pointer
	 * through ctx->read_at and decode the body as a NUL-terminated
	 * string in the field's encoding. The body text is then shown
	 * after the (*0x...) pointer literal in the rendered output. */
	if (fld->is_pointer) {
		int psz = ctx_ptr_size(ctx);
		if (avail < psz) {
			return snap_advance;
		}
		val->ptr_addr = read_ptr(buf, off, avail, ctx);
		if (fld->type == RZ_PF_ZSTRING && ctx && ctx->read_at) {
			val->count = 1;
			val->scalars = RZ_NEWS0(RzPfScalar, 1);
			if (val->scalars) {
				val->scalars[0].v_str = deref_string(
					ctx, val->ptr_addr, fld->encoding);
			}
		}
		return snap_advance + psz;
	}

	/* Struct */
	if (fld->type == RZ_PF_STRUCT) {
		return snap_advance +
			read_nested_struct(fld, buf, off, buf_len,
				base_addr, ctx, depth, val);
	}

	/* Skip */
	if (fld->type == RZ_PF_SKIP) {
		int n = (fld->array_count > 0) ? fld->array_count : 1;
		return snap_advance + RZ_MIN(n, avail);
	}

	/* Bit field -- uses and updates st->bit_cursor. */
	if (fld->type == RZ_PF_BITS) {
		return snap_advance +
			read_bits_field(fld, buf, off, avail, st, val);
	}

	/* GUID */
	if (fld->type == RZ_PF_GUID) {
		return snap_advance +
			read_guid_field(fld, buf, off, avail, val);
	}

	/* TLV */
	if (fld->type == RZ_PF_TLV) {
		return snap_advance +
			pf_tlv_read(fld, buf, off, buf_len,
				base_addr, ctx, depth, val);
	}

	/* Timestamp (uses per-field be) */
	if (fld->type == RZ_PF_TIMESTAMP) {
		int sz = rz_pf_timefmt_size(fld->timefmt);
		int cnt = resolve_array_count(fld, st);
		if (cnt < 1)
			cnt = 1;
		val->count = cnt;
		val->scalars = RZ_NEWS0(RzPfScalar, cnt);
		int total = 0;
		for (int k = 0; k < cnt && total + sz <= avail; k++) {
			total += rz_pf_timestamp_read(buf, off + total,
				avail - total, fld->timefmt, be,
				&val->scalars[k]);
		}
		return snap_advance + total;
	}

	/* Inline string -- supports optional length prefix. */
	if (fld->type == RZ_PF_ZSTRING) {
		val->count = 1;
		val->scalars = RZ_NEWS0(RzPfScalar, 1);
		int consumed;
		if (fld->str_fixed_len > 0) {
			/* Fixed-width string: read exactly N bytes, stopping
			 * display at the first NUL.
			 *
			 * Overflow heuristic: mark `ovf` only when the slot
			 * has a non-empty printable prefix followed by
			 * non-printable garbage -- a clear signature of a
			 * truncated C string. A slot that begins with a
			 * non-printable byte is treated as a binary header
			 * (e.g. ELF magic `[4]z` over `\x7fELF`) and never
			 * flagged. A slot of all printable bytes (e.g.
			 * `[2]z` over "AB") is considered fitting and also
			 * not flagged. */
			int n = RZ_MIN(fld->str_fixed_len, avail);
			int slen = 0;
			while (slen < n && buf[off + slen]) {
				slen++;
			}
			if (slen >= n) {
				int printable = 0;
				while (printable < n) {
					ut8 b = buf[off + printable];
					if (b < 0x20 || b > 0x7e) {
						break;
					}
					printable++;
				}
				if (printable > 0 && printable < n) {
					val->overflow = true;
					slen = printable;
				}
			}
			val->scalars[0].v_str = rz_str_ndup(
				(const char *)buf + off, slen);
			consumed = n;
		} else if (fld->str_len_prefix > 0) {
			consumed = read_lenprefix_string(buf, off, avail,
				fld->encoding, fld->str_len_prefix,
				fld->str_len_in_bytes, be,
				&val->scalars[0].v_str);
		} else {
			bool overflow = false;
			consumed = read_inline_string(buf, off, buf_len,
				fld->encoding, &val->scalars[0].v_str,
				&overflow);
			val->overflow = overflow;
		}
		return snap_advance + consumed;
	}

	/* String pointer (pointer read uses ctx endian) */
	if (fld->type == RZ_PF_STRPTR) {
		int psz = ctx_ptr_size(ctx);
		val->count = 1;
		val->scalars = RZ_NEWS0(RzPfScalar, 1);
		if (avail >= psz) {
			val->ptr_addr = read_ptr(buf, off, avail, ctx);
			val->scalars[0].v_str = deref_string(
				ctx, val->ptr_addr, fld->encoding);
		} else {
			val->scalars[0].v_str = strdup("");
		}
		return snap_advance + psz;
	}

	/* Generic pointer (ctx endian) */
	if (fld->type == RZ_PF_POINTER) {
		int psz = ctx_ptr_size(ctx);
		val->count = 1;
		val->scalars = RZ_NEWS0(RzPfScalar, 1);
		if (avail >= psz) {
			val->scalars[0].v_u64 = read_ptr(
				buf, off, avail, ctx);
		}
		return snap_advance + psz;
	}

	/* ULEB128 */
	if (fld->type == RZ_PF_ULEB128) {
		int cnt = resolve_array_count(fld, st);
		if (cnt < 1)
			cnt = 1;
		val->count = cnt;
		val->scalars = RZ_NEWS0(RzPfScalar, cnt);
		int total = 0;
		for (int k = 0; k < cnt; k++) {
			ut64 lv = 0;
			int c = decode_uleb128(buf + off + total,
				avail - total, &lv);
			val->scalars[k].v_u64 = lv;
			total += c;
		}
		return snap_advance + total;
	}

	/* SLEB128 */
	if (fld->type == RZ_PF_SLEB128) {
		int cnt = resolve_array_count(fld, st);
		if (cnt < 1)
			cnt = 1;
		val->count = cnt;
		val->scalars = RZ_NEWS0(RzPfScalar, cnt);
		int total = 0;
		for (int k = 0; k < cnt; k++) {
			st64 lv = 0;
			int c = decode_sleb128(buf + off + total,
				avail - total, &lv);
			val->scalars[k].v_s64 = lv;
			total += c;
		}
		return snap_advance + total;
	}

	/* Raw hex dump */
	if (fld->type == RZ_PF_HEXDUMP) {
		int n = resolve_array_count(fld, st);
		if (n < 1)
			n = 1;
		int actual = RZ_MIN(n, avail);
		val->count = 1;
		val->scalars = RZ_NEWS0(RzPfScalar, 1);
		if (actual > 0) {
			val->scalars[0].v_raw = RZ_NEWS(ut8, actual);
			if (val->scalars[0].v_raw) {
				memcpy(val->scalars[0].v_raw,
					buf + off, actual);
			}
		}
		val->raw_len = actual;
		return snap_advance + actual;
	}

	/* uint128 (byte-sequential) */
	if (fld->type == RZ_PF_UINT128) {
		val->count = 1;
		val->scalars = RZ_NEWS0(RzPfScalar, 1);
		val->scalars[0].v_raw = RZ_NEWS0(ut8, 16);
		if (val->scalars[0].v_raw && avail >= 16) {
			memcpy(val->scalars[0].v_raw, buf + off, 16);
		}
		val->raw_len = RZ_MIN(16, avail);
		return snap_advance + RZ_MIN(16, avail);
	}

	/* Fixed-size scalar / array (uses per-field be).
	 *
	 * For RZ_PF_ENUM and RZ_PF_BITFIELD the default underlying
	 * width is 4 bytes, but `[N]E` / `[N]B` in the spec may have
	 * stored an explicit 1/2/4/8 width in fld->bit_width. We
	 * fold that into elem_sz here, and read the corresponding
	 * number of bytes into v_u32 (zero-extended). */
	int elem_sz = rz_pf_field_size(fld->type);
	if (elem_sz <= 0) {
		return snap_advance;
	}
	if ((fld->type == RZ_PF_ENUM || fld->type == RZ_PF_BITFIELD) && fld->bit_width >= 1 && fld->bit_width <= 8) {
		elem_sz = fld->bit_width;
	}
	int cnt = resolve_array_count(fld, st);
	if (cnt < 1)
		cnt = 1;
	val->count = cnt;
	val->scalars = RZ_NEWS0(RzPfScalar, cnt);
	if (!val->scalars) {
		return snap_advance;
	}
	for (int k = 0; k < cnt && off + k * elem_sz + elem_sz <= buf_len; k++) {
		int elem_off = off + k * elem_sz;
		if ((fld->type == RZ_PF_ENUM || fld->type == RZ_PF_BITFIELD) && elem_sz != 4) {
			/* Read elem_sz bytes (1/2/4/8) zero-extended into u32
			 * for elem_sz<=4, or into u64 truncated to u32 for 8. */
			ut64 raw = 0;
			switch (elem_sz) {
			case 1: raw = buf[elem_off]; break;
			case 2: raw = rz_read_ble16(buf + elem_off, be); break;
			case 4: raw = rz_read_ble32(buf + elem_off, be); break;
			case 8: raw = rz_read_ble64(buf + elem_off, be); break;
			}
			val->scalars[k].v_u32 = (ut32)raw;
		} else {
			read_scalar(buf, elem_off,
				buf_len - elem_off,
				fld->type, be, &val->scalars[k]);
		}
	}
	return snap_advance + cnt * elem_sz;
}

/**
 * \brief Decode a buffer using a parsed format and return values.
 *
 * \param fmt Parsed format (from rz_pf_parse()). Must not be NULL.
 * \param buf Bytes to decode. Must not be NULL.
 * \param buf_len Number of bytes available in \p buf.
 * \param base_addr Virtual address of \p buf[0]; recorded in each
 *                  value's `offset` for display.
 * \param ctx Optional context (typedb, endianness, ptr size, deref
 *            callback). NULL is allowed; a 64-bit / depth-32 fallback
 *            is used.
 * \param out_count Optional out-param: number of RzPfValue entries
 *                  produced. NULL is allowed.
 * \return Newly-allocated array of values (size *out_count). Caller
 *         frees with rz_pf_values_free(). Returns NULL on allocation
 *         failure.
 *
 * Bit cursor and `[@name]` length-by-reference lookups are scoped per
 * top-level repetition and per nested-struct instance.
 */
RZ_API RZ_OWN RzPfValue *rz_pf_read(
	RZ_BORROW const RzPfFormat *fmt,
	const ut8 *buf, int buf_len, ut64 base_addr,
	RZ_BORROW const RzPfCtx *ctx,
	RZ_OUT int *out_count) {
	rz_return_val_if_fail(fmt && buf, NULL);
	RzPfCtx fallback = { .bits = 64, .max_depth = 32 };
	if (!ctx) {
		ctx = &fallback;
	}

	int total_cap = fmt->nfields * fmt->repeat;
	RzPfValue *vals = RZ_NEWS0(RzPfValue, total_cap);
	if (!vals) {
		if (out_count) {
			*out_count = 0;
		}
		return NULL;
	}

	int idx = 0, cur_off = 0;
	for (int rep = 0; rep < fmt->repeat && cur_off < buf_len; rep++) {
		int off = 0, max_off = 0;
		/* Per-repetition state: bit cursor resets between
		 * outer repetitions, and the sibling lookup window
		 * starts fresh too. */
		ReadState st = { 0 };
		st.siblings = vals + idx;
		for (int fi = 0; fi < fmt->nfields && idx < total_cap; fi++) {
			if (fmt->is_union) {
				off = 0;
			}
			st.n_siblings = idx - (int)(st.siblings - vals);
			int c = read_field(&fmt->fields[fi], buf,
				cur_off + off, buf_len,
				base_addr + cur_off, ctx, 0, &st, &vals[idx]);
			idx++;
			if (fmt->is_union) {
				max_off = RZ_MAX(max_off, c);
			} else {
				off += c;
			}
		}
		cur_off += fmt->is_union ? max_off : off;
	}

	if (out_count) {
		*out_count = idx;
	}
	return vals;
}

static bool is_string_type(RzPfFieldType t) {
	return t == RZ_PF_ZSTRING || t == RZ_PF_STRPTR;
}

static bool is_raw_type(RzPfFieldType t) {
	return t == RZ_PF_HEXDUMP || t == RZ_PF_UINT128 || t == RZ_PF_GUID || t == RZ_PF_TLV;
}

/**
 * \brief Release an array of RzPfValue entries.
 *
 * \param vals Array returned by rz_pf_read(); may be NULL.
 * \param count Number of entries in \p vals.
 *
 * Recurses into nested struct/TLV children. Frees owned strings,
 * scalar payloads (string and raw types specifically), and the
 * scalars array itself.
 */
RZ_API void rz_pf_values_free(RZ_NULLABLE RzPfValue *vals, int count) {
	if (!vals) {
		return;
	}
	for (int i = 0; i < count; i++) {
		RzPfValue *v = &vals[i];
		free(v->name);
		free(v->type_name);
		if (v->scalars) {
			if (is_string_type(v->type)) {
				for (int k = 0; k < v->count; k++) {
					free(v->scalars[k].v_str);
				}
			} else if (is_raw_type(v->type)) {
				for (int k = 0; k < v->count; k++) {
					free(v->scalars[k].v_raw);
				}
			}
			free(v->scalars);
		}
		rz_pf_values_free(v->children, v->nchildren);
	}
	free(vals);
}

// Render helpers

static bool field_matches(const RzPfValue *v, const char *field_filter) {
	if (RZ_STR_ISEMPTY(field_filter)) {
		return true;
	}
	return v->name && !strcmp(v->name, field_filter);
}

static void render_binary(RzStrBuf *sb, ut64 v, int bits) {
	rz_strbuf_append(sb, "0b");
	bool started = false;
	for (int i = bits - 1; i >= 0; i--) {
		int bit = (v >> i) & 1;
		if (bit) {
			started = true;
		}
		if (started || i < 8) {
			rz_strbuf_appendf(sb, "%d", bit);
			if (i > 0 && i % 4 == 0) {
				rz_strbuf_append(sb, "_");
			}
		}
	}
}

static void scalar_text(RzStrBuf *sb, const RzPfValue *val, int k,
	const RzTypeDB *typedb) {
	const RzPfScalar *s = &val->scalars[k];
	switch (val->type) {
	case RZ_PF_HEX8:
		rz_strbuf_appendf(sb, "0x%02x", s->v_u8);
		break;
	case RZ_PF_HEX16:
		rz_strbuf_appendf(sb, "0x%04x",
			(unsigned)s->v_u16);
		break;
	case RZ_PF_HEX32:
		rz_strbuf_appendf(sb, "0x%08x",
			(unsigned)s->v_u32);
		break;
	case RZ_PF_HEX64:
		rz_strbuf_appendf(sb, "0x%016" PFMT64x,
			s->v_u64);
		break;
	case RZ_PF_DEC_S8:
		rz_strbuf_appendf(sb, "%d", (int)s->v_s8);
		break;
	case RZ_PF_DEC_S16:
		rz_strbuf_appendf(sb, "%d", (int)s->v_s16);
		break;
	case RZ_PF_DEC_S32:
		rz_strbuf_appendf(sb, "%d", s->v_s32);
		break;
	case RZ_PF_DEC_S64:
		rz_strbuf_appendf(sb, "%" PFMT64d, s->v_s64);
		break;
	case RZ_PF_DEC_U8:
		rz_strbuf_appendf(sb, "%u",
			(unsigned)s->v_u8);
		break;
	case RZ_PF_DEC_U16:
		rz_strbuf_appendf(sb, "%u",
			(unsigned)s->v_u16);
		break;
	case RZ_PF_DEC_U32:
		rz_strbuf_appendf(sb, "%u",
			(unsigned)s->v_u32);
		break;
	case RZ_PF_DEC_U64:
		rz_strbuf_appendf(sb, "%" PFMT64u, s->v_u64);
		break;
	case RZ_PF_OCT8:
		rz_strbuf_appendf(sb, "0o%03o",
			(unsigned)s->v_u8);
		break;
	case RZ_PF_OCT16:
		rz_strbuf_appendf(sb, "0o%06o",
			(unsigned)s->v_u16);
		break;
	case RZ_PF_OCT32:
		rz_strbuf_appendf(sb, "0o%011o",
			(unsigned)s->v_u32);
		break;
	case RZ_PF_OCT64:
		rz_strbuf_appendf(sb, "0o%022" PFMT64o,
			s->v_u64);
		break;
	case RZ_PF_BIN8:
		render_binary(sb, s->v_u8, 8);
		break;
	case RZ_PF_BIN16:
		render_binary(sb, s->v_u16, 16);
		break;
	case RZ_PF_BIN32:
		render_binary(sb, s->v_u32, 32);
		break;
	case RZ_PF_BIN64:
		render_binary(sb, s->v_u64, 64);
		break;
	case RZ_PF_FLOAT16:
		rz_strbuf_appendf(sb, "%.4g",
			(double)s->v_f32);
		break;
	case RZ_PF_FLOAT32:
		rz_strbuf_appendf(sb, "%.9g",
			(double)s->v_f32);
		break;
	case RZ_PF_FLOAT64:
		rz_strbuf_appendf(sb, "%.17g", s->v_f64);
		break;
	case RZ_PF_CHAR: {
		ut8 c = s->v_u8;
		rz_strbuf_appendf(sb, "'%c'",
			(c >= 0x20 && c < 0x7f) ? c : '.');
		break;
	}
	case RZ_PF_ZSTRING:
	case RZ_PF_STRPTR: {
		rz_strbuf_append(sb, "\"");
		const char *str = s->v_str ? s->v_str : "";
		for (const unsigned char *q = (const unsigned char *)str; *q; q++) {
			if (*q >= 0x20 && *q < 0x7f && *q != '"' && *q != '\\') {
				rz_strbuf_appendf(sb, "%c", *q);
			} else if (*q == '"') {
				rz_strbuf_append(sb, "\\\"");
			} else if (*q == '\\') {
				rz_strbuf_append(sb, "\\\\");
			} else if (*q == '\n') {
				rz_strbuf_append(sb, "\\n");
			} else if (*q == '\r') {
				rz_strbuf_append(sb, "\\r");
			} else if (*q == '\t') {
				rz_strbuf_append(sb, "\\t");
			} else {
				rz_strbuf_appendf(sb, "\\x%02x", *q);
			}
		}
		rz_strbuf_append(sb, "\"");
		break;
	}
	case RZ_PF_POINTER:
		rz_strbuf_appendf(sb, "0x%" PFMT64x,
			s->v_u64);
		break;
	case RZ_PF_ULEB128:
		rz_strbuf_appendf(sb, "%" PFMT64u, s->v_u64);
		break;
	case RZ_PF_SLEB128:
		rz_strbuf_appendf(sb, "%" PFMT64d, s->v_s64);
		break;
	case RZ_PF_ENUM: {
		ut32 v = s->v_u32;
		rz_strbuf_appendf(sb, "0x%08x", (unsigned)v);
		/* Resolve the enum-member name via the typedb when the
		 * field carries the enum type name and the renderer was
		 * given a typedb. Output mirrors legacy `pf` so existing
		 * users see the same `; SYMBOL` suffix:
		 *
		 *   class = 0x00000002 ; ELFCLASS64
		 *
		 * When the typedb has no member at the read value, no
		 * suffix is appended -- the numeric output stands alone. */
		if (typedb && val->type_name) {
			const char *sym = rz_type_db_enum_member_by_val(
				(RzTypeDB *)typedb, val->type_name, v);
			if (sym && *sym) {
				rz_strbuf_append(sb, " ; ");
				rz_strbuf_append(sb, sym);
			}
		}
		break;
	}
	case RZ_PF_BITFIELD: {
		ut32 v = s->v_u32;
		rz_strbuf_appendf(sb, "0x%08x", (unsigned)v);
		if (val->bitflags && val->bitflag_count > 0) {
			ut32 residual = v;
			bool first = true;
			rz_strbuf_append(sb, " : ");
			for (int i = 0; i < val->bitflag_count; i++) {
				ut32 fv = (ut32)val->bitflags[i].value;
				if (fv && (v & fv) == fv) {
					if (!first) {
						rz_strbuf_append(sb, " | ");
					}
					rz_strbuf_append(sb,
						val->bitflags[i].name);
					residual &= ~fv;
					first = false;
				}
			}
			if (residual) {
				if (!first) {
					rz_strbuf_append(sb, " | ");
				}
				rz_strbuf_appendf(sb, "0x%x", residual);
			} else if (first) {
				rz_strbuf_append(sb, "0");
			}
		}
		break;
	}
	case RZ_PF_BITS:
		rz_strbuf_appendf(sb, "%" PFMT64u " (%d-bit)",
			s->v_u64, val->bit_width);
		break;
	default:
		rz_strbuf_append(sb, "?");
		break;
	}
}

/* Render a 16-byte GUID buffer with the canonical
 * xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx form, honoring the layout
 * variant stored on the value. */
static void render_guid(RzStrBuf *sb, const ut8 *b, RzPfGuidLayout lay) {
	if (!b) {
		rz_strbuf_append(sb, "00000000-0000-0000-0000-000000000000");
		return;
	}
	ut32 d1;
	ut16 d2, d3;
	switch (lay) {
	case RZ_PF_GUID_BE:
		d1 = rz_read_be32(b);
		d2 = rz_read_be16(b + 4);
		d3 = rz_read_be16(b + 6);
		break;
	case RZ_PF_GUID_LE:
		d1 = rz_read_le32(b);
		d2 = rz_read_le16(b + 4);
		d3 = rz_read_le16(b + 6);
		break;
	case RZ_PF_GUID_MS:
	default:
		d1 = rz_read_le32(b);
		d2 = rz_read_le16(b + 4);
		d3 = rz_read_le16(b + 6);
		break;
	}
	rz_strbuf_appendf(sb,
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		(unsigned)d1, (unsigned)d2, (unsigned)d3,
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

static const char *endian_tag(RzPfEndian e) {
	switch (e) {
	case RZ_PF_ENDIAN_LE: return " [LE]";
	case RZ_PF_ENDIAN_BE: return " [BE]";
	default: return "";
	}
}

// Render: text

/* Per-render context that bundles the filter and palette. NULL fields
 * mean "no filter" / "no color". A NULL ctx pointer is equivalent to
 * a zero-initialised one -- see WRAP() below. */
typedef struct {
	const char *field_filter;
	const RzPfPalette *pal;
	/* Optional typedb for enum-member name resolution. */
	const RzTypeDB *typedb;
} RenderCtx;

/* Emit \p color before \p body, then \p reset after, suppressing both
 * when either is NULL. Keeps the call sites compact. */
static void emit_colored(RzStrBuf *sb, const char *color,
	const char *body, const char *reset) {
	if (color) {
		rz_strbuf_append(sb, color);
	}
	rz_strbuf_append(sb, body);
	if (color && reset) {
		rz_strbuf_append(sb, reset);
	}
}

/* Like emit_colored() but accepts a printf-formatted body. */
RZ_PRINTF_CHECK(4, 5)
static void emit_coloredf(RzStrBuf *sb, const char *color,
	const char *reset, const char *fmt, ...) {
	va_list ap;
	char *body = NULL;
	va_start(ap, fmt);
	if (pf_vasprintf(&body, fmt, ap) < 0) {
		body = NULL;
	}
	va_end(ap);
	if (!body) {
		return;
	}
	if (color) {
		rz_strbuf_append(sb, color);
	}
	rz_strbuf_append(sb, body);
	if (color && reset) {
		rz_strbuf_append(sb, reset);
	}
	free(body);
}

static void render_val_text(RzStrBuf *sb, const RzPfValue *v,
	int indent, const RenderCtx *rc) {
	if (v->type == RZ_PF_SKIP) {
		return;
	}
	if (v->type == RZ_PF_ALIGN) {
		return;
	}
	const char *filter = rc ? rc->field_filter : NULL;
	const RzPfPalette *pal = rc ? rc->pal : NULL;
	const char *RST = pal ? pal->reset : NULL;
	if (!field_matches(v, filter)) {
		return;
	}

	for (int i = 0; i < indent; i++) {
		rz_strbuf_append(sb, "  ");
	}
	emit_coloredf(sb, pal ? pal->offset : NULL, RST,
		"0x%08" PFMT64x, v->offset);
	rz_strbuf_append(sb, " ");
	if (v->name) {
		emit_colored(sb, pal ? pal->name : NULL, v->name, RST);
		rz_strbuf_append(sb, " : ");
	}

	if (v->is_pointer) {
		rz_strbuf_append(sb, "(*");
		emit_coloredf(sb, pal ? pal->hex_literal : NULL, RST,
			"0x%" PFMT64x, v->ptr_addr);
		rz_strbuf_append(sb, ")");
		/* For pointer-to-string (`*z`), append the decoded body. */
		if (v->type == RZ_PF_ZSTRING && v->scalars
			&& v->scalars[0].v_str) {
			rz_strbuf_append(sb, " \"");
			rz_strbuf_append(sb, v->scalars[0].v_str);
			rz_strbuf_append(sb, "\"");
		}
		rz_strbuf_append(sb, "\n");
		return;
	}

	/* Struct */
	if (v->type == RZ_PF_STRUCT && v->nchildren > 0) {
		rz_strbuf_append(sb, "(");
		emit_colored(sb, pal ? pal->label : NULL,
			v->type_name ? v->type_name : "struct", RST);
		rz_strbuf_append(sb, ")\n");
		/* Recurse with filter cleared -- sub-fields are always shown
		 * once the parent matches the filter. */
		RenderCtx sub = { .field_filter = NULL,
			.pal = pal,
			.typedb = rc ? rc->typedb : NULL };
		for (int c = 0; c < v->nchildren; c++) {
			render_val_text(sb, &v->children[c], indent + 1, &sub);
		}
		return;
	}

	rz_strbuf_append(sb, " = ");

	/* Overflow indicator: when the read of an inline string ran off
	 * the end of the buffer without finding NUL (e.g. unmapped memory
	 * with io.unalloc=true filling the tail with 0xff), prefix the
	 * value with `ovf ` so the caller knows the displayed body was
	 * truncated. Matches the legacy parser's behaviour. */
	if (v->overflow && (v->type == RZ_PF_ZSTRING || v->type == RZ_PF_STRPTR)) {
		rz_strbuf_append(sb, "ovf ");
	}

	/* GUID */
	if (v->type == RZ_PF_GUID && v->scalars && v->scalars[0].v_raw) {
		/* GUID rendering goes through render_guid which uses raw
		 * sprintf into the strbuf. Wrap the whole thing in color. */
		if (pal && pal->hex_literal) {
			rz_strbuf_append(sb, pal->hex_literal);
		}
		render_guid(sb, v->scalars[0].v_raw, v->guid_layout);
		if (pal && pal->hex_literal && RST) {
			rz_strbuf_append(sb, RST);
		}
		rz_strbuf_append(sb, "\n");
		return;
	}

	/* TLV: emit header line, then recurse into children if any,
	 * otherwise dump raw bytes. */
	if (v->type == RZ_PF_TLV) {
		rz_strbuf_append(sb, "tag=");
		emit_coloredf(sb, pal ? pal->hex_literal : NULL, RST,
			"0x%" PFMT64x, v->tlv_tag);
		rz_strbuf_appendf(sb, " len=%" PFMT64u "\n", v->tlv_length);
		RenderCtx sub = { .field_filter = NULL,
			.pal = pal,
			.typedb = rc ? rc->typedb : NULL };
		if (v->nchildren > 0) {
			for (int c = 0; c < v->nchildren; c++) {
				render_val_text(sb, &v->children[c],
					indent + 1, &sub);
			}
		} else if (v->scalars && v->scalars[0].v_raw && v->raw_len > 0) {
			for (int i = 0; i < indent + 1; i++) {
				rz_strbuf_append(sb, "  ");
			}
			for (int k = 0; k < v->raw_len; k++) {
				rz_strbuf_appendf(sb, "%02x ",
					v->scalars[0].v_raw[k]);
			}
			rz_strbuf_append(sb, "\n");
		}
		return;
	}

	/* Raw / uint128 */
	if (is_raw_type(v->type) && v->scalars && v->scalars[0].v_raw) {
		for (int k = 0; k < v->raw_len; k++) {
			rz_strbuf_appendf(sb, "%02x ",
				v->scalars[0].v_raw[k]);
		}
		rz_strbuf_append(sb, "\n");
		return;
	}

	/* Timestamp */
	if (v->type == RZ_PF_TIMESTAMP) {
		rz_strbuf_appendf(sb, "[%s]",
			rz_pf_timefmt_as_string(v->timefmt));
		emit_coloredf(sb, pal ? pal->endian : NULL, RST,
			"%s", endian_tag(v->endian));
		rz_strbuf_append(sb, " ");
		if (v->count > 1 && v->scalars) {
			rz_strbuf_append(sb, "[ ");
			for (int k = 0; k < v->count; k++) {
				if (k) {
					rz_strbuf_append(sb, ", ");
				}
				rz_pf_timestamp_format_str(sb, v->timefmt,
					&v->scalars[k]);
			}
			rz_strbuf_append(sb, " ]");
		} else if (v->count == 1 && v->scalars) {
			rz_pf_timestamp_format_str(sb, v->timefmt,
				&v->scalars[0]);
		}
		rz_strbuf_append(sb, "\n");
		return;
	}

	/* Encoding annotation for strings */
	if (is_string_type(v->type) && v->encoding != RZ_STRING_ENC_UTF8) {
		rz_strbuf_appendf(sb, "[%s] ",
			rz_str_enc_as_string(v->encoding));
	}

	/* Endian tag for explicitly-endian fields */
	if (v->endian == RZ_PF_ENDIAN_LE || v->endian == RZ_PF_ENDIAN_BE) {
		emit_coloredf(sb, pal ? pal->endian : NULL, RST,
			"%s", endian_tag(v->endian));
		rz_strbuf_append(sb, " ");
	}

	/* Array or scalar. The renderer colours hex literals (0x...)
	 * after the fact by scanning the appended text; this keeps the
	 * scalar_text() helper free of palette plumbing. */
	int mark = (int)rz_strbuf_length(sb);
	if (v->count > 1 && v->scalars) {
		rz_strbuf_append(sb, "[ ");
		for (int k = 0; k < v->count; k++) {
			if (k) {
				rz_strbuf_append(sb, ", ");
			}
			scalar_text(sb, v, k, rc ? rc->typedb : NULL);
		}
		rz_strbuf_append(sb, " ]");
	} else if (v->count == 1 && v->scalars) {
		scalar_text(sb, v, 0, rc ? rc->typedb : NULL);
	}

	/* Colorize 0x... literals in the scalar output. */
	if (pal && pal->hex_literal) {
		char *cur = (char *)rz_strbuf_get(sb);
		int len = (int)rz_strbuf_length(sb);
		if (cur && len > mark) {
			char *tail = strdup(cur + mark);
			if (tail) {
				rz_strbuf_slice(sb, 0, mark);
				const char *p = tail;
				while (*p) {
					if (p[0] == '0' && p[1] == 'x' && isxdigit((ut8)p[2])) {
						const char *end = p + 2;
						while (isxdigit((ut8)*end)) {
							end++;
						}
						char *hx = rz_str_ndup(p, end - p);
						emit_colored(sb, pal->hex_literal, hx, RST);
						free(hx);
						p = end;
					} else {
						rz_strbuf_appendf(sb, "%c", *p);
						p++;
					}
				}
				free(tail);
			}
		}
	}
	rz_strbuf_append(sb, "\n");
}

static char *render_text(const RzPfValue *vals, int count,
	const RenderCtx *rc) {
	RzStrBuf *sb = rz_strbuf_new("");
	for (int i = 0; i < count; i++) {
		render_val_text(sb, &vals[i], 0, rc);
	}
	return rz_strbuf_drain(sb);
}

// Render: quiet (compact) mode
static char *render_quiet(const RzPfValue *vals, int count,
	const RenderCtx *rc) {
	const char *filter = rc ? rc->field_filter : NULL;
	RzStrBuf *sb = rz_strbuf_new("");
	for (int i = 0; i < count; i++) {
		const RzPfValue *v = &vals[i];
		if (v->type == RZ_PF_SKIP) {
			continue;
		}
		if (v->type == RZ_PF_ALIGN) {
			continue;
		}
		if (!field_matches(v, filter)) {
			continue;
		}
		if (v->type == RZ_PF_TIMESTAMP && v->count >= 1 && v->scalars) {
			rz_pf_timestamp_format_str(sb, v->timefmt,
				&v->scalars[0]);
		} else if (v->type == RZ_PF_GUID && v->scalars && v->scalars[0].v_raw) {
			render_guid(sb, v->scalars[0].v_raw, v->guid_layout);
		} else if (v->type == RZ_PF_TLV) {
			rz_strbuf_appendf(sb,
				"0x%" PFMT64x ":%" PFMT64u,
				v->tlv_tag, v->tlv_length);
		} else if (v->count >= 1 && v->scalars) {
			for (int k = 0; k < v->count; k++) {
				if (k) {
					rz_strbuf_append(sb, " ");
				}
				scalar_text(sb, v, k, rc ? rc->typedb : NULL);
			}
		}
		rz_strbuf_append(sb, "\n");
	}
	return rz_strbuf_drain(sb);
}

// Render: JSON mode
static void scalar_json(PJ *j, const RzPfValue *val, int k) {
	const RzPfScalar *s = &val->scalars[k];
	switch (val->type) {
	case RZ_PF_HEX8:
	case RZ_PF_DEC_U8:
	case RZ_PF_OCT8:
	case RZ_PF_BIN8:
		pj_n(j, s->v_u8);
		break;
	case RZ_PF_HEX16:
	case RZ_PF_DEC_U16:
	case RZ_PF_OCT16:
	case RZ_PF_BIN16:
		pj_n(j, s->v_u16);
		break;
	case RZ_PF_HEX32:
	case RZ_PF_DEC_U32:
	case RZ_PF_OCT32:
	case RZ_PF_BIN32:
	case RZ_PF_ENUM:
	case RZ_PF_BITFIELD:
		pj_n(j, s->v_u32);
		break;
	case RZ_PF_HEX64:
	case RZ_PF_DEC_U64:
	case RZ_PF_OCT64:
	case RZ_PF_BIN64:
	case RZ_PF_POINTER:
	case RZ_PF_ULEB128:
		pj_n(j, s->v_u64);
		break;
	case RZ_PF_DEC_S8: pj_N(j, s->v_s8); break;
	case RZ_PF_DEC_S16: pj_N(j, s->v_s16); break;
	case RZ_PF_DEC_S32: pj_N(j, s->v_s32); break;
	case RZ_PF_DEC_S64:
	case RZ_PF_SLEB128:
		pj_N(j, s->v_s64);
		break;
	case RZ_PF_FLOAT16:
	case RZ_PF_FLOAT32:
		pj_d(j, (double)s->v_f32);
		break;
	case RZ_PF_FLOAT64:
		pj_d(j, s->v_f64);
		break;
	case RZ_PF_CHAR: {
		char cs[2] = { (s->v_u8 >= 0x20 && s->v_u8 < 0x7f)
				? (char)s->v_u8
				: '.',
			'\0' };
		pj_s(j, cs);
		break;
	}
	case RZ_PF_ZSTRING:
	case RZ_PF_STRPTR:
		pj_s(j, s->v_str ? s->v_str : "");
		break;
	case RZ_PF_BITS:
		pj_n(j, s->v_u64);
		break;
	default:
		pj_null(j);
		break;
	}
}

static void render_val_json(PJ *j, const RzPfValue *v,
	const char *field_filter) {
	if (v->type == RZ_PF_SKIP) {
		return;
	}
	if (v->type == RZ_PF_ALIGN) {
		return;
	}
	if (!field_matches(v, field_filter)) {
		return;
	}

	pj_o(j);
	if (v->name) {
		pj_ks(j, "name", v->name);
	}
	pj_ks(j, "type", type_repr_name(v->type));

	/* Size */
	if (v->type == RZ_PF_TIMESTAMP) {
		pj_ki(j, "size", rz_pf_timefmt_size(v->timefmt));
	} else {
		int sz = rz_pf_field_size(v->type);
		if (sz > 0) {
			pj_ki(j, "size", sz);
		}
	}

	pj_kn(j, "offset", v->offset);

	/* Endianness metadata (only for explicit LE/BE) */
	if (v->endian == RZ_PF_ENDIAN_LE || v->endian == RZ_PF_ENDIAN_BE) {
		pj_ks(j, "endian", endian_str(v->endian));
	}

	/* String encoding */
	if (is_string_type(v->type)) {
		pj_ks(j, "encoding",
			rz_str_enc_as_string(v->encoding));
	}

	/* Timestamp: dual raw + formatted */
	if (v->type == RZ_PF_TIMESTAMP) {
		pj_ks(j, "timefmt",
			rz_pf_timefmt_as_string(v->timefmt));

		/* Raw */
		pj_k(j, "raw");
		if (v->count > 1) {
			pj_a(j);
			for (int k = 0; k < v->count; k++) {
				const RzPfScalar *s = &v->scalars[k];
				if (rz_pf_timefmt_is_float(v->timefmt)) {
					pj_d(j, s->v_f64);
				} else if (rz_pf_timefmt_size(v->timefmt) == 4) {
					pj_n(j, s->v_u32);
				} else {
					pj_n(j, s->v_u64);
				}
			}
			pj_end(j);
		} else if (v->count == 1) {
			const RzPfScalar *s = &v->scalars[0];
			if (rz_pf_timefmt_is_float(v->timefmt)) {
				pj_d(j, s->v_f64);
			} else if (rz_pf_timefmt_size(v->timefmt) == 4) {
				pj_n(j, s->v_u32);
			} else {
				pj_n(j, s->v_u64);
			}
		}

		/* Formatted */
		pj_k(j, "value");
		if (v->count > 1) {
			pj_a(j);
			for (int k = 0; k < v->count; k++) {
				RzStrBuf *tmp = rz_strbuf_new("");
				rz_pf_timestamp_format_str(tmp, v->timefmt,
					&v->scalars[k]);
				pj_s(j, rz_strbuf_get(tmp));
				rz_strbuf_free(tmp);
			}
			pj_end(j);
		} else if (v->count == 1) {
			RzStrBuf *tmp = rz_strbuf_new("");
			rz_pf_timestamp_format_str(tmp, v->timefmt,
				&v->scalars[0]);
			pj_s(j, rz_strbuf_get(tmp));
			rz_strbuf_free(tmp);
		}
		pj_end(j);
		return;
	}

	if (v->is_pointer) {
		pj_kn(j, "pointer", v->ptr_addr);
		pj_end(j);
		return;
	}

	/* Struct */
	if (v->type == RZ_PF_STRUCT && v->nchildren > 0) {
		if (v->type_name) {
			pj_ks(j, "struct_type", v->type_name);
		}
		pj_k(j, "fields");
		pj_a(j);
		for (int c = 0; c < v->nchildren; c++) {
			render_val_json(j, &v->children[c], NULL);
		}
		pj_end(j);
		pj_end(j);
		return;
	}

	/* GUID */
	if (v->type == RZ_PF_GUID && v->scalars && v->scalars[0].v_raw) {
		RzStrBuf *tmp = rz_strbuf_new("");
		render_guid(tmp, v->scalars[0].v_raw, v->guid_layout);
		pj_ks(j, "value", rz_strbuf_get(tmp));
		rz_strbuf_free(tmp);
		pj_end(j);
		return;
	}

	/* TLV */
	if (v->type == RZ_PF_TLV) {
		pj_kn(j, "tag", v->tlv_tag);
		pj_kn(j, "length", v->tlv_length);
		if (v->nchildren > 0) {
			pj_k(j, "fields");
			pj_a(j);
			for (int c = 0; c < v->nchildren; c++) {
				render_val_json(j, &v->children[c], NULL);
			}
			pj_end(j);
		} else if (v->scalars && v->scalars[0].v_raw) {
			pj_k(j, "value");
			pj_a(j);
			for (int k = 0; k < v->raw_len; k++) {
				pj_n(j, v->scalars[0].v_raw[k]);
			}
			pj_end(j);
		}
		pj_end(j);
		return;
	}

	/* Bitfield with inline named flags */
	if (v->type == RZ_PF_BITFIELD && v->bitflags && v->bitflag_count > 0 && v->count == 1 && v->scalars) {
		ut32 bv = v->scalars[0].v_u32;
		pj_kn(j, "value", bv);
		pj_k(j, "flags");
		pj_a(j);
		for (int i = 0; i < v->bitflag_count; i++) {
			ut32 fv = (ut32)v->bitflags[i].value;
			if (fv && (bv & fv) == fv) {
				pj_s(j, v->bitflags[i].name);
			}
		}
		pj_end(j);
		pj_end(j);
		return;
	}

	/* Raw */
	if (is_raw_type(v->type) && v->scalars && v->scalars[0].v_raw) {
		pj_k(j, "value");
		pj_a(j);
		for (int k = 0; k < v->raw_len; k++) {
			pj_n(j, v->scalars[0].v_raw[k]);
		}
		pj_end(j);
		pj_end(j);
		return;
	}

	/* Scalar / array */
	pj_k(j, "value");
	if (v->count > 1 && v->scalars) {
		pj_a(j);
		for (int k = 0; k < v->count; k++) {
			scalar_json(j, v, k);
		}
		pj_end(j);
	} else if (v->count == 1 && v->scalars) {
		scalar_json(j, v, 0);
	} else {
		pj_null(j);
	}
	pj_end(j);
}

/**
 * \brief Build a JSON document from an array of values.
 *
 * \param vals Array from rz_pf_read(); must not be NULL.
 * \param count Number of entries in \p vals.
 * \param opts Optional render-time parameters; only field_filter is
 *             consulted (palette has no effect on JSON).
 * \return Newly-allocated PJ. Caller frees with pj_free(). Returns
 *         NULL on allocation failure.
 */
RZ_API RZ_OWN PJ *rz_pf_render_json(
	RZ_BORROW const RzPfValue *vals, int count,
	RZ_NULLABLE const RzPfRenderOpts *opts) {
	rz_return_val_if_fail(vals, NULL);
	const char *filter = opts ? opts->field_filter : NULL;
	PJ *j = pj_new();
	if (!j) {
		return NULL;
	}
	pj_a(j);
	for (int i = 0; i < count; i++) {
		render_val_json(j, &vals[i], filter);
	}
	pj_end(j);
	return j;
}

// Render: C struct

static void render_val_cstruct(RzStrBuf *sb, const RzPfValue *v,
	int indent, const char *field_filter) {
	if (v->type == RZ_PF_SKIP) {
		return;
	}
	if (v->type == RZ_PF_ALIGN) {
		return;
	}
	if (!field_matches(v, field_filter)) {
		return;
	}
	const char *pad = "    ";
	for (int i = 0; i < indent; i++) {
		rz_strbuf_append(sb, pad);
	}
	const char *name = v->name ? v->name : "field";

	if (v->type == RZ_PF_STRUCT && v->nchildren > 0) {
		rz_strbuf_appendf(sb, "struct %s {\n",
			v->type_name ? v->type_name : "");
		for (int c = 0; c < v->nchildren; c++) {
			render_val_cstruct(sb, &v->children[c],
				indent + 1, NULL);
		}
		for (int i = 0; i < indent; i++) {
			rz_strbuf_append(sb, pad);
		}
		rz_strbuf_appendf(sb, "} %s;\n", name);
		return;
	}

	const char *ct = (v->type == RZ_PF_TIMESTAMP)
		? rz_pf_timefmt_ctype(v->timefmt)
		: rz_pf_field_ctype(v->type);

	if (v->count > 1) {
		rz_strbuf_appendf(sb, "%s %s[%d];", ct, name, v->count);
	} else {
		rz_strbuf_appendf(sb, "%s %s;", ct, name);
	}

	rz_strbuf_append(sb, " /* ");
	if (v->endian == RZ_PF_ENDIAN_LE || v->endian == RZ_PF_ENDIAN_BE) {
		rz_strbuf_appendf(sb, "%s, ",
			endian_str(v->endian));
	}
	if (v->is_pointer) {
		rz_strbuf_appendf(sb, "*0x%" PFMT64x, v->ptr_addr);
	} else if (v->type == RZ_PF_TIMESTAMP && v->count >= 1 && v->scalars) {
		rz_pf_timestamp_format_str(sb, v->timefmt, &v->scalars[0]);
	} else if (v->count >= 1 && v->scalars && !is_raw_type(v->type)) {
		int lim = RZ_MIN(v->count, 6);
		for (int k = 0; k < lim; k++) {
			if (k) {
				rz_strbuf_append(sb, ", ");
			}
			scalar_text(sb, v, k, NULL);
		}
		if (v->count > 6) {
			rz_strbuf_append(sb, ", ...");
		}
	}
	rz_strbuf_append(sb, " */\n");
}

static char *render_cstruct(const RzPfValue *vals, int count,
	const char *field_filter, const char *label) {
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (label && *label) {
		/* The legacy renderer emitted `struct <name> {` when the
		 * caller invoked `pfc <name>` on a typedb-registered format.
		 * Reproduce that form so consumers that parse `pfc` output
		 * (or just eyeball it) still see the format name. */
		rz_strbuf_appendf(sb, "struct %s {\n", label);
	} else {
		rz_strbuf_append(sb, "struct {\n");
	}
	for (int i = 0; i < count; i++) {
		render_val_cstruct(sb, &vals[i], 1, field_filter);
	}
	rz_strbuf_append(sb, "};\n");
	return rz_strbuf_drain(sb);
}

// Render: dot graph (Graphviz `digraph` record nodes)

/* Map a field type to the single-character glyph the legacy dot
 * renderer emits in the "type" column of each record cell. The
 * glyph is purely cosmetic -- anyone consuming the dot output for
 * layout cares about the structure, not the letter. */
static char dot_type_glyph(RzPfFieldType t) {
	switch (t) {
	case RZ_PF_HEX8: return 'x';
	case RZ_PF_HEX16: return 'w';
	case RZ_PF_HEX32: return 'x';
	case RZ_PF_HEX64: return 'q';
	case RZ_PF_DEC_S8:
	case RZ_PF_DEC_S16:
	case RZ_PF_DEC_S32:
	case RZ_PF_DEC_S64: return 'i';
	case RZ_PF_DEC_U8:
	case RZ_PF_DEC_U16:
	case RZ_PF_DEC_U32:
	case RZ_PF_DEC_U64: return 'd';
	case RZ_PF_OCT8:
	case RZ_PF_OCT16:
	case RZ_PF_OCT32:
	case RZ_PF_OCT64: return 'o';
	case RZ_PF_BIN8:
	case RZ_PF_BIN16:
	case RZ_PF_BIN32:
	case RZ_PF_BIN64: return 'b';
	case RZ_PF_FLOAT16:
	case RZ_PF_FLOAT32: return 'f';
	case RZ_PF_FLOAT64: return 'F';
	case RZ_PF_CHAR: return 'c';
	case RZ_PF_POINTER: return 'p';
	case RZ_PF_UINT128: return 'Q';
	case RZ_PF_HEXDUMP: return 'r';
	case RZ_PF_ULEB128: return 'U';
	case RZ_PF_SLEB128: return 'L';
	case RZ_PF_ZSTRING: return 'z';
	case RZ_PF_STRPTR: return 's';
	case RZ_PF_TIMESTAMP: return 't';
	case RZ_PF_ENUM: return 'E';
	case RZ_PF_BITFIELD: return 'B';
	case RZ_PF_STRUCT: return '?';
	case RZ_PF_GUID: return 'G';
	case RZ_PF_BITS: return ':';
	case RZ_PF_TLV: return 'V';
	case RZ_PF_ALIGN: return '@';
	case RZ_PF_SKIP: return '.';
	}
	return '?';
}

/* Escape a character for dot-record `label="..."` syntax. Characters
 * that need escaping in record fields: " \ | { } < > ; backslash. */
static void dot_emit_escaped(RzStrBuf *sb, const char *s) {
	if (!s) {
		return;
	}
	for (const char *p = s; *p; p++) {
		switch (*p) {
		case '"':
		case '\\':
		case '|':
		case '{':
		case '}':
		case '<':
		case '>':
			rz_strbuf_append(sb, "\\");
			/* fallthrough */
		default:
			rz_strbuf_appendf(sb, "%c", *p);
		}
	}
}

/* Render one cell value (the "value" column) for a field. Used by
 * the column-aligned DOT renderer. */
static void render_dot_value_cell(RzStrBuf *sb, const RzPfValue *v) {
	if (v->is_pointer) {
		rz_strbuf_appendf(sb, "*0x%" PFMT64x, v->ptr_addr);
		return;
	}
	if (v->type == RZ_PF_STRUCT && v->nchildren > 0) {
		rz_strbuf_appendf(sb, "%s",
			v->type_name ? v->type_name : "struct");
		return;
	}
	if (v->type == RZ_PF_BITFIELD && v->bitflags && v->bitflag_count > 0 && v->count == 1 && v->scalars) {
		const char *tn = v->type_name ? v->type_name : "";
		ut32 bv = v->scalars[0].v_u32;
		bool first = true;
		for (int i = 0; i < v->bitflag_count; i++) {
			ut32 fv = (ut32)v->bitflags[i].value;
			if (fv && (bv & fv) == fv) {
				if (!first) {
					rz_strbuf_append(sb, ", ");
				}
				if (*tn) {
					rz_strbuf_appendf(sb, "%s.", tn);
				}
				dot_emit_escaped(sb, v->bitflags[i].name);
				first = false;
			}
		}
		if (first) {
			rz_strbuf_appendf(sb, "0x%x", (unsigned)bv);
		}
		return;
	}
	if (v->type == RZ_PF_ZSTRING && v->scalars && v->scalars[0].v_str) {
		rz_strbuf_append(sb, "\\\"");
		dot_emit_escaped(sb, v->scalars[0].v_str);
		rz_strbuf_append(sb, "\\\"");
		return;
	}
	if (v->type == RZ_PF_GUID && v->scalars && v->scalars[0].v_raw) {
		render_guid(sb, v->scalars[0].v_raw, v->guid_layout);
		return;
	}
	if (v->type == RZ_PF_TIMESTAMP && v->count >= 1 && v->scalars) {
		RzStrBuf *tmp = rz_strbuf_new("");
		rz_pf_timestamp_format_str(tmp, v->timefmt,
			&v->scalars[0]);
		char *s = rz_strbuf_drain(tmp);
		dot_emit_escaped(sb, s);
		free(s);
		return;
	}
	if (v->type == RZ_PF_TLV) {
		rz_strbuf_appendf(sb, "tag=0x%" PFMT64x " len=%" PFMT64u,
			v->tlv_tag, v->tlv_length);
		return;
	}
	if (v->scalars && v->count >= 1) {
		RzStrBuf *tmp = rz_strbuf_new("");
		scalar_text(tmp, v, 0, NULL);
		char *s = rz_strbuf_drain(tmp);
		dot_emit_escaped(sb, s);
		free(s);
	}
}

/* Predicate: a field is rendered in DOT if it's not a skip/align and
 * passes the optional name filter. */
static bool dot_field_visible(const RzPfValue *v, const char *field_filter) {
	if (v->type == RZ_PF_SKIP) {
		return false;
	}
	if (v->type == RZ_PF_ALIGN) {
		return false;
	}
	return field_matches(v, field_filter);
}

static char *render_dot(const RzPfValue *vals, int count,
	const char *graph_label, const char *field_filter) {
	RzStrBuf *sb = rz_strbuf_new(
		"digraph g { graph [ rank=same; rankdir=LR; ];\n"
		"root [ rank=1; shape=record\n"
		"label=\"");
	const char *label = (graph_label && *graph_label)
		? graph_label
		: "root";
	dot_emit_escaped(sb, label);

	/* Count visible top-level fields so we can produce aligned
	 * columns. The DOT record format `{a|b|c}|{d|e|f}` is laid
	 * out by Graphviz as two rows whose cells line up when each
	 * group has the same number of entries. We exploit that to
	 * make a per-column table (offset / type / name / value). */
	int visible = 0;
	for (int i = 0; i < count; i++) {
		if (dot_field_visible(&vals[i], field_filter)) {
			visible++;
		}
	}
	if (visible == 0) {
		rz_strbuf_append(sb, "\"];\n}\n");
		return rz_strbuf_drain(sb);
	}

	/* Row 1: offsets */
	rz_strbuf_append(sb, "|{offset");
	for (int i = 0; i < count; i++) {
		const RzPfValue *v = &vals[i];
		if (!dot_field_visible(v, field_filter)) {
			continue;
		}
		rz_strbuf_appendf(sb, "|0x%" PFMT64x, v->offset);
	}
	rz_strbuf_append(sb, "}");

	/* Row 2: type glyphs */
	rz_strbuf_append(sb, "|{type");
	for (int i = 0; i < count; i++) {
		const RzPfValue *v = &vals[i];
		if (!dot_field_visible(v, field_filter)) {
			continue;
		}
		rz_strbuf_appendf(sb, "|%c", dot_type_glyph(v->type));
	}
	rz_strbuf_append(sb, "}");

	/* Row 3: field names (with port anchors for external edges) */
	rz_strbuf_append(sb, "|{name");
	for (int i = 0; i < count; i++) {
		const RzPfValue *v = &vals[i];
		if (!dot_field_visible(v, field_filter)) {
			continue;
		}
		rz_strbuf_append(sb, "|");
		if (v->name) {
			rz_strbuf_appendf(sb, "<%s>%s", v->name, v->name);
		}
	}
	rz_strbuf_append(sb, "}");

	/* Row 4: decoded values */
	rz_strbuf_append(sb, "|{value");
	for (int i = 0; i < count; i++) {
		const RzPfValue *v = &vals[i];
		if (!dot_field_visible(v, field_filter)) {
			continue;
		}
		rz_strbuf_append(sb, "|");
		render_dot_value_cell(sb, v);
	}
	rz_strbuf_append(sb, "}");

	rz_strbuf_append(sb, "\"];\n}\n");
	return rz_strbuf_drain(sb);
}

// Unified render dispatcher
/**
 * \brief Render an array of values to a string in the given mode.
 *
 * \param vals Array from rz_pf_read(); must not be NULL.
 * \param count Number of entries.
 * \param mode Output mode: TEXT (default), JSON, CSTRUCT, QUIET, DOT.
 *             WRITE mode is handled separately by the bridge.
 * \param opts Optional render-time parameters (field filter, graph
 *             label, palette). NULL = defaults.
 * \return Newly-allocated string. Caller frees. Returns NULL if
 *         allocation fails or \p count is non-positive.
 */
RZ_API RZ_OWN char *rz_pf_render(
	RZ_BORROW const RzPfValue *vals, int count,
	RzPfMode mode, RZ_NULLABLE const RzPfRenderOpts *opts) {
	rz_return_val_if_fail(vals && count > 0, NULL);
	const char *filter = opts ? opts->field_filter : NULL;
	const char *label = opts ? opts->graph_label : NULL;
	const RzPfPalette *pal = opts ? opts->palette : NULL;
	const RzTypeDB *typedb = opts ? opts->typedb : NULL;
	RenderCtx rc = { .field_filter = filter, .pal = pal,
		.typedb = typedb };
	switch (mode) {
	case RZ_PF_MODE_JSON: {
		PJ *j = rz_pf_render_json(vals, count, opts);
		if (!j) {
			return NULL;
		}
		char *s = strdup(pj_string(j));
		pj_free(j);
		return s;
	}
	case RZ_PF_MODE_CSTRUCT:
		return render_cstruct(vals, count, filter, label);
	case RZ_PF_MODE_QUIET:
		return render_quiet(vals, count, &rc);
	case RZ_PF_MODE_DOT:
		return render_dot(vals, count, label, filter);
	case RZ_PF_MODE_TEXT:
	default:
		return render_text(vals, count, &rc);
	}
}

/* Parse a single path component from `cursor` into (name, has_index, index).
 * Returns a pointer past the component (after the trailing `.` if any), or
 * NULL on parse failure. `name` is a newly-allocated string the caller must
 * free. Supports `name`, `name[N]`, and `name[N]` followed by `.subname`.
 */
static const char *pf_path_parse_one(const char *cursor,
	char **out_name, bool *out_has_idx, int *out_idx) {
	if (!cursor || !*cursor) {
		return NULL;
	}
	const char *p = cursor;
	while (*p && *p != '.' && *p != '[') {
		p++;
	}
	if (p == cursor) {
		return NULL;
	}
	*out_name = rz_str_ndup(cursor, p - cursor);
	*out_has_idx = false;
	*out_idx = 0;
	if (*p == '[') {
		const char *digits = p + 1;
		const char *end = strchr(digits, ']');
		if (!end || end == digits) {
			free(*out_name);
			*out_name = NULL;
			return NULL;
		}
		char *tail = NULL;
		long v = strtol(digits, &tail, 10);
		if (tail != end || v < 0) {
			free(*out_name);
			*out_name = NULL;
			return NULL;
		}
		*out_has_idx = true;
		*out_idx = (int)v;
		p = end + 1;
	}
	if (*p == '.') {
		p++;
	}
	return p;
}

/* Look up `name` among `vals[0..count-1]`, returning its index or -1. */
static int pf_find_named(const RzPfValue *vals, int count, const char *name) {
	if (!vals || !name) {
		return -1;
	}
	for (int i = 0; i < count; i++) {
		if (vals[i].name && !strcmp(vals[i].name, name)) {
			return i;
		}
	}
	return -1;
}

/* Walk a dotted/indexed path through a RzPfValue tree.
 *
 * The path syntax mirrors the legacy parser:
 *
 *   foo                - select field `foo` at the current level
 *   foo[3]             - element 3 of the array `foo`
 *   foo.bar            - field `bar` inside the nested struct `foo`
 *   foo[3].bar         - field `bar` inside element 3 of array `foo`
 *   foo[3].bar[0].baz  - arbitrarily deep nesting
 *
 * `path` must be a non-empty filter without leading dot. On success the
 * function populates `*out_vals` (borrowed pointer into the original tree)
 * and `*out_count` (1 for a single field, or the array length when the
 * leaf is an unindexed array). Returns false if any segment fails to
 * resolve.
 *
 * Array-of-struct selection (RzPfValue::nchildren is the flat list of all
 * iterations concatenated): element N spans children
 * [N * fields_per_iter, (N+1) * fields_per_iter). The number of fields
 * per iter is inferred from the actual array count recorded in the
 * parent value: `nchildren / array_count`.
 */
static bool pf_path_navigate(
	RZ_BORROW const RzPfValue *vals, int count,
	const char *path,
	RZ_BORROW const RzPfValue **out_vals, int *out_count,
	/* Used to slice flat children arrays of struct-arrays: we need to
	 * pass the size (in children) of a single iteration so the renderer
	 * shows just that iteration's fields. Zero means "single value". */
	int *out_stride) {
	if (!vals || count <= 0 || RZ_STR_ISEMPTY(path)) {
		return false;
	}
	*out_vals = NULL;
	*out_count = 0;
	*out_stride = 0;

	const RzPfValue *cur_arr = vals;
	int cur_count = count;
	const RzPfValue *last_match = NULL;
	int last_match_stride = 0;
	int last_match_count = 1;
	const char *p = path;

	while (p && *p) {
		char *name = NULL;
		bool has_idx = false;
		int idx = 0;
		const char *next = pf_path_parse_one(p, &name, &has_idx, &idx);
		if (!next || !name) {
			free(name);
			return false;
		}
		int field_idx = pf_find_named(cur_arr, cur_count, name);
		free(name);
		if (field_idx < 0) {
			return false;
		}
		const RzPfValue *match = &cur_arr[field_idx];
		if (has_idx) {
			/* Indexed access into an array. Two layouts:
			 *  - Scalar array: match->count > 1, scalars[idx] is
			 *    the element. We expose it by leaving `match`
			 *    pointing here but recording the index for the
			 *    renderer via stride=-1.
			 *  - Struct array: match->nchildren > 0 with N
			 *    iterations; element idx is children
			 *    [idx*stride .. (idx+1)*stride). */
			if (match->nchildren > 0) {
				/* Struct array: dive into element idx's
				 * children. */
				int iters = (match->count > 0) ? match->count : 1;
				if (iters < 1) {
					iters = 1;
				}
				int stride = match->nchildren / iters;
				if (idx < 0 || idx >= iters || stride <= 0) {
					return false;
				}
				cur_arr = &match->children[idx * stride];
				cur_count = stride;
				last_match = NULL; /* the slice is the match */
				last_match_count = stride;
				last_match_stride = 0;
				if (!*next) {
					/* Path ends at struct-array element:
					 * render the slice. */
					*out_vals = cur_arr;
					*out_count = cur_count;
					*out_stride = 0;
					return true;
				}
			} else if (match->count > 1 && match->scalars) {
				/* Scalar array. Path must end here (you can't
				 * descend further from a scalar). */
				if (*next) {
					return false;
				}
				*out_vals = match;
				*out_count = 1;
				*out_stride = idx + 1; /* encode index+1, 0=whole */
				return true;
			} else {
				return false;
			}
		} else {
			last_match = match;
			last_match_count = 1;
			last_match_stride = 0;
			if (!*next) {
				/* Plain `field` at end: render this single
				 * value. */
				*out_vals = match;
				*out_count = 1;
				*out_stride = 0;
				return true;
			}
			/* Descend into nested struct children. */
			if (match->nchildren <= 0) {
				return false;
			}
			cur_arr = match->children;
			cur_count = match->nchildren;
		}
		p = next;
	}
	if (last_match) {
		*out_vals = last_match;
		*out_count = last_match_count;
		*out_stride = last_match_stride;
		return true;
	}
	if (cur_arr && cur_count > 0) {
		*out_vals = cur_arr;
		*out_count = cur_count;
		*out_stride = 0;
		return true;
	}
	return false;
}

/**
 * \brief One-shot parse + read + render convenience wrapper.
 *
 * \param fmt_str Format string. Must be non-empty.
 * \param buf Input bytes. Must not be NULL.
 * \param buf_len Bytes available in \p buf. Must be positive.
 * \param base_addr Virtual address of \p buf[0] (recorded as the
 *                  field offset in the rendered output).
 * \param ctx Optional context for typedb/endian/ptr resolution.
 * \param mode Output mode (TEXT, JSON, CSTRUCT, QUIET, DOT).
 * \param opts Optional render-time parameters.
 * \return Newly-allocated rendered string, or NULL on error.
 *
 * Equivalent to chaining rz_pf_parse(), rz_pf_read(), rz_pf_render()
 * and the corresponding *_free() calls.
 */
RZ_API RZ_OWN char *rz_pf_format(
	const char *fmt_str,
	const ut8 *buf, int buf_len, ut64 base_addr,
	RZ_BORROW const RzPfCtx *ctx,
	RzPfMode mode, RZ_NULLABLE const RzPfRenderOpts *opts) {
	rz_return_val_if_fail(fmt_str && buf && buf_len > 0, NULL);
	RzPfFormat *fmt = rz_pf_parse(fmt_str);
	if (!fmt) {
		return NULL;
	}
	int count = 0;
	RzPfValue *vals = rz_pf_read(
		fmt, buf, buf_len, base_addr, ctx, &count);
	if (!vals || count < 1) {
		rz_pf_values_free(vals, count);
		rz_pf_format_free(fmt);
		return NULL;
	}
	/* If the caller passed a filter path like "name[3].sub", resolve it
	 * by walking the value tree and rendering only the matched subtree.
	 * Plain `name` paths are left to the existing field_matches() check
	 * in the renderer so its alignment / formatting code stays simple. */
	char *result = NULL;
	const RzPfValue *render_vals = vals;
	int render_count = count;
	bool used_path = false;
	RzPfValue scalar_slice; /* keeps a local copy of a scalar-array
	                         * element so the renderer prints just one
	                         * value without touching the original tree. */
	bool scalar_slice_active = false;
	const char *filter = opts ? opts->field_filter : NULL;
	if (!RZ_STR_ISEMPTY(filter) &&
		(strchr(filter, '[') || strchr(filter, '.'))) {
		const RzPfValue *sub = NULL;
		int sub_count = 0;
		int sub_stride = 0;
		if (pf_path_navigate(vals, count, filter,
			&sub, &sub_count, &sub_stride)) {
			if (sub_stride > 0 && sub && sub->scalars) {
				/* Scalar array element selection. Build a
				 * temporary RzPfValue that views just the
				 * requested element so the renderer prints a
				 * single value, not the whole array. The
				 * pointers in `scalars` are borrowed from the
				 * original tree, which stays alive until the
				 * end of this function. */
				int idx = sub_stride - 1;
				int width = rz_pf_field_size(sub->type);
				if (width <= 0) {
					width = 1;
				}
				memset(&scalar_slice, 0, sizeof(scalar_slice));
				scalar_slice.type = sub->type;
				scalar_slice.endian = sub->endian;
				scalar_slice.name = sub->name;
				scalar_slice.type_name = sub->type_name;
				scalar_slice.encoding = sub->encoding;
				scalar_slice.timefmt = sub->timefmt;
				scalar_slice.offset = sub->offset + idx * width;
				scalar_slice.is_pointer = sub->is_pointer;
				scalar_slice.ptr_addr = sub->ptr_addr;
				scalar_slice.count = 1;
				scalar_slice.scalars = &sub->scalars[idx];
				scalar_slice.raw_len = sub->raw_len;
				scalar_slice.bit_width = sub->bit_width;
				scalar_slice.bit_offset = sub->bit_offset;
				scalar_slice.guid_layout = sub->guid_layout;
				scalar_slice.bitflags = sub->bitflags;
				scalar_slice.bitflag_count = sub->bitflag_count;
				render_vals = &scalar_slice;
				render_count = 1;
				scalar_slice_active = true;
				used_path = true;
			} else {
				render_vals = sub;
				render_count = sub_count;
				used_path = true;
			}
		} else {
			/* Path didn't resolve: render nothing rather than the
			 * whole tree (matching legacy behaviour where an
			 * unknown sub-field produced no output). */
			rz_pf_values_free(vals, count);
			rz_pf_format_free(fmt);
			return strdup("");
		}
	}
	(void)scalar_slice_active;
	RzPfRenderOpts opts_local;
	const RzPfRenderOpts *opts_eff = opts;
	if (used_path && opts) {
		opts_local = *opts;
		opts_local.field_filter = NULL;
		opts_eff = &opts_local;
	}
	/* The format owns the inline-bitflag name strings borrowed by
	 * the values. Keep it alive until after render, otherwise the
	 * bitfield renderer dereferences a freed pointer. */
	result = rz_pf_render(render_vals, render_count, mode, opts_eff);
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	return result;
}

// Legacy bridge

/**
 * \brief Compute the byte size of a parsed pf format.
 *
 * Walks the format once, summing the byte width of every field. Nested
 * struct fields recurse through the typedb. Used by the legacy callers
 * in cmd_print.c / cprint.c to pre-size their read buffer before
 * invoking the formatter; new code can call this directly when it just
 * needs the size without actually reading.
 *
 * Returns 0 if the format is unknown or empty. Variable-length fields
 * (zstrings, hex dumps, LEB128, timestamps with no fixed size) report
 * their *minimum* width, since their actual size depends on input data.
 *
 * \param typedb Type database used to resolve named-format references.
 * \param f Either a named format (resolved via typedb) or a raw pf string.
 * \param mode Unused, kept for ABI compatibility.
 * \param n Unused, kept for ABI compatibility.
 */
/* Recursion-bound for the struct-size computation. Must match the
 * read-path bound (RzPfCtx::max_depth default of 32) since the size
 * walk and the read walk traverse the same typedb graph and should
 * agree on what is considered "too deep". */
#define PF_STRUCT_SIZE_MAX_DEPTH 32

static int pf_struct_size_impl(const RzTypeDB *typedb, const char *f,
	int depth) {
	if (RZ_STR_ISEMPTY(f)) {
		return 0;
	}
	if (depth >= PF_STRUCT_SIZE_MAX_DEPTH) {
		RZ_LOG_WARN("pf: struct-size recursion limit at '%s'\n", f);
		return 0;
	}
	const char *raw = f;
	if (typedb) {
		const char *resolved = rz_pf_resolve_name(typedb, f);
		if (resolved) {
			raw = resolved;
		}
	}
	RzPfFormat *fmt = rz_pf_parse(raw);
	if (!fmt) {
		return 0;
	}

	int total = 0;
	for (int i = 0; i < fmt->nfields; i++) {
		const RzPfField *fld = &fmt->fields[i];
		int cnt = (fld->array_count > 0) ? fld->array_count : 1;
		int sz = 0;

		if (fld->is_pointer) {
			/* Pointer width is target-dependent; assume 8 as a
			 * safe upper bound for sizing. The exact value would
			 * need an RzPfCtx, which struct_size doesn't take. */
			sz = 8;
		} else if (fld->type == RZ_PF_TIMESTAMP) {
			sz = rz_pf_timefmt_size(fld->timefmt);
		} else if (fld->type == RZ_PF_STRUCT && typedb && fld->type_name) {
			sz = pf_struct_size_impl(typedb,
				fld->type_name, depth + 1);
		} else if (fld->type == RZ_PF_UINT128) {
			sz = 16;
		} else {
			sz = rz_pf_field_size(fld->type);
			if (sz < 0) {
				/* Variable-length: count as 0 for the
				 * lower-bound estimate. */
				sz = 0;
			}
			/* Honour the `[N]E`/`[N]B` byte-width override. */
			if ((fld->type == RZ_PF_ENUM || fld->type == RZ_PF_BITFIELD) && fld->bit_width >= 1 && fld->bit_width <= 8) {
				sz = fld->bit_width;
			}
			/* Honour the `[N]z`/`[N]s` fixed-string-length form. */
			if ((fld->type == RZ_PF_ZSTRING || fld->type == RZ_PF_STRPTR) && fld->str_fixed_len > 0) {
				sz = fld->str_fixed_len;
			}
		}

		total += sz * cnt;
	}

	int repeat = fmt->is_union ? 1 : fmt->repeat;
	if (fmt->is_union) {
		/* Union width = max field width, not sum. */
		total = 0;
		for (int i = 0; i < fmt->nfields; i++) {
			const RzPfField *fld = &fmt->fields[i];
			int cnt = (fld->array_count > 0) ? fld->array_count : 1;
			int sz;
			if (fld->is_pointer) {
				sz = 8;
			} else if (fld->type == RZ_PF_TIMESTAMP) {
				sz = rz_pf_timefmt_size(fld->timefmt);
			} else if (fld->type == RZ_PF_STRUCT && typedb && fld->type_name) {
				sz = pf_struct_size_impl(typedb,
					fld->type_name, depth + 1);
			} else if (fld->type == RZ_PF_UINT128) {
				sz = 16;
			} else {
				sz = RZ_MAX(0, rz_pf_field_size(fld->type));
				if ((fld->type == RZ_PF_ENUM || fld->type == RZ_PF_BITFIELD) && fld->bit_width >= 1 && fld->bit_width <= 8) {
					sz = fld->bit_width;
				}
				if ((fld->type == RZ_PF_ZSTRING || fld->type == RZ_PF_STRPTR) && fld->str_fixed_len > 0) {
					sz = fld->str_fixed_len;
				}
			}
			total = RZ_MAX(total, sz * cnt);
		}
	}

	rz_pf_format_free(fmt);
	return total * repeat;
}

RZ_API int rz_type_format_struct_size(const RzTypeDB *typedb,
	const char *f, int mode, int n) {
	(void)mode;
	(void)n;
	return pf_struct_size_impl(typedb, f, 0);
}

/* Transitional shim for the legacy rz_type_format_data() entry point.
 * Callers in librz/core/cprint.c and librz/core/disasm.c are migrated
 * to the new <rz_pf.h> API in the librz/core integration commit;
 * this shim keeps the build link-clean during the interim. */
RZ_API RZ_OWN char *rz_type_format_data(RZ_BORROW RzTypeDB *t, RzPrint *p,
		ut64 seek, const ut8 *b, const int len,
		const char *formatname, int mode,
		const char *setval, char *ofield) {
	(void)p; (void)setval; (void)ofield;
	const char *resolved = rz_pf_resolve_name(t, formatname);
	const char *raw = resolved ? resolved : formatname;
	RzPfCtx ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.typedb = t;
	ctx.max_depth = 32;
	RzPfMode pfmode;
	if (mode & RZ_PRINT_JSON)        { pfmode = RZ_PF_MODE_JSON; }
	else if (mode & RZ_PRINT_STRUCT) { pfmode = RZ_PF_MODE_CSTRUCT; }
	else if (mode & RZ_PRINT_DOT)    { pfmode = RZ_PF_MODE_DOT; }
	else if (mode & RZ_PRINT_QUIET)  { pfmode = RZ_PF_MODE_QUIET; }
	else                              { pfmode = RZ_PF_MODE_TEXT; }
	return rz_pf_format(raw, b, len, seek, &ctx, pfmode, NULL);
}
