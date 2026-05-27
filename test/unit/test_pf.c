// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file test_pf.c
 * \brief Unit tests for the pf format parser, reader, and renderers.
 *
 * Covers the public RZ_API surface of pf_parser.h and pf_parser_time.h:
 * field sizing, ctype mapping, every parse path (sized ints, floats,
 * strings with encodings, timestamps with all wire formats, repeat,
 * union, pointer and array prefixes, struct/enum/bitfield typedb
 * references), the reader pipeline against in-memory buffers, the
 * timestamp decoders and the new DSL extensions.
 *
 * Tests use the minunit harness (test/unit/minunit.h).
 */

#include <rz_util.h>
#include "../../librz/type/pf_parser.h"
#include "../../librz/type/pf_parser_time.h"
#include "minunit.h"

/* --------------------------------------------------------------------
 *  Helper: simple in-memory read callback for rz_pf_read tests
 * -------------------------------------------------------------------- */
typedef struct {
	const ut8 *data;
	int len;
} MemBuf;

static int mem_read_at(void *user, ut64 addr, ut8 *buf, int len) {
	MemBuf *m = (MemBuf *)user;
	if (!m || (int)addr >= m->len) {
		return 0;
	}
	int avail = m->len - (int)addr;
	int n = (len < avail) ? len : avail;
	memcpy(buf, m->data + addr, n);
	return n;
}

/* --------------------------------------------------------------------
 *  1. rz_pf_field_size -- byte sizes for every fixed-size type
 * -------------------------------------------------------------------- */
static bool test_pf_field_size_1byte(void) {
	mu_assert_eq(rz_pf_field_size(RZ_PF_HEX8), 1, "HEX8 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_DEC_S8), 1, "DEC_S8 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_DEC_U8), 1, "DEC_U8 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_OCT8), 1, "OCT8 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_BIN8), 1, "BIN8 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_CHAR), 1, "CHAR size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_SKIP), 1, "SKIP size");
	mu_end;
}

static bool test_pf_field_size_2byte(void) {
	mu_assert_eq(rz_pf_field_size(RZ_PF_HEX16), 2, "HEX16 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_DEC_S16), 2, "DEC_S16 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_DEC_U16), 2, "DEC_U16 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_OCT16), 2, "OCT16 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_BIN16), 2, "BIN16 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_FLOAT16), 2, "FLOAT16 size");
	mu_end;
}

static bool test_pf_field_size_4byte(void) {
	mu_assert_eq(rz_pf_field_size(RZ_PF_HEX32), 4, "HEX32 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_DEC_S32), 4, "DEC_S32 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_DEC_U32), 4, "DEC_U32 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_OCT32), 4, "OCT32 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_BIN32), 4, "BIN32 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_FLOAT32), 4, "FLOAT32 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_ENUM), 4, "ENUM size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_BITFIELD), 4, "BITFIELD size");
	mu_end;
}

static bool test_pf_field_size_8byte(void) {
	mu_assert_eq(rz_pf_field_size(RZ_PF_HEX64), 8, "HEX64 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_DEC_S64), 8, "DEC_S64 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_DEC_U64), 8, "DEC_U64 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_OCT64), 8, "OCT64 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_BIN64), 8, "BIN64 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_FLOAT64), 8, "FLOAT64 size");
	mu_end;
}

static bool test_pf_field_size_special(void) {
	mu_assert_eq(rz_pf_field_size(RZ_PF_UINT128), 16, "UINT128 size");
	mu_assert_eq(rz_pf_field_size(RZ_PF_TIMESTAMP), -1, "TIMESTAMP size is variable");
	mu_assert_eq(rz_pf_field_size(RZ_PF_ZSTRING), -1, "ZSTRING size is variable");
	mu_assert_eq(rz_pf_field_size(RZ_PF_STRPTR), -1, "STRPTR size is variable");
	mu_assert_eq(rz_pf_field_size(RZ_PF_POINTER), -1, "POINTER size is variable");
	mu_assert_eq(rz_pf_field_size(RZ_PF_HEXDUMP), -1, "HEXDUMP size is variable");
	mu_assert_eq(rz_pf_field_size(RZ_PF_ULEB128), -1, "ULEB128 size is variable");
	mu_assert_eq(rz_pf_field_size(RZ_PF_SLEB128), -1, "SLEB128 size is variable");
	mu_end;
}

/* --------------------------------------------------------------------
 *  2. rz_pf_field_ctype -- C type string for each field type
 * -------------------------------------------------------------------- */
static bool test_pf_field_ctype_unsigned(void) {
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_HEX8), "uint8_t", "HEX8 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_DEC_U8), "uint8_t", "DEC_U8 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_OCT8), "uint8_t", "OCT8 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_BIN8), "uint8_t", "BIN8 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_HEX16), "uint16_t", "HEX16 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_DEC_U16), "uint16_t", "DEC_U16 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_HEX32), "uint32_t", "HEX32 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_DEC_U32), "uint32_t", "DEC_U32 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_HEX64), "uint64_t", "HEX64 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_DEC_U64), "uint64_t", "DEC_U64 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_UINT128), "uint128_t", "UINT128 ctype");
	mu_end;
}

static bool test_pf_field_ctype_signed(void) {
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_DEC_S8), "int8_t", "DEC_S8 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_CHAR), "int8_t", "CHAR ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_DEC_S16), "int16_t", "DEC_S16 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_DEC_S32), "int32_t", "DEC_S32 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_DEC_S64), "int64_t", "DEC_S64 ctype");
	mu_end;
}

static bool test_pf_field_ctype_float(void) {
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_FLOAT16), "_Float16", "FLOAT16 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_FLOAT32), "float", "FLOAT32 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_FLOAT64), "double", "FLOAT64 ctype");
	mu_end;
}

static bool test_pf_field_ctype_misc(void) {
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_ZSTRING), "char*", "ZSTRING ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_STRPTR), "char*", "STRPTR ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_POINTER), "void*", "POINTER ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_HEXDUMP), "uint8_t[]", "HEXDUMP ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_ULEB128), "leb128_t", "ULEB128 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_SLEB128), "leb128_t", "SLEB128 ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_ENUM), "enum", "ENUM ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_BITFIELD), "bitfield", "BITFIELD ctype");
	mu_assert_streq(rz_pf_field_ctype(RZ_PF_SKIP), "unknown", "SKIP ctype");
	mu_end;
}

/* --------------------------------------------------------------------
 *  3. rz_pf_enc_null_unit_size -- null-terminator width per encoding
 * -------------------------------------------------------------------- */
static bool test_pf_enc_null_unit_size(void) {
	mu_assert_eq(rz_pf_enc_null_unit_size(RZ_STRING_ENC_UTF8), 1, "UTF8 null unit");
	mu_assert_eq(rz_pf_enc_null_unit_size(RZ_STRING_ENC_8BIT), 1, "8BIT null unit");
	mu_assert_eq(rz_pf_enc_null_unit_size(RZ_STRING_ENC_UTF16LE), 2, "UTF16LE null unit");
	mu_assert_eq(rz_pf_enc_null_unit_size(RZ_STRING_ENC_UTF16BE), 2, "UTF16BE null unit");
	mu_assert_eq(rz_pf_enc_null_unit_size(RZ_STRING_ENC_UTF32LE), 4, "UTF32LE null unit");
	mu_assert_eq(rz_pf_enc_null_unit_size(RZ_STRING_ENC_UTF32BE), 4, "UTF32BE null unit");
	mu_end;
}

/* --------------------------------------------------------------------
 *  4. Timestamp format utilities
 * -------------------------------------------------------------------- */
static bool test_pf_timefmt_from_string(void) {
	mu_assert_eq(rz_pf_timefmt_from_string("unix32"), RZ_PF_TIMEFMT_UNIX32, "unix32");
	mu_assert_eq(rz_pf_timefmt_from_string("unix64"), RZ_PF_TIMEFMT_UNIX64, "unix64");
	mu_assert_eq(rz_pf_timefmt_from_string("unixms"), RZ_PF_TIMEFMT_UNIXMS, "unixms");
	mu_assert_eq(rz_pf_timefmt_from_string("unixus"), RZ_PF_TIMEFMT_UNIXUS, "unixus");
	mu_assert_eq(rz_pf_timefmt_from_string("unixns"), RZ_PF_TIMEFMT_UNIXNS, "unixns");
	mu_assert_eq(rz_pf_timefmt_from_string("filetime"), RZ_PF_TIMEFMT_FILETIME, "filetime");
	mu_assert_eq(rz_pf_timefmt_from_string("ntfs"), RZ_PF_TIMEFMT_FILETIME, "ntfs alias");
	mu_assert_eq(rz_pf_timefmt_from_string("dos"), RZ_PF_TIMEFMT_DOS, "dos");
	mu_assert_eq(rz_pf_timefmt_from_string("hfs"), RZ_PF_TIMEFMT_HFS, "hfs");
	mu_assert_eq(rz_pf_timefmt_from_string("oletime"), RZ_PF_TIMEFMT_OLETIME, "oletime");
	mu_assert_eq(rz_pf_timefmt_from_string("webkit"), RZ_PF_TIMEFMT_WEBKIT, "webkit");
	mu_assert_eq(rz_pf_timefmt_from_string("cocoa"), RZ_PF_TIMEFMT_COCOA, "cocoa");
	mu_end;
}

static bool test_pf_timefmt_from_string_case_insensitive(void) {
	mu_assert_eq(rz_pf_timefmt_from_string("UNIX32"), RZ_PF_TIMEFMT_UNIX32, "UNIX32 upper");
	mu_assert_eq(rz_pf_timefmt_from_string("FileTime"), RZ_PF_TIMEFMT_FILETIME, "FileTime mixed");
	mu_assert_eq(rz_pf_timefmt_from_string("DOS"), RZ_PF_TIMEFMT_DOS, "DOS upper");
	mu_end;
}

static bool test_pf_timefmt_from_string_unknown(void) {
	/* Unknown or empty defaults to UNIX32 */
	mu_assert_eq(rz_pf_timefmt_from_string(""), RZ_PF_TIMEFMT_UNIX32, "empty -> unix32");
	mu_assert_eq(rz_pf_timefmt_from_string(NULL), RZ_PF_TIMEFMT_UNIX32, "NULL -> unix32");
	mu_assert_eq(rz_pf_timefmt_from_string("bogus"), RZ_PF_TIMEFMT_UNIX32, "bogus -> unix32");
	mu_end;
}

static bool test_pf_timefmt_as_string(void) {
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_UNIX32), "unix32", "unix32 str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_UNIX64), "unix64", "unix64 str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_UNIXMS), "unixms", "unixms str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_UNIXUS), "unixus", "unixus str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_UNIXNS), "unixns", "unixns str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_FILETIME), "filetime", "filetime str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_DOS), "dos", "dos str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_HFS), "hfs", "hfs str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_OLETIME), "oletime", "oletime str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_WEBKIT), "webkit", "webkit str");
	mu_assert_streq(rz_pf_timefmt_as_string(RZ_PF_TIMEFMT_COCOA), "cocoa", "cocoa str");
	mu_end;
}

static bool test_pf_timefmt_size(void) {
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_UNIX32), 4, "unix32 4B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_DOS), 4, "dos 4B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_HFS), 4, "hfs 4B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_UNIX64), 8, "unix64 8B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_UNIXMS), 8, "unixms 8B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_UNIXUS), 8, "unixus 8B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_UNIXNS), 8, "unixns 8B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_FILETIME), 8, "filetime 8B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_OLETIME), 8, "oletime 8B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_WEBKIT), 8, "webkit 8B");
	mu_assert_eq(rz_pf_timefmt_size(RZ_PF_TIMEFMT_COCOA), 8, "cocoa 8B");
	mu_end;
}

static bool test_pf_timefmt_is_float(void) {
	mu_assert_true(rz_pf_timefmt_is_float(RZ_PF_TIMEFMT_OLETIME), "oletime is float");
	mu_assert_true(rz_pf_timefmt_is_float(RZ_PF_TIMEFMT_COCOA), "cocoa is float");
	mu_assert_false(rz_pf_timefmt_is_float(RZ_PF_TIMEFMT_UNIX32), "unix32 not float");
	mu_assert_false(rz_pf_timefmt_is_float(RZ_PF_TIMEFMT_UNIX64), "unix64 not float");
	mu_assert_false(rz_pf_timefmt_is_float(RZ_PF_TIMEFMT_FILETIME), "filetime not float");
	mu_assert_false(rz_pf_timefmt_is_float(RZ_PF_TIMEFMT_DOS), "dos not float");
	mu_assert_false(rz_pf_timefmt_is_float(RZ_PF_TIMEFMT_HFS), "hfs not float");
	mu_assert_false(rz_pf_timefmt_is_float(RZ_PF_TIMEFMT_WEBKIT), "webkit not float");
	mu_end;
}

/* --------------------------------------------------------------------
 *  5. rz_pf_parse -- NULL / empty input
 * -------------------------------------------------------------------- */
static bool test_pf_parse_null(void) {
	RzPfFormat *fmt = rz_pf_parse(NULL);
	mu_assert_null(fmt, "NULL input returns NULL");
	/* Empty input returns an empty format (zero fields, zero
	 * diagnostics), not NULL, so callers don't have to special-
	 * case the empty string. See test_pf_parse_empty_input below. */
	fmt = rz_pf_parse("");
	mu_assert_notnull(fmt, "empty input returns empty format, not NULL");
	mu_assert_eq(fmt->nfields, 0, "empty format has zero fields");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  6. Parse: sized hex integers (LE)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_hex_le(void) {
	RzPfFormat *fmt = rz_pf_parse("x1x2x4x8");
	mu_assert_notnull(fmt, "parse hex LE");
	mu_assert_eq(fmt->nfields, 4, "4 hex fields");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX8, "x1 -> HEX8");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "x1 LE");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_HEX16, "x2 -> HEX16");
	mu_assert_eq(fmt->fields[1].endian, RZ_PF_ENDIAN_LE, "x2 LE");
	mu_assert_eq(fmt->fields[2].type, RZ_PF_HEX32, "x4 -> HEX32");
	mu_assert_eq(fmt->fields[2].endian, RZ_PF_ENDIAN_LE, "x4 LE");
	mu_assert_eq(fmt->fields[3].type, RZ_PF_HEX64, "x8 -> HEX64");
	mu_assert_eq(fmt->fields[3].endian, RZ_PF_ENDIAN_LE, "x8 LE");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  7. Parse: sized hex integers (BE)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_hex_be(void) {
	RzPfFormat *fmt = rz_pf_parse("X1X2X4X8");
	mu_assert_notnull(fmt, "parse hex BE");
	mu_assert_eq(fmt->nfields, 4, "4 hex BE fields");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX8, "X1 -> HEX8");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_BE, "X1 BE");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_HEX16, "X2 -> HEX16");
	mu_assert_eq(fmt->fields[1].endian, RZ_PF_ENDIAN_BE, "X2 BE");
	mu_assert_eq(fmt->fields[2].type, RZ_PF_HEX32, "X4 -> HEX32");
	mu_assert_eq(fmt->fields[2].endian, RZ_PF_ENDIAN_BE, "X4 BE");
	mu_assert_eq(fmt->fields[3].type, RZ_PF_HEX64, "X8 -> HEX64");
	mu_assert_eq(fmt->fields[3].endian, RZ_PF_ENDIAN_BE, "X8 BE");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  8. Parse: signed decimal (LE + BE)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_dec_signed(void) {
	RzPfFormat *fmt = rz_pf_parse("d1d2d4d8D1D2D4D8");
	mu_assert_notnull(fmt, "parse signed dec");
	mu_assert_eq(fmt->nfields, 8, "8 signed dec fields");

	mu_assert_eq(fmt->fields[0].type, RZ_PF_DEC_S8, "d1");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "d1 LE");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_DEC_S16, "d2");
	mu_assert_eq(fmt->fields[2].type, RZ_PF_DEC_S32, "d4");
	mu_assert_eq(fmt->fields[3].type, RZ_PF_DEC_S64, "d8");

	mu_assert_eq(fmt->fields[4].type, RZ_PF_DEC_S8, "D1");
	mu_assert_eq(fmt->fields[4].endian, RZ_PF_ENDIAN_BE, "D1 BE");
	mu_assert_eq(fmt->fields[5].type, RZ_PF_DEC_S16, "D2");
	mu_assert_eq(fmt->fields[5].endian, RZ_PF_ENDIAN_BE, "D2 BE");
	mu_assert_eq(fmt->fields[6].type, RZ_PF_DEC_S32, "D4");
	mu_assert_eq(fmt->fields[7].type, RZ_PF_DEC_S64, "D8");

	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  9. Parse: unsigned decimal (LE + BE)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_dec_unsigned(void) {
	RzPfFormat *fmt = rz_pf_parse("u1u2u4u8");
	mu_assert_notnull(fmt, "parse unsigned dec");
	mu_assert_eq(fmt->nfields, 4, "4 unsigned dec fields");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_DEC_U8, "u1");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "u1 LE");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_DEC_U16, "u2");
	mu_assert_eq(fmt->fields[2].type, RZ_PF_DEC_U32, "u4");
	mu_assert_eq(fmt->fields[3].type, RZ_PF_DEC_U64, "u8");
	rz_pf_format_free(fmt);

	/* BE variants */
	fmt = rz_pf_parse("U1U2U4U8");
	mu_assert_notnull(fmt, "parse unsigned dec BE");
	mu_assert_eq(fmt->nfields, 4, "4 unsigned dec BE fields");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_DEC_U8, "U1");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_BE, "U1 BE");
	mu_assert_eq(fmt->fields[1].endian, RZ_PF_ENDIAN_BE, "U2 BE");
	mu_assert_eq(fmt->fields[2].endian, RZ_PF_ENDIAN_BE, "U4 BE");
	mu_assert_eq(fmt->fields[3].endian, RZ_PF_ENDIAN_BE, "U8 BE");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  10. Parse: octal (LE + BE)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_octal(void) {
	RzPfFormat *fmt = rz_pf_parse("o1o2o4o8O1O2O4O8");
	mu_assert_notnull(fmt, "parse octal");
	mu_assert_eq(fmt->nfields, 8, "8 octal fields");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_OCT8, "o1");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "o1 LE");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_OCT16, "o2");
	mu_assert_eq(fmt->fields[2].type, RZ_PF_OCT32, "o4");
	mu_assert_eq(fmt->fields[3].type, RZ_PF_OCT64, "o8");
	mu_assert_eq(fmt->fields[4].type, RZ_PF_OCT8, "O1");
	mu_assert_eq(fmt->fields[4].endian, RZ_PF_ENDIAN_BE, "O1 BE");
	mu_assert_eq(fmt->fields[5].type, RZ_PF_OCT16, "O2");
	mu_assert_eq(fmt->fields[6].type, RZ_PF_OCT32, "O4");
	mu_assert_eq(fmt->fields[7].type, RZ_PF_OCT64, "O8");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  11. Parse: binary representation (LE + BE)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_binary(void) {
	RzPfFormat *fmt = rz_pf_parse("b1b2b4b8B1B2B4B8");
	mu_assert_notnull(fmt, "parse binary");
	mu_assert_eq(fmt->nfields, 8, "8 binary fields");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_BIN8, "b1");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "b1 LE");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_BIN16, "b2");
	mu_assert_eq(fmt->fields[2].type, RZ_PF_BIN32, "b4");
	mu_assert_eq(fmt->fields[3].type, RZ_PF_BIN64, "b8");
	mu_assert_eq(fmt->fields[4].type, RZ_PF_BIN8, "B1");
	mu_assert_eq(fmt->fields[4].endian, RZ_PF_ENDIAN_BE, "B1 BE");
	mu_assert_eq(fmt->fields[5].type, RZ_PF_BIN16, "B2");
	mu_assert_eq(fmt->fields[6].type, RZ_PF_BIN32, "B4");
	mu_assert_eq(fmt->fields[7].type, RZ_PF_BIN64, "B8");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  12. Parse: sized floats (LE + BE)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_float_sized(void) {
	RzPfFormat *fmt = rz_pf_parse("f2f4f8F2F4F8");
	mu_assert_notnull(fmt, "parse sized floats");
	mu_assert_eq(fmt->nfields, 6, "6 float fields");

	mu_assert_eq(fmt->fields[0].type, RZ_PF_FLOAT16, "f2 -> FLOAT16");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "f2 LE");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_FLOAT32, "f4 -> FLOAT32");
	mu_assert_eq(fmt->fields[1].endian, RZ_PF_ENDIAN_LE, "f4 LE");
	mu_assert_eq(fmt->fields[2].type, RZ_PF_FLOAT64, "f8 -> FLOAT64");
	mu_assert_eq(fmt->fields[2].endian, RZ_PF_ENDIAN_LE, "f8 LE");

	mu_assert_eq(fmt->fields[3].type, RZ_PF_FLOAT16, "F2 -> FLOAT16");
	mu_assert_eq(fmt->fields[3].endian, RZ_PF_ENDIAN_BE, "F2 BE");
	mu_assert_eq(fmt->fields[4].type, RZ_PF_FLOAT32, "F4 -> FLOAT32");
	mu_assert_eq(fmt->fields[4].endian, RZ_PF_ENDIAN_BE, "F4 BE");
	mu_assert_eq(fmt->fields[5].type, RZ_PF_FLOAT64, "F8 -> FLOAT64");
	mu_assert_eq(fmt->fields[5].endian, RZ_PF_ENDIAN_BE, "F8 BE");

	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  13. Parse: bare deprecated 'f' and 'F'
 * -------------------------------------------------------------------- */
static bool test_pf_parse_float_bare_deprecated(void) {
	/* Bare 'f' -> FLOAT32 LE (deprecated) */
	RzPfFormat *fmt = rz_pf_parse("f");
	mu_assert_notnull(fmt, "parse bare f");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_FLOAT32, "bare f -> FLOAT32");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "bare f LE");
	rz_pf_format_free(fmt);

	/* Bare 'F' -> FLOAT64 BE (deprecated) */
	fmt = rz_pf_parse("F");
	mu_assert_notnull(fmt, "parse bare F");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_FLOAT64, "bare F -> FLOAT64");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_BE, "bare F BE");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  14. Parse: single-char specifiers (c, p, Q, r, U, L, E, B, ?, .)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_single_char_specifiers(void) {
	RzPfFormat *fmt = rz_pf_parse("cpQrULE.?B");
	mu_assert_notnull(fmt, "parse single-char");
	/* '.' is SKIP and consumes no name, but still a field */
	mu_assert_eq(fmt->nfields, 10, "10 fields");

	mu_assert_eq(fmt->fields[0].type, RZ_PF_CHAR, "c -> CHAR");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_CTX, "c CTX");

	mu_assert_eq(fmt->fields[1].type, RZ_PF_POINTER, "p -> POINTER");
	mu_assert_eq(fmt->fields[1].endian, RZ_PF_ENDIAN_CTX, "p CTX");

	mu_assert_eq(fmt->fields[2].type, RZ_PF_UINT128, "Q -> UINT128");
	mu_assert_eq(fmt->fields[2].endian, RZ_PF_ENDIAN_CTX, "Q CTX");

	mu_assert_eq(fmt->fields[3].type, RZ_PF_HEXDUMP, "r -> HEXDUMP");
	mu_assert_eq(fmt->fields[3].endian, RZ_PF_ENDIAN_CTX, "r CTX");

	mu_assert_eq(fmt->fields[4].type, RZ_PF_ULEB128, "U -> ULEB128");
	mu_assert_eq(fmt->fields[4].endian, RZ_PF_ENDIAN_CTX, "U CTX");

	mu_assert_eq(fmt->fields[5].type, RZ_PF_SLEB128, "L -> SLEB128");
	mu_assert_eq(fmt->fields[5].endian, RZ_PF_ENDIAN_CTX, "L CTX");

	mu_assert_eq(fmt->fields[6].type, RZ_PF_ENUM, "E -> ENUM");
	mu_assert_eq(fmt->fields[6].endian, RZ_PF_ENDIAN_CTX, "E CTX");

	mu_assert_eq(fmt->fields[7].type, RZ_PF_SKIP, ". -> SKIP");
	mu_assert_eq(fmt->fields[7].endian, RZ_PF_ENDIAN_CTX, ". CTX");

	mu_assert_eq(fmt->fields[8].type, RZ_PF_STRUCT, "? -> STRUCT");
	mu_assert_eq(fmt->fields[8].endian, RZ_PF_ENDIAN_CTX, "? CTX");

	mu_assert_eq(fmt->fields[9].type, RZ_PF_BITFIELD, "bare B -> BITFIELD");
	mu_assert_eq(fmt->fields[9].endian, RZ_PF_ENDIAN_CTX, "B CTX");

	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  15. Parse: strings -- z and s (default UTF-8)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_string_default(void) {
	RzPfFormat *fmt = rz_pf_parse("zs");
	mu_assert_notnull(fmt, "parse z s");
	mu_assert_eq(fmt->nfields, 2, "2 string fields");

	mu_assert_eq(fmt->fields[0].type, RZ_PF_ZSTRING, "z -> ZSTRING");
	mu_assert_eq(fmt->fields[0].encoding, RZ_STRING_ENC_UTF8, "z default UTF8");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_CTX, "z CTX");

	mu_assert_eq(fmt->fields[1].type, RZ_PF_STRPTR, "s -> STRPTR");
	mu_assert_eq(fmt->fields[1].encoding, RZ_STRING_ENC_UTF8, "s default UTF8");
	mu_assert_eq(fmt->fields[1].endian, RZ_PF_ENDIAN_CTX, "s CTX");

	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  16. Parse: strings with encoding annotation
 * -------------------------------------------------------------------- */
static bool test_pf_parse_string_encoding(void) {
	RzPfFormat *fmt = rz_pf_parse("z(utf16le)s(utf32be)");
	mu_assert_notnull(fmt, "parse string encodings");
	mu_assert_eq(fmt->nfields, 2, "2 fields");

	mu_assert_eq(fmt->fields[0].type, RZ_PF_ZSTRING, "z(...) -> ZSTRING");
	mu_assert_eq(fmt->fields[0].encoding, RZ_STRING_ENC_UTF16LE, "z(utf16le)");

	mu_assert_eq(fmt->fields[1].type, RZ_PF_STRPTR, "s(...) -> STRPTR");
	mu_assert_eq(fmt->fields[1].encoding, RZ_STRING_ENC_UTF32BE, "s(utf32be)");

	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  17. Parse: deprecated 'Z' -> ZSTRING with UTF16LE
 * -------------------------------------------------------------------- */
static bool test_pf_parse_deprecated_Z(void) {
	RzPfFormat *fmt = rz_pf_parse("Z");
	mu_assert_notnull(fmt, "parse deprecated Z");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_ZSTRING, "Z -> ZSTRING");
	mu_assert_eq(fmt->fields[0].encoding, RZ_STRING_ENC_UTF16LE, "Z -> UTF16LE");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  18. Parse: deprecated 'w' -> HEX16 LE
 * -------------------------------------------------------------------- */
static bool test_pf_parse_deprecated_w(void) {
	RzPfFormat *fmt = rz_pf_parse("w");
	mu_assert_notnull(fmt, "parse deprecated w");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX16, "w -> HEX16");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "w LE");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  19. Parse: timestamps -- t(name) and T(name)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_timestamp_named(void) {
	RzPfFormat *fmt = rz_pf_parse("t(unix32)T(filetime)t(dos)t(hfs)");
	mu_assert_notnull(fmt, "parse named timestamps");
	mu_assert_eq(fmt->nfields, 4, "4 timestamp fields");

	mu_assert_eq(fmt->fields[0].type, RZ_PF_TIMESTAMP, "t(unix32) type");
	mu_assert_eq(fmt->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX32, "t(unix32) fmt");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "t LE");

	mu_assert_eq(fmt->fields[1].type, RZ_PF_TIMESTAMP, "T(filetime) type");
	mu_assert_eq(fmt->fields[1].timefmt, RZ_PF_TIMEFMT_FILETIME, "T(filetime) fmt");
	mu_assert_eq(fmt->fields[1].endian, RZ_PF_ENDIAN_BE, "T BE");

	mu_assert_eq(fmt->fields[2].timefmt, RZ_PF_TIMEFMT_DOS, "t(dos) fmt");
	mu_assert_eq(fmt->fields[3].timefmt, RZ_PF_TIMEFMT_HFS, "t(hfs) fmt");

	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_timestamp_all_formats(void) {
	RzPfFormat *fmt = rz_pf_parse(
		"t(unix32)t(unix64)t(unixms)t(unixus)t(unixns)"
		"t(filetime)t(ntfs)t(dos)t(hfs)t(oletime)t(webkit)t(cocoa)");
	mu_assert_notnull(fmt, "parse all timestamp formats");
	mu_assert_eq(fmt->nfields, 12, "12 timestamp fields");

	mu_assert_eq(fmt->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX32, "unix32");
	mu_assert_eq(fmt->fields[1].timefmt, RZ_PF_TIMEFMT_UNIX64, "unix64");
	mu_assert_eq(fmt->fields[2].timefmt, RZ_PF_TIMEFMT_UNIXMS, "unixms");
	mu_assert_eq(fmt->fields[3].timefmt, RZ_PF_TIMEFMT_UNIXUS, "unixus");
	mu_assert_eq(fmt->fields[4].timefmt, RZ_PF_TIMEFMT_UNIXNS, "unixns");
	mu_assert_eq(fmt->fields[5].timefmt, RZ_PF_TIMEFMT_FILETIME, "filetime");
	mu_assert_eq(fmt->fields[6].timefmt, RZ_PF_TIMEFMT_FILETIME, "ntfs alias");
	mu_assert_eq(fmt->fields[7].timefmt, RZ_PF_TIMEFMT_DOS, "dos");
	mu_assert_eq(fmt->fields[8].timefmt, RZ_PF_TIMEFMT_HFS, "hfs");
	mu_assert_eq(fmt->fields[9].timefmt, RZ_PF_TIMEFMT_OLETIME, "oletime");
	mu_assert_eq(fmt->fields[10].timefmt, RZ_PF_TIMEFMT_WEBKIT, "webkit");
	mu_assert_eq(fmt->fields[11].timefmt, RZ_PF_TIMEFMT_COCOA, "cocoa");

	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  20. Parse: deprecated timestamp forms (t4, t8, bare t/T)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_timestamp_deprecated(void) {
	/* t4 -> unix32 LE */
	RzPfFormat *fmt = rz_pf_parse("t4");
	mu_assert_notnull(fmt, "parse t4");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_TIMESTAMP, "t4 type");
	mu_assert_eq(fmt->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX32, "t4 -> unix32");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "t4 LE");
	rz_pf_format_free(fmt);

	/* t8 -> unix64 LE */
	fmt = rz_pf_parse("t8");
	mu_assert_notnull(fmt, "parse t8");
	mu_assert_eq(fmt->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX64, "t8 -> unix64");
	rz_pf_format_free(fmt);

	/* T4 -> unix32 BE */
	fmt = rz_pf_parse("T4");
	mu_assert_notnull(fmt, "parse T4");
	mu_assert_eq(fmt->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX32, "T4 -> unix32");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_BE, "T4 BE");
	rz_pf_format_free(fmt);

	/* T8 -> unix64 BE */
	fmt = rz_pf_parse("T8");
	mu_assert_notnull(fmt, "parse T8");
	mu_assert_eq(fmt->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX64, "T8 -> unix64");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_BE, "T8 BE");
	rz_pf_format_free(fmt);

	/* bare t -> unix32 LE */
	fmt = rz_pf_parse("t");
	mu_assert_notnull(fmt, "parse bare t");
	mu_assert_eq(fmt->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX32, "bare t -> unix32");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_LE, "bare t LE");
	rz_pf_format_free(fmt);

	/* bare T -> unix32 BE */
	fmt = rz_pf_parse("T");
	mu_assert_notnull(fmt, "parse bare T");
	mu_assert_eq(fmt->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX32, "bare T -> unix32");
	mu_assert_eq(fmt->fields[0].endian, RZ_PF_ENDIAN_BE, "bare T BE");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  21. Parse: repeat count (leading digit)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_repeat_digit(void) {
	RzPfFormat *fmt = rz_pf_parse("5x4");
	mu_assert_notnull(fmt, "parse 5x4");
	mu_assert_eq(fmt->repeat, 5, "repeat = 5");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX32, "x4");
	mu_assert_false(fmt->is_union, "not union");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  22. Parse: repeat count ({N} form)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_repeat_brace(void) {
	RzPfFormat *fmt = rz_pf_parse("{10}x4");
	mu_assert_notnull(fmt, "parse {10}x4");
	mu_assert_eq(fmt->repeat, 10, "repeat = 10");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  23. Parse: default repeat = 1
 * -------------------------------------------------------------------- */
static bool test_pf_parse_repeat_default(void) {
	RzPfFormat *fmt = rz_pf_parse("x4");
	mu_assert_notnull(fmt, "parse x4 no repeat");
	mu_assert_eq(fmt->repeat, 1, "default repeat = 1");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  24. Parse: union flag (leading '0')
 * -------------------------------------------------------------------- */
static bool test_pf_parse_union(void) {
	RzPfFormat *fmt = rz_pf_parse("0x4d4");
	mu_assert_notnull(fmt, "parse union");
	mu_assert_true(fmt->is_union, "is_union set");
	mu_assert_eq(fmt->nfields, 2, "2 fields");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX32, "first field x4");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_DEC_S32, "second field d4");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_no_union(void) {
	RzPfFormat *fmt = rz_pf_parse("x4d4");
	mu_assert_notnull(fmt, "parse no union");
	mu_assert_false(fmt->is_union, "not union");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  25. Parse: pointer prefix (*)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_pointer_prefix(void) {
	RzPfFormat *fmt = rz_pf_parse("*x4x2");
	mu_assert_notnull(fmt, "parse pointer prefix");
	mu_assert_eq(fmt->nfields, 2, "2 fields");
	mu_assert_true(fmt->fields[0].is_pointer, "field[0] is_pointer");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX32, "field[0] HEX32");
	mu_assert_false(fmt->fields[1].is_pointer, "field[1] not pointer");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_HEX16, "field[1] HEX16");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  26. Parse: array prefix [N]
 * -------------------------------------------------------------------- */
static bool test_pf_parse_array_prefix(void) {
	RzPfFormat *fmt = rz_pf_parse("[4]x1[16]u1");
	mu_assert_notnull(fmt, "parse array prefix");
	mu_assert_eq(fmt->nfields, 2, "2 fields");
	mu_assert_eq(fmt->fields[0].array_count, 4, "first array 4");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX8, "first HEX8");
	mu_assert_eq(fmt->fields[1].array_count, 16, "second array 16");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_DEC_U8, "second DEC_U8");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_scalar_no_array(void) {
	RzPfFormat *fmt = rz_pf_parse("x4");
	mu_assert_notnull(fmt, "parse scalar");
	mu_assert_eq(fmt->fields[0].array_count, -1, "scalar array_count = -1");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  27. Parse: combined pointer + array
 * -------------------------------------------------------------------- */
static bool test_pf_parse_pointer_array(void) {
	RzPfFormat *fmt = rz_pf_parse("*[8]x4");
	mu_assert_notnull(fmt, "parse *[8]x4");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_true(fmt->fields[0].is_pointer, "is_pointer");
	mu_assert_eq(fmt->fields[0].array_count, 8, "array 8");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX32, "HEX32");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  28. Parse: field names
 * -------------------------------------------------------------------- */
static bool test_pf_parse_field_names(void) {
	RzPfFormat *fmt = rz_pf_parse("x4d4 magic version");
	mu_assert_notnull(fmt, "parse with names");
	mu_assert_eq(fmt->nfields, 2, "2 fields");
	mu_assert_notnull(fmt->fields[0].name, "field[0] name set");
	mu_assert_streq(fmt->fields[0].name, "magic", "field[0] = magic");
	mu_assert_notnull(fmt->fields[1].name, "field[1] name set");
	mu_assert_streq(fmt->fields[1].name, "version", "field[1] = version");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_skip_no_name(void) {
	/* '.' fields do not consume a name */
	RzPfFormat *fmt = rz_pf_parse("x4.d4 magic value");
	mu_assert_notnull(fmt, "parse skip + names");
	mu_assert_eq(fmt->nfields, 3, "3 fields");
	mu_assert_streq(fmt->fields[0].name, "magic", "magic");
	mu_assert_null(fmt->fields[1].name, "skip has no name");
	mu_assert_streq(fmt->fields[2].name, "value", "value");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  29. Parse: struct/enum/bitfield type_name via annotated name
 * -------------------------------------------------------------------- */
static bool test_pf_parse_struct_type_name(void) {
	RzPfFormat *fmt = rz_pf_parse("? (my_struct)child");
	mu_assert_notnull(fmt, "parse struct type_name");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_STRUCT, "STRUCT");
	mu_assert_notnull(fmt->fields[0].type_name, "type_name set");
	mu_assert_streq(fmt->fields[0].type_name, "my_struct", "type_name");
	mu_assert_notnull(fmt->fields[0].name, "field name set");
	mu_assert_streq(fmt->fields[0].name, "child", "field name");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_enum_type_name(void) {
	RzPfFormat *fmt = rz_pf_parse("E (my_enum)flags");
	mu_assert_notnull(fmt, "parse enum type_name");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_ENUM, "ENUM");
	mu_assert_notnull(fmt->fields[0].type_name, "type_name set");
	mu_assert_streq(fmt->fields[0].type_name, "my_enum", "type_name");
	mu_assert_streq(fmt->fields[0].name, "flags", "field name");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_bitfield_type_name(void) {
	RzPfFormat *fmt = rz_pf_parse("B (my_bits)bits");
	mu_assert_notnull(fmt, "parse bitfield type_name");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_BITFIELD, "BITFIELD");
	mu_assert_streq(fmt->fields[0].type_name, "my_bits", "type_name");
	mu_assert_streq(fmt->fields[0].name, "bits", "field name");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  30. Parse: repeat + union combined
 * -------------------------------------------------------------------- */
static bool test_pf_parse_repeat_union_combined(void) {
	RzPfFormat *fmt = rz_pf_parse("3 0x4d4");
	mu_assert_notnull(fmt, "parse repeat + union");
	mu_assert_eq(fmt->repeat, 3, "repeat = 3");
	mu_assert_true(fmt->is_union, "is_union");
	mu_assert_eq(fmt->nfields, 2, "2 fields");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  31. Parse: whitespace handling
 * -------------------------------------------------------------------- */
static bool test_pf_parse_leading_whitespace(void) {
	RzPfFormat *fmt = rz_pf_parse("   x4");
	mu_assert_notnull(fmt, "leading whitespace");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX32, "HEX32");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  32. Parse: complex mixed format string
 * -------------------------------------------------------------------- */
static bool test_pf_parse_complex_mixed(void) {
	RzPfFormat *fmt = rz_pf_parse(
		"x4d2u8f4.z magic ver size weight name");
	mu_assert_notnull(fmt, "parse complex");
	mu_assert_eq(fmt->nfields, 6, "6 fields (including skip)");

	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX32, "x4");
	mu_assert_streq(fmt->fields[0].name, "magic", "magic");

	mu_assert_eq(fmt->fields[1].type, RZ_PF_DEC_S16, "d2");
	mu_assert_streq(fmt->fields[1].name, "ver", "ver");

	mu_assert_eq(fmt->fields[2].type, RZ_PF_DEC_U64, "u8");
	mu_assert_streq(fmt->fields[2].name, "size", "size");

	mu_assert_eq(fmt->fields[3].type, RZ_PF_FLOAT32, "f4");
	mu_assert_streq(fmt->fields[3].name, "weight", "weight");

	/* Skip fields do not consume a name from the name list. */
	mu_assert_eq(fmt->fields[4].type, RZ_PF_SKIP, "skip");
	mu_assert_null(fmt->fields[4].name, "skip no name");

	mu_assert_eq(fmt->fields[5].type, RZ_PF_ZSTRING, "z");
	mu_assert_streq(fmt->fields[5].name, "name", "name");

	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  33. Parse: deprecated bare 'X' (hexdump)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_deprecated_bare_X(void) {
	RzPfFormat *fmt = rz_pf_parse("X");
	mu_assert_notnull(fmt, "parse bare X");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEXDUMP, "bare X -> HEXDUMP");
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  34. rz_pf_read: unsigned 8-bit hex
 * -------------------------------------------------------------------- */
static bool test_pf_read_hex8(void) {
	RzPfFormat *fmt = rz_pf_parse("x1 val");
	mu_assert_notnull(fmt, "parse x1");

	const ut8 buf[] = { 0xAB };
	RzPfCtx *ctx = rz_pf_ctx_new();
	mu_assert_notnull(ctx, "ctx");
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0x1000, ctx, &count);
	mu_assert_notnull(vals, "read x1");
	mu_assert_eq(count, 1, "1 value");
	mu_assert_eq(vals[0].type, RZ_PF_HEX8, "type HEX8");
	mu_assert_eq(vals[0].count, 1, "scalar count");
	mu_assert_eq(vals[0].scalars[0].v_u8, 0xAB, "value 0xAB");
	mu_assert_eq(vals[0].offset, 0x1000, "offset");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  35. rz_pf_read: 16-bit LE / BE hex
 * -------------------------------------------------------------------- */
static bool test_pf_read_hex16_le(void) {
	RzPfFormat *fmt = rz_pf_parse("x2 val");
	mu_assert_notnull(fmt, "parse x2");

	const ut8 buf[] = { 0x34, 0x12 }; /* LE -> 0x1234 */
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read x2 LE");
	mu_assert_eq(vals[0].scalars[0].v_u16, 0x1234, "LE 0x1234");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

static bool test_pf_read_hex16_be(void) {
	RzPfFormat *fmt = rz_pf_parse("X2 val");
	mu_assert_notnull(fmt, "parse X2");

	const ut8 buf[] = { 0x12, 0x34 }; /* BE -> 0x1234 */
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read X2 BE");
	mu_assert_eq(vals[0].scalars[0].v_u16, 0x1234, "BE 0x1234");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  36. rz_pf_read: 32-bit LE hex
 * -------------------------------------------------------------------- */
static bool test_pf_read_hex32_le(void) {
	RzPfFormat *fmt = rz_pf_parse("x4 val");
	mu_assert_notnull(fmt, "parse x4");

	const ut8 buf[] = { 0x78, 0x56, 0x34, 0x12 }; /* LE -> 0x12345678 */
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read x4");
	mu_assert_eq(vals[0].scalars[0].v_u32, 0x12345678, "LE 0x12345678");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  37. rz_pf_read: 64-bit LE hex
 * -------------------------------------------------------------------- */
static bool test_pf_read_hex64_le(void) {
	RzPfFormat *fmt = rz_pf_parse("x8 val");
	mu_assert_notnull(fmt, "parse x8");

	const ut8 buf[] = {
		0xEF, 0xCD, 0xAB, 0x90,
		0x78, 0x56, 0x34, 0x12
	}; /* LE -> 0x1234567890ABCDEF */
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 64, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read x8");
	mu_assert_eq(vals[0].scalars[0].v_u64, 0x1234567890ABCDEFULL, "LE 64-bit");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  38. rz_pf_read: signed 32-bit LE (negative value)
 * -------------------------------------------------------------------- */
static bool test_pf_read_signed32_le(void) {
	RzPfFormat *fmt = rz_pf_parse("d4 val");
	mu_assert_notnull(fmt, "parse d4");

	/* -1 in LE 32-bit = 0xFFFFFFFF */
	const ut8 buf[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read d4");
	mu_assert_eq(vals[0].scalars[0].v_s32, -1, "signed -1");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  39. rz_pf_read: unsigned 32-bit LE
 * -------------------------------------------------------------------- */
static bool test_pf_read_unsigned32_le(void) {
	RzPfFormat *fmt = rz_pf_parse("u4 val");
	mu_assert_notnull(fmt, "parse u4");

	/* 0x80000001 in LE */
	const ut8 buf[] = { 0x01, 0x00, 0x00, 0x80 };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read u4");
	mu_assert_eq(vals[0].scalars[0].v_u32, 0x80000001U, "unsigned 0x80000001");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  40. rz_pf_read: float32 LE
 * -------------------------------------------------------------------- */
static bool test_pf_read_float32_le(void) {
	RzPfFormat *fmt = rz_pf_parse("f4 val");
	mu_assert_notnull(fmt, "parse f4");

	/* IEEE 754 LE representation of 3.14f:
	   3.14f = 0x4048F5C3 -> bytes C3 F5 48 40 */
	const ut8 buf[] = { 0xC3, 0xF5, 0x48, 0x40 };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read f4");
	/* Allow small epsilon for floating point comparison */
	float diff = vals[0].scalars[0].v_f32 - 3.14f;
	mu_assert_true(diff > -0.001f && diff < 0.001f, "float ~3.14");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  41. rz_pf_read: float64 LE
 * -------------------------------------------------------------------- */
static bool test_pf_read_float64_le(void) {
	RzPfFormat *fmt = rz_pf_parse("f8 val");
	mu_assert_notnull(fmt, "parse f8");

	/* IEEE 754 LE representation of 3.14:
	   3.14 = 0x40091EB851EB851F
	   bytes: 1F 85 EB 51 B8 1E 09 40 */
	const ut8 buf[] = { 0x1F, 0x85, 0xEB, 0x51, 0xB8, 0x1E, 0x09, 0x40 };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 64, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read f8");
	double diff = vals[0].scalars[0].v_f64 - 3.14;
	mu_assert_true(diff > -0.0001 && diff < 0.0001, "double ~3.14");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  42. rz_pf_read: char
 * -------------------------------------------------------------------- */
static bool test_pf_read_char(void) {
	RzPfFormat *fmt = rz_pf_parse("c val");
	mu_assert_notnull(fmt, "parse c");

	const ut8 buf[] = { 'A' };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read char");
	mu_assert_eq(vals[0].scalars[0].v_u8, 'A', "char A");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  43. rz_pf_read: multiple fields (offset tracking)
 * -------------------------------------------------------------------- */
static bool test_pf_read_multi_field_offsets(void) {
	RzPfFormat *fmt = rz_pf_parse("x1x2x4 a b c");
	mu_assert_notnull(fmt, "parse multi");

	const ut8 buf[] = {
		0xAA, /* x1: offset 0 */
		0xBB, 0xCC, /* x2: offset 1 */
		0xDD, 0xEE, 0xFF, 0x11 /* x4: offset 3 */
	};
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0x100, ctx, &count);
	mu_assert_notnull(vals, "read multi");
	mu_assert_eq(count, 3, "3 values");

	mu_assert_eq(vals[0].offset, 0x100, "offset[0]");
	mu_assert_eq(vals[0].scalars[0].v_u8, 0xAA, "val[0]");

	mu_assert_eq(vals[1].offset, 0x101, "offset[1]");
	mu_assert_eq(vals[1].scalars[0].v_u16, 0xCCBB, "val[1] LE");

	mu_assert_eq(vals[2].offset, 0x103, "offset[2]");
	mu_assert_eq(vals[2].scalars[0].v_u32, 0x11FFEEDD, "val[2] LE");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  44. rz_pf_read: skip field
 * -------------------------------------------------------------------- */
static bool test_pf_read_skip(void) {
	RzPfFormat *fmt = rz_pf_parse("x1.x1 a b");
	mu_assert_notnull(fmt, "parse skip");

	const ut8 buf[] = { 0x11, 0xFF, 0x22 };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read skip");
	/* The skip field is present but offset advances by 1 */
	/* Check that last field read the byte after the skipped one */
	bool found_0x22 = false;
	for (int i = 0; i < count; i++) {
		if (vals[i].type == RZ_PF_HEX8 && vals[i].offset == 2) {
			mu_assert_eq(vals[i].scalars[0].v_u8, 0x22, "after skip = 0x22");
			found_0x22 = true;
		}
	}
	mu_assert_true(found_0x22, "found value after skip");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  45. rz_pf_read: array of u8
 * -------------------------------------------------------------------- */
static bool test_pf_read_array(void) {
	RzPfFormat *fmt = rz_pf_parse("[4]x1 arr");
	mu_assert_notnull(fmt, "parse array");

	const ut8 buf[] = { 0x0A, 0x0B, 0x0C, 0x0D };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read array");
	mu_assert_eq(count, 1, "1 value (array)");
	mu_assert_eq(vals[0].count, 4, "4 elements");
	mu_assert_eq(vals[0].scalars[0].v_u8, 0x0A, "elem[0]");
	mu_assert_eq(vals[0].scalars[1].v_u8, 0x0B, "elem[1]");
	mu_assert_eq(vals[0].scalars[2].v_u8, 0x0C, "elem[2]");
	mu_assert_eq(vals[0].scalars[3].v_u8, 0x0D, "elem[3]");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  46. rz_pf_read: buffer too short
 * -------------------------------------------------------------------- */
static bool test_pf_read_buffer_too_short(void) {
	RzPfFormat *fmt = rz_pf_parse("x4 val");
	mu_assert_notnull(fmt, "parse x4 for short buf");

	const ut8 buf[] = { 0x01, 0x02 }; /* only 2 bytes, need 4 */
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	/* Reader returns a value slot but does not read past the end:
	 * the scalar stays zero-initialised. Caller can inspect names and
	 * see the value is unset. */
	mu_assert_notnull(vals, "vals returned");
	mu_assert_eq(count, 1, "one slot for the named field");
	mu_assert_eq(vals[0].scalars[0].v_u32, 0, "no bytes read, zero value");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  47. rz_pf_read: timestamp unix32 LE
 * -------------------------------------------------------------------- */
static bool test_pf_read_timestamp_unix32(void) {
	RzPfFormat *fmt = rz_pf_parse("t(unix32) ts");
	mu_assert_notnull(fmt, "parse t(unix32)");

	/* 1700000000 = 0x65571A80 -> LE: 80 1A 57 65 */
	const ut8 buf[] = { 0x80, 0x1A, 0x57, 0x65 };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read unix32 ts");
	mu_assert_eq(count, 1, "1 value");
	mu_assert_eq(vals[0].type, RZ_PF_TIMESTAMP, "TIMESTAMP type");
	mu_assert_eq(vals[0].timefmt, RZ_PF_TIMEFMT_UNIX32, "unix32 fmt");
	mu_assert_eq(vals[0].scalars[0].v_u32, 0x65571A80U, "raw value");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  48. rz_pf_read: z-string (null terminated UTF-8)
 * -------------------------------------------------------------------- */
static bool test_pf_read_zstring(void) {
	RzPfFormat *fmt = rz_pf_parse("z name");
	mu_assert_notnull(fmt, "parse z");

	const ut8 buf[] = { 'H', 'e', 'l', 'l', 'o', '\0', 0xFF };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read zstring");
	mu_assert_eq(count, 1, "1 value");
	mu_assert_eq(vals[0].type, RZ_PF_ZSTRING, "ZSTRING type");
	mu_assert_notnull(vals[0].scalars[0].v_str, "string not null");
	mu_assert_streq(vals[0].scalars[0].v_str, "Hello", "string = Hello");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  49. rz_pf_timestamp_to_tm: unix32
 * -------------------------------------------------------------------- */
static bool test_pf_timestamp_to_tm_unix32(void) {
	RzPfScalar raw = { 0 };
	raw.v_u32 = 0; /* epoch: 1970-01-01 00:00:00 UTC */
	struct tm tm_out;
	int subsec = -1;
	bool ok = rz_pf_timestamp_to_tm(RZ_PF_TIMEFMT_UNIX32,
		&raw, &tm_out, &subsec);
	mu_assert_true(ok, "unix32 epoch conversion");
	mu_assert_eq(tm_out.tm_year, 70, "1970");
	mu_assert_eq(tm_out.tm_mon, 0, "January");
	mu_assert_eq(tm_out.tm_mday, 1, "1st");
	mu_assert_eq(tm_out.tm_hour, 0, "00h");
	mu_assert_eq(tm_out.tm_min, 0, "00m");
	mu_assert_eq(tm_out.tm_sec, 0, "00s");
	mu_assert_eq(subsec, 0, "no subsec");
	mu_end;
}

/* --------------------------------------------------------------------
 *  50. rz_pf_timestamp_to_tm: unixms (with sub-second)
 * -------------------------------------------------------------------- */
static bool test_pf_timestamp_to_tm_unixms(void) {
	RzPfScalar raw = { 0 };
	raw.v_u64 = 1000500; /* 1000 seconds + 500 ms */
	struct tm tm_out;
	int subsec = -1;
	bool ok = rz_pf_timestamp_to_tm(RZ_PF_TIMEFMT_UNIXMS,
		&raw, &tm_out, &subsec);
	mu_assert_true(ok, "unixms conversion");
	/* 1000 seconds from epoch = 00:16:40 */
	mu_assert_eq(tm_out.tm_min, 16, "16 min");
	mu_assert_eq(tm_out.tm_sec, 40, "40 sec");
	mu_assert_eq(subsec, 500000000, "500ms in ns");
	mu_end;
}

/* --------------------------------------------------------------------
 *  51. rz_pf_format_free: NULL safety
 * -------------------------------------------------------------------- */
static bool test_pf_format_free_null(void) {
	/* Should not crash */
	rz_pf_format_free(NULL);
	mu_end;
}

/* --------------------------------------------------------------------
 *  52. rz_pf_values_free: NULL safety
 * -------------------------------------------------------------------- */
static bool test_pf_values_free_null(void) {
	/* Should not crash */
	rz_pf_values_free(NULL, 0);
	rz_pf_values_free(NULL, 5);
	mu_end;
}

/* --------------------------------------------------------------------
 *  53. rz_pf_ctx_new / free: lifecycle
 * -------------------------------------------------------------------- */
static bool test_pf_ctx_lifecycle(void) {
	RzPfCtx *ctx = rz_pf_ctx_new();
	mu_assert_notnull(ctx, "ctx alloc");
	rz_pf_ctx_setup(ctx, NULL, true, 64, NULL, NULL);
	mu_assert_true(ctx->big_endian, "big_endian set");
	mu_assert_eq(ctx->bits, 64, "bits = 64");
	rz_pf_ctx_free(ctx);

	/* NULL free should not crash */
	rz_pf_ctx_free(NULL);
	mu_end;
}

/* --------------------------------------------------------------------
 *  54. Parse: many fields (realloc path, >16 fields)
 * -------------------------------------------------------------------- */
static bool test_pf_parse_many_fields(void) {
	/* 20 x1 fields to trigger realloc beyond initial cap=16 */
	RzPfFormat *fmt = rz_pf_parse("x1x1x1x1x1x1x1x1x1x1x1x1x1x1x1x1x1x1x1x1");
	mu_assert_notnull(fmt, "parse 20 fields");
	mu_assert_eq(fmt->nfields, 20, "20 fields");
	for (int i = 0; i < 20; i++) {
		mu_assert_eq(fmt->fields[i].type, RZ_PF_HEX8, "all HEX8");
	}
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------------------------------------------------------------------
 *  55. rz_pf_read: union mode (all fields at offset 0)
 * -------------------------------------------------------------------- */
static bool test_pf_read_union(void) {
	RzPfFormat *fmt = rz_pf_parse("0x4d4 hex_val dec_val");
	mu_assert_notnull(fmt, "parse union");
	mu_assert_true(fmt->is_union, "is_union");

	const ut8 buf[] = { 0x01, 0x00, 0x00, 0x00 };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0x200, ctx, &count);
	mu_assert_notnull(vals, "read union");
	mu_assert_eq(count, 2, "2 values");
	/* Both fields should share offset 0x200 in union mode */
	mu_assert_eq(vals[0].offset, 0x200, "union offset[0]");
	mu_assert_eq(vals[1].offset, 0x200, "union offset[1]");
	mu_assert_eq(vals[0].scalars[0].v_u32, 1, "hex val");
	mu_assert_eq(vals[1].scalars[0].v_s32, 1, "dec val");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  56. rz_pf_read: BE 32-bit integer via X4
 * -------------------------------------------------------------------- */
static bool test_pf_read_hex32_be(void) {
	RzPfFormat *fmt = rz_pf_parse("X4 val");
	mu_assert_notnull(fmt, "parse X4");

	const ut8 buf[] = { 0x12, 0x34, 0x56, 0x78 }; /* BE -> 0x12345678 */
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read X4 BE");
	mu_assert_eq(vals[0].scalars[0].v_u32, 0x12345678U, "BE 0x12345678");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  57. rz_pf_read: signed 8-bit
 * -------------------------------------------------------------------- */
static bool test_pf_read_signed8(void) {
	RzPfFormat *fmt = rz_pf_parse("d1 val");
	mu_assert_notnull(fmt, "parse d1");

	const ut8 buf[] = { 0x80 }; /* -128 as signed */
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read d1");
	mu_assert_eq(vals[0].scalars[0].v_s8, -128, "signed -128");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  58. rz_pf_read: signed 16-bit LE
 * -------------------------------------------------------------------- */
static bool test_pf_read_signed16_le(void) {
	RzPfFormat *fmt = rz_pf_parse("d2 val");
	mu_assert_notnull(fmt, "parse d2");

	/* -256 = 0xFF00 -> LE: 00 FF */
	const ut8 buf[] = { 0x00, 0xFF };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read d2");
	mu_assert_eq(vals[0].scalars[0].v_s16, -256, "signed -256");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  59. rz_pf_read: signed 64-bit LE
 * -------------------------------------------------------------------- */
static bool test_pf_read_signed64_le(void) {
	RzPfFormat *fmt = rz_pf_parse("d8 val");
	mu_assert_notnull(fmt, "parse d8");

	/* -1 as 64-bit LE */
	const ut8 buf[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 64, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read d8");
	mu_assert_eq(vals[0].scalars[0].v_s64, -1LL, "signed -1 64-bit");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* --------------------------------------------------------------------
 *  60. rz_pf_read: array of x4 LE
 * -------------------------------------------------------------------- */
static bool test_pf_read_array_x4(void) {
	RzPfFormat *fmt = rz_pf_parse("[3]x4 items");
	mu_assert_notnull(fmt, "parse [3]x4");

	const ut8 buf[] = {
		0x01,
		0x00,
		0x00,
		0x00,
		0x02,
		0x00,
		0x00,
		0x00,
		0x03,
		0x00,
		0x00,
		0x00,
	};
	RzPfCtx *ctx = rz_pf_ctx_new();
	rz_pf_ctx_setup(ctx, NULL, false, 32, NULL, NULL);

	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, ctx, &count);
	mu_assert_notnull(vals, "read [3]x4");
	mu_assert_eq(count, 1, "1 array value");
	mu_assert_eq(vals[0].count, 3, "3 elements");
	mu_assert_eq(vals[0].scalars[0].v_u32, 1, "elem[0] = 1");
	mu_assert_eq(vals[0].scalars[1].v_u32, 2, "elem[1] = 2");
	mu_assert_eq(vals[0].scalars[2].v_u32, 3, "elem[2] = 3");

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

/* DSL extensions: parse-side and read-side coverage. */

static bool test_pf_parse_align(void) {
	RzPfFormat *fmt = rz_pf_parse("x1@4x4 a b");
	mu_assert_notnull(fmt, "parse @4");
	mu_assert_eq(fmt->nfields, 3, "3 fields incl align");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_HEX8, "x1");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_ALIGN, "@");
	mu_assert_eq(fmt->fields[1].align_to, 4, "align to 4");
	mu_assert_eq(fmt->fields[2].type, RZ_PF_HEX32, "x4");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_align(void) {
	/* x1 takes 1 byte, @4 pads 3, x4 reads next 4 bytes. */
	RzPfFormat *fmt = rz_pf_parse("x1@4x4 a b");
	const ut8 buf[] = {
		0xAA,
		0xFF,
		0xFF,
		0xFF, /* padding bytes are skipped */
		0x44,
		0x33,
		0x22,
		0x11,
	};
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read align");
	mu_assert_eq(count, 3, "3 values incl align");
	mu_assert_eq(vals[0].scalars[0].v_u8, 0xAA, "first byte");
	mu_assert_eq(vals[2].scalars[0].v_u32, 0x11223344u, "post-align u32 LE");
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_bits(void) {
	RzPfFormat *fmt = rz_pf_parse(":3:5x1 mode rest tail");
	mu_assert_notnull(fmt, "parse :3:5");
	mu_assert_eq(fmt->nfields, 3, "3 fields");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_BITS, "first bits");
	mu_assert_eq(fmt->fields[0].bit_width, 3, "3 bits");
	mu_assert_eq(fmt->fields[1].type, RZ_PF_BITS, "second bits");
	mu_assert_eq(fmt->fields[1].bit_width, 5, "5 bits");
	mu_assert_eq(fmt->fields[2].type, RZ_PF_HEX8, "tail x1");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_bits_msb(void) {
	/* Byte 0xA5 = 0b10100101. MSB-first :4 -> 0xA, :4 -> 0x5. */
	RzPfFormat *fmt = rz_pf_parse(":4:4 hi lo");
	const ut8 buf[] = { 0xA5, 0x00 };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read bits");
	mu_assert_eq(count, 2, "2 values");
	mu_assert_eq(vals[0].scalars[0].v_u64, 0xA, "high nibble");
	mu_assert_eq(vals[1].scalars[0].v_u64, 0x5, "low nibble");
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_bits_lsb(void) {
	/* Byte 0xA5. LSB-first :4< -> 0x5, :4< -> 0xA. */
	RzPfFormat *fmt = rz_pf_parse(":4<:4< lo hi");
	const ut8 buf[] = { 0xA5, 0x00 };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read bits LSB");
	mu_assert_eq(vals[0].scalars[0].v_u64, 0x5, "LSB nibble");
	mu_assert_eq(vals[1].scalars[0].v_u64, 0xA, "next nibble");
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

/* --------- bitvector (v(N)) tests ----------------------------------- */

static bool test_pf_parse_bitvec_basic(void) {
	RzPfFormat *fmt = rz_pf_parse("v(8) bits");
	mu_assert_notnull(fmt, "parse v(8)");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_BITVEC, "BITVEC");
	mu_assert_eq(fmt->fields[0].bit_width, 8, "8-bit");
	mu_assert_eq(fmt->fields[0].bit_order, RZ_PF_BITORDER_MSB,
		"default MSB");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_bitvec_partial_byte(void) {
	/* v(12) reads 2 bytes but only 12 bits are exposed. */
	RzPfFormat *fmt = rz_pf_parse("v(12) bits");
	mu_assert_notnull(fmt, "parse v(12)");
	mu_assert_eq(fmt->fields[0].bit_width, 12, "12-bit width");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_bitvec_lsb_msb_kw(void) {
	RzPfFormat *fmt = rz_pf_parse("v(16,lsb) bits");
	mu_assert_notnull(fmt, "parse v(16,lsb)");
	mu_assert_eq(fmt->fields[0].bit_order, RZ_PF_BITORDER_LSB,
		"LSB order");
	rz_pf_format_free(fmt);

	fmt = rz_pf_parse("v(16,msb) bits");
	mu_assert_notnull(fmt, "parse v(16,msb)");
	mu_assert_eq(fmt->fields[0].bit_order, RZ_PF_BITORDER_MSB,
		"MSB order");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_bitvec_clamp_low(void) {
	/* v(0) -> clamped to 1 with a warning. */
	RzPfFormat *fmt = rz_pf_parse("v(0) bits");
	mu_assert_notnull(fmt, "parse v(0)");
	mu_assert_eq(fmt->fields[0].bit_width, 1, "clamped low to 1");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_bitvec_clamp_high(void) {
	/* v(99999) -> clamped to 4096 with a warning. */
	RzPfFormat *fmt = rz_pf_parse("v(99999) bits");
	mu_assert_notnull(fmt, "parse v(99999)");
	mu_assert_eq(fmt->fields[0].bit_width, 4096, "clamped high to 4096");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_bitvec_missing_paren(void) {
	/* `v` without `(` is a syntax error; parser logs and skips. */
	RzPfFormat *fmt = rz_pf_parse("v bits");
	mu_assert_notnull(fmt, "parse v (degraded)");
	mu_assert(fmt->nerrors > 0, "diagnostic recorded");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_bitvec_msb(void) {
	/* Byte 0xAB = 0b10101011, MSB-first => bits 1,0,1,0,1,0,1,1 */
	RzPfFormat *fmt = rz_pf_parse("v(8) bits");
	const ut8 buf[] = { 0xAB, 0x00 };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read v(8) MSB");
	mu_assert_eq(count, 1, "1 value");
	mu_assert_eq(vals[0].type, RZ_PF_BITVEC, "BITVEC type");
	mu_assert_eq(vals[0].count, 8, "8 bit-scalars");
	mu_assert_eq(vals[0].bit_width, 8, "bit_width=8");
	const ut8 expected[] = { 1, 0, 1, 0, 1, 0, 1, 1 };
	for (int i = 0; i < 8; i++) {
		mu_assert_eq(vals[0].scalars[i].v_u8, expected[i],
			"MSB bit i");
	}
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_bitvec_lsb(void) {
	/* Byte 0xAB, LSB-first => bits 1,1,0,1,0,1,0,1 */
	RzPfFormat *fmt = rz_pf_parse("v(8,lsb) bits");
	const ut8 buf[] = { 0xAB, 0x00 };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read v(8) LSB");
	const ut8 expected[] = { 1, 1, 0, 1, 0, 1, 0, 1 };
	for (int i = 0; i < 8; i++) {
		mu_assert_eq(vals[0].scalars[i].v_u8, expected[i],
			"LSB bit i");
	}
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_bitvec_partial(void) {
	/* v(12) over 0xAB 0xCD MSB-first:
	 *   0xAB = 10101011, 0xCD = 11001101  -> first 12 bits =
	 *   1 0 1 0 1 0 1 1 | 1 1 0 0
	 * Consumes 2 bytes from buf. */
	RzPfFormat *fmt = rz_pf_parse("v(12)x1 bits tail");
	const ut8 buf[] = { 0xAB, 0xCD, 0xEF };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read v(12)");
	mu_assert_eq(count, 2, "2 values (bits + tail)");
	mu_assert_eq(vals[0].count, 12, "12 bits");
	const ut8 expected[] = { 1, 0, 1, 0, 1, 0, 1, 1,
		1, 1, 0, 0 };
	for (int i = 0; i < 12; i++) {
		mu_assert_eq(vals[0].scalars[i].v_u8, expected[i],
			"bit i");
	}
	/* tail should be the third byte 0xEF, proving v(12) consumed
	 * exactly ceil(12/8) = 2 bytes. */
	mu_assert_eq(vals[1].scalars[0].v_u8, 0xEF, "tail after bitvec");
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_render_bitvec_text(void) {
	RzPfFormat *fmt = rz_pf_parse("v(12) bits");
	const ut8 buf[] = { 0xAB, 0xCD };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	char *out = rz_pf_render(vals, count, RZ_PF_MODE_TEXT, NULL);
	mu_assert_notnull(out, "render text");
	/* Format: `[ 1 0 1 0 1 0 1 1 | 1 1 0 0 ] (12-bit)` */
	mu_assert(strstr(out, "[ 1 0 1 0 1 0 1 1 | 1 1 0 0 ]"),
		"grouped-by-8 rendering present");
	mu_assert(strstr(out, "(12-bit)"), "width suffix present");
	free(out);
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_guid(void) {
	RzPfFormat *fmt = rz_pf_parse("G uuid");
	mu_assert_notnull(fmt, "parse G");
	mu_assert_eq(fmt->nfields, 1, "1 field");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_GUID, "GUID");
	mu_assert_eq(fmt->fields[0].guid_layout, RZ_PF_GUID_MS, "default MS");
	rz_pf_format_free(fmt);

	fmt = rz_pf_parse("G(be) uuid");
	mu_assert_notnull(fmt, "parse G(be)");
	mu_assert_eq(fmt->fields[0].guid_layout, RZ_PF_GUID_BE, "BE layout");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_guid(void) {
	RzPfFormat *fmt = rz_pf_parse("G uuid");
	const ut8 buf[16] = {
		0x44,
		0x33,
		0x22,
		0x11, /* MS D1 LE -> 0x11223344 */
		0x66,
		0x55, /* D2 LE -> 0x5566 */
		0x88,
		0x77, /* D3 LE -> 0x7788 */
		0x99,
		0xAA, /* D4 raw */
		0xBB,
		0xCC,
		0xDD,
		0xEE,
		0xFF,
		0x00,
	};
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read GUID");
	mu_assert_eq(vals[0].raw_len, 16, "16 bytes");
	mu_assert_eq(vals[0].scalars[0].v_raw[0], 0x44, "raw byte 0");
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_lenref_array(void) {
	RzPfFormat *fmt = rz_pf_parse("u1[@count]x4 count items");
	mu_assert_notnull(fmt, "parse [@count]");
	mu_assert_eq(fmt->nfields, 2, "2 fields");
	mu_assert_streq(fmt->fields[1].length_ref, "count",
		"length_ref set");
	mu_assert_eq(fmt->fields[1].array_count, -1, "no literal");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_lenref_array(void) {
	RzPfFormat *fmt = rz_pf_parse("u1[@count]x4 count items");
	const ut8 buf[] = {
		0x03, /* count = 3 */
		0x01,
		0x00,
		0x00,
		0x00, /* items[0] LE */
		0x02,
		0x00,
		0x00,
		0x00,
		0x03,
		0x00,
		0x00,
		0x00,
	};
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read lenref array");
	mu_assert_eq(count, 2, "2 fields");
	mu_assert_eq(vals[0].scalars[0].v_u8, 3, "count = 3");
	mu_assert_eq(vals[1].count, 3, "items has 3 elements");
	mu_assert_eq(vals[1].scalars[0].v_u32, 1, "items[0]=1");
	mu_assert_eq(vals[1].scalars[2].v_u32, 3, "items[2]=3");
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_lenprefix_string(void) {
	RzPfFormat *fmt = rz_pf_parse("z[1] name");
	mu_assert_notnull(fmt, "parse z[1]");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_ZSTRING, "z");
	mu_assert_eq(fmt->fields[0].str_len_prefix, 1, "1-byte prefix");
	mu_assert_false(fmt->fields[0].str_len_in_bytes, "chars by default");
	rz_pf_format_free(fmt);

	fmt = rz_pf_parse("z(utf16le)[2b] name");
	mu_assert_notnull(fmt, "parse z(utf16le)[2b]");
	mu_assert_eq(fmt->fields[0].str_len_prefix, 2, "2-byte prefix");
	mu_assert_true(fmt->fields[0].str_len_in_bytes, "bytes flag set");
	mu_assert_eq(fmt->fields[0].encoding, RZ_STRING_ENC_UTF16LE,
		"utf16le encoding");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_lenprefix_string(void) {
	RzPfFormat *fmt = rz_pf_parse("z[1] greet");
	const ut8 buf[] = { 0x05, 'h', 'e', 'l', 'l', 'o' };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read pascal string");
	mu_assert_streq(vals[0].scalars[0].v_str, "hello", "decoded body");
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_inline_bitfield(void) {
	RzPfFormat *fmt = rz_pf_parse("B4(R=1,W=2,X=4) perms");
	mu_assert_notnull(fmt, "parse B4(...)");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_BITFIELD,
		"reinterpreted as BITFIELD");
	mu_assert_eq(fmt->fields[0].bitfield_size, 4, "4 bytes");
	mu_assert_eq(fmt->fields[0].bitflag_count, 3, "3 flags");
	mu_assert_streq(fmt->fields[0].bitflags[0].name, "R", "flag R");
	mu_assert_eq(fmt->fields[0].bitflags[0].value, 1, "R=1");
	mu_assert_eq(fmt->fields[0].bitflags[2].value, 4, "X=4");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_inline_bitfield_render(void) {
	/* The text renderer should expand named flags.
	 * `B4` is upper-case so the integer is read BE. Bytes laid out
	 * for value 0x00000005 = R | X. */
	RzPfFormat *fmt = rz_pf_parse("B4(R=1,W=2,X=4) perms");
	const ut8 buf[] = { 0x00, 0x00, 0x00, 0x05 };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read bitfield");
	char *out = rz_pf_render(vals, count, RZ_PF_MODE_TEXT, NULL);
	mu_assert_notnull(out, "render");
	mu_assert_true(strstr(out, "R") != NULL, "R present in output");
	mu_assert_true(strstr(out, "X") != NULL, "X present in output");
	mu_assert_true(strstr(out, "W") == NULL, "W not present");
	free(out);
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_parse_tlv(void) {
	RzPfFormat *fmt = rz_pf_parse("V(t=u1,l=u2,d=my_table) record");
	mu_assert_notnull(fmt, "parse V(...)");
	mu_assert_eq(fmt->fields[0].type, RZ_PF_TLV, "TLV");
	mu_assert_notnull(fmt->fields[0].tlv_spec, "spec set");
	mu_assert_eq(fmt->fields[0].tlv_spec->tag_size, 1, "tag u1");
	mu_assert_eq(fmt->fields[0].tlv_spec->len_size, 2, "len u2");
	mu_assert_streq(fmt->fields[0].tlv_spec->dispatch_name,
		"my_table", "dispatch name");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_tlv_raw(void) {
	/* No dispatch registered -> value stored as raw bytes. */
	RzPfFormat *fmt = rz_pf_parse("V(t=u1,l=u2) rec");
	const ut8 buf[] = {
		0x42, /* tag */
		0x03, 0x00, /* length = 3 LE */
		0xDE, 0xAD, 0xBE, /* value bytes */
	};
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "read TLV");
	mu_assert_eq(vals[0].tlv_tag, 0x42, "tag");
	mu_assert_eq(vals[0].tlv_length, 3, "value len");
	mu_assert_eq(vals[0].raw_len, 3, "raw bytes stored");
	mu_assert_eq(vals[0].scalars[0].v_raw[0], 0xDE, "value[0]");
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

/* Phase 5: render-mode coverage, every timestamp format, pointer
 * dereference via the mem_read_at callback, and malformed-input /
 * recursion-bound smoke tests. */

static bool test_pf_render_modes_basic(void) {
	RzPfFormat *fmt = rz_pf_parse("x4 magic");
	const ut8 buf[] = { 0xEF, 0xBE, 0xAD, 0xDE };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);

	char *t = rz_pf_render(vals, count, RZ_PF_MODE_TEXT, NULL);
	mu_assert_notnull(t, "text");
	mu_assert_true(strstr(t, "magic") != NULL, "text has name");
	mu_assert_true(strstr(t, "0xdeadbeef") != NULL, "text has hex");
	free(t);

	char *j = rz_pf_render(vals, count, RZ_PF_MODE_JSON, NULL);
	mu_assert_notnull(j, "json");
	mu_assert_true(j[0] == '[' && j[1] == '{', "json array of objects");
	mu_assert_true(strstr(j, "\"name\":\"magic\"") != NULL, "json name");
	mu_assert_true(strstr(j, "\"endian\":\"little\"") != NULL,
		"json endian");
	free(j);

	char *c = rz_pf_render(vals, count, RZ_PF_MODE_CSTRUCT, NULL);
	mu_assert_notnull(c, "cstruct");
	mu_assert_true(strstr(c, "uint32_t magic;") != NULL,
		"cstruct decl");
	free(c);

	char *q = rz_pf_render(vals, count, RZ_PF_MODE_QUIET, NULL);
	mu_assert_notnull(q, "quiet");
	mu_assert_true(strstr(q, "0xdeadbeef") != NULL, "quiet value");
	mu_assert_true(strstr(q, "magic") == NULL,
		"quiet has no field name");
	free(q);

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_render_quiet_ofield_filter(void) {
	RzPfFormat *fmt = rz_pf_parse("x4d4 a b");
	const ut8 buf[] = {
		0xEF,
		0xBE,
		0xAD,
		0xDE,
		0x39,
		0x05,
		0x00,
		0x00,
	};
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_eq(count, 2, "two values");

	char *t = rz_pf_render(vals, count, RZ_PF_MODE_TEXT, &(RzPfRenderOpts){ .field_filter = "b" });
	mu_assert_notnull(t, "filtered text");
	mu_assert_true(strstr(t, "1337") != NULL, "b value present");
	mu_assert_true(strstr(t, "0xdeadbeef") == NULL,
		"a value not present");
	free(t);

	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_timestamp_all_formats_size(void) {
	const struct {
		RzPfTimeFmt fmt;
		int expected_sz;
		const char *name;
	} cases[] = {
		{ RZ_PF_TIMEFMT_UNIX32, 4, "unix32" },
		{ RZ_PF_TIMEFMT_UNIX64, 8, "unix64" },
		{ RZ_PF_TIMEFMT_UNIXMS, 8, "unixms" },
		{ RZ_PF_TIMEFMT_UNIXUS, 8, "unixus" },
		{ RZ_PF_TIMEFMT_UNIXNS, 8, "unixns" },
		{ RZ_PF_TIMEFMT_FILETIME, 8, "filetime" },
		{ RZ_PF_TIMEFMT_DOS, 4, "dos" },
		{ RZ_PF_TIMEFMT_HFS, 4, "hfs" },
		{ RZ_PF_TIMEFMT_OLETIME, 8, "oletime" },
		{ RZ_PF_TIMEFMT_WEBKIT, 8, "webkit" },
		{ RZ_PF_TIMEFMT_COCOA, 8, "cocoa" },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int sz = rz_pf_timefmt_size(cases[i].fmt);
		mu_assert_eq(sz, cases[i].expected_sz, cases[i].name);
	}
	mu_end;
}

static bool test_pf_timestamp_filetime_decode(void) {
	/* 0x01c126cea1130000 ~= 2001 epoch in Windows FILETIME. */
	RzPfFormat *fmt = rz_pf_parse("t(filetime) ts");
	const ut64 ft_ticks = 0x01c126cea1130000ULL;
	ut8 buf[8];
	for (int i = 0; i < 8; i++) {
		buf[i] = (ut8)(ft_ticks >> (i * 8));
	}
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, sizeof(buf), 0, NULL, &count);
	mu_assert_notnull(vals, "decode filetime");
	mu_assert_eq(count, 1, "1 value");
	char *q = rz_pf_render(vals, count, RZ_PF_MODE_QUIET, NULL);
	mu_assert_notnull(q, "quiet");
	mu_assert_true(strstr(q, "2001") != NULL,
		"filetime renders year 2001");
	free(q);
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_pointer_deref_via_callback(void) {
	ut8 mem[0x300];
	memset(mem, 0, sizeof(mem));
	mem[0x100] = 0x00;
	mem[0x101] = 0x02;
	const char *body = "world";
	memcpy(mem + 0x200, body, strlen(body) + 1);

	RzPfCtx *ctx = rz_pf_ctx_new();
	MemBuf mb = { .data = mem, .len = sizeof(mem) };
	rz_pf_ctx_setup(ctx, NULL, false, 64, mem_read_at, &mb);

	RzPfFormat *fmt = rz_pf_parse("s greeting");
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, mem + 0x100, 8, 0, ctx, &count);
	mu_assert_notnull(vals, "deref");
	mu_assert_eq(count, 1, "1 value");
	mu_assert_eq(vals[0].ptr_addr, 0x200, "ptr addr");
	mu_assert_notnull(vals[0].scalars[0].v_str, "string decoded");
	mu_assert_streq(vals[0].scalars[0].v_str, "world",
		"deref body matches");
	rz_pf_values_free(vals, count);
	rz_pf_format_free(fmt);
	rz_pf_ctx_free(ctx);
	mu_end;
}

static bool test_pf_parse_empty_returns_empty(void) {
	RzPfFormat *fmt = rz_pf_parse("");
	mu_assert_notnull(fmt, "empty input gives empty format");
	mu_assert_eq(fmt->nfields, 0, "zero fields");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_read_zero_length_buffer(void) {
	RzPfFormat *fmt = rz_pf_parse("x4 a");
	const ut8 buf[1] = { 0 };
	int count = 0;
	RzPfValue *vals = rz_pf_read(fmt, buf, 0, 0, NULL, &count);
	if (vals) {
		mu_assert_true(count <= 1, "no extra values");
		rz_pf_values_free(vals, count);
	}
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_format_oneshot(void) {
	const ut8 buf[] = { 0xEF, 0xBE, 0xAD, 0xDE };
	char *out = rz_pf_format("x4 magic", buf, sizeof(buf), 0,
		NULL, RZ_PF_MODE_TEXT, NULL);
	mu_assert_notnull(out, "oneshot");
	mu_assert_true(strstr(out, "magic") != NULL, "has name");
	mu_assert_true(strstr(out, "0xdeadbeef") != NULL, "has value");
	free(out);
	mu_end;
}

/* Diagnostic / error-reporting tests -- exercise the position-aware
 * RzPfError pipeline introduced for issue-driven error reporting. */

static bool test_pf_diag_unknown_specifier_position(void) {
	/* '!' is not a known specifier; parser records a positioned
	 * syntax diagnostic. */
	RzPfFormat *fmt = rz_pf_parse("x4!x4 a b");
	mu_assert_notnull(fmt, "parse with bad mid-token");
	mu_assert_true(fmt->nerrors >= 1, "diagnostic emitted");
	bool found = false;
	for (int i = 0; i < fmt->nerrors; i++) {
		if (fmt->errors[i].category == RZ_PF_ERRC_SYNTAX && fmt->errors[i].pos == 2) {
			found = true;
			break;
		}
	}
	mu_assert_true(found, "syntax error at position 2");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_diag_bits_without_width(void) {
	RzPfFormat *fmt = rz_pf_parse(":x4 a b");
	mu_assert_notnull(fmt, "parse with bare ':'");
	bool found = false;
	for (int i = 0; i < fmt->nerrors; i++) {
		if (fmt->errors[i].category == RZ_PF_ERRC_SYNTAX && fmt->errors[i].pos == 0) {
			found = true;
			break;
		}
	}
	mu_assert_true(found, "diagnostic at position 0");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_diag_align_without_n(void) {
	RzPfFormat *fmt = rz_pf_parse("x1@x4 a b");
	mu_assert_notnull(fmt, "parse with bare '@'");
	bool found = false;
	for (int i = 0; i < fmt->nerrors; i++) {
		if (fmt->errors[i].category == RZ_PF_ERRC_SYNTAX && fmt->errors[i].pos == 2) {
			found = true;
			break;
		}
	}
	mu_assert_true(found, "diagnostic at @ position");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_diag_deprecated_w(void) {
	RzPfFormat *fmt = rz_pf_parse("w foo");
	mu_assert_notnull(fmt, "parse deprecated w");
	bool found = false;
	for (int i = 0; i < fmt->nerrors; i++) {
		if (fmt->errors[i].category == RZ_PF_ERRC_DEPRECATED && fmt->errors[i].severity == RZ_PF_ERR_WARN) {
			found = true;
			break;
		}
	}
	mu_assert_true(found, "deprecation warning recorded");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_diag_tlv_missing_close_paren(void) {
	RzPfFormat *fmt = rz_pf_parse("V(t=u1,l=u2 record");
	mu_assert_notnull(fmt, "parse V(...");
	bool found = false;
	for (int i = 0; i < fmt->nerrors; i++) {
		if (fmt->errors[i].category == RZ_PF_ERRC_SYNTAX && fmt->errors[i].severity == RZ_PF_ERR_ERROR && fmt->errors[i].message && strstr(fmt->errors[i].message, "closing")) {
			found = true;
			break;
		}
	}
	mu_assert_true(found, "TLV missing-paren diagnostic");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_diag_tlv_bad_tag_type(void) {
	RzPfFormat *fmt = rz_pf_parse("V(t=u3) record");
	mu_assert_notnull(fmt, "parse V(t=u3)");
	bool found = false;
	for (int i = 0; i < fmt->nerrors; i++) {
		if (fmt->errors[i].category == RZ_PF_ERRC_RANGE && fmt->errors[i].message && strstr(fmt->errors[i].message, "tag")) {
			found = true;
			break;
		}
	}
	mu_assert_true(found, "u3 rejected as tag type");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_diag_tlv_unknown_key(void) {
	RzPfFormat *fmt = rz_pf_parse("V(t=u1,xyz=1) record");
	mu_assert_notnull(fmt, "parse V with bad key");
	bool found = false;
	for (int i = 0; i < fmt->nerrors; i++) {
		if (fmt->errors[i].category == RZ_PF_ERRC_SEMANTIC && fmt->errors[i].message && strstr(fmt->errors[i].message, "xyz")) {
			found = true;
			break;
		}
	}
	mu_assert_true(found, "unknown TLV key reported");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_diag_errors_to_string(void) {
	RzPfFormat *fmt = rz_pf_parse("x4!x4 a b");
	mu_assert_notnull(fmt, "parse");
	char *s = rz_pf_format_errors_to_string(fmt);
	mu_assert_notnull(s, "rendered diagnostics");
	mu_assert_true(strstr(s, "syntax") != NULL, "category tag");
	mu_assert_true(strstr(s, "x4!x4") != NULL, "source line");
	mu_assert_true(strstr(s, "^") != NULL, "caret line");
	free(s);
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_diag_clean_parse_no_errors(void) {
	RzPfFormat *fmt = rz_pf_parse("x4d4 a b");
	mu_assert_notnull(fmt, "parse");
	mu_assert_eq(fmt->nerrors, 0, "no spurious diagnostics");
	char *s = rz_pf_format_errors_to_string(fmt);
	mu_assert_null(s, "no string for clean parse");
	rz_pf_format_free(fmt);
	mu_end;
}

static bool test_pf_diag_source_captured(void) {
	const char *src = "x4 a";
	RzPfFormat *fmt = rz_pf_parse(src);
	mu_assert_notnull(fmt, "parse");
	mu_assert_notnull(fmt->source, "source captured");
	mu_assert_streq(fmt->source, src, "source matches input");
	rz_pf_format_free(fmt);
	mu_end;
}

/* Ambiguity audit -- exercises the boundaries between superficially
 * unambiguous field type. These tests document the parser's
 * disambiguation rules so future changes don't accidentally regress
 * them.
 *
 *   b4         -> BIN32 (sized binary)
 *   B4         -> BITFIELD (typedb-resolved by default)
 *   B4(K=V)    -> inline BITFIELD discriminated by `=` in parens
 *   t4         -> TIMESTAMP unix32 (deprecated bare form)
 *   t(unix32)  -> TIMESTAMP unix32 (canonical)
 *   z(utf16le) -> ZSTRING utf16-le
 *   z(utf8)[N] -> length-prefixed zstring
 *   V          -> TLV with defaults
 *   V(...)     -> TLV with key=value spec
 */

static bool test_pf_ambig_b4_vs_B4(void) {
	/* Both lowercase and uppercase `b4`/`B4` produce BIN32; the
	 * difference is endian. Their interpretation as BITFIELD
	 * happens only when a (typename) qualifier is attached, which
	 * the next test exercises. */
	RzPfFormat *bin = rz_pf_parse("b4 lower");
	RzPfFormat *be = rz_pf_parse("B4 upper");
	mu_assert_notnull(bin, "lowercase b4");
	mu_assert_notnull(be, "uppercase B4");
	mu_assert_eq(bin->fields[0].type, RZ_PF_BIN32, "b4 = BIN32 LE");
	mu_assert_eq(bin->fields[0].endian, RZ_PF_ENDIAN_LE, "b4 LE");
	mu_assert_eq(be->fields[0].type, RZ_PF_BIN32, "B4 = BIN32 BE");
	mu_assert_eq(be->fields[0].endian, RZ_PF_ENDIAN_BE, "B4 BE");
	rz_pf_format_free(bin);
	rz_pf_format_free(be);
	mu_end;
}

static bool test_pf_ambig_inline_bitfield_vs_typed(void) {
	/* `B4(R=1,W=2)` carries `=` inside parens -> inline bitfield
	 * (the parser discriminates on the presence of `=`).
	 * `B4 (perm) flags` references the typedb-named `perm` bitfield. */
	RzPfFormat *inline_bf = rz_pf_parse("B4(R=1,W=2,X=4) perm");
	RzPfFormat *typed_bf = rz_pf_parse("B4 (perm)flags");
	mu_assert_notnull(inline_bf, "inline");
	mu_assert_notnull(typed_bf, "typed");
	mu_assert_eq(inline_bf->fields[0].type, RZ_PF_BITFIELD,
		"inline is BITFIELD");
	mu_assert_eq(inline_bf->fields[0].bitflag_count, 3,
		"3 inline bitflags");
	mu_assert_null(inline_bf->fields[0].type_name,
		"inline has no typedb name");
	/* Typed B4 (perm) attaches the typedb name. Whether the
	 * field's discrim type ends up as BITFIELD or sized BIN
	 * depends on whether resolver runs at parse-time vs read-time;
	 * the contract we lock down here is that the type_name is
	 * recorded so the read pass can dispatch correctly. */
	mu_assert_streq(typed_bf->fields[0].type_name, "perm",
		"typed has typedb name");
	mu_assert_eq(typed_bf->fields[0].bitflag_count, 0,
		"typed has no inline bitflags");
	rz_pf_format_free(inline_bf);
	rz_pf_format_free(typed_bf);
	mu_end;
}

static bool test_pf_ambig_t4_vs_t_paren(void) {
	/* `t4` should map to deprecated unix32; `t(unix32)` is canonical. */
	RzPfFormat *legacy = rz_pf_parse("t4 ts1");
	RzPfFormat *canon = rz_pf_parse("t(unix32) ts2");
	mu_assert_notnull(legacy, "t4");
	mu_assert_notnull(canon, "t(unix32)");
	mu_assert_eq(legacy->fields[0].type, RZ_PF_TIMESTAMP,
		"t4 is TIMESTAMP");
	mu_assert_eq(legacy->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX32,
		"t4 = unix32");
	mu_assert_eq(canon->fields[0].type, RZ_PF_TIMESTAMP,
		"t(unix32) is TIMESTAMP");
	mu_assert_eq(canon->fields[0].timefmt, RZ_PF_TIMEFMT_UNIX32,
		"t(unix32) = unix32");
	/* The deprecated form should produce a deprecation warning. */
	bool has_dep = false;
	for (int i = 0; i < legacy->nerrors; i++) {
		if (legacy->errors[i].category == RZ_PF_ERRC_DEPRECATED) {
			has_dep = true;
			break;
		}
	}
	mu_assert_true(has_dep, "t4 emits deprecation warning");
	rz_pf_format_free(legacy);
	rz_pf_format_free(canon);
	mu_end;
}

static bool test_pf_ambig_z_vs_z_paren_vs_z_lenprefix(void) {
	/* `z` = NUL-terminated string with default encoding;
	 * `z(utf16le)` = encoding override; `z[2]` = length-prefixed. */
	RzPfFormat *bare = rz_pf_parse("z s1");
	RzPfFormat *enc = rz_pf_parse("z(utf16le) s2");
	RzPfFormat *lp = rz_pf_parse("z[2] s3");
	mu_assert_notnull(bare, "bare z");
	mu_assert_notnull(enc, "z(...)");
	mu_assert_notnull(lp, "z[2]");
	mu_assert_eq(bare->fields[0].type, RZ_PF_ZSTRING, "z=ZSTRING");
	mu_assert_eq(enc->fields[0].type, RZ_PF_ZSTRING,
		"z(utf16le)=ZSTRING");
	mu_assert_eq(enc->fields[0].encoding, RZ_STRING_ENC_UTF16LE,
		"utf16le encoding stored");
	mu_assert_eq(lp->fields[0].type, RZ_PF_ZSTRING,
		"z[2]=ZSTRING");
	mu_assert_eq(lp->fields[0].str_len_prefix, 2,
		"z[2] has 2-byte prefix");
	rz_pf_format_free(bare);
	rz_pf_format_free(enc);
	rz_pf_format_free(lp);
	mu_end;
}

static bool test_pf_ambig_V_bare_vs_V_paren(void) {
	/* Bare `V` uses defaults; `V(...)` configures the TLV. */
	RzPfFormat *bare = rz_pf_parse("V rec1");
	RzPfFormat *full = rz_pf_parse("V(t=u2,l=u4) rec2");
	mu_assert_notnull(bare, "V");
	mu_assert_notnull(full, "V(...)");
	mu_assert_eq(bare->fields[0].type, RZ_PF_TLV, "V=TLV");
	mu_assert_eq(bare->fields[0].tlv_spec->tag_size, 1,
		"V defaults to t=u1");
	mu_assert_eq(bare->fields[0].tlv_spec->len_size, 2,
		"V defaults to l=u2");
	mu_assert_eq(full->fields[0].tlv_spec->tag_size, 2,
		"V(t=u2) uses t=u2");
	mu_assert_eq(full->fields[0].tlv_spec->len_size, 4,
		"V(l=u4) uses l=u4");
	rz_pf_format_free(bare);
	rz_pf_format_free(full);
	mu_end;
}

static bool test_pf_ambig_struct_vs_skip(void) {
	/* `?(name)var` is a nested struct; `?` alone is also a struct.
	 * `.` is SKIP. They differ in `type`. */
	RzPfFormat *st = rz_pf_parse("?(inner) nested");
	RzPfFormat *sk = rz_pf_parse("x1.x1 a b");
	mu_assert_notnull(st, "?(...)");
	mu_assert_notnull(sk, "x.x");
	mu_assert_eq(st->fields[0].type, RZ_PF_STRUCT,
		"? is STRUCT");
	mu_assert_streq(st->fields[0].type_name, "inner",
		"struct typename");
	mu_assert_eq(sk->fields[1].type, RZ_PF_SKIP,
		". is SKIP");
	rz_pf_format_free(st);
	rz_pf_format_free(sk);
	mu_end;
}

static bool test_pf_ambig_x4_vs_x(void) {
	/* `x` (bare) is deprecated for HEXDUMP; `x4` is sized HEX32.
	 * Since I retired bare-x in the new DSL, bare `x` is now a
	 * deprecated alias for HEX32 by default. The sized form is
	 * the canonical one. */
	RzPfFormat *sized = rz_pf_parse("x4 a");
	mu_assert_notnull(sized, "x4");
	mu_assert_eq(sized->fields[0].type, RZ_PF_HEX32, "x4=HEX32");
	mu_assert_eq(rz_pf_field_size(sized->fields[0].type), 4,
		"x4 is 4 bytes");
	rz_pf_format_free(sized);
	mu_end;
}

static bool test_pf_ambig_d_vs_D_endian(void) {
	/* `d4` LE-decimal, `D4` BE-decimal. */
	RzPfFormat *le = rz_pf_parse("d4 a");
	RzPfFormat *be = rz_pf_parse("D4 a");
	mu_assert_notnull(le, "d4");
	mu_assert_notnull(be, "D4");
	mu_assert_eq(le->fields[0].endian, RZ_PF_ENDIAN_LE, "d=LE");
	mu_assert_eq(be->fields[0].endian, RZ_PF_ENDIAN_BE, "D=BE");
	rz_pf_format_free(le);
	rz_pf_format_free(be);
	mu_end;
}

static bool test_pf_ambig_align_vs_skip(void) {
	/* `@4` aligns to next multiple of 4; `.` skips one byte. Both
	 * are name-less. */
	RzPfFormat *al = rz_pf_parse("x1@4x1 a b");
	RzPfFormat *sk = rz_pf_parse("x1.x1 a b");
	mu_assert_notnull(al, "@4");
	mu_assert_notnull(sk, ".");
	mu_assert_eq(al->fields[1].type, RZ_PF_ALIGN, "@ is ALIGN");
	mu_assert_eq(al->fields[1].align_to, 4, "align_to=4");
	mu_assert_eq(sk->fields[1].type, RZ_PF_SKIP, ". is SKIP");
	rz_pf_format_free(al);
	rz_pf_format_free(sk);
	mu_end;
}

static bool test_pf_ambig_bits_lt_gt(void) {
	/* `:8` defaults to MSB-first; `:8<` is LSB-first explicit;
	 * `:8>` is MSB-first explicit. */
	RzPfFormat *def = rz_pf_parse(":8 a");
	RzPfFormat *lsb = rz_pf_parse(":8< a");
	RzPfFormat *msb = rz_pf_parse(":8> a");
	mu_assert_notnull(def, ":8");
	mu_assert_notnull(lsb, ":8<");
	mu_assert_notnull(msb, ":8>");
	mu_assert_eq(def->fields[0].type, RZ_PF_BITS, "default BITS");
	mu_assert_eq(def->fields[0].bit_order, RZ_PF_BITORDER_MSB,
		"default = MSB");
	mu_assert_eq(lsb->fields[0].bit_order, RZ_PF_BITORDER_LSB,
		"< = LSB");
	mu_assert_eq(msb->fields[0].bit_order, RZ_PF_BITORDER_MSB,
		"> = MSB");
	rz_pf_format_free(def);
	rz_pf_format_free(lsb);
	rz_pf_format_free(msb);
	mu_end;
}

/* Palette in render (issue rizinorg/rizin#782) -- verifies that the
 * text renderer emits ANSI escapes inline when an RzPfPalette is
 * supplied via RzPfRenderOpts. The renderer with NULL palette
 * remains color-free so integration tests keep matching exact bytes. */

static const RzPfPalette pal_test = {
	.offset = "\x1b[32m",
	.name = "\x1b[33m",
	.endian = "\x1b[34m",
	.hex_literal = "\x1b[36m",
	.label = "\x1b[35m",
	.reset = "\x1b[0m",
};

static bool test_pf_palette_text_basic(void) {
	const ut8 buf[] = { 0xEF, 0xBE, 0xAD, 0xDE };
	RzPfRenderOpts opts = { .palette = &pal_test };
	char *colored = rz_pf_format("x4 magic", buf, sizeof(buf), 0,
		NULL, RZ_PF_MODE_TEXT, &opts);
	mu_assert_notnull(colored, "render");
	mu_assert_true(strstr(colored, "\x1b[32m") != NULL,
		"green offset escape present");
	mu_assert_true(strstr(colored, "\x1b[33mmagic\x1b[0m") != NULL,
		"yellow name");
	mu_assert_true(strstr(colored, "\x1b[34m [LE]\x1b[0m") != NULL,
		"blue endian tag (trailing)");
	mu_assert_true(strstr(colored, "\x1b[36m0xdeadbeef\x1b[0m") != NULL,
		"cyan hex literal");
	free(colored);
	mu_end;
}

static bool test_pf_palette_null_no_color(void) {
	/* NULL palette yields canonical color-free output. */
	const ut8 buf[] = { 0xEF, 0xBE, 0xAD, 0xDE };
	char *plain = rz_pf_format("x4 magic", buf, sizeof(buf), 0,
		NULL, RZ_PF_MODE_TEXT, NULL);
	mu_assert_notnull(plain, "render");
	mu_assert_true(strchr(plain, '\x1b') == NULL,
		"no escape codes when palette is NULL");
	free(plain);
	mu_end;
}

static bool test_pf_palette_partial_palette(void) {
	/* A palette with only some fields set highlights only those.
	 * Other tokens are uncolored. */
	const ut8 buf[] = { 0xEF, 0xBE, 0xAD, 0xDE };
	RzPfPalette partial = { 0 };
	partial.hex_literal = "\x1b[36m";
	partial.reset = "\x1b[0m";
	RzPfRenderOpts opts = { .palette = &partial };
	char *out = rz_pf_format("x4 magic", buf, sizeof(buf), 0,
		NULL, RZ_PF_MODE_TEXT, &opts);
	mu_assert_notnull(out, "render");
	mu_assert_true(strstr(out, "\x1b[36m0xdeadbeef\x1b[0m") != NULL,
		"hex literal colored");
	/* "magic" appears uncolored (no escape before it). */
	const char *m = strstr(out, "magic");
	mu_assert_notnull(m, "name present");
	mu_assert_true(m == out || m[-1] != 'm',
		"name not preceded by escape sequence");
	free(out);
	mu_end;
}

/* When the palette is NULL, the renderer must not emit any color
 * escapes itself. Even when the input bytes contain ESC characters
 * (which would otherwise leak through if the renderer accidentally
 * passed raw bytes), no ESC byte should appear in the renderer
 * scaffolding (before the value). The value column escapes
 * non-printable bytes (including ESC) as \xNN so the rendered
 * string is always 7-bit-clean. Surfaced by the property-based
 * test harness (pf-property-harness). */
static bool test_pf_palette_null_passes_through_input_esc(void) {
	const ut8 buf[] = { 'A', '\x1b', 'B', 0 };
	char *out = rz_pf_format("z s", buf, sizeof(buf), 0,
		NULL, RZ_PF_MODE_TEXT, NULL);
	mu_assert_notnull(out, "render");
	/* Whole output must be ESC-free with NULL palette. */
	mu_assert_true(strchr(out, '\x1b') == NULL,
		"no ESC bytes in output when palette is NULL");
	/* Renderer must escape the input ESC byte as the literal
	 * sequence \x1b in the value cell. */
	mu_assert_true(strstr(out, "\\x1b") != NULL,
		"input ESC byte escaped as \\x1b in value");
	free(out);
	mu_end;
}

/* The DOT renderer must call into rz_pf_timestamp_format_str for
 * timestamp fields rather than falling through to scalar_text(),
 * which would emit "?". Surfaced while building the PR showcase
 * with `pfd "t(unix32)" created_at`. */
static bool test_pf_render_dot_timestamp(void) {
	/* 2021-02-09 13:48:14 UTC = 0x6022929e */
	const ut8 buf[] = { 0x9e, 0x92, 0x22, 0x60 };
	char *out = rz_pf_format("t(unix32) ts", buf, sizeof(buf), 0,
		NULL, RZ_PF_MODE_DOT, NULL);
	mu_assert_notnull(out, "render");
	mu_assert_true(strstr(out, "2021-02-09") != NULL,
		"date present in DOT output");
	mu_assert_true(strstr(out, ">?") == NULL,
		"no fallback placeholder");
	free(out);
	mu_end;
}

/* Column-aligned DOT layout: each row (offset / type / name / value)
 * must contain the same number of cells as the visible-field count,
 * so Graphviz produces a regular grid with aligned columns. */
static bool test_pf_render_dot_column_aligned(void) {
	const ut8 buf[] = { 0x7f, 0x45, 0x4c, 0x46 };
	char *out = rz_pf_format("x1x1x1x1 magic class data version",
		buf, sizeof(buf), 0, NULL, RZ_PF_MODE_DOT, NULL);
	mu_assert_notnull(out, "render");
	/* Each row group is present exactly once and contains the
	 * header + 4 field cells. */
	mu_assert_true(strstr(out, "{offset|0x0|0x1|0x2|0x3}") != NULL,
		"offset row aligned");
	mu_assert_true(strstr(out, "{type|x|x|x|x}") != NULL,
		"type row aligned");
	mu_assert_true(strstr(out,
			       "{name|<magic>magic|<class>class|<data>data|<version>version}") != NULL,
		"name row aligned");
	mu_assert_true(strstr(out, "{value|0x7f|0x45|0x4c|0x46}") != NULL,
		"value row aligned");
	free(out);
	mu_end;
}

/* When only one field passes the filter, columns degenerate to a
 * single value-cell per row, but the layout structure stays the
 * same so a downstream tool can rely on the row order. */
static bool test_pf_render_dot_single_field(void) {
	const ut8 buf[] = { 0xde, 0xad, 0xbe, 0xef };
	char *out = rz_pf_format("x4 magic", buf, sizeof(buf), 0,
		NULL, RZ_PF_MODE_DOT, NULL);
	mu_assert_notnull(out, "render");
	mu_assert_true(strstr(out, "{offset|0x0}") != NULL,
		"offset row single");
	mu_assert_true(strstr(out, "{type|x}") != NULL,
		"type row single");
	mu_assert_true(strstr(out, "{name|<magic>magic}") != NULL,
		"name row single");
	mu_assert_true(strstr(out, "{value|0xefbeadde}") != NULL,
		"value row single");
	free(out);
	mu_end;
}

/* When no fields are visible (everything filtered out or empty),
 * we still emit a well-formed digraph -- just without any rows. */
static bool test_pf_render_dot_empty(void) {
	const ut8 buf[] = { 0xde, 0xad, 0xbe, 0xef };
	RzPfRenderOpts opts = { .field_filter = "nonexistent" };
	char *out = rz_pf_format("x4 magic", buf, sizeof(buf), 0,
		NULL, RZ_PF_MODE_DOT, &opts);
	mu_assert_notnull(out, "render");
	mu_assert_true(strstr(out, "digraph g") != NULL,
		"well-formed digraph header");
	mu_assert_true(strstr(out, "{offset") == NULL,
		"no offset row when nothing visible");
	free(out);
	mu_end;
}

/* TLV in DOT mode: was falling through to scalar_text and emitting
 * "?". Now renders "tag=0xN len=M" in the value cell. */
static bool test_pf_render_dot_tlv(void) {
	/* tag=0x0005 (BE), length=0x0004 (BE), value=de ad be ef */
	const ut8 buf[] = { 0x00, 0x05, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef };
	char *out = rz_pf_format("V(t=u2,l=u2,e=be) rec",
		buf, sizeof(buf), 0, NULL, RZ_PF_MODE_DOT, NULL);
	mu_assert_notnull(out, "render");
	mu_assert_true(strstr(out, "tag=0x5 len=4") != NULL,
		"TLV header in value cell");
	mu_assert_true(strstr(out, "{value|?}") == NULL,
		"no fallback placeholder for TLV");
	free(out);
	mu_end;
}

/* Empty input must parse to an empty format object rather than NULL.
 * Surfaced by p_parse_empty_input in the property harness; the old
 * behaviour was an rz_return_val_if_fail() that forced every caller
 * to special-case the empty string. */
static bool test_pf_parse_empty_input(void) {
	RzPfFormat *fmt = rz_pf_parse("");
	mu_assert_notnull(fmt, "empty input gives empty format, not NULL");
	mu_assert_eq(fmt->nfields, 0, "zero fields");
	mu_assert_eq(fmt->nerrors, 0, "zero diagnostics");
	mu_assert_notnull(fmt->source, "source preserved");
	mu_assert_streq(fmt->source, "", "source is empty");
	rz_pf_format_free(fmt);
	mu_end;
}

/* NULL input must yield NULL safely (no crash, no diagnostic). */
static bool test_pf_parse_null_input(void) {
	RzPfFormat *fmt = rz_pf_parse(NULL);
	mu_assert_null(fmt, "NULL input -> NULL");
	mu_end;
}

/* Bitfield entry without '=' must produce an ERROR diagnostic
 * instead of being silently skipped. Surfaced by the malformed
 * input generator with B4(=1). */
static bool test_pf_parse_bitfield_missing_eq_diagnostic(void) {
	RzPfFormat *fmt = rz_pf_parse("B4(BADNAME) flags");
	mu_assert_notnull(fmt, "parse returns object");
	int n_err = 0;
	for (int i = 0; i < fmt->nerrors; i++) {
		if (fmt->errors[i].severity == RZ_PF_ERR_ERROR) {
			n_err++;
		}
	}
	mu_assert_true(n_err > 0,
		"bitfield entry without '=' produces ERROR diagnostic");
	rz_pf_format_free(fmt);
	mu_end;
}

/* Bitfield entry with empty name/value (e.g. B4(=1) or B4(a=))
 * must also produce an ERROR diagnostic. */
static bool test_pf_parse_bitfield_empty_field_diagnostic(void) {
	RzPfFormat *fmt = rz_pf_parse("B4(=1) flags");
	mu_assert_notnull(fmt, "parse returns object");
	int n_err = 0;
	for (int i = 0; i < fmt->nerrors; i++) {
		if (fmt->errors[i].severity == RZ_PF_ERR_ERROR) {
			n_err++;
		}
	}
	mu_assert_true(n_err > 0,
		"bitfield entry with empty name produces ERROR");
	rz_pf_format_free(fmt);
	mu_end;
}

/* Inline bitfield render must be deterministic across calls.
 * Surfaced by the property harness `render_is_idempotent`: the
 * legacy rz_pf_format() freed the parsed format before rendering,
 * but RzPfValue::bitflags borrowed pointers into that format's
 * RzPfBitflag::name strings. The use-after-free caused the
 * bitfield's flag-name column to print uninitialized memory and
 * differ on every call. */
static bool test_pf_render_bitfield_inline_idempotent(void) {
	const ut8 buf[] = { 0x01, 0x02, 0x03, 0x07 };
	char *a = rz_pf_format("B4(R=1,W=2,X=4) flags",
		buf, sizeof(buf), 0, NULL, RZ_PF_MODE_TEXT, NULL);
	char *b = rz_pf_format("B4(R=1,W=2,X=4) flags",
		buf, sizeof(buf), 0, NULL, RZ_PF_MODE_TEXT, NULL);
	mu_assert_notnull(a, "first render");
	mu_assert_notnull(b, "second render");
	mu_assert_streq(a, b, "rendering must be deterministic");
	mu_assert_true(strstr(a, "R | W | X") != NULL,
		"flag names are decoded, not uninitialized memory");
	free(a);
	free(b);
	mu_end;
}

static int all_tests(void) {
	/* Field size */
	mu_run_test(test_pf_field_size_1byte);
	mu_run_test(test_pf_field_size_2byte);
	mu_run_test(test_pf_field_size_4byte);
	mu_run_test(test_pf_field_size_8byte);
	mu_run_test(test_pf_field_size_special);

	/* Field C type */
	mu_run_test(test_pf_field_ctype_unsigned);
	mu_run_test(test_pf_field_ctype_signed);
	mu_run_test(test_pf_field_ctype_float);
	mu_run_test(test_pf_field_ctype_misc);

	/* Encoding null unit size */
	mu_run_test(test_pf_enc_null_unit_size);

	/* Timestamp utilities */
	mu_run_test(test_pf_timefmt_from_string);
	mu_run_test(test_pf_timefmt_from_string_case_insensitive);
	mu_run_test(test_pf_timefmt_from_string_unknown);
	mu_run_test(test_pf_timefmt_as_string);
	mu_run_test(test_pf_timefmt_size);
	mu_run_test(test_pf_timefmt_is_float);

	/* Parse: edge cases */
	mu_run_test(test_pf_parse_null);
	mu_run_test(test_pf_parse_leading_whitespace);

	/* Parse: sized integers */
	mu_run_test(test_pf_parse_hex_le);
	mu_run_test(test_pf_parse_hex_be);
	mu_run_test(test_pf_parse_dec_signed);
	mu_run_test(test_pf_parse_dec_unsigned);
	mu_run_test(test_pf_parse_octal);
	mu_run_test(test_pf_parse_binary);

	/* Parse: floats */
	mu_run_test(test_pf_parse_float_sized);
	mu_run_test(test_pf_parse_float_bare_deprecated);

	/* Parse: single-char specifiers */
	mu_run_test(test_pf_parse_single_char_specifiers);

	/* Parse: strings */
	mu_run_test(test_pf_parse_string_default);
	mu_run_test(test_pf_parse_string_encoding);
	mu_run_test(test_pf_parse_deprecated_Z);
	mu_run_test(test_pf_parse_deprecated_w);
	mu_run_test(test_pf_parse_deprecated_bare_X);

	/* Parse: timestamps */
	mu_run_test(test_pf_parse_timestamp_named);
	mu_run_test(test_pf_parse_timestamp_all_formats);
	mu_run_test(test_pf_parse_timestamp_deprecated);

	/* Parse: repeat / union / prefix */
	mu_run_test(test_pf_parse_repeat_digit);
	mu_run_test(test_pf_parse_repeat_brace);
	mu_run_test(test_pf_parse_repeat_default);
	mu_run_test(test_pf_parse_union);
	mu_run_test(test_pf_parse_no_union);
	mu_run_test(test_pf_parse_repeat_union_combined);
	mu_run_test(test_pf_parse_pointer_prefix);
	mu_run_test(test_pf_parse_array_prefix);
	mu_run_test(test_pf_parse_scalar_no_array);
	mu_run_test(test_pf_parse_pointer_array);

	/* Parse: names / type_name */
	mu_run_test(test_pf_parse_field_names);
	mu_run_test(test_pf_parse_skip_no_name);
	mu_run_test(test_pf_parse_struct_type_name);
	mu_run_test(test_pf_parse_enum_type_name);
	mu_run_test(test_pf_parse_bitfield_type_name);

	/* Parse: complex */
	mu_run_test(test_pf_parse_complex_mixed);
	mu_run_test(test_pf_parse_many_fields);

	/* Read: integers */
	mu_run_test(test_pf_read_hex8);
	mu_run_test(test_pf_read_hex16_le);
	mu_run_test(test_pf_read_hex16_be);
	mu_run_test(test_pf_read_hex32_le);
	mu_run_test(test_pf_read_hex32_be);
	mu_run_test(test_pf_read_hex64_le);
	mu_run_test(test_pf_read_signed8);
	mu_run_test(test_pf_read_signed16_le);
	mu_run_test(test_pf_read_signed32_le);
	mu_run_test(test_pf_read_signed64_le);
	mu_run_test(test_pf_read_unsigned32_le);

	/* Read: floats */
	mu_run_test(test_pf_read_float32_le);
	mu_run_test(test_pf_read_float64_le);

	/* Read: char */
	mu_run_test(test_pf_read_char);

	/* Read: multi-field offsets */
	mu_run_test(test_pf_read_multi_field_offsets);

	/* Read: skip */
	mu_run_test(test_pf_read_skip);

	/* Read: arrays */
	mu_run_test(test_pf_read_array);
	mu_run_test(test_pf_read_array_x4);

	/* Read: buffer boundary */
	mu_run_test(test_pf_read_buffer_too_short);

	/* Read: union */
	mu_run_test(test_pf_read_union);

	/* Read: timestamps */
	mu_run_test(test_pf_read_timestamp_unix32);

	/* Read: strings */
	mu_run_test(test_pf_read_zstring);

	/* Timestamp conversion */
	mu_run_test(test_pf_timestamp_to_tm_unix32);
	mu_run_test(test_pf_timestamp_to_tm_unixms);

	/* Lifecycle / NULL safety */
	mu_run_test(test_pf_format_free_null);
	mu_run_test(test_pf_values_free_null);
	mu_run_test(test_pf_ctx_lifecycle);

	/* DSL extensions */
	mu_run_test(test_pf_parse_align);
	mu_run_test(test_pf_read_align);
	mu_run_test(test_pf_parse_bits);
	mu_run_test(test_pf_read_bits_msb);
	mu_run_test(test_pf_read_bits_lsb);
	mu_run_test(test_pf_parse_bitvec_basic);
	mu_run_test(test_pf_parse_bitvec_partial_byte);
	mu_run_test(test_pf_parse_bitvec_lsb_msb_kw);
	mu_run_test(test_pf_parse_bitvec_clamp_low);
	mu_run_test(test_pf_parse_bitvec_clamp_high);
	mu_run_test(test_pf_parse_bitvec_missing_paren);
	mu_run_test(test_pf_read_bitvec_msb);
	mu_run_test(test_pf_read_bitvec_lsb);
	mu_run_test(test_pf_read_bitvec_partial);
	mu_run_test(test_pf_render_bitvec_text);
	mu_run_test(test_pf_parse_guid);
	mu_run_test(test_pf_read_guid);
	mu_run_test(test_pf_parse_lenref_array);
	mu_run_test(test_pf_read_lenref_array);
	mu_run_test(test_pf_parse_lenprefix_string);
	mu_run_test(test_pf_read_lenprefix_string);
	mu_run_test(test_pf_parse_inline_bitfield);
	mu_run_test(test_pf_read_inline_bitfield_render);
	mu_run_test(test_pf_parse_tlv);
	mu_run_test(test_pf_read_tlv_raw);

	/* Phase 5: render modes, timestamp coverage, pointer deref */
	mu_run_test(test_pf_render_modes_basic);
	mu_run_test(test_pf_render_quiet_ofield_filter);
	mu_run_test(test_pf_timestamp_all_formats_size);
	mu_run_test(test_pf_timestamp_filetime_decode);
	mu_run_test(test_pf_pointer_deref_via_callback);
	mu_run_test(test_pf_parse_empty_returns_empty);
	mu_run_test(test_pf_read_zero_length_buffer);
	mu_run_test(test_pf_format_oneshot);

	/* Diagnostic / error reporting */
	mu_run_test(test_pf_diag_unknown_specifier_position);
	mu_run_test(test_pf_diag_bits_without_width);
	mu_run_test(test_pf_diag_align_without_n);
	mu_run_test(test_pf_diag_deprecated_w);
	mu_run_test(test_pf_diag_tlv_missing_close_paren);
	mu_run_test(test_pf_diag_tlv_bad_tag_type);
	mu_run_test(test_pf_diag_tlv_unknown_key);
	mu_run_test(test_pf_diag_errors_to_string);
	mu_run_test(test_pf_diag_clean_parse_no_errors);
	mu_run_test(test_pf_diag_source_captured);

	/* Ambiguity audit -- disambiguation between similar DSL forms */
	mu_run_test(test_pf_ambig_b4_vs_B4);
	mu_run_test(test_pf_ambig_inline_bitfield_vs_typed);
	mu_run_test(test_pf_ambig_t4_vs_t_paren);
	mu_run_test(test_pf_ambig_z_vs_z_paren_vs_z_lenprefix);
	mu_run_test(test_pf_ambig_V_bare_vs_V_paren);
	mu_run_test(test_pf_ambig_struct_vs_skip);
	mu_run_test(test_pf_ambig_x4_vs_x);
	mu_run_test(test_pf_ambig_d_vs_D_endian);
	mu_run_test(test_pf_ambig_align_vs_skip);
	mu_run_test(test_pf_ambig_bits_lt_gt);

	/* Palette / color (issue #782) */
	mu_run_test(test_pf_palette_text_basic);
	mu_run_test(test_pf_palette_null_no_color);
	mu_run_test(test_pf_palette_partial_palette);
	mu_run_test(test_pf_palette_null_passes_through_input_esc);

	/* DOT mode regression (surfaced building PR showcase) */
	mu_run_test(test_pf_render_dot_timestamp);
	mu_run_test(test_pf_render_dot_column_aligned);
	mu_run_test(test_pf_render_dot_single_field);
	mu_run_test(test_pf_render_dot_empty);
	mu_run_test(test_pf_render_dot_tlv);

	/* Regressions surfaced by the property harness */
	mu_run_test(test_pf_parse_empty_input);
	mu_run_test(test_pf_parse_null_input);
	mu_run_test(test_pf_parse_bitfield_missing_eq_diagnostic);
	mu_run_test(test_pf_parse_bitfield_empty_field_diagnostic);
	mu_run_test(test_pf_render_bitfield_inline_idempotent);

	return tests_passed != tests_run;
}

mu_main(all_tests)
