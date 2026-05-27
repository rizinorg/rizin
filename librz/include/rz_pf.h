// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PF_H
#define RZ_PF_H

#include <rz_util.h>
#include <rz_type.h>

#ifdef __cplusplus
extern "C" {
#endif

// Output mode
typedef enum {
	RZ_PF_MODE_TEXT = 0,
	RZ_PF_MODE_JSON = 1,
	RZ_PF_MODE_CSTRUCT = 2,
	RZ_PF_MODE_QUIET = 3,
	RZ_PF_MODE_WRITE = 4,
	RZ_PF_MODE_DOT = 5, //<< Graphviz `digraph` rendering
} RzPfMode;

// Diagnostic severity
typedef enum {
	RZ_PF_ERR_WARN = 0, //<< recoverable, parsing continues
	RZ_PF_ERR_ERROR = 1, //<< structural problem; output is degraded
} RzPfErrSeverity;

// Diagnostic category -- coarse grouping for filtering / tests
typedef enum {
	RZ_PF_ERRC_SYNTAX, //<< malformed token, unknown specifier
	RZ_PF_ERRC_SEMANTIC, //<< well-formed token but contradictory
	RZ_PF_ERRC_RANGE, //<< value out of range (bit width, prefix)
	RZ_PF_ERRC_DEPRECATED, //<< legacy syntax with a new equivalent
	RZ_PF_ERRC_DATA, //<< buffer too short, unresolved [@name]
	RZ_PF_ERRC_DEPTH, //<< recursion bound hit
} RzPfErrCategory;

/* A single diagnostic emitted during parsing or reading. The `pos`
 * field is a 0-based offset into the format string where the
 * offending token starts; for diagnostics raised at read-time
 * (`unresolved [@name]`, buffer too short) `pos` is the position of
 * the field's spec inside the source format. */
typedef struct {
	RzPfErrSeverity severity;
	RzPfErrCategory category;
	int pos;
	char *message; //<< owned
} RzPfError;

/**
 * \brief Optional palette of ANSI / terminal color codes for text
 *        rendering.
 *
 * When passed to rz_pf_render() in MODE_TEXT, each non-NULL string
 * is emitted before the corresponding token and the `reset` field
 * is emitted after. When the palette pointer itself is NULL the
 * renderer produces uncolored canonical output (this is the default
 * and what integration tests match against).
 *
 * Lifetime: the palette and its strings are borrowed; the renderer
 * does not copy them. The caller must keep them alive for the
 * duration of the render call.
 */
typedef struct {
	const char *offset; //<< field offset prefix (0x...)
	const char *name; //<< field name
	const char *endian; //<< [LE] / [BE] markers
	const char *hex_literal; //<< value hex literals (0x...)
	const char *label; //<< trailing typedb-resolved labels
	const char *reset; //<< terminator (e.g. "\x1b[0m")
} RzPfPalette;

/**
 * \brief Optional render-time parameters.
 *
 * Bundles the three non-essential inputs to rz_pf_render so the API
 * stays compact as more options are added. All fields are optional;
 * a NULL pointer or an all-NULL struct selects the default behaviour
 * (no filter, no special label, no colorisation).
 */
typedef struct {
	/* Filter: when set, only top-level fields whose name equals
	 * this string are emitted. Other fields are dropped. Used by
	 * `pf .foo.bar` syntax to display a single sub-field. */
	const char *field_filter;

	/* DOT-mode label: top-level graph label, used by `pfd <name>`
	 * to put the format's name on the root record. Ignored in
	 * non-DOT modes. */
	const char *graph_label;

	/* Optional color palette for MODE_TEXT. */
	const RzPfPalette *palette;

	/* Optional typedb borrow used at render time to resolve enum
	 * member names (so `pf E (elf_type)type` can print
	 * `; ET_DYN` after the numeric value). When NULL the renderer
	 * still emits the numeric value but no symbolic suffix. */
	const RzTypeDB *typedb;

	/* When true, MODE_TEXT renders offsets as deltas from the format's
	 * base address (`+<n>` with width-2 zero-padded hex) instead of
	 * the absolute address. The first field at offset 0 is shown as
	 * `   0` for alignment. Useful for self-contained struct dumps
	 * where the absolute load address is noise. Controlled via the
	 * `scr.pf.short` core config option. */
	bool short_offsets;
} RzPfRenderOpts;

// Per-field endianess
typedef enum {
	RZ_PF_ENDIAN_CTX = 0, //<< inherit from RzPfCtx::big_endian
	RZ_PF_ENDIAN_LE = 1, //<< explicitly little-endian (lower case)
	RZ_PF_ENDIAN_BE = 2, //<< explicitly big-endian    (UPPER CASE)
} RzPfEndian;

// Timestamp format enum
typedef enum {
	RZ_PF_TIMEFMT_UNIX32,
	RZ_PF_TIMEFMT_UNIX64,
	RZ_PF_TIMEFMT_UNIXMS,
	RZ_PF_TIMEFMT_UNIXUS,
	RZ_PF_TIMEFMT_UNIXNS,
	RZ_PF_TIMEFMT_FILETIME,
	RZ_PF_TIMEFMT_DOS,
	RZ_PF_TIMEFMT_HFS,
	RZ_PF_TIMEFMT_OLETIME,
	RZ_PF_TIMEFMT_WEBKIT,
	RZ_PF_TIMEFMT_COCOA,
} RzPfTimeFmt;

// Field type enum -- consistent {repr}{bytes} scheme for integers,
// encoding-aware strings, and sized timestamps.
typedef enum {
	// Hex (x)
	RZ_PF_HEX8, //<< x1
	RZ_PF_HEX16, //<< x2
	RZ_PF_HEX32, //<< x4
	RZ_PF_HEX64, //<< x8

	// Signed decimal (d)
	RZ_PF_DEC_S8, //<< d1
	RZ_PF_DEC_S16, //<< d2
	RZ_PF_DEC_S32, //<< d4
	RZ_PF_DEC_S64, //<< d8

	// Unsigned decimal (u)
	RZ_PF_DEC_U8, //<< u1
	RZ_PF_DEC_U16, //<< u2
	RZ_PF_DEC_U32, //<< u4
	RZ_PF_DEC_U64, //<< u8

	// Octal (o)
	RZ_PF_OCT8, //<< o1
	RZ_PF_OCT16, //<< o2
	RZ_PF_OCT32, //<< o4
	RZ_PF_OCT64, //<< o8

	// Binary (b)
	RZ_PF_BIN8, //<< b1
	RZ_PF_BIN16, //<< b2
	RZ_PF_BIN32, //<< b4
	RZ_PF_BIN64, //<< b8

	// IEEE 754 floats
	RZ_PF_FLOAT16, //<< f2 / F2
	RZ_PF_FLOAT32, //<< f4 / F4
	RZ_PF_FLOAT64, //<< f8 / F8

	// Special fixed-size
	RZ_PF_CHAR, //<< c  -- single byte, displayed as character
	RZ_PF_UINT128, //<< Q  -- 128-bit unsigned

	// Parameterized timestamp
	RZ_PF_TIMESTAMP, //<< t(...) / T(...)

	// Encoding-aware strings
	RZ_PF_ZSTRING, //<< z or z(enc) -- inline null-terminated string with optional encoding
	RZ_PF_STRPTR, //<< s or s(enc) -- pointer to null-terminated string with optional encoding

	// Pointers / variable-length
	RZ_PF_POINTER, //<< p  -- pointer with symbol resolution
	RZ_PF_HEXDUMP, //<< X  -- raw hex byte dump
	RZ_PF_ULEB128, //<< U  -- unsigned LEB128
	RZ_PF_SLEB128, //<< L  -- signed LEB128

	// Typed composites
	RZ_PF_ENUM, //<< E  -- enum (4 bytes, resolved via typedb)
	RZ_PF_BITFIELD, //<< B  -- bitfield (4 bytes, resolved via typedb or
			//        inline B4(K=V,...) with named flags)
	RZ_PF_STRUCT, //<< ?  -- nested struct
	RZ_PF_SKIP, //<< .  -- skip bytes

	// DSL extensions
	RZ_PF_ALIGN, //<< @N -- align read cursor to N-byte boundary
	RZ_PF_BITS, //<< :N -- read N bits (1..64) from a packed bitstream
	RZ_PF_GUID, //<< G  -- 16-byte GUID/UUID, layout-aware
	RZ_PF_TLV, //<< V(t=..,l=..,...)  -- single TLV record
} RzPfFieldType;

// Bit order for RZ_PF_BITS within a byte.
typedef enum {
	RZ_PF_BITORDER_MSB = 0, //<< default, network/DWARF order
	RZ_PF_BITORDER_LSB = 1, //<< Intel-ish order
} RzPfBitOrder;

// GUID/UUID layout variants.
typedef enum {
	RZ_PF_GUID_MS = 0, //<< default: Microsoft mixed-endian
			   //   (D1 LE u32, D2 LE u16, D3 LE u16, D4 8 raw)
	RZ_PF_GUID_BE = 1, //<< RFC 4122 big-endian (network order)
	RZ_PF_GUID_LE = 2, //<< all-little-endian
} RzPfGuidLayout;

// Bitfield flag entry parsed from inline B4(NAME=VALUE,...) syntax.
typedef struct {
	char *name; //<< owned
	ut64 value;
} RzPfBitflag;

// TLV record parameters parsed from V(t=...,l=...,d=...,h=...,e=...).
typedef struct {
	int tag_size; //<< 1, 2, 4 or 8 bytes
	int len_size; //<< 1, 2, 4 or 8 bytes
	RzPfEndian tag_endian;
	RzPfEndian len_endian;
	bool len_includes_header; //<< if true, len counts tag+len+value
	char *dispatch_name; //<< owned, may be NULL -- typedb registry name
} RzPfTlvSpec;

// Parsed field descriptor
typedef struct {
	RzPfFieldType type;
	RzPfEndian endian; //<< per-field byte order
	char *name; //<< field name (owned, may be NULL)
	char *type_name; //<< struct/enum/bitfield type (owned, may be NULL)
	RzStrEnc encoding; //<< for z/s: string encoding (default UTF8)
	RzPfTimeFmt timefmt; //<< for t/T: timestamp format
	int array_count; //<< -1 = scalar, >=1 = fixed-size array
	bool is_pointer; //<< '*' prefix: dereference through pointer

	/* DSL extensions */
	char *length_ref; //<< [@name]: name of earlier scalar field
			  //   to read as the array count; owned.
	int str_len_prefix; //<< for z/s: 0 = NUL-terminated (default),
			    //   else 1/2/4/8 = length-prefix size.
	bool str_len_in_bytes; //<< for z/s with prefix: true = length is in
			       //  bytes (BSTR-style), false = chars (default).
	int str_fixed_len; //<< for z/s introduced via `[N]z`/`[N]s`:
			   //   read exactly N bytes; 0 = not fixed.
	int align_to; //<< for RZ_PF_ALIGN: alignment in bytes.
	int bit_width; //<< for RZ_PF_BITS: 1..64.
		       //   For RZ_PF_ENUM/BITFIELD introduced via the
		       //   `[N]E`/`[N]B` form, N (1..8) is the byte
		       //   width of the underlying scalar; otherwise
		       //   the default of 4 bytes applies.
	RzPfBitOrder bit_order;
	RzPfGuidLayout guid_layout;

	/* Inline bitfield K=V map (when type==BITFIELD and given inline,
	 * not via typedb). Owned array; sized via bitflag_count. */
	RzPfBitflag *bitflags;
	int bitflag_count;
	int bitfield_size; //<< for inline B(N=..): 1/2/4/8

	RzPfTlvSpec *tlv_spec; //<< for RZ_PF_TLV: owned, non-NULL.
} RzPfField;

// Parsed format
typedef struct {
	RzPfField *fields;
	int nfields;
	int repeat; //<< outer repetition (default 1)
	bool is_union; //<< leading '0': all fields share offset 0

	/* Diagnostics collected during parsing. Owned array. Even when
	 * `nerrors > 0` the parse may have succeeded with degraded
	 * output; check both `fields` and `errors`. */
	RzPfError *errors;
	int nerrors;

	/* Source string copy, kept for relative position diagnostics from
	 * later read / render passes (NULL if not captured). Owned. */
	char *source;
} RzPfFormat;

// Typed scalar value
typedef union {
	ut8 v_u8;
	st8 v_s8;
	ut16 v_u16;
	st16 v_s16;
	ut32 v_u32;
	st32 v_s32;
	ut64 v_u64;
	st64 v_s64;
	float v_f32;
	double v_f64;
	char *v_str; //<< owned string (always stored as UTF-8)
	ut8 *v_raw; //<< owned raw bytes (X, Q)
} RzPfScalar;

// Read value -- one field's data after reading binary
typedef struct rz_pf_value_t {
	RzPfFieldType type;
	RzPfEndian endian;

	char *name; //<< owned, may be NULL
	char *type_name; //<< owned, may be NULL
	RzStrEnc encoding; //<< for string types: original encoding
	RzPfTimeFmt timefmt;
	ut64 offset; //<< virtual address of this field
	bool is_pointer;
	bool overflow; //<< set when an inline string read reached the
	               //   end of the buffer without finding NUL; the
	               //   renderer emits `ovf "..."` to signal the
	               //   truncated display (matches legacy semantics
	               //   for unmapped / unterminated memory).
	ut64 ptr_addr; //<< if is_pointer, the dereferenced address

	int count; //<< 1 for scalar, >1 for array
	RzPfScalar *scalars; //<< owned array[count]
	int raw_len; //<< total byte length for raw fields (X, Q)

	/* Bit field metadata */
	int bit_width; //<< 1..64 for RZ_PF_BITS
	int bit_offset; //<< 0..7, position within the starting byte

	/* GUID metadata */
	RzPfGuidLayout guid_layout;

	/* Inline bitfield flag list (borrowed from the parsed field) */
	const RzPfBitflag *bitflags;
	int bitflag_count;

	/* TLV metadata */
	ut64 tlv_tag;
	ut64 tlv_length; //<< value length (not including header)

	/* Nested struct children */
	struct rz_pf_value_t *children;
	int nchildren;
} RzPfValue;

typedef int (*RzPfReadAtCb)(void *user, ut64 addr, ut8 *buf, int len);

// Context -- configuration carried through the pipeline
typedef struct {
	RzTypeDB *typedb;
	bool big_endian; //<< default for p, E, B(bare), s
	int bits; //<< 16, 32, or 64 -> pointer width
	RzPfReadAtCb read_at;
	void *read_at_user;
	int max_depth; //<< recursion guard (default 32)
} RzPfCtx;

/* Context */
RZ_API RZ_OWN RzPfCtx *rz_pf_ctx_new(void);
RZ_API void rz_pf_ctx_setup(RZ_BORROW RzPfCtx *ctx,
	RZ_NULLABLE RzTypeDB *typedb, bool big_endian, int bits,
	RZ_NULLABLE RzPfReadAtCb read_at, RZ_NULLABLE void *user);
RZ_API void rz_pf_ctx_free(RZ_NULLABLE RzPfCtx *ctx);

/* Parse */
RZ_API RZ_OWN RzPfFormat *rz_pf_parse(const char *fmt_str);
RZ_API void rz_pf_format_free(RZ_NULLABLE RzPfFormat *fmt);

/* Named format resolution */
RZ_API RZ_BORROW const char *rz_pf_resolve_name(
	RZ_BORROW const RzTypeDB *typedb, const char *name);

/* Read */
RZ_API RZ_OWN RzPfValue *rz_pf_read(
	RZ_BORROW const RzPfFormat *fmt,
	const ut8 *buf, int buf_len, ut64 base_addr,
	RZ_BORROW const RzPfCtx *ctx,
	RZ_OUT int *out_count);
RZ_API void rz_pf_values_free(RZ_NULLABLE RzPfValue *vals, int count);

/* Render
 *
 * \p opts is optional; pass NULL for default behaviour (no filter,
 * no graph label, no colorisation). See RzPfRenderOpts. */
RZ_API RZ_OWN char *rz_pf_render(
	RZ_BORROW const RzPfValue *vals, int count,
	RzPfMode mode, RZ_NULLABLE const RzPfRenderOpts *opts);
RZ_API RZ_OWN PJ *rz_pf_render_json(
	RZ_BORROW const RzPfValue *vals, int count,
	RZ_NULLABLE const RzPfRenderOpts *opts);

/* One-shot convenience: parse + read + render in a single call.
 * \p opts has the same semantics as in rz_pf_render(). */
RZ_API RZ_OWN char *rz_pf_format(
	const char *fmt_str,
	const ut8 *buf, int buf_len, ut64 base_addr,
	RZ_BORROW const RzPfCtx *ctx,
	RzPfMode mode, RZ_NULLABLE const RzPfRenderOpts *opts);

/* Utilities */
RZ_API int rz_pf_field_size(RzPfFieldType type);
RZ_API const char *rz_pf_field_ctype(RzPfFieldType type);
RZ_API int rz_pf_enc_null_unit_size(RzStrEnc enc);

/* TLV dispatch registry (see pf_parser_tlv.c).
 *
 * Format strings of the form `V(t=u1,l=u2,d=<name>)` look up `<name>`
 * in a per-typedb table; each entry maps a TLV tag (numeric) to a
 * named pf format which is then applied to the value payload. Storage
 * uses the typedb's `formats` hash with a `tlv.<name>.<hex-tag>` key
 * convention. */
RZ_API void rz_pf_tlv_register(RZ_BORROW RzTypeDB *typedb,
	const char *table_name, ut64 tag, const char *child_format_name);
RZ_API RZ_BORROW const char *rz_pf_tlv_lookup(
	RZ_BORROW const RzTypeDB *typedb,
	const char *table_name, ut64 tag);

/* Format diagnostics from rz_pf_parse(). Returns a multi-line human
 * readable rendering of all errors attached to \p fmt, using \p src
 * as the original format string for caret-position lines. The caller
 * frees the returned string. If \p fmt has no errors, returns NULL. */
RZ_API RZ_OWN char *rz_pf_format_errors_to_string(
	RZ_BORROW const RzPfFormat *fmt);

/* Convenience wrapper: parse, log all warnings/errors via RZ_LOG,
 * and return the format (or NULL on hard failure). Useful at the
 * boundary between user input and the parser. */
RZ_API RZ_OWN RzPfFormat *rz_pf_parse_verbose(const char *fmt_str);

#ifdef __cplusplus
}
#endif

#endif /* RZ_PF_H */
