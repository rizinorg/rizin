// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_internal.h
 * \brief Cross-translation-unit glue for the pf parser engine.
 *
 * The pf engine is split across several .c files under librz/type/pf/:
 *
 *   pf_parser.c           parse driver, dispatch, ctx, public API, reader core
 *   pf_parser_string.c    string/encoding spec parsing + reading
 *   pf_parser_struct.c    nested struct / union read
 *   pf_parser_bitfield.c  inline + typed bitfield parsing
 *   pf_parser_bitvec.c    v(N) bitvector parsing + reading
 *   pf_parser_array.c     array-count resolution helpers
 *   pf_parser_time.c      timestamp wire-formats
 *   pf_parser_tlv.c       TLV records
 *   pf_render.c           shared render helpers + rz_pf_render dispatch
 *   pf_render_text.c      text + quiet renderers
 *   pf_render_json.c      JSON renderer
 *   pf_render_cstruct.c   C-struct renderer
 *   pf_render_dot.c       Graphviz DOT renderer
 *   pf_render_sd.c        RzStructuredData renderer
 *
 * This header declares the handful of symbols that cross those file
 * boundaries. It is private to librz/type/pf/ and is not installed.
 *
 * Diagnostics: the leaf parse helpers record positioned warnings/errors
 * onto the format object that rz_pf_parse() is currently building. That
 * object (and the source-string base pointer used to compute column
 * positions) lives in file-static state in pf_parser.c; the accessors
 * pf_current_fmt() / pf_current_src() expose it, and the PF_DIAG macro
 * below wraps the common "emit to format + mirror to RZ_LOG_WARN" path
 * so every TU writes diagnostics the same way.
 *
 * Naming: symbols already prefixed pf_ / rz_pf_ keep their names; the
 * helpers promoted from file-static to cross-TU during the split are
 * likewise prefixed pf_ to make their shared status obvious.
 */

#ifndef PF_INTERNAL_H
#define PF_INTERNAL_H

#include <rz_pf.h>
#include "pf_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Diagnostics (defined in pf_parser.c) ---------------------------- */

void pf_emit_error(RzPfFormat *fmt, RzPfErrSeverity sev,
	RzPfErrCategory cat, int pos, const char *fmt_str, ...);
RzPfFormat *pf_current_fmt(void);
const char *pf_current_src(void);
int pf_pos_of(const char *p);

/* Position-aware diagnostic usable from any parse helper in any pf TU. */
#define PF_DIAG(sev, cat, src_ptr, ...) \
	do { \
		int _pos = pf_pos_of(src_ptr); \
		RzPfFormat *_fmt = pf_current_fmt(); \
		if (_fmt) { \
			pf_emit_error(_fmt, (sev), (cat), _pos, __VA_ARGS__); \
		} \
		RZ_LOG_WARN(__VA_ARGS__); \
	} while (0)

/* ---- Shared parse helpers (defined in pf_parser.c) ------------------- */

int pf_parse_paren_annotation(const char *p, const char *end, char **out_name);

/* ---- String / encoding (pf_parser_string.c) -------------------------- */

int pf_parse_string_spec(const char *p, const char *end, RzPfField *fld);
char *pf_decode_string(const ut8 *raw, int raw_len, RzStrEnc enc);
int pf_read_inline_string(const ut8 *buf, int off, int buf_len,
	RzStrEnc enc, char **out_str, bool *out_overflow);
int pf_read_lenprefix_string(const ut8 *buf, int off, int avail,
	RzStrEnc enc, int prefix_size, bool len_in_bytes,
	bool be, char **out_str);
char *pf_deref_string(const RzPfCtx *ctx, ut64 addr, RzStrEnc enc);

/* ---- Bitfields (pf_parser_bitfield.c) -------------------------------- */

int pf_parse_bitflag_list(const char *body,
	RzPfBitflag **out_arr, int *out_count);
int pf_maybe_inline_bitfield(const char *p_after_spec,
	const char *spec_end, RzPfField *fld, int size_bytes);

/* ---- Bitvector (pf_parser_bitvec.c) ---------------------------------- */

int pf_parse_bitvec_spec(const char *p, const char *spec_end, RzPfField *fld);
int pf_read_bitvec_field(const RzPfField *fld, const ut8 *buf,
	int off, int avail, RzPfValue *val);

/* ---- Arrays (pf_parser_array.c) -------------------------------------- */

/* Per-format reading state. Threads the bit cursor through consecutive
 * :N fields and lets [@name] fields look back at previously-parsed
 * siblings in the same format scope. Tagged so it can be forward-declared
 * across TUs. */
struct pf_read_state_t {
	int bit_cursor; //<< 0..7, bit position within the
			//   current byte for :N fields.
	const RzPfValue *siblings; //<< borrowed array of values already
				   //   parsed in this scope (for [@name]).
	int n_siblings;
};
typedef struct pf_read_state_t ReadState;

ut64 pf_lookup_sibling_value(const ReadState *st, const char *name);
int pf_resolve_array_count(const RzPfField *fld, const ReadState *st);

/* ---- Struct / union read (pf_parser_struct.c) ------------------------ */

int pf_read_nested_struct(const RzPfField *fld, const ut8 *buf,
	int off, int buf_len, ut64 base_addr,
	const RzPfCtx *ctx, int depth, RzPfValue *val);

/* The core single-field reader. Defined in pf_parser.c; declared here so
 * the struct reader can recurse back into it. */
int pf_read_field(const RzPfField *fld, const ut8 *buf, int off,
	int buf_len, ut64 base_addr, const RzPfCtx *ctx,
	int depth, ReadState *st, RzPfValue *val);

/* ---- TLV (pf_parser_tlv.c) ------------------------------------------- */

int pf_parse_tlv_spec(const char *p, const char *end, RzPfField *fld);
int pf_tlv_read(const RzPfField *fld, const ut8 *buf, int off,
	int buf_len, ut64 base_addr, const RzPfCtx *ctx,
	int depth, RzPfValue *val);

#ifdef __cplusplus
}
#endif

#endif /* PF_INTERNAL_H */
