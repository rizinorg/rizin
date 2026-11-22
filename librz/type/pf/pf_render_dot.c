// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_render_dot.c
 * \brief Graphviz DOT renderer for the pf engine.
 *
 * Emits a `digraph` with each top-level field as a record cell inside a
 * single `shape=record` node. Used by `pfd`.
 *
 * Shared helpers (pf_field_matches,
 * pf_render_guid, pf_scalar_text) are declared in pf_render.h.
 */

#include <rz_util.h>

#include "pf_parser.h"
#include "pf_parser_time.h"
#include "pf_render.h"

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
	case RZ_PF_BITVEC: return 'v';
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
 * the column-aligned DOT renderer. The typedb is consulted so RZ_PF_ENUM
 * values surface their symbolic name (e.g., `0x0000ffff ; ET_HIPROC`)
 * the same way text mode already does -- without it, the DOT graph
 * shows only the raw hex. */
static void render_dot_value_cell(RzStrBuf *sb, const RzPfValue *v,
	const RzTypeDB *typedb) {
	if (v->is_pointer) {
		rz_strbuf_appendf(sb, "*0x%" PFMT64x, v->ptr_addr);
		return;
	}
	if (v->type == RZ_PF_STRUCT && v->nchildren > 0) {
		rz_strbuf_appendf(sb, "%s",
			v->type_name ? v->type_name : "struct");
		return;
	}
	if (pf_value_has_inline_bitflags(v)) {
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
		pf_render_guid(sb, v->scalars[0].v_raw, v->guid_layout);
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
		pf_scalar_text(tmp, v, 0, typedb);
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
	return pf_field_matches(v, field_filter);
}

char *pf_render_dot(const RzPfValue *vals, int count,
	const char *graph_label, const char *field_filter,
	const RzTypeDB *typedb) {
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
		render_dot_value_cell(sb, v, typedb);
	}
	rz_strbuf_append(sb, "}");

	rz_strbuf_append(sb, "\"];\n}\n");
	return rz_strbuf_drain(sb);
}
