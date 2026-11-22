// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_render.c
 * \brief Shared render helpers and the rz_pf_render() dispatcher.
 *
 * Rendering is split into one translation unit per output mode (see
 * pf_render.h for the map). This file holds:
 *
 *   - the helpers shared across modes: pf_field_matches(),
 *     pf_scalar_text() (text/cstruct/dot), and pf_render_guid()
 *     (text/json/cstruct/dot);
 *   - rz_pf_render(), the mode dispatcher that fans out to the
 *     per-mode entry points declared in pf_render.h.
 *
 * The per-mode renderers live in pf_render_text.c, pf_render_json.c,
 * pf_render_cstruct.c, pf_render_dot.c and pf_render_sd.c. Helpers
 * shared with pf_parser.c (is_string_type / is_raw_type) live in
 * pf_parser.h as static inlines.
 */

#include <rz_endian.h>
#include <rz_util.h>

#include "pf_parser.h"
#include "pf_parser_time.h"
#include "pf_render.h"

// Render helpers

bool pf_field_matches(const RzPfValue *v, const char *field_filter) {
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

void pf_scalar_text(RzStrBuf *sb, const RzPfValue *val, int k,
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
		} else if (typedb && val->type_name) {
			/* No inline `B4(K=V,...)` flags but we do have a named
			 * type. Look it up in the typedb and treat each enum
			 * case as a set-bit name, so `B (pe_characteristics)`
			 * over 0x00008140 renders as
			 * `0x00008140 : IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
			 *               | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
			 *               | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE`.
			 * Unmatched bits are emitted as a trailing hex residual
			 * so the caller can see what couldn't be named. */
			RzBaseType *bt = rz_type_db_get_base_type(
				(RzTypeDB *)typedb, val->type_name);
			if (bt && bt->kind == RZ_BASE_TYPE_KIND_ENUM) {
				ut32 residual = v;
				bool first = true;
				rz_strbuf_append(sb, " : ");
				RzTypeEnumCase *cas;
				rz_vector_foreach (&bt->enum_data.cases, cas) {
					ut32 fv = (ut32)cas->val;
					if (fv && (v & fv) == fv) {
						if (!first) {
							rz_strbuf_append(sb, " | ");
						}
						rz_strbuf_append(sb, cas->name);
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
		}
		break;
	}
	case RZ_PF_BITS:
		rz_strbuf_appendf(sb, "%" PFMT64u " (%d-bit)",
			s->v_u64, val->bit_width);
		break;
	case RZ_PF_BITVEC:
		/* Quiet rendering uses the same per-element loop as numeric
		 * arrays, so each scalar is just the 0/1 bit. */
		rz_strbuf_appendf(sb, "%d", (int)(s->v_u8 & 1));
		break;
	default:
		rz_strbuf_append(sb, "?");
		break;
	}
}

/* Render a 16-byte GUID buffer with the canonical
 * xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx form, honoring the layout
 * variant stored on the value. */
void pf_render_guid(RzStrBuf *sb, const ut8 *b, RzPfGuidLayout lay) {
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
	bool short_off = opts ? opts->short_offsets : false;
	RenderCtx rc = {
		.field_filter = filter,
		.pal = pal,
		.short_offsets = short_off,
		.base_offset = count > 0 ? vals[0].offset : 0,
		.typedb = typedb,
	};
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
		return pf_render_cstruct(vals, count, filter, label, typedb);
	case RZ_PF_MODE_QUIET:
		return pf_render_quiet(vals, count, &rc);
	case RZ_PF_MODE_DOT:
		return pf_render_dot(vals, count, label, filter, typedb);
	case RZ_PF_MODE_TEXT:
	default:
		return pf_render_text(vals, count, &rc);
	}
}
