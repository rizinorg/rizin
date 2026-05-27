// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_render_json.c
 * \brief JSON renderer for the pf engine.
 *
 * Emits a JSON array of field objects, each annotated with type, size,
 * offset, endianness and (for nested structs) a "fields" array under a
 * "struct_type" key. The public rz_pf_render_json() returns the PJ
 * object directly so callers can embed it; rz_pf_render() wraps it to
 * produce a string.
 *
 * Shared helpers (pf_field_matches, pf_render_guid) are declared in
 * pf_render.h; pf_type_repr_name is file-local to this TU.
 */

#include <rz_util.h>

#include "pf_parser.h"
#include "pf_parser_time.h"
#include "pf_render.h"

/* JSON "type" field for a parsed RzPfFieldType. Returns a stable
 * string literal; for types not enumerated below, falls back to the
 * C-type spelling from rz_pf_field_ctype(). */
static const char *pf_type_repr_name(RzPfFieldType type) {
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
	case RZ_PF_BITVEC: return "bitvec";
	case RZ_PF_TLV: return "tlv";
	case RZ_PF_ALIGN: return "align";
	default:
		return rz_pf_field_ctype(type);
	}
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
	if (!pf_field_matches(v, field_filter)) {
		return;
	}

	pj_o(j);
	if (v->name) {
		pj_ks(j, "name", v->name);
	}
	pj_ks(j, "type", pf_type_repr_name(v->type));

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
		pf_render_guid(tmp, v->scalars[0].v_raw, v->guid_layout);
		pj_ks(j, "value", rz_strbuf_get(tmp));
		rz_strbuf_free(tmp);
		pj_end(j);
		return;
	}

	/* Bitvector -- compact as a string of '0'/'1' so consumers can
	 * regex-match runs without iterating an array. Also include the
	 * bit width as a sibling field so size info isn't lost. */
	if (v->type == RZ_PF_BITVEC) {
		pj_kn(j, "bit_width", v->bit_width);
		char *bits = malloc(v->count + 1);
		if (bits) {
			for (int k = 0; k < v->count; k++) {
				bits[k] = '0' + (v->scalars[k].v_u8 & 1);
			}
			bits[v->count] = '\0';
			pj_ks(j, "value", bits);
			free(bits);
		}
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
	if (pf_value_has_inline_bitflags(v)) {
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
