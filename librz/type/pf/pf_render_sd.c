// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_render_sd.c
 * \brief RzStructuredData renderer for the pf engine.
 *
 * Converts a decoded RzPfValue[] vector into an RzStructuredData tree --
 * the generic key/value document model that rz_bin, ASN.1 and PKCS#7
 * already produce. Unlike the JSON renderer (which annotates each field
 * with size/offset/endian metadata), the structured-data tree is
 * value-centric: it mirrors the logical shape of the parsed data so it
 * composes naturally with rz_structured_data_to_json() / _to_yaml() and
 * the generic iterator.
 *
 * Mapping:
 *   - top level             -> map keyed by field name
 *   - scalar field          -> unsigned / signed / double / string
 *   - char                  -> 1-char string
 *   - array of scalars      -> array
 *   - nested struct         -> sub-map (struct_type recorded under "_type")
 *   - struct array          -> array of sub-maps
 *   - bitvector v(N)        -> array of 0/1 unsigned entries
 *   - raw / uint128 / GUID  -> byte block (hex)
 *   - timestamp             -> formatted string (+ raw under "<name>_raw")
 *   - pointer               -> unsigned pointer value (deref shown when present)
 *
 * Names: fields without a name get `field_<index>` so every entry has a
 * stable key. Cross-TU entry point declared in rz_pf.h.
 */

#include <rz_util.h>
#include <string.h>

#include "pf_parser.h"
#include "pf_parser_time.h"
#include "pf_internal.h"

/* A scalar decoded into one of structured-data's primitive shapes. The
 * two emit paths (map-keyed and array-appended) share this single
 * classification so the per-type switch lives in exactly one place. */
typedef enum {
	SD_UNSIGNED,
	SD_SIGNED,
	SD_DOUBLE,
	SD_STRING, //<< str points at borrowed external memory
	SD_CHAR, //<< a single printable char, stored in chbuf
} SdScalarKind;

typedef struct {
	SdScalarKind kind;
	bool hex; //<< for SD_UNSIGNED: render as hexadecimal
	ut64 u; //<< SD_UNSIGNED
	st64 s; //<< SD_SIGNED
	double d; //<< SD_DOUBLE
	const char *str; //<< SD_STRING (borrowed; never NULL)
	char chbuf[2]; //<< SD_CHAR backing store (self-contained, copy-safe)
} SdScalar;

/* Resolve the string view for SD_STRING / SD_CHAR. For SD_CHAR this
 * returns a pointer into the scalar's own chbuf, which is why callers
 * must pass the *copy* they hold (not the classifier's temporary). */
static const char *sd_str_of(const SdScalar *c) {
	if (c->kind == SD_CHAR) {
		return c->chbuf;
	}
	return c->str ? c->str : "";
}

/* Classify scalar index \p k of value \p v into an SdScalar. */
static SdScalar sd_classify_scalar(const RzPfValue *v, int k) {
	const RzPfScalar *s = &v->scalars[k];
	SdScalar out = { 0 };
	switch (v->type) {
	case RZ_PF_HEX8:
		out.kind = SD_UNSIGNED, out.hex = true, out.u = s->v_u8;
		break;
	case RZ_PF_HEX16:
		out.kind = SD_UNSIGNED, out.hex = true, out.u = s->v_u16;
		break;
	case RZ_PF_HEX32:
	case RZ_PF_ENUM:
	case RZ_PF_BITFIELD:
		out.kind = SD_UNSIGNED, out.hex = true, out.u = s->v_u32;
		break;
	case RZ_PF_HEX64:
	case RZ_PF_POINTER:
		out.kind = SD_UNSIGNED, out.hex = true, out.u = s->v_u64;
		break;
	case RZ_PF_DEC_U8:
	case RZ_PF_OCT8:
	case RZ_PF_BIN8:
		out.kind = SD_UNSIGNED, out.u = s->v_u8;
		break;
	case RZ_PF_DEC_U16:
	case RZ_PF_OCT16:
	case RZ_PF_BIN16:
		out.kind = SD_UNSIGNED, out.u = s->v_u16;
		break;
	case RZ_PF_DEC_U32:
	case RZ_PF_OCT32:
	case RZ_PF_BIN32:
		out.kind = SD_UNSIGNED, out.u = s->v_u32;
		break;
	case RZ_PF_DEC_U64:
	case RZ_PF_OCT64:
	case RZ_PF_BIN64:
	case RZ_PF_ULEB128:
	case RZ_PF_BITS:
		out.kind = SD_UNSIGNED, out.u = s->v_u64;
		break;
	case RZ_PF_BITVEC:
		/* The bitvector reader stores each bit in v_u8 (one scalar
		 * per bit). Reading v_u64 here would alias to a different
		 * byte of the union on big-endian hosts, so read v_u8. */
		out.kind = SD_UNSIGNED, out.u = s->v_u8 & 1;
		break;
	case RZ_PF_DEC_S8:
		out.kind = SD_SIGNED, out.s = s->v_s8;
		break;
	case RZ_PF_DEC_S16:
		out.kind = SD_SIGNED, out.s = s->v_s16;
		break;
	case RZ_PF_DEC_S32:
		out.kind = SD_SIGNED, out.s = s->v_s32;
		break;
	case RZ_PF_DEC_S64:
	case RZ_PF_SLEB128:
		out.kind = SD_SIGNED, out.s = s->v_s64;
		break;
	case RZ_PF_FLOAT16:
	case RZ_PF_FLOAT32:
		out.kind = SD_DOUBLE, out.d = (double)s->v_f32;
		break;
	case RZ_PF_FLOAT64:
		out.kind = SD_DOUBLE, out.d = s->v_f64;
		break;
	case RZ_PF_CHAR:
		out.kind = SD_CHAR;
		out.chbuf[0] = (s->v_u8 >= 0x20 && s->v_u8 < 0x7f)
			? (char)s->v_u8
			: '.';
		out.chbuf[1] = '\0';
		break;
	case RZ_PF_ZSTRING:
	case RZ_PF_STRPTR:
		out.kind = SD_STRING, out.str = s->v_str ? s->v_str : "";
		break;
	default:
		out.kind = SD_UNSIGNED, out.hex = true, out.u = s->v_u64;
		break;
	}
	return out;
}

/* Append a classified scalar to an array node. */
static void sd_array_add(RzStructuredData *arr, const SdScalar *c) {
	switch (c->kind) {
	case SD_UNSIGNED:
		rz_structured_data_array_add_unsigned(arr, c->u, c->hex);
		break;
	case SD_SIGNED:
		rz_structured_data_array_add_signed(arr, c->s);
		break;
	case SD_DOUBLE:
		rz_structured_data_array_add_double(arr, c->d);
		break;
	case SD_STRING:
	case SD_CHAR:
		rz_structured_data_array_add_string(arr, sd_str_of(c));
		break;
	}
}

/* Add a classified scalar to a map node under \p key. */
static void sd_map_add(RzStructuredData *m, const char *key,
	const SdScalar *c) {
	switch (c->kind) {
	case SD_UNSIGNED:
		rz_structured_data_map_add_unsigned(m, key, c->u, c->hex);
		break;
	case SD_SIGNED:
		rz_structured_data_map_add_signed(m, key, c->s);
		break;
	case SD_DOUBLE:
		rz_structured_data_map_add_double(m, key, c->d);
		break;
	case SD_STRING:
	case SD_CHAR:
		rz_structured_data_map_add_string(m, key, sd_str_of(c));
		break;
	}
}

/* True for fields that carry no value and should be skipped entirely. */
static bool sd_is_skippable(const RzPfValue *v) {
	return v->type == RZ_PF_SKIP || v->type == RZ_PF_ALIGN;
}

/* Forward decl: a struct child is itself rendered into a fresh sub-map. */
static void sd_fill_map(RzStructuredData *map,
	const RzPfValue *vals, int count, const char *filter);

/* Render \p v under \p key into the parent map \p m. */
static void sd_map_add_value(RzStructuredData *m, const char *key,
	const RzPfValue *v) {
	/* Timestamp: human-readable string, plus the raw scalar under a
	 * sibling "<key>_raw" key so consumers can recover the wire value. */
	if (v->type == RZ_PF_TIMESTAMP && v->count >= 1 && v->scalars) {
		RzStrBuf *tmp = rz_strbuf_new("");
		rz_pf_timestamp_format_str(tmp, v->timefmt, &v->scalars[0]);
		rz_structured_data_map_add_string(m, key, rz_strbuf_get(tmp));
		rz_strbuf_free(tmp);
		char *rawk = rz_str_newf("%s_raw", key);
		if (rawk) {
			if (rz_pf_timefmt_is_float(v->timefmt)) {
				rz_structured_data_map_add_double(m, rawk,
					v->scalars[0].v_f64);
			} else {
				rz_structured_data_map_add_unsigned(m, rawk,
					v->scalars[0].v_u64, false);
			}
			free(rawk);
		}
		return;
	}

	/* Raw byte payloads (hexdump, uint128, GUID): emit as a byte block.
	 * GUID prints with colon separators to echo the canonical form;
	 * everything else uses the plain hex stream. */
	if (is_raw_type(v->type) && v->scalars && v->scalars[0].v_raw) {
		RzStructuredDataFormat fmt =
			(v->type == RZ_PF_GUID)
			? RZ_STRUCTURED_DATA_FORMAT_COLON
			: RZ_STRUCTURED_DATA_FORMAT_DEFAULT;
		rz_structured_data_map_add_bytes(m, key,
			v->scalars[0].v_raw, v->raw_len, fmt);
		return;
	}

	/* Nested struct: a sub-map of its children. When the pointer-to-
	 * struct deref produced children they are rendered the same way. */
	if (v->type == RZ_PF_STRUCT && v->nchildren > 0) {
		RzStructuredData *sub =
			rz_structured_data_map_add_map(m, key);
		if (!sub) {
			return;
		}
		if (v->type_name) {
			rz_structured_data_map_add_string(sub, "_type",
				v->type_name);
		}
		sd_fill_map(sub, v->children, v->nchildren, NULL);
		return;
	}

	/* Pointer with no struct body: the pointer value itself, plus the
	 * dereferenced scalar/string when the reader captured one. */
	if (v->is_pointer) {
		rz_structured_data_map_add_unsigned(m, key, v->ptr_addr, true);
		if (v->scalars && v->count >= 1) {
			char *dk = rz_str_newf("%s_deref", key);
			if (dk) {
				SdScalar c = sd_classify_scalar(v, 0);
				sd_map_add(m, dk, &c);
				free(dk);
			}
		}
		return;
	}

	/* Bitvector and multi-element arrays: an array of values. */
	if (v->type == RZ_PF_BITVEC ||
		(v->count > 1 && v->scalars && !is_raw_type(v->type))) {
		RzStructuredData *arr =
			rz_structured_data_map_add_array(m, key);
		if (!arr) {
			return;
		}
		for (int k = 0; k < v->count; k++) {
			SdScalar c = sd_classify_scalar(v, k);
			sd_array_add(arr, &c);
		}
		return;
	}

	/* Plain single scalar. */
	if (v->scalars && v->count >= 1) {
		SdScalar c = sd_classify_scalar(v, 0);
		sd_map_add(m, key, &c);
		return;
	}

	/* No payload (e.g. empty string pointer): record an empty string so
	 * the key is still present. */
	rz_structured_data_map_add_string(m, key, "");
}

/* Fill \p map with one entry per value in \p vals, honouring \p filter
 * (a plain field name; NULL renders everything). */
static void sd_fill_map(RzStructuredData *map,
	const RzPfValue *vals, int count, const char *filter) {
	for (int i = 0; i < count; i++) {
		const RzPfValue *v = &vals[i];
		if (sd_is_skippable(v)) {
			continue;
		}
		if (!RZ_STR_ISEMPTY(filter) &&
			(!v->name || strcmp(v->name, filter))) {
			continue;
		}
		char namebuf[32];
		const char *key = v->name;
		if (!key) {
			rz_strf(namebuf, "field_%d", i);
			key = namebuf;
		}
		sd_map_add_value(map, key, v);
	}
}

/**
 * \brief Render decoded pf values into an RzStructuredData tree.
 *
 * Builds a value-centric key/value document (the model shared with
 * rz_bin, ASN.1 and PKCS#7): a top-level map keyed by field name
 * (unnamed fields become `field_<n>`), with scalars as typed entries,
 * arrays and bitvectors as arrays, nested structs as sub-maps tagged
 * with `_type`, raw/GUID payloads as byte blocks, and timestamps as a
 * formatted string plus a `<name>_raw` sibling. The result composes
 * directly with rz_structured_data_to_json() / _to_yaml().
 *
 * \param vals  Decoded value vector from rz_pf_read(); must be non-NULL.
 * \param count Number of top-level values; must be > 0.
 * \param opts  Optional render options; only \c field_filter is used
 *              (restricting output to a single named field). May be NULL.
 * \return Newly-allocated map tree, or NULL on bad input or allocation
 *         failure. Caller frees with rz_structured_data_free().
 */
RZ_API RZ_OWN RzStructuredData *rz_pf_render_sd(
	RZ_BORROW const RzPfValue *vals, int count,
	RZ_NULLABLE const RzPfRenderOpts *opts) {
	rz_return_val_if_fail(vals && count > 0, NULL);
	const char *filter = opts ? opts->field_filter : NULL;
	RzStructuredData *map = rz_structured_data_new_map();
	if (!map) {
		return NULL;
	}
	sd_fill_map(map, vals, count, filter);
	return map;
}
