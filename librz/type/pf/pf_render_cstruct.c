// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_render_cstruct.c
 * \brief C-struct renderer for the pf engine.
 *
 * Emits a C `struct { ... }` declaration mirroring the field types,
 * with decoded values in trailing comments. When invoked as
 * `pfc <name>` against a typedb-registered format, the format name is
 * included after the `struct` keyword.
 *
 * Shared helpers (pf_field_matches,
 * pf_render_guid, pf_scalar_text) are declared in pf_render.h.
 */

#include <rz_util.h>

#include "pf_parser.h"
#include "pf_parser_time.h"
#include "pf_render.h"

static void render_val_cstruct(RzStrBuf *sb, const RzPfValue *v,
	int indent, const char *field_filter, const RzTypeDB *typedb) {
	if (v->type == RZ_PF_SKIP) {
		return;
	}
	if (v->type == RZ_PF_ALIGN) {
		return;
	}
	if (!pf_field_matches(v, field_filter)) {
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
				indent + 1, NULL, typedb);
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
			/* Pass the typedb so RZ_PF_ENUM / RZ_PF_BITFIELD can
			 * resolve their value to a member name. Without this
			 * the cstruct (pfc) output stays at the raw hex
			 * `0x00000002`; with it the comment becomes
			 * `0x00000002 ; ELFCLASS64`, matching the text-mode
			 * `pf` output. */
			pf_scalar_text(sb, v, k, typedb);
		}
		if (v->count > 6) {
			rz_strbuf_append(sb, ", ...");
		}
	}
	rz_strbuf_append(sb, " */\n");
}

char *pf_render_cstruct(const RzPfValue *vals, int count,
	const char *field_filter, const char *label, const RzTypeDB *typedb) {
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
		render_val_cstruct(sb, &vals[i], 1, field_filter, typedb);
	}
	rz_strbuf_append(sb, "};\n");
	return rz_strbuf_drain(sb);
}
