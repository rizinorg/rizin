// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_render_text.c
 * \brief Text and quiet renderers for the pf engine.
 *
 * The text mode is the default human-readable form
 * (`<offset> <name> : [endian] <value>`, one field per line, with
 * indented nested-struct children and optional palette colouring). The
 * quiet mode (`pfq` / `pfv`) emits values only, one per line, with no
 * names, offsets, or colour.
 *
 * Shared helpers (pf_scalar_text, pf_render_guid, pf_field_matches) and
 * the RenderCtx record are declared in pf_render.h.
 */

#include <rz_util.h>
#include <stdarg.h>
#include <stdio.h>

#include "pf_parser.h"
#include "pf_parser_time.h"
#include "pf_render.h"

static const char *endian_tag(RzPfEndian e) {
	switch (e) {
	case RZ_PF_ENDIAN_LE: return " [LE]";
	case RZ_PF_ENDIAN_BE: return " [BE]";
	default: return "";
	}
}

/* Compute the max name width among the children of a value (or, at
 * top level, among a vector of values). Used to right-align names
 * within one nesting level so values line up on the `=` column. */
static int compute_name_width(const RzPfValue *vals, int count) {
	int max = 0;
	for (int i = 0; i < count; i++) {
		const RzPfValue *v = &vals[i];
		if (v->type == RZ_PF_SKIP || v->type == RZ_PF_ALIGN) {
			continue;
		}
		if (v->name) {
			int n = (int)strlen(v->name);
			if (n > max) {
				max = n;
			}
		}
	}
	return max;
}

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
	int name_w = rc ? rc->name_width : 0;
	if (!pf_field_matches(v, filter)) {
		return;
	}

	for (int i = 0; i < indent; i++) {
		rz_strbuf_append(sb, "   ");
	}
	/* New layout: `<addr> : <right-padded-name> = <value> [endian]`.
	 *   - The address comes first so visually-aligned columns work
	 *     when several lines are stacked.
	 *   - The name is right-aligned within name_width so all `=`
	 *     signs line up on a single column at this nesting level.
	 *   - The endian tag (when explicit) follows the value so it
	 *     does not push the value-column right.
	 *   - Anonymous fields drop the `: name = ` part entirely and
	 *     emit just `<addr> = <value>`.
	 *   - When rc->short_offsets is set, the offset column shows
	 *     `+<n>` (delta from rc->base_offset) or `   0` for the
	 *     base. */
	if (rc && rc->short_offsets) {
		ut64 delta = v->offset >= rc->base_offset
			? (v->offset - rc->base_offset)
			: 0;
		if (delta == 0) {
			emit_coloredf(sb, pal ? pal->offset : NULL, RST,
				"%4s", "0");
		} else {
			/* ut64 decimal: at most 20 digits + sign + NUL = 22; round up to 24. */
			char buf[24];
			snprintf(buf, sizeof(buf), "+%" PFMT64u, delta);
			emit_coloredf(sb, pal ? pal->offset : NULL, RST,
				"%4s", buf);
		}
	} else {
		emit_coloredf(sb, pal ? pal->offset : NULL, RST,
			"0x%08" PFMT64x, v->offset);
	}
	if (v->name) {
		int pad = name_w - (int)strlen(v->name);
		if (pad < 0) {
			pad = 0;
		}
		rz_strbuf_append(sb, " : ");
		for (int i = 0; i < pad; i++) {
			rz_strbuf_append(sb, " ");
		}
		emit_colored(sb, pal ? pal->name : NULL, v->name, RST);
	}

	if (v->is_pointer) {
		rz_strbuf_append(sb, " = (*");
		emit_coloredf(sb, pal ? pal->hex_literal : NULL, RST,
			"0x%" PFMT64x, v->ptr_addr);
		rz_strbuf_append(sb, ")");
		/* For pointer-to-string (`*z`), append the decoded body. */
		if (v->type == RZ_PF_ZSTRING && v->scalars && v->scalars[0].v_str) {
			rz_strbuf_append(sb, " \"");
			rz_strbuf_append(sb, v->scalars[0].v_str);
			rz_strbuf_append(sb, "\"");
			rz_strbuf_append(sb, "\n");
			return;
		} else if (v->type == RZ_PF_STRUCT && v->nchildren > 0) {
			/* Pointer-to-struct (`*?`): the reader recursed through
			 * the pointer and populated children. Show them after
			 * the `(*ptr)` annotation, matching the legacy
			 * pointer-chasing rendering. NULL/zero targets fall
			 * through to the bare `(*0x0)` form. */
			rz_strbuf_append(sb, " struct<");
			emit_colored(sb, pal ? pal->label : NULL,
				v->type_name ? v->type_name : "anon", RST);
			rz_strbuf_append(sb, "> {\n");
			RenderCtx sub = { .field_filter = NULL,
				.pal = pal,
				.name_width = compute_name_width(v->children, v->nchildren),
				.short_offsets = rc ? rc->short_offsets : false,
				.base_offset = rc ? rc->base_offset : 0,
				.typedb = rc ? rc->typedb : NULL };
			for (int c = 0; c < v->nchildren; c++) {
				render_val_text(sb, &v->children[c], indent + 1, &sub);
			}
			for (int i = 0; i < indent; i++) {
				rz_strbuf_append(sb, "   ");
			}
			rz_strbuf_append(sb, "}\n");
			return;
		} else if (v->scalars && v->count >= 1) {
			/* Numeric pointer (e.g. `*d4`, `*x2`, `*u8`): the
			 * reader populated scalars[0] with the dereferenced
			 * value. Show it after the pointer literal so the
			 * user sees both the target address and the value
			 * stored there. */
			rz_strbuf_append(sb, " ");
			pf_scalar_text(sb, v, 0, rc ? rc->typedb : NULL);
		}
		rz_strbuf_append(sb, "\n");
		return;
	}

	/* String pointer (bare `s`): the field type itself is a pointer-to-
	 * string -- v->ptr_addr is the dereferenced target, scalars[0].v_str
	 * is the decoded body. When the deref produced a non-empty string,
	 * mirror the `*z` form so the user sees both the pointer target and
	 * the string; when it didn't (unmapped target / NUL at target),
	 * fall back to a bare `""` to match the legacy behaviour and avoid
	 * advertising a phantom pointer. */
	if (v->type == RZ_PF_STRPTR && v->scalars) {
		const char *s = v->scalars[0].v_str;
		bool have_body = s && *s;
		rz_strbuf_append(sb, " = ");
		if (have_body) {
			rz_strbuf_append(sb, "(*");
			emit_coloredf(sb, pal ? pal->hex_literal : NULL, RST,
				"0x%" PFMT64x, v->ptr_addr);
			rz_strbuf_append(sb, ") ");
		}
		rz_strbuf_append(sb, "\"");
		if (s) {
			rz_strbuf_append(sb, s);
		}
		rz_strbuf_append(sb, "\"\n");
		return;
	}

	/* Struct: header line `<addr> : <name> = struct<typename> {`,
	 * then children indented by one level with their own
	 * sibling-alignment, then `}` on its own line at parent indent. */
	if (v->type == RZ_PF_STRUCT && v->nchildren > 0) {
		rz_strbuf_append(sb, " = struct<");
		emit_colored(sb, pal ? pal->label : NULL,
			v->type_name ? v->type_name : "anon", RST);
		rz_strbuf_append(sb, "> {\n");
		/* Recurse with filter cleared and child name_width
		 * computed from the immediate children. */
		RenderCtx sub = { .field_filter = NULL,
			.pal = pal,
			.name_width = compute_name_width(v->children, v->nchildren),
			.short_offsets = rc ? rc->short_offsets : false,
			.base_offset = rc ? rc->base_offset : 0,
			.typedb = rc ? rc->typedb : NULL };
		for (int c = 0; c < v->nchildren; c++) {
			render_val_text(sb, &v->children[c], indent + 1, &sub);
		}
		for (int i = 0; i < indent; i++) {
			rz_strbuf_append(sb, "   ");
		}
		rz_strbuf_append(sb, "}\n");
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
		/* GUID rendering goes through pf_render_guid which uses raw
		 * sprintf into the strbuf. Wrap the whole thing in color. */
		if (pal && pal->hex_literal) {
			rz_strbuf_append(sb, pal->hex_literal);
		}
		pf_render_guid(sb, v->scalars[0].v_raw, v->guid_layout);
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
				if (k) {
					rz_strbuf_append(sb, " ");
				}
				rz_strbuf_appendf(sb, "%02x",
					v->scalars[0].v_raw[k]);
			}
			rz_strbuf_append(sb, "\n");
		}
		return;
	}

	/* Raw / uint128 */
	if (is_raw_type(v->type) && v->scalars && v->scalars[0].v_raw) {
		for (int k = 0; k < v->raw_len; k++) {
			if (k) {
				rz_strbuf_append(sb, " ");
			}
			rz_strbuf_appendf(sb, "%02x",
				v->scalars[0].v_raw[k]);
		}
		rz_strbuf_append(sb, "\n");
		return;
	}

	/* Bitvector -- render N bits as `[ 1 0 1 1 0 0 1 0 | 1 1 0 0 ]`
	 * with a `|` separator every 8 bits for readability, and an
	 * `(N-bit)` suffix for orientation. */
	if (v->type == RZ_PF_BITVEC) {
		rz_strbuf_append(sb, "[ ");
		for (int k = 0; k < v->count; k++) {
			if (k && (k % 8) == 0) {
				rz_strbuf_append(sb, "| ");
			}
			rz_strbuf_appendf(sb, "%d ",
				(int)v->scalars[k].v_u8);
		}
		rz_strbuf_appendf(sb, "] (%d-bit)\n", v->bit_width);
		return;
	}

	/* Timestamp */
	if (v->type == RZ_PF_TIMESTAMP) {
		rz_strbuf_appendf(sb, "[%s]",
			rz_pf_timefmt_as_string(v->timefmt));
		emit_coloredf(sb, pal ? pal->endian : NULL, RST,
			"%s", endian_tag(v->endian));
		if (v->count >= 1 && v->scalars) {
			rz_strbuf_append(sb, " ");
			if (v->count > 1) {
				rz_strbuf_append(sb, "[ ");
				for (int k = 0; k < v->count; k++) {
					if (k) {
						rz_strbuf_append(sb, ", ");
					}
					rz_pf_timestamp_format_str(sb, v->timefmt,
						&v->scalars[k]);
				}
				rz_strbuf_append(sb, " ]");
			} else {
				rz_pf_timestamp_format_str(sb, v->timefmt,
					&v->scalars[0]);
			}
		}
		rz_strbuf_append(sb, "\n");
		return;
	}

	/* Pristine omits the endian/encoding tags inline; they're
	 * implicit in the spec. Keeping them suppressed preserves the
	 * `<addr> = <value>` shape that integration tests assert on. */

	/* Array or scalar. The renderer colours hex literals (0x...)
	 * after the fact by scanning the appended text; this keeps the
	 * pf_scalar_text() helper free of palette plumbing. */
	int mark = (int)rz_strbuf_length(sb);
	if (v->count > 1 && v->scalars) {
		rz_strbuf_append(sb, "[ ");
		for (int k = 0; k < v->count; k++) {
			if (k) {
				rz_strbuf_append(sb, ", ");
			}
			pf_scalar_text(sb, v, k, rc ? rc->typedb : NULL);
		}
		rz_strbuf_append(sb, " ]");
	} else if (v->count == 1 && v->scalars) {
		pf_scalar_text(sb, v, 0, rc ? rc->typedb : NULL);
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
	/* Trailing endian tag (when explicit). Placed AFTER the value
	 * so it doesn't disturb the `=`-column alignment. The
	 * endian_tag() returns its own leading space. */
	if (v->endian == RZ_PF_ENDIAN_LE || v->endian == RZ_PF_ENDIAN_BE) {
		emit_coloredf(sb, pal ? pal->endian : NULL, RST,
			"%s", endian_tag(v->endian));
	}
	/* When the field type didn't produce a value (e.g. an unknown
	 * inline type like "pf"), strip the dangling trailing space
	 * before the newline so the EXPECT output is clean. */
	{
		const char *buf = rz_strbuf_get(sb);
		int len = (int)rz_strbuf_length(sb);
		if (buf && len > 0 && buf[len - 1] == ' ') {
			rz_strbuf_slice(sb, 0, len - 1);
		}
	}
	rz_strbuf_append(sb, "\n");
}

char *pf_render_text(const RzPfValue *vals, int count,
	const RenderCtx *rc) {
	RzStrBuf *sb = rz_strbuf_new("");
	/* Compute the top-level name-alignment width once. The caller's
	 * RenderCtx (if any) is augmented with this width so each
	 * render_val_text call right-aligns its name to the same column. */
	RenderCtx top = {
		.field_filter = rc ? rc->field_filter : NULL,
		.pal = rc ? rc->pal : NULL,
		.name_width = compute_name_width(vals, count),
		.short_offsets = rc ? rc->short_offsets : false,
		.base_offset = rc ? rc->base_offset
				  : (count > 0 ? vals[0].offset : 0),
		.typedb = rc ? rc->typedb : NULL,
	};
	for (int i = 0; i < count; i++) {
		render_val_text(sb, &vals[i], 0, &top);
	}
	return rz_strbuf_drain(sb);
}

// Render: quiet (compact) mode
char *pf_render_quiet(const RzPfValue *vals, int count,
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
		if (!pf_field_matches(v, filter)) {
			continue;
		}
		if (v->type == RZ_PF_TIMESTAMP && v->count >= 1 && v->scalars) {
			rz_pf_timestamp_format_str(sb, v->timefmt,
				&v->scalars[0]);
		} else if (v->type == RZ_PF_GUID && v->scalars && v->scalars[0].v_raw) {
			pf_render_guid(sb, v->scalars[0].v_raw, v->guid_layout);
		} else if (v->type == RZ_PF_TLV) {
			rz_strbuf_appendf(sb,
				"0x%" PFMT64x ":%" PFMT64u,
				v->tlv_tag, v->tlv_length);
		} else if (is_raw_type(v->type) && v->scalars && v->scalars[0].v_raw) {
			/* Raw byte-sequential types (RZ_PF_UINT128, RZ_PF_HEXDUMP):
			 * pf_scalar_text() has no per-byte case for these, so handle
			 * them locally as a space-separated hex stream. Without
			 * this branch, quiet/pfv/pfq mode emitted '?' for `pf Q`. */
			for (int k = 0; k < v->raw_len; k++) {
				if (k) {
					rz_strbuf_append(sb, " ");
				}
				rz_strbuf_appendf(sb, "%02x",
					v->scalars[0].v_raw[k]);
			}
		} else if (v->count >= 1 && v->scalars) {
			for (int k = 0; k < v->count; k++) {
				if (k) {
					rz_strbuf_append(sb, " ");
				}
				pf_scalar_text(sb, v, k, rc ? rc->typedb : NULL);
			}
		}
		rz_strbuf_append(sb, "\n");
	}
	return rz_strbuf_drain(sb);
}
