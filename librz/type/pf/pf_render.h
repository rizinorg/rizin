// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_render.h
 * \brief Cross-translation-unit glue for the pf renderers.
 *
 * Rendering is split across one TU per output mode under librz/type/pf/:
 *
 *   pf_render.c           shared helpers + the rz_pf_render() dispatcher
 *   pf_render_text.c      text + quiet modes
 *   pf_render_json.c      JSON mode (+ rz_pf_render_json entry point)
 *   pf_render_cstruct.c   C-struct mode
 *   pf_render_dot.c       Graphviz DOT mode
 *   pf_render_sd.c        RzStructuredData tree (rz_pf_render_sd)
 *
 * This header declares the handful of helpers and the RenderCtx record
 * shared between those TUs. It is private to librz/type/pf/ and is not
 * installed. The per-mode entry points themselves (render_text,
 * render_quiet, render_json, render_cstruct, render_dot) are declared
 * here too so the dispatcher in pf_render.c can call across files.
 */

#ifndef PF_RENDER_H
#define PF_RENDER_H

#include <rz_pf.h>
#include <rz_util/rz_strbuf.h>
#include "pf_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Per-render context that bundles the filter, palette, and the
 * sibling-name alignment width. The name_width is set by the parent
 * frame so that all values at one nesting level line up on the `=`
 * column. NULL fields mean "no filter" / "no color" / "no alignment". */
typedef struct {
	const char *field_filter;
	const RzPfPalette *pal;
	int name_width;
	/* When true, format offsets as `+<delta>` from base_offset. */
	bool short_offsets;
	/* The format's base address. Used to compute deltas in short
	 * mode; ignored otherwise. */
	ut64 base_offset;
	/* Optional typedb for enum-member name resolution. */
	const RzTypeDB *typedb;
} RenderCtx;

/* ---- Shared helpers (defined in pf_render.c) ------------------------- */

/* True when \p v passes the (possibly empty) field-name filter. */
bool pf_field_matches(const RzPfValue *v, const char *field_filter);

/* Render the 16 GUID bytes \p b in the canonical xxxxxxxx-... form,
 * honouring the layout (MS mixed-endian / BE / LE). */
void pf_render_guid(RzStrBuf *sb, const ut8 *b, RzPfGuidLayout lay);

/* Render one scalar (index \p k of \p val) as human-readable text,
 * resolving enum/bitflag member names through \p typedb when present. */
void pf_scalar_text(RzStrBuf *sb, const RzPfValue *val, int k,
	const RzTypeDB *typedb);

/* True when \p v is a single bitfield value that carries a resolved
 * inline flag list (B4(R=1,...) or a typedb-named bitfield). The JSON
 * and DOT renderers both special-case this to emit the active flag
 * names; the predicate keeps that test in one place. */
static inline bool pf_value_has_inline_bitflags(const RzPfValue *v) {
	return v->type == RZ_PF_BITFIELD && v->bitflags &&
		v->bitflag_count > 0 && v->count == 1 && v->scalars;
}

/* ---- Per-mode entry points (each defined in its own TU) -------------- */

char *pf_render_text(const RzPfValue *vals, int count, const RenderCtx *rc);
char *pf_render_quiet(const RzPfValue *vals, int count, const RenderCtx *rc);
char *pf_render_cstruct(const RzPfValue *vals, int count,
	const char *filter, const char *struct_name, const RzTypeDB *typedb);
char *pf_render_dot(const RzPfValue *vals, int count,
	const char *graph_label, const char *filter, const RzTypeDB *typedb);

#ifdef __cplusplus
}
#endif

#endif /* PF_RENDER_H */
