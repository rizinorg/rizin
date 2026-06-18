// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file pf_parser_struct.c
 * \brief Nested struct / union reading for the pf engine.
 *
 * A `?(typename)` field (or a `(typename)name` annotation) names a pf
 * format already registered in the type DB. pf_read_nested_struct()
 * resolves that name, parses the sub-format, and walks it over the
 * buffer, producing the child value tree. Unions (`0`-prefixed formats)
 * overlay all members at offset 0; arrays repeat the whole sub-format.
 *
 * Recursion bottoms out via ctx->max_depth and goes back through
 * pf_read_field() (the core single-field reader in pf_parser.c).
 *
 * Cross-TU entry points carry the pf_ prefix (see pf_internal.h).
 */

#include <rz_util.h>
#include <stdlib.h>

#include "pf_parser.h"
#include "pf_internal.h"

int pf_read_nested_struct(const RzPfField *fld, const ut8 *buf,
	int off, int buf_len, ut64 base_addr,
	const RzPfCtx *ctx, int depth, RzPfValue *val) {
	if (!ctx || !ctx->typedb || !fld->type_name) {
		return 0;
	}
	if (depth >= ctx->max_depth) {
		RZ_LOG_WARN("pf: max depth for '%s'\n", fld->type_name);
		return 0;
	}
	const char *sub_str = rz_pf_resolve_name(
		ctx->typedb, fld->type_name);
	if (RZ_STR_ISEMPTY(sub_str)) {
		RZ_LOG_WARN("pf: unknown format '%s'\n", fld->type_name);
		return 0;
	}
	RzPfFormat *sub = rz_pf_parse(sub_str);
	if (!sub) {
		return 0;
	}

	int repeat = (fld->array_count > 0)
		? fld->array_count
		: sub->repeat;
	int child_cap = sub->nfields * repeat;
	val->children = RZ_NEWS0(RzPfValue, child_cap);
	val->nchildren = 0;
	/* Record the array length so filter-path navigators (e.g.
	 * `name.field[N]`) can slice the flat children list into a
	 * per-iteration window of `nchildren / count` entries. For a
	 * scalar struct field (no array prefix) `repeat` is 1, which
	 * matches the default. */
	val->count = repeat;

	int total = 0;
	for (int r = 0; r < repeat && off + total < buf_len; r++) {
		int soff = 0, max_soff = 0;
		/* Fresh per-iteration read state: bit cursor and sibling
		 * lookup are scoped to this struct instance. */
		ReadState sub_st = { 0 };
		sub_st.siblings = val->children;
		for (int fi = 0; fi < sub->nfields; fi++) {
			if (sub->is_union) {
				soff = 0;
			}
			if (val->nchildren >= child_cap) {
				child_cap *= 2;
				val->children = realloc(val->children,
					child_cap * sizeof(RzPfValue));
				sub_st.siblings = val->children;
			}
			sub_st.n_siblings = val->nchildren;
			int c = pf_read_field(&sub->fields[fi], buf,
				off + total + soff, buf_len,
				base_addr, ctx, depth + 1,
				&sub_st,
				&val->children[val->nchildren]);
			val->nchildren++;
			if (sub->is_union) {
				max_soff = RZ_MAX(max_soff, c);
			} else {
				soff += c;
			}
		}
		total += sub->is_union ? max_soff : soff;
	}
	rz_pf_format_free(sub);
	return total;
}
