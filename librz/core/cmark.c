// SPDX-FileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types_base.h>
#include <rz_util/rz_str.h>
#include <rz_cmd.h>
#include <rz_mark.h>
#include <rz_util.h>
#include <rz_cons.h>

struct print_mark_t {
	RzMark *b;
	PJ *pj;
	RzTable *tbl;
	bool in_range;
	ut64 range_from;
	ut64 range_to;
};

static bool print_mark_name(RzMarkItem *bm, void *user) {
	struct print_mark_t *u = (struct print_mark_t *)user;
	if (u->in_range &&
		!(RZ_BETWEEN(u->range_from, bm->from, u->range_to) || RZ_BETWEEN(u->range_from, bm->to, u->range_to) ||
			RZ_BETWEEN(bm->from, u->range_from, bm->to) || RZ_BETWEEN(bm->from, u->range_to, bm->to))) {
		return true;
	}
	rz_cons_printf("%s\n", bm->name);
	return true;
}

static bool print_mark_json(RzMarkItem *bm, void *user) {
	struct print_mark_t *u = (struct print_mark_t *)user;
	if (u->in_range &&
		!(RZ_BETWEEN(u->range_from, bm->from, u->range_to) || RZ_BETWEEN(u->range_from, bm->to, u->range_to) ||
			RZ_BETWEEN(bm->from, u->range_from, bm->to) || RZ_BETWEEN(bm->from, u->range_to, bm->to))) {
		return true;
	}
	const char *realname = RZ_STR_ISEMPTY(bm->realname) ? bm->name : bm->realname;
	pj_o(u->pj);
	pj_kn(u->pj, "from", bm->from);
	pj_kn(u->pj, "to", bm->to);
	pj_ks(u->pj, "name", bm->name);
	pj_ks(u->pj, "realname", realname);
	pj_ki(u->pj, "size", (bm->to >= bm->from) ? (bm->to - bm->from) : 0);
	if (bm->comment) {
		pj_ks(u->pj, "comment", bm->comment);
	}
	pj_end(u->pj);
	return true;
}

static bool print_mark_range_name(RzMarkItem *bm, void *user) {
	struct print_mark_t *u = (struct print_mark_t *)user;
	if (u->in_range &&
		!(RZ_BETWEEN(u->range_from, bm->from, u->range_to) || RZ_BETWEEN(u->range_from, bm->to, u->range_to) ||
			RZ_BETWEEN(bm->from, u->range_from, bm->to) || RZ_BETWEEN(bm->from, u->range_to, bm->to))) {
		return true;
	}
	rz_cons_printf("[0x%08" PFMT64x " - 0x%08" PFMT64x "] %s\n",
		bm->from, bm->to, bm->name);
	return true;
}

static bool print_mark_table(RzMarkItem *bm, void *user) {
	struct print_mark_t *u = (struct print_mark_t *)user;
	if (u->in_range &&
		!(RZ_BETWEEN(u->range_from, bm->from, u->range_to) || RZ_BETWEEN(u->range_from, bm->to, u->range_to) ||
			RZ_BETWEEN(bm->from, u->range_from, bm->to) || RZ_BETWEEN(bm->from, u->range_to, bm->to))) {
		return true;
	}
	if (!RZ_STR_ISEMPTY(bm->name)) {
		const char *realname = RZ_STR_ISEMPTY(bm->realname) ? bm->name : bm->realname;
		rz_table_add_rowf(u->tbl, "XXss", bm->from, bm->to, bm->name, realname);
	}
	return true;
}

static void mark_print(RzMark *b, RzCmdStateOutput *state,
	ut64 range_from, ut64 range_to, bool in_range) {
	rz_return_if_fail(b);
	struct print_mark_t u = {
		.b = b,
		.in_range = in_range,
		.range_from = range_from,
		.range_to = range_to
	};

	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_mark_foreach(b, print_mark_name, &u);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_mark_foreach(b, print_mark_range_name, &u);
		break;
	case RZ_OUTPUT_MODE_JSON:
		u.pj = state->d.pj;
		pj_a(state->d.pj);
		rz_mark_foreach(b, print_mark_json, &u);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		u.tbl = state->d.t;
		rz_cmd_state_output_set_columnsf(state, "XXss", "from", "to", "name", "realname");
		rz_mark_foreach(b, print_mark_table, &u);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI void rz_core_mark_print(RzMark *b, RzCmdStateOutput *state) {
	mark_print(b, state, UT64_MAX, UT64_MAX, false);
}

RZ_IPI void rz_core_mark_range_print(RzMark *b, RzCmdStateOutput *state,
	ut64 range_from, ut64 range_to) {
	mark_print(b, state, range_from, range_to, true);
}
