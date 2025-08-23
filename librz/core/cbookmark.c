#include "rz_util/rz_str.h"
#include <rz_cmd.h>
#include <rz_bookmark.h>
#include <rz_util.h>
#include <rz_cons.h>

struct print_bookmark_t {
	RzBookmark *b;
	PJ *pj;
	RzTable *tbl;
	bool in_range;
	ut64 range_from;
	ut64 range_to;
};

static bool print_bookmark_name(RzBookmarkItem *bm, void *user) {
	struct print_bookmark_t *u = (struct print_bookmark_t *)user;
	if (u->in_range && (bm->to < u->range_from || bm->from > u->range_to)) {
		return true;
	}
	rz_cons_printf("%s\n", bm->name);
	return true;
}

static bool print_bookmark_json(RzBookmarkItem *bm, void *user) {
	struct print_bookmark_t *u = (struct print_bookmark_t *)user;
	if (u->in_range && (bm->to < u->range_from || bm->from > u->range_to)) {
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

static bool print_bookmark_range_name(RzBookmarkItem *bm, void *user) {
	struct print_bookmark_t *u = (struct print_bookmark_t *)user;
	if (u->in_range && (bm->to < u->range_from || bm->from > u->range_to)) {
		return true;
	}
	rz_cons_printf("[0x%08" PFMT64x " - 0x%08" PFMT64x "] %s\n",
		bm->from, bm->to, bm->name);
	return true;
}

static bool print_bookmark_rizin(RzBookmarkItem *bm, void *user) {
	struct print_bookmark_t *u = (struct print_bookmark_t *)user;
	if (u->in_range && (bm->to < u->range_from || bm->from > u->range_to)) {
		return true;
	}
	char *comment_b64 = NULL, *tmp = NULL;
	if (RZ_STR_ISNOTEMPTY(bm->comment)) {
		comment_b64 = rz_base64_encode_dyn((const ut8 *)bm->comment, strlen(bm->comment));
		// prefix the armored string with "base64:"
		if (comment_b64) {
			tmp = rz_str_newf("base64:%s", comment_b64);
			free(comment_b64);
			comment_b64 = tmp;
		}
	}
	ut64 size = (bm->to >= bm->from) ? (bm->to - bm->from) : 0;
	rz_cons_printf("[0x%08" PFMT64x " - 0x%08" PFMT64x "] %s %" PFMT64u " %s\n",
		bm->from, bm->to, bm->name, size, rz_str_get_null(comment_b64));

	return true;
}

static bool print_bookmark_table(RzBookmarkItem *bm, void *user) {
	struct print_bookmark_t *u = (struct print_bookmark_t *)user;
	if (u->in_range && (bm->to < u->range_from || bm->from > u->range_to)) {
		return true;
	}
	if (!RZ_STR_ISEMPTY(bm->name)) {
		const char *realname = RZ_STR_ISEMPTY(bm->realname) ? bm->name : bm->realname;
		rz_table_add_rowf(u->tbl, "XXss", bm->from, bm->to, bm->name, realname);
	}
	return true;
}

static void bookmark_print(RzBookmark *b, RzCmdStateOutput *state,
	ut64 range_from, ut64 range_to, bool in_range) {
	rz_return_if_fail(b);
	struct print_bookmark_t u = {
		.b = b,
		.in_range = in_range,
		.range_from = range_from,
		.range_to = range_to
	};

	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_bookmark_foreach(b, print_bookmark_name, &u);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_bookmark_foreach(b, print_bookmark_range_name, &u);
		break;
	case RZ_OUTPUT_MODE_JSON:
		u.pj = state->d.pj;
		pj_a(state->d.pj);
		rz_bookmark_foreach(b, print_bookmark_json, &u);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		rz_bookmark_foreach(b, print_bookmark_rizin, &u);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		u.tbl = state->d.t;
		rz_cmd_state_output_set_columnsf(state, "XXss", "from", "to", "name", "realname");
		rz_bookmark_foreach(b, print_bookmark_table, &u);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI void rz_core_bookmark_print(RzBookmark *b, RzCmdStateOutput *state) {
	bookmark_print(b, state, UT64_MAX, UT64_MAX, false);
}

RZ_IPI void rz_core_bookmark_range_print(RzBookmark *b, RzCmdStateOutput *state,
	ut64 range_from, ut64 range_to) {
	bookmark_print(b, state, range_from, range_to, true);
}
