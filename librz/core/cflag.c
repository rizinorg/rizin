// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_flag.h>
#include <rz_util.h>
#include <rz_cons.h>

struct print_flag_t {
	RzFlag *f;
	PJ *pj;
	RzTable *tbl;
	bool in_range;
	ut64 range_from;
	ut64 range_to;
	RzSpace *fs;
	bool real;
};

static bool print_flag_name(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (rz_flag_item_get_offset(flag) < u->range_from || rz_flag_item_get_offset(flag) >= u->range_to)) {
		return true;
	}
	rz_cons_printf("%s\n", rz_flag_item_get_name(flag));
	return true;
}

static bool print_flag_json(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (rz_flag_item_get_offset(flag) < u->range_from || rz_flag_item_get_offset(flag) >= u->range_to)) {
		return true;
	}
	const char *realname = RZ_STR_ISEMPTY(rz_flag_item_get_realname(flag)) ? rz_flag_item_get_name(flag) : rz_flag_item_get_realname(flag);
	pj_o(u->pj);
	pj_ks(u->pj, "name", rz_flag_item_get_name(flag));
	pj_ks(u->pj, "realname", realname);
	pj_ki(u->pj, "size", rz_flag_item_get_size(flag));
	if (rz_flag_item_get_alias(flag)) {
		pj_ks(u->pj, "alias", rz_flag_item_get_alias(flag));
	} else {
		pj_kn(u->pj, "offset", rz_flag_item_get_offset(flag));
	}
	if (rz_flag_item_get_comment(flag)) {
		pj_ks(u->pj, "comment", rz_flag_item_get_comment(flag));
	}
	pj_end(u->pj);
	return true;
}

static bool print_flag_rizin(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	char *comment_b64 = NULL, *tmp = NULL;
	if (u->in_range && (rz_flag_item_get_offset(flag) < u->range_from || rz_flag_item_get_offset(flag) >= u->range_to)) {
		return true;
	}
	if (!u->fs || rz_flag_item_get_space(flag) != u->fs) {
		u->fs = rz_flag_item_get_space(flag);
		rz_cons_printf("fs %s\n", u->fs ? u->fs->name : "*");
	}
	if (RZ_STR_ISNOTEMPTY(rz_flag_item_get_comment(flag))) {
		comment_b64 = rz_base64_encode_dyn((const ut8 *)rz_flag_item_get_comment(flag), strlen(rz_flag_item_get_comment(flag)));
		// prefix the armored string with "base64:"
		if (comment_b64) {
			tmp = rz_str_newf("base64:%s", comment_b64);
			free(comment_b64);
			comment_b64 = tmp;
		}
	}
	if (rz_flag_item_get_alias(flag)) {
		rz_cons_printf("fa %s %s\n", rz_flag_item_get_name(flag), rz_flag_item_get_alias(flag));
		if (comment_b64) {
			rz_cons_printf("\"fC %s %s\"\n",
				rz_flag_item_get_name(flag), rz_str_get(comment_b64));
		}
	} else {
		rz_cons_printf("f %s %" PFMT64d " 0x%08" PFMT64x " %s\n",
			rz_flag_item_get_name(flag), rz_flag_item_get_size(flag), rz_flag_item_get_offset(flag),
			rz_str_get(comment_b64));
	}

	free(comment_b64);
	return true;
}

static bool print_flag_orig_name(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (rz_flag_item_get_offset(flag) < u->range_from || rz_flag_item_get_offset(flag) >= u->range_to)) {
		return true;
	}
	if (rz_flag_item_get_alias(flag)) {
		const char *n = u->real ? rz_flag_item_get_realname(flag) : rz_flag_item_get_name(flag);
		rz_cons_printf("%s %" PFMT64d " %s\n", rz_flag_item_get_alias(flag), rz_flag_item_get_size(flag), n);
	} else {
		const char *n = u->real ? rz_flag_item_get_realname(flag) : (u->f->realnames ? rz_flag_item_get_realname(flag) : rz_flag_item_get_name(flag));
		rz_cons_printf("0x%08" PFMT64x " %" PFMT64d " %s\n", rz_flag_item_get_offset(flag), rz_flag_item_get_size(flag), n);
	}
	return true;
}

static bool print_flag_table(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (rz_flag_item_get_offset(flag) < u->range_from || rz_flag_item_get_offset(flag) >= u->range_to)) {
		return true;
	}
	if (!RZ_STR_ISEMPTY(rz_flag_item_get_name(flag))) {
		RzSpace *space = rz_flag_item_get_space(flag);
		const char *spaceName = (space && space->name) ? space->name : "";
		const char *realname = RZ_STR_ISEMPTY(rz_flag_item_get_realname(flag)) ? rz_flag_item_get_name(flag) : rz_flag_item_get_realname(flag);
		rz_table_add_rowf(u->tbl, "Xdsss", rz_flag_item_get_offset(flag), rz_flag_item_get_size(flag), spaceName, rz_flag_item_get_name(flag), realname);
	}
	return true;
}

static void flag_print(RzFlag *f, RzCmdStateOutput *state, ut64 range_from, ut64 range_to, bool in_range) {
	rz_return_if_fail(f);
	struct print_flag_t u = {
		.f = f,
		.in_range = in_range,
		.range_from = range_from,
		.range_to = range_to,
		.real = false
	};

	switch (state->mode) {
	case RZ_OUTPUT_MODE_QUIET:
		rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_name, &u);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_orig_name, &u);
		break;
	case RZ_OUTPUT_MODE_JSON:
		u.pj = state->d.pj;
		pj_a(state->d.pj);
		rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_json, &u);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_RIZIN:
		rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_rizin, &u);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		u.tbl = state->d.t;
		rz_cmd_state_output_set_columnsf(state, "Xdsss", "addr", "size", "space", "name", "realname");
		rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_table, &u);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI void rz_core_flag_print(RzFlag *f, RzCmdStateOutput *state) {
	flag_print(f, state, UT64_MAX, UT64_MAX, false);
}

RZ_IPI void rz_core_flag_real_name_print(RzFlag *f, RzCmdStateOutput *state) {
	struct print_flag_t u = {
		.f = f,
		.in_range = false,
		.range_from = UT64_MAX,
		.range_to = UT64_MAX,
		.real = true
	};
	rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_orig_name, &u);
}

RZ_IPI void rz_core_flag_range_print(RzFlag *f, RzCmdStateOutput *state, ut64 range_from, ut64 range_to) {
	flag_print(f, state, range_from, range_to, true);
}
