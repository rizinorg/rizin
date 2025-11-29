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
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	rz_cons_printf("%s\n", flag->name);
	return true;
}

static bool print_flag_json(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	const char *realname = RZ_STR_ISEMPTY(flag->realname) ? flag->name : flag->realname;
	pj_o(u->pj);
	pj_ks(u->pj, "name", flag->name);
	pj_ks(u->pj, "realname", realname);
	pj_ki(u->pj, "size", flag->size);
	if (flag->alias) {
		pj_ks(u->pj, "alias", flag->alias);
	} else {
		pj_kn(u->pj, "offset", flag->offset);
	}
	if (flag->comment) {
		pj_ks(u->pj, "comment", flag->comment);
	}
	pj_end(u->pj);
	return true;
}

static bool print_flag_orig_name(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	if (flag->alias) {
		const char *n = u->real ? flag->realname : flag->name;
		rz_cons_printf("%s %" PFMT64d " %s\n", flag->alias, flag->size, n);
	} else {
		const char *n = u->real ? flag->realname : (u->f->realnames ? flag->realname : flag->name);
		rz_cons_printf("0x%08" PFMT64x " %" PFMT64d " %s\n", flag->offset, flag->size, n);
	}
	return true;
}

static bool print_flag_table(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	if (!RZ_STR_ISEMPTY(flag->name)) {
		const char *spaceName = (flag->space && flag->space->name) ? flag->space->name : "";
		const char *realname = RZ_STR_ISEMPTY(flag->realname) ? flag->name : flag->realname;
		rz_table_add_rowf(u->tbl, "Xdsss", flag->offset, flag->size, spaceName, flag->name, realname);
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
