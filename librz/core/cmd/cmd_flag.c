// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <rz_cons.h>
#include <rz_core.h>
#include "../core_private.h"

static bool listFlag(RzFlagItem *flag, void *user) {
	rz_list_append(user, flag);
	return true;
}

static size_t countMatching(const char *a, const char *b) {
	size_t matches = 0;
	for (; *a && *b; a++, b++) {
		if (*a != *b) {
			break;
		}
		matches++;
	}
	return matches;
}

static const char *__isOnlySon(RzCore *core, RzList /*<RzFlagItem *>*/ *flags, const char *kw) {
	RzListIter *iter;
	RzFlagItem *f;

	size_t count = 0;
	char *fname = NULL;
	rz_list_foreach (flags, iter, f) {
		if (!strncmp(f->name, kw, strlen(kw))) {
			count++;
			if (count > 1) {
				return NULL;
			}
			fname = f->name;
		}
	}
	return fname;
}

static RzList /*<char *>*/ *__childrenFlagsOf(RzCore *core, RzList /*<RzFlagItem *>*/ *flags, const char *prefix) {
	RzList *list = rz_list_newf(free);
	RzListIter *iter, *iter2;
	RzFlagItem *f, *f2;
	char *fn;

	const size_t prefix_len = strlen(prefix);
	rz_list_foreach (flags, iter, f) {
		if (prefix_len > 0 && strncmp(f->name, prefix, prefix_len)) {
			continue;
		}
		if (prefix_len > strlen(f->name)) {
			continue;
		}
		if (rz_cons_is_breaked()) {
			break;
		}
		const char *name = f->name;
		int name_len = strlen(name);
		rz_list_foreach (flags, iter2, f2) {
			if (prefix_len > strlen(f2->name)) {
				continue;
			}
			if (prefix_len > 0 && strncmp(f2->name, prefix, prefix_len)) {
				continue;
			}
			int matching = countMatching(name, f2->name);
			if (matching < prefix_len || matching == name_len) {
				continue;
			}
			if (matching > name_len) {
				break;
			}
			if (matching < name_len) {
				name_len = matching;
			}
		}
		char *kw = rz_str_ndup(name, name_len + 1);
		const int kw_len = strlen(kw);
		const char *only = __isOnlySon(core, flags, kw);
		if (only) {
			free(kw);
			kw = strdup(only);
		} else {
			const char *fname = NULL;
			size_t fname_len = 0;
			rz_list_foreach (flags, iter2, f2) {
				if (strncmp(f2->name, kw, kw_len)) {
					continue;
				}
				if (fname) {
					int matching = countMatching(fname, f2->name);
					if (fname_len) {
						if (matching < fname_len) {
							fname_len = matching;
						}
					} else {
						fname_len = matching;
					}
				} else {
					fname = f2->name;
				}
			}
			if (fname_len > 0) {
				free(kw);
				kw = rz_str_ndup(fname, fname_len);
			}
		}

		bool found = false;
		rz_list_foreach (list, iter2, fn) {
			if (!strcmp(fn, kw)) {
				found = true;
				break;
			}
		}
		if (found) {
			free(kw);
		} else {
			if (strcmp(prefix, kw)) {
				rz_list_append(list, kw);
			} else {
				free(kw);
			}
		}
	}
	return list;
}

static void __printRecursive(RzCore *core, RzList /*<RzFlagItem *>*/ *flags, const char *name, RzOutputMode mode, int depth) {
	char *fn;
	RzListIter *iter;
	if (mode == RZ_OUTPUT_MODE_RIZIN && RZ_STR_ISEMPTY(name)) {
		rz_cons_printf("agn root\n");
	}
	if (rz_flag_get(core->flags, name)) {
		return;
	}
	RzList *children = __childrenFlagsOf(core, flags, name);
	const int name_len = strlen(name);
	rz_list_foreach (children, iter, fn) {
		if (!strcmp(fn, name)) {
			continue;
		}
		if (mode == RZ_OUTPUT_MODE_RIZIN) {
			rz_cons_printf("agn %s %s\n", fn, fn + name_len);
			rz_cons_printf("age %s %s\n", RZ_STR_ISNOTEMPTY(name) ? name : "root", fn);
		} else {
			char *pad = rz_str_pad(' ', name_len);
			rz_cons_printf("%s %s\n", pad, fn + name_len);
			free(pad);
		}
		// rz_cons_printf (".fg %s\n", fn);
		__printRecursive(core, flags, fn, mode, depth + 1);
	}
	rz_list_free(children);
}

typedef struct {
	RzAnalysisFunction *fcn;
	RzCmdStateOutput *state;
} PrintFcnLabelsCtx;

static bool print_function_labels_cb(void *user, const ut64 addr, const void *v) {
	const PrintFcnLabelsCtx *ctx = user;
	const char *name = v;
	switch (ctx->state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(ctx->state->d.pj);
		pj_kn(ctx->state->d.pj, name, addr);
		pj_end(ctx->state->d.pj);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_cons_printf("%s\n", name);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("0x%08" PFMT64x " %s   [%s + %" PFMT64d "]\n",
			addr,
			name, ctx->fcn->name,
			addr - ctx->fcn->addr);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	return true;
}

static bool flag_set_comment(RzFlagItem *item, const char *comment) {
	if (!strncmp(comment, "base64:", 7)) {
		const char *b64str = comment + 7;
		char *dec = (char *)rz_base64_decode_dyn(b64str, -1);
		if (!dec) {
			RZ_LOG_ERROR("Failed to decode base64-encoded string: \"%s\"\n", b64str);
			return false;
		}
		rz_flag_item_set_comment(item, dec);
		free(dec);
	} else {
		rz_flag_item_set_comment(item, comment);
	}
	return true;
}

RZ_IPI RzCmdStatus rz_flag_add_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *item;
	bool addFlag = true;
	ut64 size = argc > 2 ? rz_num_math(core->num, argv[2]) : 1;
	if ((item = rz_flag_get_at(core->flags, core->offset, false))) {
		RZ_LOG_ERROR("Cannot create flag \"%s\" at 0x%" PFMT64x
			     " because there is already \"%s\" flag\n",
			argv[1],
			core->offset, item->name);
		addFlag = false;
	}
	if (addFlag) {
		item = rz_flag_set(core->flags, argv[1], core->offset, size);
	}
	if (!item) {
		RZ_LOG_ERROR("Cannot create flag \"%s\" at 0x%" PFMT64x "\n", argv[1], core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc > 3) {
		return bool2status(flag_set_comment(item, argv[3]));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_append_handler(RzCore *core, int argc, const char **argv) {
	ut64 size = argc > 2 ? rz_num_math(core->num, argv[2]) : 1;
	RzFlagItem *item = rz_flag_set(core->flags, argv[1], core->offset, size);
	if (!item) {
		RZ_LOG_ERROR("Cannot create flag \"%s\" at 0x%" PFMT64x "\n", argv[1], core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc > 3) {
		return bool2status(flag_set_comment(item, argv[3]));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_local_add_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find function at 0x%" PFMT64x " offset\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_analysis_function_set_label(fcn, argv[1], core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_local_remove_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find function at 0x%" PFMT64x " offset\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_analysis_function_delete_label(fcn, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_local_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	if (!fcn) {
		RZ_LOG_ERROR("Cannot find function at 0x%" PFMT64x " offset\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cmd_state_output_array_start(state);
	PrintFcnLabelsCtx ctx = { fcn, state };
	ht_up_foreach(fcn->labels, print_function_labels_cb, &ctx);
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_local_list_all_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *fcn;
	void **it;
	rz_cmd_state_output_array_start(state);
	rz_pvector_foreach (core->analysis->fcns, it) {
		fcn = *it;
		if (!fcn->labels->count) {
			continue;
		}
		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			pj_k(state->d.pj, fcn->name);
		}
		PrintFcnLabelsCtx ctx = { fcn, state };
		ht_up_foreach(fcn->labels, print_function_labels_cb, &ctx);
		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			pj_end(state->d.pj);
		}
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_graph_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzList *flags = rz_list_newf(NULL);
	rz_flag_foreach_space(core->flags, rz_flag_space_cur(core->flags), listFlag, flags);
	if (!argv[1]) {
		__printRecursive(core, flags, "", state->mode, 0);
	} else {
		__printRecursive(core, flags, argv[1], state->mode, 0);
	}
	rz_list_free(flags);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_relocate_handler(RzCore *core, int argc, const char **argv) {
	ut64 mask = 0xffff;
	if (argc > 3) {
		mask = rz_num_math(core->num, argv[3]);
	}
	ut64 from = rz_num_math(core->num, argv[1]);
	ut64 to = rz_num_math(core->num, argv[2]);
	int ret = rz_flag_relocate(core->flags, from, mask, to);
	RZ_LOG_INFO("Relocated %d flags\n", ret);
	return RZ_CMD_STATUS_OK;
}

static int cmpflag(const void *_a, const void *_b, void *user) {
	const RzFlagItem *flag1 = _a, *flag2 = _b;
	return (flag1->offset - flag2->offset);
}

RZ_IPI void rz_core_flag_describe(RzCore *core, ut64 addr, bool strict_offset, RzCmdStateOutput *state) {
	RzFlagItem *f = rz_flag_get_at(core->flags, addr, !strict_offset);
	if (!f) {
		return;
	}
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(pj);
		pj_kn(pj, "offset", f->offset);
		pj_ks(pj, "name", f->name);
		// Print flag's real name if defined
		if (f->realname) {
			pj_ks(pj, "realname", f->realname);
		}
		pj_end(pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD: {
		// Print realname if exists and asm.flags.real is enabled
		const char *name = core->flags->realnames && f->realname ? f->realname : f->name;
		if (f->offset != addr) {
			rz_cons_printf("%s + %d\n", name, (int)(addr - f->offset));
		} else {
			rz_cons_println(name);
		}
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI RzCmdStatus rz_flag_describe_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_flag_describe(core, core->offset, false, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_describe_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const RzList *flags = rz_flag_get_list(core->flags, core->offset);
	if (!flags) {
		return RZ_CMD_STATUS_OK;
	}
	PJ *pj = state->d.pj;
	rz_cmd_state_output_array_start(state);
	RzFlagItem *flag;
	RzListIter *iter;
	// Sometimes an address has multiple flags assigned to, show them all
	rz_list_foreach (flags, iter, flag) {
		if (!flag) {
			continue;
		}
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ks(pj, "name", flag->name);
			if (flag->realname) {
				pj_ks(pj, "realname", flag->realname);
			}
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			// Print realname if exists and asm.flags.real is enabled
			if (core->flags->realnames && flag->realname) {
				rz_cons_println(flag->realname);
			} else {
				rz_cons_println(flag->name);
			}
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_describe_closest_handler(RzCore *core, int argc, const char **argv) {
	RzList *temp = rz_flag_all_list(core->flags, true);
	if (!temp) {
		return RZ_CMD_STATUS_OK;
	}
	ut64 loff = 0;
	ut64 uoff = 0;
	ut64 curseek = core->offset;
	char *lmatch = NULL, *umatch = NULL;
	RzFlagItem *flag;
	RzListIter *iter;
	rz_list_sort(temp, &cmpflag, NULL);
	rz_list_foreach (temp, iter, flag) {
		if (strstr(flag->name, argv[1]) != NULL) {
			if (flag->offset < core->offset) {
				loff = flag->offset;
				lmatch = flag->name;
				continue;
			}
			uoff = flag->offset;
			umatch = flag->name;
			break;
		}
	}
	char *match = (curseek - loff) < (uoff - curseek) ? lmatch : umatch;
	if (match) {
		if (*match) {
			rz_cons_println(match);
		}
	}
	rz_list_free(temp);
	return RZ_CMD_STATUS_OK;
}

static void flag_zone_list(RzFlag *f, RzCmdStateOutput *state) {
	if (!f->zones) {
		return;
	}
	RzListIter *iter;
	RzFlagZoneItem *zi;
	PJ *pj = state->d.pj;
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (f->zones, iter, zi) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ks(pj, "name", zi->name);
			pj_ki(pj, "from", zi->from);
			pj_ki(pj, "to", zi->to);
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x08%" PFMT64x "  0x%08" PFMT64x "  %s\n",
				zi->from, zi->to, zi->name);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
}

RZ_IPI RzCmdStatus rz_flag_zone_add_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_zone_add(core->flags, argv[1], core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_zone_remove_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_zone_del(core->flags, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_zone_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_zone_reset(core->flags);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_zone_around_handler(RzCore *core, int argc, const char **argv) {
	const char *a = NULL, *b = NULL;
	rz_flag_zone_around(core->flags, core->offset, &a, &b);
	rz_cons_printf("%s %s\n", a ? a : "~", b ? b : "~");
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_zone_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	flag_zone_list(core->flags, state);
	return RZ_CMD_STATUS_OK;
}

struct flagbar_t {
	RzCore *core;
	int cols;
};

static bool flagbar_foreach(RzFlagItem *fi, void *user) {
	struct flagbar_t *u = (struct flagbar_t *)user;
	ut64 min = 0, max = rz_io_size(u->core->io);
	RzIOMap *m = rz_io_map_get(u->core->io, fi->offset);
	if (m) {
		min = m->itv.addr;
		max = m->itv.addr + m->itv.size;
	}
	rz_cons_printf("0x%08" PFMT64x " ", fi->offset);
	RzBarOptions opts = {
		.unicode = false,
		.thinline = false,
		.legend = true,
		.offset = false,
		.offpos = 0,
		.cursor = false,
		.curpos = 0,
		.color = false
	};
	RzStrBuf *strbuf = rz_rangebar(&opts, fi->offset, fi->offset + fi->size, min, max, u->cols);
	if (!strbuf) {
		RZ_LOG_ERROR("Cannot generate rangebar\n");
	} else {
		rz_cons_print(rz_strbuf_drain(strbuf));
	}
	rz_cons_printf("  %s\n", fi->name);
	return true;
}

static void flagbars(RzCore *core, const char *glob) {
	int cols = rz_cons_get_size(NULL);
	cols -= 80;
	if (cols < 0) {
		cols += 80;
	}

	struct flagbar_t u = { .core = core, .cols = cols };
	rz_flag_foreach_space_glob(core->flags, glob, rz_flag_space_cur(core->flags), flagbar_foreach, &u);
}

struct flag_to_flag_t {
	ut64 next;
	ut64 offset;
};

static bool flag_to_flag_foreach(RzFlagItem *fi, void *user) {
	struct flag_to_flag_t *u = (struct flag_to_flag_t *)user;
	if (fi->offset < u->next && fi->offset > u->offset) {
		u->next = fi->offset;
	}
	return true;
}

static int flag_to_flag(RzCore *core, const char *glob) {
	rz_return_val_if_fail(glob, 0);
	glob = rz_str_trim_head_ro(glob);
	struct flag_to_flag_t u = { .next = UT64_MAX, .offset = core->offset };
	rz_flag_foreach_glob(core->flags, glob, flag_to_flag_foreach, &u);
	if (u.next != UT64_MAX && u.next > core->offset) {
		return u.next - core->offset;
	}
	return 0;
}

RZ_IPI RzCmdStatus rz_flag_tag_add_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_tags_set(core->flags, argv[1], argv[2]);
	return RZ_CMD_STATUS_OK;
}

static void flag_tag_print(RzCore *core, const char *tag, RzCmdStateOutput *state) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON: {
		pj_k(pj, tag);
		pj_a(pj);
		RzList *flags = rz_flag_tags_get(core->flags, tag);
		if (!flags) {
			pj_end(pj);
			break;
		}
		RzListIter *iter;
		RzFlagItem *flag;
		rz_list_foreach (flags, iter, flag) {
			pj_s(pj, flag->name);
		}
		pj_end(pj);
		rz_list_free(flags);
		break;
	}
	case RZ_OUTPUT_MODE_LONG: {
		rz_cons_printf("%s:\n", tag);
		RzList *flags = rz_flag_tags_get(core->flags, tag);
		if (!flags) {
			break;
		}
		RzListIter *iter;
		RzFlagItem *flag;
		rz_list_foreach (flags, iter, flag) {
			rz_cons_printf("0x%08" PFMT64x "  %s\n", flag->offset, flag->name);
		}
		rz_list_free(flags);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%s\n", tag);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI RzCmdStatus rz_flag_tag_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzList *list = rz_flag_tags_list(core->flags);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	const char *tag;
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (list, iter, tag) {
		flag_tag_print(core, tag, state);
	}
	rz_list_free(list);
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_tag_search_handler(RzCore *core, int argc, const char **argv) {
	RzList *flags = rz_flag_tags_get(core->flags, argv[1]);
	if (!flags) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	RzFlagItem *flag;
	rz_list_foreach (flags, iter, flag) {
		rz_cons_printf("0x%08" PFMT64x "  %s\n", flag->offset, flag->name);
	}
	return RZ_CMD_STATUS_OK;
}

struct rename_flag_t {
	RzCore *core;
	const char *pfx;
	int count;
};

static bool rename_flag_ordinal(RzFlagItem *fi, void *user) {
	struct rename_flag_t *u = (struct rename_flag_t *)user;
	char *newName = rz_str_newf("%s%d", u->pfx, u->count++);
	if (!newName) {
		return false;
	}
	rz_flag_rename(u->core->flags, fi, newName);
	free(newName);
	return true;
}

static void flag_ordinals(RzCore *core, const char *glob) {
	char *pfx = strdup(glob);
	char *p = strchr(pfx, '*');
	if (p) {
		*p = 0;
	}
	struct rename_flag_t u = { .core = core, .pfx = pfx, .count = 0 };
	rz_flag_foreach_glob(core->flags, glob, rename_flag_ordinal, &u);
	free(pfx);
}

static void print_space_stack(RzFlag *f, int ordinal, const char *name, bool selected, RzCmdStateOutput *state) {
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON: {
		char *ename = rz_str_escape(name);
		if (!ename) {
			return;
		}
		pj_o(state->d.pj);
		pj_ki(state->d.pj, "ordinal", ordinal);
		pj_ks(state->d.pj, "name", ename);
		pj_kb(state->d.pj, "selected", selected);
		pj_end(state->d.pj);
		free(ename);
		break;
	}
	default:
		rz_cons_printf("%-2d %s%s\n", ordinal, name, selected ? " (selected)" : "");
		break;
	}
}

RZ_IPI RzCmdStatus rz_flag_space_add_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_set(core->flags, argv[1]));
}

RZ_IPI RzCmdStatus rz_flag_space_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_spaces_print(core, &core->flags->spaces, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_space_move_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *f = rz_flag_get_i(core->flags, core->offset);
	if (!f) {
		RZ_LOG_ERROR("Cannot find any flag at 0x%" PFMT64x ".\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	f->space = rz_flag_space_cur(core->flags);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_space_remove_handler(RzCore *core, int argc, const char **argv) {
	const RzSpace *sp = rz_flag_space_cur(core->flags);
	if (!sp) {
		RZ_LOG_ERROR("No flag space currently selected.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_flag_space_unset(core->flags, sp->name));
}

RZ_IPI RzCmdStatus rz_flag_space_remove_all_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_unset(core->flags, NULL));
}

RZ_IPI RzCmdStatus rz_flag_space_rename_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_rename(core->flags, NULL, argv[1]));
}

RZ_IPI RzCmdStatus rz_flag_space_stack_push_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_push(core->flags, argv[1]));
}

RZ_IPI RzCmdStatus rz_flag_space_stack_pop_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_pop(core->flags));
}

RZ_IPI RzCmdStatus rz_flag_space_stack_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzListIter *iter;
	char *space;
	int i = 0;
	rz_list_foreach (core->flags->spaces.spacestack, iter, space) {
		print_space_stack(core->flags, i++, space, false, state);
	}
	const char *cur_name = rz_flag_space_cur_name(core->flags);
	print_space_stack(core->flags, i++, cur_name, true, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_remove_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2) {
		return bool2status(rz_flag_unset_all_off(core->flags, core->offset));
	}
	if (rz_flag_unset_glob(core->flags, argv[1]) < 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_unset_all(core->flags);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_alias_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *fi = rz_flag_get(core->flags, argv[1]);
	if (!fi) {
		fi = rz_flag_set(core->flags, argv[1], core->offset, 1);
	}
	if (!fi) {
		RZ_LOG_ERROR("Cannot find flag '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_flag_item_set_alias(fi, argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_exists_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *item = rz_flag_get(core->flags, argv[1]);
	if (!item) {
		RZ_LOG_ERROR("Cannot find flag '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	RZ_LOG_DEBUG("Find flag '%s' at 0x%" PFMT64x "\n", argv[1], item->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_distance_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", flag_to_flag(core, argv[1]));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_move_handler(RzCore *core, int argc, const char **argv) {
	ut64 address = rz_num_math(core->num, argv[1]);
	return bool2status(rz_flag_move(core->flags, core->offset, address));
}

RZ_IPI RzCmdStatus rz_flag_length_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *item = rz_flag_get_i(core->flags, core->offset);
	if (!item) {
		RZ_LOG_ERROR("Cannot find flag at 0x%" PFMT64x " offset\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc < 2) {
		rz_cons_printf("0x%08" PFMT64x "\n", item->size);
	} else {
		item->size = rz_num_math(core->num, argv[1]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_realname_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *item = argc > 1 ? rz_flag_get(core->flags, argv[1])
				    : rz_flag_get_i(core->flags, core->offset);
	if (!item) {
		RZ_LOG_ERROR("Cannot find flag\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc < 3) {
		rz_cons_printf("%s\n", item->realname);
	} else {
		rz_flag_item_set_realname(item, argv[2]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_list_ascii_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		flagbars(core, argv[1]);
	} else {
		flagbars(core, NULL);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_color_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *fi = rz_flag_get(core->flags, argv[1]);
	if (!fi) {
		RZ_LOG_ERROR("Cannot find the flag '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	const char *ret = rz_flag_item_set_color(fi, argv[2]);
	if (ret) {
		rz_cons_println(ret);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_comment_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *item;
	if (argc > 2) {
		item = rz_flag_get(core->flags, argv[1]);
		if (!item) {
			RZ_LOG_ERROR("Cannot find flag with name '%s'\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		return bool2status(flag_set_comment(item, argv[2]));
	} else {
		item = rz_flag_get_i(core->flags, rz_num_math(core->num, argv[1]));
		if (item && item->comment) {
			rz_cons_println(item->comment);
		} else {
			RZ_LOG_ERROR("Cannot find the flag\n");
			return RZ_CMD_STATUS_ERROR;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_ordinals_handler(RzCore *core, int argc, const char **argv) {
	flag_ordinals(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_rename_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *item = rz_flag_get(core->flags, argv[1]);
	if (!item && !strncmp(argv[1], "fcn.", 4)) {
		item = rz_flag_get(core->flags, argv[1] + 4);
	}
	if (!item) {
		RZ_LOG_ERROR("Cannot find matching flag\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_flag_rename(core->flags, item, argv[2])) {
		RZ_LOG_ERROR("Invalid new flag name\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_hexdump_handler(RzCore *core, int argc, const char **argv) {
	char cmd[128];
	ut64 address = rz_num_math(core->num, argv[1]);
	RzFlagItem *item = rz_flag_get_i(core->flags, address);
	if (!item) {
		RZ_LOG_ERROR("Cannot find flag '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("0x%08" PFMT64x "\n", item->offset);
	// FIXME: Use the API directly instead of calling the command
	snprintf(cmd, sizeof(cmd), "px@%" PFMT64d ":%" PFMT64d, item->offset, item->size);
	rz_core_cmd0(core, cmd);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_range_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		ut64 size = rz_num_math(core->num, argv[1]);
		rz_core_flag_range_print(core->flags, state, core->offset, core->offset + size);
	} else {
		rz_core_flag_range_print(core->flags, state, core->offset, core->offset + core->blocksize);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_list_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_flag_range_print(core->flags, state, core->offset, core->offset + 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_flag_print(core->flags, state);
	return RZ_CMD_STATUS_OK;
}
