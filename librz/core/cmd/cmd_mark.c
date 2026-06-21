// SPDX-FileCopyrightText: 2009-2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <../core_private.h>
#include <rz_mark.h>
#include <rz_cmd.h>
#include <rz_flag.h>
#include <rz_util/rz_log.h>

static bool mark_set_comment(RzMarkItem *item, const char *comment) {
	if (!strncmp(comment, "base64:", 7)) {
		const char *b64str = comment + 7;
		char *dec = (char *)rz_base64_decode_dyn(b64str, -1);
		if (!dec) {
			RZ_LOG_ERROR("Failed to decode base64-encoded string: \"%s\"\n", b64str);
			return false;
		}
		rz_mark_item_set_comment(item, dec);
		free(dec);
	} else {
		rz_mark_item_set_comment(item, comment);
	}
	return true;
}

struct mark_to_mark_t {
	ut64 next;
	ut64 offset;
};

static bool mark_to_mark_foreach(RzMarkItem *bi, void *user) {
	struct mark_to_mark_t *u = (struct mark_to_mark_t *)user;
	if (bi->from < u->next && bi->from > u->offset) {
		u->next = bi->from;
	}
	return true;
}

static int mark_to_mark(RzCore *core, const char *glob) {
	rz_return_val_if_fail(core, 0);
	rz_return_val_if_fail(glob, 0);
	glob = rz_str_trim_head_ro(glob);
	struct mark_to_mark_t u = { .next = UT64_MAX, .offset = core->offset };
	rz_mark_foreach_regex(core->marks, glob, mark_to_mark_foreach, &u);
	if (u.next != UT64_MAX && u.next > core->offset) {
		return u.next - core->offset;
	}
	return 0;
}

static void mark_add_flag(RzFlag *f, RzMarkItem *bi) {
	if (!f || !bi) {
		return;
	}
	RzSpace *prev_space = rz_flag_space_cur(f);
	RzSpace *mark_space = rz_flag_space_get(f, "marks");
	if (!mark_space) {
		mark_space = rz_flag_space_set(f, "marks");
	} else {
		rz_flag_space_set(f, "marks");
	}

	rz_flag_set(f, bi->name, bi->from, (ut32)(bi->to - bi->from));
	if (prev_space) {
		rz_flag_space_set(f, prev_space->name);
	}
}

RZ_IPI RzCmdStatus rz_mark_add_handler(RzCore *core, int argc, const char **argv) {
	RzMarkItem *item;
	bool addMark = true;
	ut64 end = rz_num_math(core->num, argv[2]);
	if ((item = rz_mark_get_at(core->marks, core->offset))) {
		RZ_LOG_ERROR("Cannot create mark \"%s\" from 0x%" PFMT64x " to 0x%" PFMT64x " because there is already \"%s\" mark\n", argv[1], core->offset, end, item->name);
		addMark = false;
	}

	if (end < core->offset) {
		RZ_LOG_ERROR("Ending offset (0x%" PFMT64x ") must be greater than or equal to starting offset (0x%" PFMT64x ")\n",
			end, core->offset);
		return RZ_CMD_STATUS_ERROR;
	}

	if (addMark) {
		item = rz_mark_set(core->marks, argv[1], core->offset, end);
		if (item) {
			mark_add_flag(core->flags, item);
		}
	}
	if (!item) {
		RZ_LOG_ERROR(
			"Cannot create mark \"%s\" from 0x%" PFMT64x " to 0x%" PFMT64x "\n", argv[1], core->offset, end);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc > 3) {
		return bool2status(mark_set_comment(item, argv[3]));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_append_handler(RzCore *core, int argc, const char **argv) {
	ut64 end = rz_num_math(core->num, argv[2]);
	RzMarkItem *item = rz_mark_set(core->marks, argv[1], core->offset, end);
	if (!item) {
		RZ_LOG_ERROR(
			"Cannot create mark \"%s\" from 0x%" PFMT64x " to 0x%" PFMT64x "\n", argv[1], core->offset, end);
		return RZ_CMD_STATUS_ERROR;
	}
	mark_add_flag(core->flags, item);
	if (argc > 3) {
		return bool2status(mark_set_comment(item, argv[3]));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_remove_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2) {
		RzList *list = rz_mark_get_all_off(core->marks, core->offset);
		RzListIter *it;
		RzMarkItem *bi;
		rz_list_foreach (list, it, bi) {
			RzFlagItem *fi = rz_flag_get(core->flags, bi->name);
			rz_flag_unset(core->flags, fi);
		}
		rz_mark_unset_all_off(core->marks, core->offset);
		return RZ_CMD_STATUS_OK;
	}
	if (rz_mark_unset_glob(core->marks, argv[1]) < 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzFlagItem *fi = rz_flag_get(core->flags, argv[1]);
	if (fi) {
		rz_flag_unset(core->flags, fi);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_mark_print(core->marks, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_remove_all_handler(RzCore *core, int argc, const char **argv) {
	RzList *list = rz_mark_all_list(core->marks);
	RzListIter *it;
	RzMarkItem *bi;
	rz_list_foreach (list, it, bi) {
		RzFlagItem *fi = rz_flag_get(core->flags, bi->name);
		if (fi) {
			rz_flag_unset(core->flags, fi);
		}
	}
	rz_list_free(list);
	rz_mark_unset_all(core->marks);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_color_handler(RzCore *core, int argc, const char **argv) {
	RzMarkItem *bi = rz_mark_get(core->marks, argv[1]);
	if (!bi) {
		RZ_LOG_ERROR("Cannot find the mark '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc < 3) {
		if (bi->color) {
			rz_cons_println(bi->color);
		}
		return RZ_CMD_STATUS_OK;
	}
	const char *ret = rz_mark_item_set_color(bi, argv[2]);
	if (ret) {
		rz_cons_println(ret);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_list_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_mark_range_print(core->marks, state, core->offset, core->offset + 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_comment_handler(RzCore *core, int argc, const char **argv) {
	RzMarkItem *item;
	if (argc > 2) {
		item = rz_mark_get(core->marks, argv[1]);
		if (!item) {
			RZ_LOG_ERROR("Cannot find mark with name '%s'\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		return bool2status(mark_set_comment(item, argv[2]));
	} else {
		item = rz_mark_get(core->marks, argv[1]);
		if (!item) {
			RZ_LOG_ERROR("Cannot find mark\n");
			return RZ_CMD_STATUS_ERROR;
		} else if (item->comment) {
			rz_cons_println(item->comment);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_rename_handler(RzCore *core, int argc, const char **argv) {
	RzMarkItem *item = rz_mark_get(core->marks, argv[1]);
	if (!item) {
		RZ_LOG_ERROR("Cannot find matching mark\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_mark_rename(core->marks, item, argv[2])) {
		RZ_LOG_ERROR("Invalid new mark name\n");
		return RZ_CMD_STATUS_ERROR;
	}
	RzFlagItem *fi = rz_flag_get(core->flags, argv[1]);
	rz_flag_rename(core->flags, fi, argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_realname_handler(RzCore *core, int argc, const char **argv) {
	RzMarkItem *item = rz_mark_get(core->marks, argv[1]);
	if (!item) {
		RZ_LOG_ERROR("Cannot find mark\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc < 3) {
		rz_cons_printf("%s\n", item->realname);
	} else {
		rz_mark_item_set_realname(item, argv[2]);
		RzFlagItem *fi = rz_flag_get(core->flags, item->name);
		rz_flag_item_set_realname(fi, argv[2]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_move_handler(RzCore *core, int argc, const char **argv) {
	RzMarkItem *item = rz_mark_get(core->marks, argv[1]);
	if (!item) {
		RZ_LOG_ERROR("Cannot find matching mark\n");
		return RZ_CMD_STATUS_OK;
	}
	ut64 new_start = rz_num_math(core->num, argv[2]);
	ut64 new_end = rz_num_math(core->num, argv[3]);
	RzMarkItem *new_item = rz_mark_set(core->marks, item->name, new_start, new_end);
	if (!new_item) {
		RZ_LOG_ERROR(
			"Cannot move mark \"%s\" to 0x%" PFMT64x " - 0x%" PFMT64x "\n", argv[1], new_start, new_end);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_flag_set(core->flags, item->name, new_start, (ut32)(new_end - new_start));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_distance_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", mark_to_mark(core, argv[1]));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_core_mark_describe(RzCore *core, ut64 addr, RzMarkItem *b, RzCmdStateOutput *state) {
	ut64 size = (b->to >= b->from) ? (b->to - b->from) : 0;
	PJ *pj = state->d.pj;
	rz_cmd_state_output_set_columnsf(state, "ssXXds", "name", "realname",
		"from", "to", "size", "comment");
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(pj);
		pj_ks(pj, "name", b->name);
		pj_kn(pj, "from", b->from);
		pj_kn(pj, "to", b->to);
		pj_kn(pj, "size", size);
		if (b->comment) {
			pj_ks(pj, "comment", b->comment);
		}
		if (b->realname) {
			pj_ks(pj, "realname", b->realname);
		}
		pj_end(pj);
		break;

	case RZ_OUTPUT_MODE_TABLE: {
		ut64 size = (b->to >= b->from) ? (b->to - b->from) : 0;
		const char *name = b->realname ? b->realname : b->name;
		if (addr >= b->from && addr <= b->to) {
			rz_table_add_rowf(state->d.t, "ssXXds", b->name, name, b->from, b->to, size, b->comment);
		} else if (addr < b->from) {
			const char *descr_name = rz_str_newf("%s - %d", name, (int)(b->from - addr));
			rz_table_add_rowf(state->d.t, "ssXXds", b->name, descr_name, b->from, b->to, size, b->comment);
		} else {
			const char *descr_name = rz_str_newf("%s + %d", name, (int)(addr - b->to));
			rz_table_add_rowf(state->d.t, "ssXXds", b->name, descr_name, b->from, b->to, size, b->comment);
		}
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD: {
		const char *name = b->realname ? b->realname : b->name;
		if (addr >= b->from && addr <= b->to) {
			rz_cons_printf("[0x%08" PFMT64x " - 0x%08" PFMT64x "] %s\n", b->from, b->to, name);
		} else if (addr < b->from) {
			rz_cons_printf("[0x%08" PFMT64x " - 0x%08" PFMT64x "] %s - %d\n", b->from, b->to, name, (int)(b->from - addr));
		} else {
			rz_cons_printf("[0x%08" PFMT64x " - 0x%08" PFMT64x "] %s + %d\n", b->from, b->to, name, (int)(addr - b->to));
		}
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_describe_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzMarkItem *b;
	if (argc > 1) {
		b = rz_mark_get(core->marks, argv[1]);
	} else {
		b = rz_mark_get_at(core->marks, core->offset);
	}
	if (!b) {
		RZ_LOG_ERROR("Cannot find mark\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_mark_describe(core, core->offset, b, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_mark_range_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		ut64 size = rz_num_math(core->num, argv[1]);
		rz_core_mark_range_print(core->marks, state, core->offset, core->offset + size);
	} else {
		rz_core_mark_range_print(core->marks, state, core->offset, core->offset + core->blocksize);
	}
	return RZ_CMD_STATUS_OK;
}
