// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <rz_cons.h>
#include <rz_core.h>
#include "../core_private.h"
#include "rz_bookmark.h"
#include "rz_cmd.h"
#include "rz_util/rz_log.h"

static bool bookmark_set_comment(RzBookmarkItem *item, const char *comment) {
	if (!strncmp(comment, "base64:", 7)) {
		const char *b64str = comment + 7;
		char *dec = (char *)rz_base64_decode_dyn(b64str, -1);
		if (!dec) {
			RZ_LOG_ERROR("Failed to decode base64-encoded string: \"%s\"\n", b64str);
			return false;
		}
		rz_bookmark_item_set_comment(item, dec);
		free(dec);
	} else {
		rz_bookmark_item_set_comment(item, comment);
	}
	return true;
}

struct bookmark_to_bookmark_t {
	ut64 next;
	ut64 offset;
};

static bool bookmark_to_bookmark_foreach(RzBookmarkItem *bi, void *user) {
	struct bookmark_to_bookmark_t *u = (struct bookmark_to_bookmark_t *)user;
	if (bi->from < u->next && bi->from > u->offset) {
		u->next = bi->from;
	}
	return true;
}

static int bookmark_to_bookmark(RzCore *core, const char *glob) {
	rz_return_val_if_fail(glob, 0);
	glob = rz_str_trim_head_ro(glob);
	struct bookmark_to_bookmark_t u = { .next = UT64_MAX, .offset = core->offset };
	rz_bookmark_foreach_glob(core->bookmarks, glob, bookmark_to_bookmark_foreach, &u);
	if (u.next != UT64_MAX && u.next > core->offset) {
		return u.next - core->offset;
	}
	return 0;
}

RZ_IPI RzCmdStatus rz_bookmark_add_handler(RzCore *core, int argc, const char **argv) {
	RzBookmarkItem *item;
	bool addBookmark = true;
	ut64 end = rz_num_math(core->num, argv[2]);
	if ((item = rz_bookmark_get_at(core->bookmarks, core->offset))) {
		RZ_LOG_ERROR("Cannot create bookmark \"%s\" from 0x%" PFMT64x " to 0x%" PFMT64x " because there is already \"%s\" bookmark\n", argv[1], core->offset, end, item->name);
		addBookmark = false;
	}

	if (end < core->offset) {
		RZ_LOG_ERROR("Ending offset (0x%" PFMT64x ") must be greater than or equal to starting offset (0x%" PFMT64x ")\n",
			end, core->offset);
		return RZ_CMD_STATUS_ERROR;
	}

	if (addBookmark) {
		item = rz_bookmark_set(core->bookmarks, argv[1], core->offset, end);
	}
	if (!item) {
		RZ_LOG_ERROR(
			"Cannot create bookmark \"%s\" from 0x%" PFMT64x " to 0x%" PFMT64x "\n", argv[1], core->offset, end);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc > 3) {
		return bool2status(bookmark_set_comment(item, argv[3]));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_append_handler(RzCore *core, int argc, const char **argv) {
	ut64 end = rz_num_math(core->num, argv[2]);
	RzBookmarkItem *item = rz_bookmark_set(core->bookmarks, argv[1], core->offset, end);
	if (!item) {
		RZ_LOG_ERROR(
			"Cannot create bookmark \"%s\" from 0x%" PFMT64x " to 0x%" PFMT64x "\n", argv[1], core->offset, end);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc > 3) {
		return bool2status(bookmark_set_comment(item, argv[3]));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_remove_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2) {
		return bool2status(rz_bookmark_unset_all_off(core->bookmarks, core->offset));
	}
	if (rz_bookmark_unset_glob(core->bookmarks, argv[1]) < 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bookmark_print(core->bookmarks, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_bookmark_unset_all(core->bookmarks);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_color_handler(RzCore *core, int argc, const char **argv) {
	RzBookmarkItem *bi = rz_bookmark_get(core->bookmarks, argv[1]);
	if (!bi) {
		RZ_LOG_ERROR("Cannot find the bookmark '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc < 3) {
		rz_cons_println(bi->color);
		return RZ_CMD_STATUS_OK;
	}
	const char *ret = rz_bookmark_item_set_color(bi, argv[2]);
	if (ret) {
		rz_cons_println(ret);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_list_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_bookmark_range_print(core->bookmarks, state, core->offset, core->offset + 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_comment_handler(RzCore *core, int argc, const char **argv) {
	RzBookmarkItem *item;
	if (argc > 2) {
		item = rz_bookmark_get(core->bookmarks, argv[1]);
		if (!item) {
			RZ_LOG_ERROR("Cannot find bookmark with name '%s'\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		return bool2status(bookmark_set_comment(item, argv[2]));
	} else {
		item = rz_bookmark_get(core->bookmarks, argv[1]);
		if (item && item->comment) {
			rz_cons_println(item->comment);
		} else {
			RZ_LOG_ERROR("Cannot find the bookmark\n");
			return RZ_CMD_STATUS_ERROR;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_rename_handler(RzCore *core, int argc, const char **argv) {
	RzBookmarkItem *item = rz_bookmark_get(core->bookmarks, argv[1]);
	if (!item) {
		RZ_LOG_ERROR("Cannot find matching bookmark\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_bookmark_rename(core->bookmarks, item, argv[2])) {
		RZ_LOG_ERROR("Invalid new bookmark name\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_realname_handler(RzCore *core, int argc, const char **argv) {
	RzBookmarkItem *item = rz_bookmark_get(core->bookmarks, argv[1]);
	if (!item) {
		RZ_LOG_ERROR("Cannot find bookmark\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (argc < 3) {
		rz_cons_printf("%s\n", item->realname);
	} else {
		rz_bookmark_item_set_realname(item, argv[2]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_move_handler(RzCore *core, int argc, const char **argv) {
	RzBookmarkItem *item = rz_bookmark_get(core->bookmarks, argv[1]);
	if (!item) {
		RZ_LOG_ERROR("Cannot find matching bookmark\n");
		return RZ_CMD_STATUS_OK;
	}
	ut64 new_start = rz_num_math(core->num, argv[2]);
	ut64 new_end = rz_num_math(core->num, argv[3]);
	RzBookmarkItem *new_item = rz_bookmark_set(core->bookmarks, item->name, new_start, new_end);
	if (!new_item) {
		RZ_LOG_ERROR(
			"Cannot move bookmark \"%s\" to 0x%" PFMT64x " - 0x%" PFMT64x "\n", argv[1], new_start, new_end);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_distance_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", bookmark_to_bookmark(core, argv[1]));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_core_bookmark_describe(RzCore *core, ut64 addr, RzBookmarkItem *b, RzCmdStateOutput *state) {
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
		pj_ks(pj, "comment", b->comment);
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

RZ_IPI RzCmdStatus rz_bookmark_describe_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzBookmarkItem *b;
	if (argc > 1) {
		b = rz_bookmark_get(core->bookmarks, argv[1]);
	} else {
		b = rz_bookmark_get_at(core->bookmarks, core->offset);
	}
	if (!b) {
		RZ_LOG_ERROR("Cannot find bookmark\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_bookmark_describe(core, core->offset, b, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_bookmark_range_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		ut64 size = rz_num_math(core->num, argv[1]);
		rz_core_bookmark_range_print(core->bookmarks, state, core->offset, core->offset + size);
	} else {
		rz_core_bookmark_range_print(core->bookmarks, state, core->offset, core->offset + core->blocksize);
	}
	return RZ_CMD_STATUS_OK;
}
