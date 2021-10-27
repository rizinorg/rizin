// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

typedef struct {
	ut64 addr;
	ut64 faddr;
	RzAnalysisFunction *fcn;
	int pos; // related to columns
	int cur; // current row selected
	RzList *columns;
	RzCore *core;
	bool canLeft;
	bool canRight;
} RzCoreVisualViewZigns;

static const char *cur_name = NULL;

static char *print_item(void *_core, void *_item, bool selected) {
	RzSignItem *item = _item;
	int i;
	int bytes_mask = 0;
	int bytes_size = item->bytes->size;
	//  int bytes_null = bytes_size - bytes_mask;
	if (item->bytes->mask) {
		for (i = 0; i < bytes_size; i++) {
			if (item->bytes->mask[i]) {
				bytes_mask++;
			}
		}
	}
	if (selected && item->name) {
		cur_name = strdup(item->name);
	}
	return rz_str_newf("%c 0x%08" PFMT64x " bytes=%d/%d %20s\n", selected ? '>' : ' ',
		item->addr, bytes_mask, bytes_size, item->name);
}

static RzList *__signs(RzCoreVisualViewZigns *status, ut64 addr, bool update) {
	RzCore *core = status->core;
	return rz_sign_get_list(core->analysis);
}

RZ_API int __core_visual_view_zigns_update(RzCore *core, RzCoreVisualViewZigns *status) {
	int h, w = rz_cons_get_size(&h);
	rz_cons_clear00();
	int colh = h - 2;
	int colw = w - 1;
	RzList *col0 = __signs(status, status->addr, true);
	char *col0str = rz_str_widget_list(core, col0, colh, status->cur, print_item);

	char *title = rz_str_newf("[rz-visual-signatures] 0x%08" PFMT64x " 0x%08" PFMT64x, status->addr, status->faddr);
	if (title) {
		rz_cons_strcat_at(title, 0, 0, w - 1, 2);
		free(title);
	}
	rz_cons_strcat_at(col0str, 0, 2, colw, colh);
	rz_list_free(col0);
	rz_cons_flush();
	return 0;
}

RZ_API int rz_core_visual_view_zigns(RzCore *core) {
	RzCoreVisualViewZigns status = { 0 };
	status.core = core;
	status.addr = core->offset;
	status.fcn = NULL;

	while (true) {
		__core_visual_view_zigns_update(core, &status);
		int ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			return true;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'g':
			rz_core_cmd0(core, "zg");
			break;
		case 'h':
			if (status.canLeft) {
				if (status.pos) {
					status.addr = status.faddr;
				}
				status.pos = 1;
				status.cur = 0;
			}
			break;
		case 'l':
			if (status.canRight) {
				if (status.pos) {
					status.addr = status.faddr;
				}
				status.pos = 2;
				status.cur = 0;
			}
			break;
		case 'd':
			if (cur_name && *cur_name) {
				rz_sign_delete(core->analysis, cur_name);
				RZ_FREE(cur_name);
			}
			break;
		case 'J':
			status.cur += 10;
			break;
		case 'K':
			if (status.cur > 10) {
				status.cur -= 10;
			} else {
				status.cur = 0;
			}
			break;
		case '.':
			status.pos = 0;
			break;
		case 9:
		case ' ':
		case '\r':
		case '\n':
			if (status.pos) {
				rz_core_seek(core, status.faddr, true);
			} else {
				rz_core_seek(core, status.addr, true);
			}
			return true;
			break;
		case '_':
			rz_core_cmd0(core, "z*~...");
			break;
		case 'j':
			status.cur++;
			break;
		case 'k':
			if (status.cur > 0) {
				status.cur--;
			} else {
				status.cur = 0;
			}
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf(
				"vbz: Visual Zignatures:\n\n"
				" jkJK  - scroll up/down\n"
				" d     - delete current signature\n"
				" g     - regenerate signatures\n"
				" q     - quit this visual mode\n"
				" _     - enter the hud\n"
				" :     - enter command\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case 'q':
			RZ_FREE(cur_name);
			return false;
		case ':': // TODO: move this into a separate helper function
		{
			char cmd[1024];
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			cmd[0] = '\0';
			rz_line_set_prompt(":> ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			rz_core_cmd0(core, cmd);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			if (cmd[0]) {
				rz_cons_any_key(NULL);
			}
			rz_cons_clear();
		} break;
		}
	}
	return false;
}
