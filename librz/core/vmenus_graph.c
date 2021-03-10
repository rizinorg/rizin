// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#define SORT_ADDRESS 0
#define SORT_NAME    1

// find a better name and move to rz_util or rz_cons?
RZ_API char *rz_str_widget_list(void *user, RzList *list, int rows, int cur, PrintItemCallback cb) {
	void *item;
	RzStrBuf *sb = rz_strbuf_new("");
	RzListIter *iter;
	int count = 0;
	int skip = 0;
	if (cur > (rows / 2)) {
		skip = cur - (rows / 2);
	}
	rz_list_foreach (list, iter, item) {
		if (rows >= 0) {
			if (skip > 0) {
				skip--;
			} else {
				char *line = cb(user, item, cur == count);
				if (line) {
					rz_strbuf_appendf(sb, "%s", line);
					free(line);
				}
				rows--;
				if (rows == 0) {
					break;
				}
			}
		}
		count++;
	}
	return rz_strbuf_drain(sb);
}

typedef struct {
	ut64 addr;
	RzAnalysisFunction *fcn;
	int cur; // current row selected
	int cur_sort; // holds current sort
	RzCore *core;
	RzList *mainCol;
	RzList *xrefsCol;
	RzList *refsCol;
} RzCoreVisualViewGraph;

typedef struct {
	ut64 addr;
	const char *name;
	RzAnalysisFunction *fcn;
} RzCoreVisualViewGraphItem;

static char *print_item(void *_core, void *_item, bool selected) {
	RzCoreVisualViewGraphItem *item = _item;
	if (item->name && *item->name) {
		if (false && item->fcn && item->addr > item->fcn->addr) {
			st64 delta = item->addr - item->fcn->addr;
			return rz_str_newf("%c %s+0x%" PFMT64x "\n", selected ? '>' : ' ', item->name, delta);
		} else {
			return rz_str_newf("%c %s\n", selected ? '>' : ' ', item->name);
		}
	}
	return rz_str_newf("%c 0x%08" PFMT64x "\n", selected ? '>' : ' ', item->addr);
}

static RzList *__xrefs(RzCore *core, ut64 addr) {
	RzList *r = rz_list_newf(free);
	RzListIter *iter;
	RzAnalysisRef *ref;
	RzList *xrefs = rz_analysis_xrefs_get(core->analysis, addr);
	rz_list_foreach (xrefs, iter, ref) {
		if (ref->type != 'C') {
			continue;
		}
		RzCoreVisualViewGraphItem *item = RZ_NEW0(RzCoreVisualViewGraphItem);
		RzFlagItem *f = rz_flag_get_at(core->flags, ref->addr, 0);
		item->addr = ref->addr;
		item->name = f ? f->name : NULL;
		RzAnalysisFunction *rf = rz_analysis_get_fcn_in(core->analysis, ref->addr, 0);
		item->fcn = rf;
		if (rf) {
			item->name = rf->name;
		}
		rz_list_append(r, item);
	}
	return r;
}

static RzList *__refs(RzCore *core, ut64 addr) {
	RzList *r = rz_list_newf(free);
	RzListIter *iter;
	RzAnalysisRef *ref;
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
	if (!fcn) {
		return r;
	}
	RzList *refs = rz_analysis_function_get_refs(fcn);
	rz_list_foreach (refs, iter, ref) {
		if (ref->type != 'C') {
			continue;
		}
		RzCoreVisualViewGraphItem *item = RZ_NEW0(RzCoreVisualViewGraphItem);
		RzFlagItem *f = rz_flag_get_at(core->flags, ref->addr, 0);
		item->addr = ref->addr;
		item->name = f ? f->name : NULL;
		RzAnalysisFunction *rf = rz_analysis_get_fcn_in(core->analysis, ref->addr, 0);
		if (rf) {
			item->name = rf->name;
			item->fcn = rf;
		}
		rz_list_append(r, item);
	}
	return r;
}

static RzList *__fcns(RzCore *core) {
	RzList *r = rz_list_newf(free);
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		RzCoreVisualViewGraphItem *item = RZ_NEW0(RzCoreVisualViewGraphItem);
		item->addr = fcn->addr;
		item->name = fcn->name;
		item->fcn = fcn;
		rz_list_append(r, item);
	}
	return r; // core->analysis->fcns;
}

static void __seek_cursor(RzCoreVisualViewGraph *status) {
	ut64 target = 0;
	if (status->fcn) {
		target = status->fcn->addr;
	} else {
		target = status->addr;
	}

	RzListIter *iter;
	RzCoreVisualViewGraphItem *item;
	int cur = 0;
	rz_list_foreach (status->mainCol, iter, item) {
		if (target == item->addr) {
			status->cur = cur;
		}
		cur++;
	}
	return;
}

static int cmpaddr(const void *_a, const void *_b) {
	const RzCoreVisualViewGraphItem *a = _a, *b = _b;
	return a->addr - b->addr;
}

static int cmpname(const void *_a, const void *_b) {
	const RzCoreVisualViewGraphItem *a = _a, *b = _b;
	if (!a || !b || !a->name || !b->name) {
		return 0;
	}
	return (int)strcmp(a->name, b->name);
}

static void __sort(RzCoreVisualViewGraph *status, RzList *list) {
	rz_return_if_fail(status && list);
	RzListComparator cmp = (status->cur_sort == SORT_ADDRESS) ? cmpaddr : cmpname;
	list->sorted = false;
	rz_list_sort(list, cmp);
}

static void __toggleSort(RzCoreVisualViewGraph *status) {
	rz_return_if_fail(status);
	status->cur_sort = (status->cur_sort == SORT_ADDRESS) ? SORT_NAME : SORT_ADDRESS;
	__sort(status, status->mainCol);
	__sort(status, status->refsCol);
	__sort(status, status->xrefsCol);
	__seek_cursor(status);
}

static void __reset_status(RzCoreVisualViewGraph *status) {
	status->addr = status->core->offset;
	status->fcn = rz_analysis_get_function_at(status->core->analysis, status->addr);

	status->mainCol = __fcns(status->core);
	__sort(status, status->mainCol);
	__seek_cursor(status);

	return;
}

static void __sync_status_with_cursor(RzCoreVisualViewGraph *status) {
	RzCoreVisualViewGraphItem *item = rz_list_get_n(status->mainCol, status->cur);
	if (!item) {
		rz_list_free(status->mainCol);
		__reset_status(status);
		return;
	}

	status->addr = item->addr;
	status->fcn = item->fcn;

	// Update xrefs and refs columns based on selected element in fcns column
	if (status->fcn && status->fcn->addr) {
		status->xrefsCol = __xrefs(status->core, status->fcn->addr);
		status->refsCol = __refs(status->core, status->fcn->addr);
	} else {
		status->xrefsCol = __xrefs(status->core, status->addr);
		status->refsCol = rz_list_newf(free);
	}
	__sort(status, status->xrefsCol);
	__sort(status, status->refsCol);
}

RZ_API int __core_visual_view_graph_update(RzCore *core, RzCoreVisualViewGraph *status) {
	int h, w = rz_cons_get_size(&h);
	const int colw = w / 4;
	const int colh = h / 2;
	const int colx = w / 3;
	rz_cons_clear00();

	char *xrefsColstr = rz_str_widget_list(core, status->xrefsCol, colh, 0, print_item);
	char *mainColstr = rz_str_widget_list(core, status->mainCol, colh, status->cur, print_item);
	char *refsColstr = rz_str_widget_list(core, status->refsCol, colh, 0, print_item);

	/* if (rz_list_empty (status->xrefsCol) && rz_list_empty (status->refsCol)) { */
	/* 	// We've found ourselves in a bad state, reset the view */
	/* rz_list_free (status->mainCol); */
	/* 	__reset_status (status); */
	/* } */

	char *title = rz_str_newf("[rz-visual-browser] addr=0x%08" PFMT64x " faddr=0x%08" PFMT64x "", status->addr, status->fcn ? status->fcn->addr : 0);
	if (title) {
		rz_cons_strcat_at(title, 0, 0, w - 1, 2);
		free(title);
	}
	rz_cons_strcat_at(xrefsColstr, 0, 2, colw, colh);
	rz_cons_strcat_at(mainColstr, colx, 2, colw * 2, colh);
	rz_cons_strcat_at(refsColstr, colx * 2, 2, colw, colh);

	char *output = rz_core_cmd_strf(core, "pd %d @e:asm.flags=0@ 0x%08" PFMT64x "; pds 256 @ 0x%08" PFMT64x "\n",
		32, status->addr, status->addr);
	int disy = colh + 2;
	rz_cons_strcat_at(output, 10, disy, w, h - disy);
	free(output);
	rz_cons_flush();

	free(xrefsColstr);
	free(mainColstr);
	free(refsColstr);
	return 0;
}

RZ_API int rz_core_visual_view_graph(RzCore *core) {
	RzCoreVisualViewGraph status = { 0 };
	status.core = core;
	status.cur_sort = SORT_NAME;
	__reset_status(&status);
	__sync_status_with_cursor(&status);
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, status.addr, 0);
	if (fcn) {
		status.addr = fcn->addr;
		status.fcn = fcn;
	}
	while (true) {
		__core_visual_view_graph_update(core, &status);
		int ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			return true;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'h':
			if (!rz_list_empty(status.xrefsCol)) {
				status.cur = 0;
				rz_list_free(status.mainCol);
				rz_list_free(status.refsCol);
				status.mainCol = status.xrefsCol;

				__sync_status_with_cursor(&status);
			}
			break;
		case 'l':
			if (!rz_list_empty(status.refsCol)) {
				status.cur = 0;
				rz_list_free(status.mainCol);
				rz_list_free(status.xrefsCol);
				status.mainCol = status.refsCol;

				__sync_status_with_cursor(&status);
			}
			break;
		case 'J': {
			status.cur += 10;
			int length = rz_list_length(status.mainCol);
			if (status.cur >= length) {
				status.cur = length - 1;
			}
			rz_list_free(status.xrefsCol);
			rz_list_free(status.refsCol);
			__sync_status_with_cursor(&status);
		} break;
		case 'K':
			if (status.cur > 10) {
				status.cur -= 10;
			} else {
				status.cur = 0;
			}
			rz_list_free(status.xrefsCol);
			rz_list_free(status.refsCol);
			__sync_status_with_cursor(&status);
			break;
		case '.':
			// reset view and seek status->cur to current function
			rz_list_free(status.mainCol);
			__reset_status(&status);
			break;
		case 9:
		case ' ':
		case '\r':
		case '\n': {
			RzCoreVisualViewGraphItem *item = rz_list_get_n(status.mainCol, status.cur);
			rz_core_seek(core, item->addr, true);
		}
			return true;
			break;
		case '_':
			rz_core_visual_hudstuff(core);
			rz_list_free(status.mainCol);
			rz_list_free(status.xrefsCol);
			rz_list_free(status.refsCol);
			__reset_status(&status);
			__sync_status_with_cursor(&status);
			break;
		case 'r':
			rz_list_free(status.mainCol);
			rz_list_free(status.xrefsCol);
			rz_list_free(status.refsCol);
			__reset_status(&status);
			__sync_status_with_cursor(&status);
			break;
		case 'j': {
			status.cur++;
			int length = rz_list_length(status.mainCol);
			if (status.cur >= length) {
				status.cur = length - 1;
			}
			rz_list_free(status.xrefsCol);
			rz_list_free(status.refsCol);
			__sync_status_with_cursor(&status);
		} break;
		case 'k':
			if (status.cur > 0) {
				status.cur--;
			} else {
				status.cur = 0;
			}
			rz_list_free(status.xrefsCol);
			rz_list_free(status.refsCol);
			__sync_status_with_cursor(&status);
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf(
				"vbg: Visual Browser (Code) Graph:\n\n"
				" jkJK  - scroll up/down\n"
				" hl    - move to the left/right panel\n"
				" q     - quit this visual mode\n"
				" _     - enter the hud\n"
				" .     - go back to the initial function list view\n"
				" :     - enter command\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case '/': {
			char cmd[1024];
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			cmd[0] = '\0';
			rz_line_set_prompt(":> ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			rz_config_set(core->config, "scr.highlight", cmd);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			rz_cons_clear();
		} break;
		case 'q':
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
		case '!': {
			__toggleSort(&status);
		} break;
		}
	}
	return false;
}
