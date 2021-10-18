// SPDX-FileCopyrightText: 2014-2020 pancake
// SPDX-FileCopyrightText: 2014-2020 ret2libc
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cons.h>
#include <rz_util/rz_graph_drawable.h>
#include <ht_pu.h>
#include <ctype.h>
#include <limits.h>
#include "../core_private.h"

static int mousemode = 0;
static int disMode = 0;
static const char *mousemodes[] = {
	"canvas-y",
	"canvas-x",
	"node-y",
	"node-x",
	NULL
};

static char *get_title(ut64 addr) {
	return rz_str_newf("0x%" PFMT64x, addr);
}

static int next_mode(int mode) {
	return (mode + 1) % RZ_AGRAPH_MODE_MAX;
}

static int prev_mode(int mode) {
	return (mode + RZ_AGRAPH_MODE_MAX - 1) % RZ_AGRAPH_MODE_MAX;
}

struct agraph_refresh_data {
	RzCore *core;
	RzAGraph *g;
	RzAnalysisFunction **fcn;
	bool follow_offset;
	int fs;
};

static int agraph_refresh(struct agraph_refresh_data *grd) {
	if (!grd) {
		return 0;
	}
	rz_cons_singleton()->event_data = grd;
	RzCore *core = grd->core;
	RzAGraph *g = grd->g;
	RzAnalysisFunction *f = NULL;
	RzAnalysisFunction **fcn = grd->fcn;

	if (!fcn) {
		return agraph_print(g, grd->fs, core, NULL);
	}

	// allow to change the current function during debugging
	if (g->is_instep && core->bin->is_debugger) {
		// seek only when the graph node changes
		const char *pc = rz_reg_get_name(core->dbg->reg, RZ_REG_NAME_PC);
		RzRegItem *r = rz_reg_get(core->dbg->reg, pc, -1);
		ut64 addr = rz_reg_get_value(core->dbg->reg, r);
		RzANode *acur = get_anode(g->curnode);

		RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, addr);
		char *title = get_title(block ? block->addr : addr);
		if (!acur || strcmp(acur->title, title)) {
			rz_core_seek_to_register(core, "PC", false);
		}
		free(title);
		g->is_instep = false;
	}

	if (grd->follow_offset) {
		if (rz_io_is_valid_offset(core->io, core->offset, 0)) {
			f = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			if (!f) {
				if (!g->is_dis) {
					if (!rz_cons_yesno('y', "\rNo function at 0x%08" PFMT64x ". Define it here (Y/n)? ", core->offset)) {
						return 0;
					}
					rz_core_analysis_function_add(core, NULL, core->offset, false);
				}
				f = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
				g->need_reload_nodes = true;
			}
			if (f && fcn && f != *fcn) {
				*fcn = f;
				check_function_modified(core, *fcn);
				g->need_reload_nodes = true;
				g->force_update_seek = true;
			}
		} else {
			// TODO: maybe go back to avoid seeking from graph view to an scary place?
			rz_cons_message("This is not a valid offset\n");
			rz_cons_flush();
		}
	}

	int res = agraph_print(g, grd->fs, core, *fcn);

	if (rz_config_get_i(core->config, "scr.scrollbar")) {
		rz_core_print_scrollbar(core);
	}

	return res;
}

static void agraph_refresh_oneshot(struct agraph_refresh_data *grd) {
	rz_core_task_enqueue_oneshot(&grd->core->tasks, (RzCoreTaskOneShot)agraph_refresh, grd);
}

static void agraph_set_need_reload_nodes(struct agraph_refresh_data *grd) {
	grd->g->need_reload_nodes = true;
}

static void agraph_follow_innodes(RzAGraph *g, bool in) {
	int count = 0;
	RzListIter *iter;
	RzANode *an = get_anode(g->curnode);
	if (!an) {
		return;
	}
	const RzList *list = in ? an->gnode->in_nodes : an->gnode->out_nodes;
	int nth = -1;
	if (rz_list_length(list) == 0) {
		return;
	}
	rz_cons_gotoxy(0, 2);
	rz_cons_printf(in ? "Input nodes:\n" : "Output nodes:\n");
	RzList *options = rz_list_newf(NULL);
	RzList *gnodes = in ? an->gnode->in_nodes : an->gnode->out_nodes;
	RzGraphNode *gn;
	rz_list_foreach (gnodes, iter, gn) {
		RzANode *an = get_anode(gn);
		RzGraphNode *gnn = agraph_get_title(g, an, in);
		if (gnn) {
			RzANode *nnn = gnn->data;
			RzANode *o;
			RzListIter *iter2;
			// avoid dupes
			rz_list_foreach (options, iter2, o) {
				if (!strcmp(o->title, nnn->title)) {
					continue;
				}
			}
			rz_cons_printf("%d %s\n", count, nnn->title);
			rz_list_append(options, nnn);
			count++;
		}
	}
	rz_cons_flush();
	if (rz_list_length(list) == 1) {
		nth = 0;
	} else if (rz_list_length(list) < 10) {
		// just 1 key
		char ch = rz_cons_readchar();
		if (ch >= '0' && ch <= '9') {
			nth = ch - '0';
		}
	} else {
		rz_cons_show_cursor(true);
		rz_cons_enable_mouse(false);
		char *nth_string = rz_cons_input("index> ");
		nth = atoi(nth_string);
		if (nth == 0 && *nth_string != '0') {
			nth = -1;
		}
		free(nth_string);
	}
	if (nth != -1) {
		RzANode *selected_node = rz_list_get_n(options, nth);
		rz_agraph_set_curnode(g, selected_node);
	}
	rz_list_free(options);
	agraph_update_seek(g, get_anode(g->curnode), false);
}

static void agraph_follow_true(RzAGraph *g) {
	follow_nth(g, 0);
	agraph_update_seek(g, get_anode(g->curnode), false);
}

static void agraph_follow_false(RzAGraph *g) {
	follow_nth(g, 1);
	agraph_update_seek(g, get_anode(g->curnode), false);
}



static void agraph_toggle_speed(RzAGraph *g, RzCore *core) {
	const int alt = rz_config_get_i(core->config, "graph.scroll");
	g->movspeed = g->movspeed == DEFAULT_SPEED ? alt : DEFAULT_SPEED;
}

static void agraph_toggle_tiny(RzAGraph *g) {
	g->is_tiny = !g->is_tiny;
	g->need_update_dim = 1;
	agraph_refresh(rz_cons_singleton()->event_data);
	agraph_set_layout((RzAGraph *)g);
	//remove_dummy_nodes (g);
}

static void agraph_toggle_mini(RzAGraph *g) {
	RzANode *n = get_anode(g->curnode);
	if (n) {
		n->is_mini = !n->is_mini;
	}
	g->need_update_dim = 1;
	agraph_refresh(rz_cons_singleton()->event_data);
	agraph_set_layout((RzAGraph *)g);
}

static void visual_offset(RzAGraph *g, RzCore *core) {
	char buf[256];
	int rows;
	rz_cons_get_size(&rows);
	rz_cons_gotoxy(0, rows);
	rz_cons_flush();
	core->cons->line->prompt_type = RZ_LINE_PROMPT_OFFSET;
	rz_line_set_hist_callback(core->cons->line, &rz_line_hist_offset_up, &rz_line_hist_offset_down);
	rz_line_set_prompt("[offset]> ");
	strcpy(buf, "s ");
	if (rz_cons_fgets(buf + 2, sizeof(buf) - 2, 0, NULL) > 0) {
		if (buf[2] == '.') {
			buf[1] = '.';
		}
		rz_core_cmd0(core, buf);
		rz_line_set_hist_callback(core->cons->line, &rz_line_hist_cmd_up, &rz_line_hist_cmd_down);
	}
	core->cons->line->prompt_type = RZ_LINE_PROMPT_DEFAULT;
}

static void goto_asmqjmps(RzAGraph *g, RzCore *core) {
	const char *h = "[Fast goto call/jmp]> ";
	char obuf[RZ_CORE_ASMQJMPS_LEN_LETTERS + 1];
	int rows, i = 0;
	bool cont;

	rz_cons_get_size(&rows);
	rz_cons_gotoxy(0, rows);
	rz_cons_clear_line(0);
	rz_cons_print(Color_RESET);
	rz_cons_print(h);
	rz_cons_flush();

	do {
		char ch = rz_cons_readchar();
		obuf[i++] = ch;
		rz_cons_printf("%c", ch);
		cont = isalpha((ut8)ch) && !islower((ut8)ch);
	} while (i < RZ_CORE_ASMQJMPS_LEN_LETTERS && cont);
	rz_cons_flush();

	obuf[i] = '\0';
	ut64 addr = rz_core_get_asmqjmps(core, obuf);
	if (addr != UT64_MAX) {
		char *title = get_title(addr);
		RzANode *addr_node = rz_agraph_get_node(g, title);
		if (addr_node) {
			rz_agraph_set_curnode(g, addr_node);
			rz_core_seek(core, addr, false);
			agraph_update_seek(g, addr_node, true);
		} else {
			rz_core_seek_and_save(core, addr, false);
		}
		free(title);
	}
}

static void seek_to_node(RzANode *n, RzCore *core) {
	RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	char *title = get_title(block ? block->addr : core->offset);

	if (title && strcmp(title, n->title)) {
		char *cmd = rz_str_newf("s %s", n->title);
		if (cmd) {
			if (*cmd) {
				rz_core_cmd0(core, cmd);
			}
			free(cmd);
		}
	}
	free(title);
}

static void graph_single_step_in(RzCore *core, RzAGraph *g) {
	rz_core_debug_single_step_in(core);
	g->is_instep = true;
	g->need_reload_nodes = true;
}

static void graph_single_step_over(RzCore *core, RzAGraph *g) {
	rz_core_debug_single_step_over(core);
	g->is_instep = true;
	g->need_reload_nodes = true;
}

static void graph_breakpoint(RzCore *core) {
	ut64 addr = core->print->cur_enabled ? core->offset + core->print->cur : core->offset;
	rz_core_debug_breakpoint_toggle(core, addr);
}

static void graph_continue(RzCore *core) {
	rz_core_debug_continue(core);
}
static void applyDisMode(RzCore *core) {
	switch (disMode) {
	case 0:
		rz_config_set(core->config, "asm.pseudo", "false");
		rz_config_set(core->config, "asm.esil", "false");
		break;
	case 1:
		rz_config_set(core->config, "asm.pseudo", "true");
		rz_config_set(core->config, "asm.esil", "false");
		break;
	case 2:
		rz_config_set(core->config, "asm.pseudo", "false");
		rz_config_set(core->config, "asm.esil", "true");
		break;
	}
}

static void rotateColor(RzCore *core) {
	int color = rz_config_get_i(core->config, "scr.color");
	if (++color > 2) {
		color = 0;
	}
	rz_config_set_i(core->config, "scr.color", color);
}

static char *get_graph_string(RzCore *core, RzAGraph *g) {
	int c = rz_config_get_i(core->config, "scr.color");
	int u = rz_config_get_i(core->config, "scr.utf8");
	rz_config_set_i(core->config, "scr.color", 0);
	rz_config_set_i(core->config, "scr.utf8", 0);
	rz_core_visual_graph(core, g, NULL, false);
	char *s = rz_cons_get_buffer_dup();
	rz_cons_reset();
	rz_config_set_i(core->config, "scr.color", c);
	rz_config_set_i(core->config, "scr.utf8", u);
	return s;
}

static void nextword(RzCore *core, RzAGraph *g, const char *word) {
	rz_return_if_fail(core && core->graph && g && g->can && word);
	if (RZ_STR_ISEMPTY(word)) {
		return;
	}
	RzAGraphHits *gh = &g->ghits;
	RzConsCanvas *can = g->can;
	if (gh->word_list.len && gh->old_word && !strcmp(word, gh->old_word)) {
		if (gh->word_nth >= gh->word_list.len) {
			gh->word_nth = 0;
		}

		struct rz_agraph_location *pos = rz_vector_index_ptr(&gh->word_list, gh->word_nth);
		gh->word_nth++;
		if (pos) {
			can->sx = -pos->x + can->w / 2;
			can->sy = -pos->y + can->h / 2;
		}
		return;
	} else {
		rz_vector_clear(&gh->word_list);
	}
	char *s = get_graph_string(core, g);
	rz_cons_clear00();
	rz_cons_flush();
	const size_t MAX_COUNT = 4096;
	const char *a = NULL;
	size_t count = 0;
	int x = 0, y = 0;
	for (count = 0; count < MAX_COUNT; count++) {
		a = rz_str_str_xy(s, word, a, &x, &y);
		if (!a) {
			break;
		}
		struct rz_agraph_location *pos = rz_vector_push(&gh->word_list, NULL);
		if (pos) {
			pos->x = x + g->x;
			pos->y = y + g->y;
		}
	}
	free(gh->old_word);
	gh->old_word = strdup(word);
	free(s);
	if (!a && count == 0) {
		return;
	}
	nextword(core, g, word);
}

/* seek the next node in visual order */
static void agraph_next_node(RzAGraph *g) {
	RzANode *a = get_anode(find_near_of(g, g->curnode, true));
	while (a && a->is_dummy) {
		a = get_anode(find_near_of(g, a->gnode, true));
	}
	rz_agraph_set_curnode(g, a);
	agraph_update_seek(g, get_anode(g->curnode), false);
}

/* seek the previous node in visual order */
static void agraph_prev_node(RzAGraph *g) {
	RzANode *a = get_anode(find_near_of(g, g->curnode, false));
	while (a && a->is_dummy) {
		a = get_anode(find_near_of(g, a->gnode, false));
	}
	rz_agraph_set_curnode(g, a);
	agraph_update_seek(g, get_anode(g->curnode), false);
}

static void agraph_set_zoom(RzAGraph *g, int v) {
	if (v >= -10) {
		g->is_tiny = false;
		if (v == 0) {
			g->mode = RZ_AGRAPH_MODE_MINI;
		} else if (v < 0) {
			g->mode = RZ_AGRAPH_MODE_TINY;
			g->is_tiny = true;
		} else {
			g->mode = RZ_AGRAPH_MODE_NORMAL;
		}
		const int K = 920;
		if (g->zoom < v) {
			g->can->sy = (g->can->sy * K) / 1000;
		} else {
			g->can->sy = (g->can->sy * 1000) / K;
		}
		g->zoom = v;
		g->need_update_dim = true;
		g->need_set_layout = true;
	}
}

static void agraph_toggle_callgraph(RzAGraph *g) {
	g->is_callgraph = !g->is_callgraph;
	g->need_reload_nodes = true;
	g->force_update_seek = true;
}

// duplicated from visual.c
static void rotateAsmemu(RzCore *core) {
	const bool isEmuStr = rz_config_get_i(core->config, "emu.str");
	const bool isEmu = rz_config_get_i(core->config, "asm.emu");
	if (isEmu) {
		if (isEmuStr) {
			rz_config_set(core->config, "emu.str", "false");
		} else {
			rz_config_set(core->config, "asm.emu", "false");
		}
	} else {
		rz_config_set(core->config, "emu.str", "true");
	}
}

static void showcursor(RzCore *core, int x) {
	if (!x) {
		int wheel = rz_config_get_i(core->config, "scr.wheel");
		if (wheel) {
			rz_cons_enable_mouse(true);
		}
	} else {
		rz_cons_enable_mouse(false);
	}
	rz_cons_show_cursor(x);
}

static int bbcmp(RzAnalysisBlock *a, RzAnalysisBlock *b) {
	return a->addr - b->addr;
}

static void get_bbupdate(RzAGraph *g, RzCore *core, RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzListIter *iter;
	bool emu = rz_config_get_i(core->config, "asm.emu");
	ut64 saved_gp = core->analysis->gp;
	ut8 *saved_arena = NULL;
	int saved_stackptr = core->analysis->stackptr;
	char *shortcut = 0;
	int shortcuts = 0;
	core->keep_asmqjmps = false;

	if (emu) {
		saved_arena = rz_reg_arena_peek(core->analysis->reg);
	}
	if (!fcn) {
		RZ_FREE(saved_arena);
		return;
	}
	rz_list_sort(fcn->bbs, (RzListComparator)bbcmp);

	shortcuts = rz_config_get_i(core->config, "graph.nodejmps");
	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char *body = get_bb_body(core, bb, mode2opts(g), fcn, emu, saved_gp, saved_arena);
		char *title = get_title(bb->addr);

		if (shortcuts) {
			shortcut = rz_core_add_asmqjmp(core, bb->addr);
			if (shortcut) {
				sdb_set(g->db, sdb_fmt("agraph.nodes.%s.shortcut", title), shortcut, 0);
				free(shortcut);
			}
		}
		RzANode *node = rz_agraph_get_node(g, title);
		if (node) {
			free(node->body);
			node->body = body;
		} else {
			free(body);
		}
		free(title);
		core->keep_asmqjmps = true;
	}

	if (emu) {
		core->analysis->gp = saved_gp;
		if (saved_arena) {
			rz_reg_arena_poke(core->analysis->reg, saved_arena);
			RZ_FREE(saved_arena);
		}
	}
	core->analysis->stackptr = saved_stackptr;
}

RZ_API int rz_core_visual_graph(RzCore *core, RzAGraph *g, RzAnalysisFunction *_fcn, int is_interactive) {
	if (is_interactive && !rz_cons_is_interactive()) {
		eprintf("Interactive graph mode requires scr.interactive=true.\n");
		return 0;
	}
	int o_asmqjmps_letter = core->is_asmqjmps_letter;
	int o_vmode = core->vmode;
	int exit_graph = false, is_error = false;
	int update_seek = false;
	struct agraph_refresh_data *grd;
	int okey, key;
	RzAnalysisFunction *fcn = NULL;
	const char *key_s;
	RzConsCanvas *can, *o_can = NULL;
	bool graph_allocated = false;
	int movspeed;
	int ret, invscroll;
	RzConfigHold *hc = rz_config_hold_new(core->config);
	if (!hc) {
		return false;
	}
	rz_config_hold_i(hc, "asm.pseudo", "asm.esil", "asm.cmt.right", NULL);

	int h, w = rz_cons_get_size(&h);
	can = rz_cons_canvas_new(w, h);
	if (!can) {
		w = 80;
		h = 25;
		can = rz_cons_canvas_new(w, h);
		if (!can) {
			eprintf("Cannot create RzCons.canvas context. Invalid screen "
				"size? See scr.columns + scr.rows\n");
			rz_config_hold_free(hc);
			return false;
		}
	}
	can->linemode = rz_config_get_i(core->config, "graph.linemode");
	can->color = rz_config_get_i(core->config, "scr.color");

	if (!g) {
		graph_allocated = true;
		fcn = _fcn ? _fcn : rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		if (!fcn) {
			rz_config_hold_restore(hc);
			rz_config_hold_free(hc);
			rz_cons_canvas_free(can);
			return false;
		}
		check_function_modified(core, fcn);
		g = rz_agraph_new(can);
		if (!g) {
			rz_cons_canvas_free(can);
			rz_config_hold_restore(hc);
			rz_config_hold_free(hc);
			return false;
		}
		g->is_tiny = is_interactive == 2;
		g->layout = rz_config_get_i(core->config, "graph.layout");
		g->dummy = rz_config_get_i(core->config, "graph.dummy");
		g->show_node_titles = rz_config_get_i(core->config, "graph.ntitles");
	} else {
		o_can = g->can;
	}
	g->can = can;
	g->movspeed = rz_config_get_i(core->config, "graph.scroll");
	g->show_node_titles = rz_config_get_i(core->config, "graph.ntitles");
	g->show_node_body = rz_config_get_i(core->config, "graph.body");
	g->on_curnode_change = (RzANodeCallback)seek_to_node;
	g->on_curnode_change_data = core;
	g->edgemode = rz_config_get_i(core->config, "graph.edges");
	g->hints = rz_config_get_i(core->config, "graph.hints");
	g->is_interactive = is_interactive;
	bool asm_comments = rz_config_get_i(core->config, "asm.comments");
	rz_config_set(core->config, "asm.comments",
		rz_str_bool(rz_config_get_i(core->config, "graph.comments")));

	/* we want letters as shortcuts for call/jmps */
	core->is_asmqjmps_letter = true;
	core->vmode = true;

	grd = RZ_NEW0(struct agraph_refresh_data);
	if (!grd) {
		rz_cons_canvas_free(can);
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		rz_agraph_free(g);
		return false;
	}
	grd->g = g;
	grd->fs = is_interactive == 1;
	grd->core = core;
	grd->follow_offset = _fcn == NULL;
	grd->fcn = fcn != NULL ? &fcn : NULL;
	ret = agraph_refresh(grd);
	if (!ret || is_interactive != 1) {
		rz_cons_newline();
		exit_graph = true;
		is_error = !ret;
	}

	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = grd;
	core->cons->event_resize = (RzConsEvent)agraph_refresh_oneshot;

	rz_cons_break_push(NULL, NULL);

	while (!exit_graph && !is_error && !rz_cons_is_breaked()) {
		rz_cons_get_size(&h);
		invscroll = rz_config_get_i(core->config, "graph.invscroll");
		ret = agraph_refresh(grd);

		if (!ret) {
			is_error = true;
			break;
		}
		showcursor(core, false);

		// rz_core_graph_inputhandle()
		okey = rz_cons_readchar();
		key = rz_cons_arrow_to_hjkl(okey);

		if (core->cons->mouse_event) {
			movspeed = rz_config_get_i(core->config, "scr.wheel.speed");
			switch (key) {
			case 'j':
			case 'k':
				switch (mousemode) {
				case 0: break;
				case 1: key = key == 'k' ? 'h' : 'l'; break;
				case 2: key = key == 'k' ? 'J' : 'K'; break;
				case 3: key = key == 'k' ? 'L' : 'H'; break;
				}
				break;
			}
		} else {
			movspeed = g->movspeed;
		}
		const char *cmd;
		switch (key) {
		case '-':
			agraph_set_zoom(g, g->zoom - ZOOM_STEP);
			g->force_update_seek = true;
			break;
		case '+':
			agraph_set_zoom(g, g->zoom + ZOOM_STEP);
			g->force_update_seek = true;
			break;
		case '0':
			agraph_set_zoom(g, ZOOM_DEFAULT);
			agraph_update_seek(g, get_anode(g->curnode), true);
			// update scroll (with minor shift)
			break;
		case '=': { // TODO: edit
			showcursor(core, true);
			const char *cmd = rz_config_get(core->config, "cmd.gprompt");
			rz_line_set_prompt("cmd.gprompt> ");
			core->cons->line->contents = strdup(cmd);
			const char *buf = rz_line_readline();
			core->cons->line->contents = NULL;
			rz_config_set(core->config, "cmd.gprompt", buf);
			showcursor(core, false);
		} break;
		case '|': {
			int e = rz_config_get_i(core->config, "graph.layout");
			if (++e > 1) {
				e = 0;
			}
			rz_config_set_i(core->config, "graph.layout", e);
			g->layout = rz_config_get_i(core->config, "graph.layout");
			g->need_update_dim = true;
			g->need_set_layout = true;
			g->y_scroll = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		}
		case 'e': {
			int e = rz_config_get_i(core->config, "graph.edges");
			e++;
			if (e > 2) {
				e = 0;
			}
			rz_config_set_i(core->config, "graph.edges", e);
			g->edgemode = e;
			g->need_update_dim = true;
			get_bbupdate(g, core, fcn);
		} break;
		case '\\':
			nextword(core, g, rz_config_get(core->config, "scr.highlight"));
			break;
		case 'b':
			rz_core_visual_browse(core, "");
			break;
		case 'E': {
			int e = rz_config_get_i(core->config, "graph.linemode");
			e--;
			if (e < 0) {
				e = 1;
			}
			rz_config_set_i(core->config, "graph.linemode", e);
			g->can->linemode = e;
			get_bbupdate(g, core, fcn);
		} break;
		case 13:
			agraph_update_seek(g, get_anode(g->curnode), true);
			update_seek = true;
			exit_graph = true;
			break;
		case '>':
			if (fcn && rz_cons_yesno('y', "Compute function callgraph? (Y/n)")) {
				rz_core_agraph_reset(core);
				rz_core_cmd0(core, ".agc* @$FB;.axfg @$FB");
				rz_core_agraph_print_interactive(core);
			}
			break;
		case '<':
			// rz_core_visual_xrefs (core, true, false);
			if (fcn) {
				rz_core_agraph_reset(core);
				rz_core_cmd0(core, ".axtg $FB");
				rz_core_agraph_print_interactive(core);
			}
			break;
		case 'G':
			rz_core_agraph_reset(core);
			rz_core_cmd0(core, ".dtg*");
			rz_core_agraph_print_interactive(core);
			break;
		case 'V':
			if (fcn) {
				agraph_toggle_callgraph(g);
			}
			break;
		case 'Z':
			if (okey == 27) { // shift-tab
				agraph_prev_node(g);
			}
			break;
		case 's':
			if (!fcn) {
				break;
			}
			key_s = rz_config_get(core->config, "key.s");
			if (key_s && *key_s) {
				rz_core_cmd0(core, key_s);
			} else {
				graph_single_step_in(core, g);
			}
			g->y_scroll = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'S':
			if (fcn) {
				graph_single_step_over(core, g);
			}
			break;
		case 'x':
		case 'X': {
			if (!fcn) {
				break;
			}
			ut64 old_off = core->offset;
			RzAnalysisBlock *block = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
			if (block) {
				rz_core_seek(core, block->addr, false);
			}
			if ((key == 'x' && !rz_core_visual_xrefs(core, true, true)) ||
				(key == 'X' && !rz_core_visual_xrefs(core, false, true))) {
				rz_core_seek(core, old_off, false);
			}
			break;
		}
		case 9: // tab
			agraph_next_node(g);
			g->y_scroll = 0;
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf("Visual Ascii Art graph keybindings:\n"
				       " :e cmd.gprompt = agft   - show tinygraph in one side\n"
				       " +/-/0        - zoom in/out/default\n"
				       " ;            - add comment in current basic block\n"
				       " . (dot)      - center graph to the current node\n"
				       " , (comma)    - toggle graph.few\n"
				       " ^            - seek to the first bb of the function\n"
				       " =            - toggle graph.layout\n"
				       " :cmd         - run rizin command\n"
				       " '            - toggle graph.comments\n"
				       " \"            - toggle graph.refs\n"
				       " #            - toggle graph.hints\n"
				       " /            - highlight text\n"
				       " \\            - scroll the graph canvas to the next highlight location\n"
				       " |            - set cmd.gprompt\n"
				       " _            - enter hud selector\n"
				       " >            - show function callgraph (see graph.refs)\n"
				       " <            - show program callgraph (see graph.refs)\n"
				       " (            - reverse conditional branch of last instruction in bb\n"
				       " )            - rotate asm.emu and emu.str\n"
				       " Home/End     - go to the top/bottom of the canvas\n"
				       " Page-UP/DOWN - scroll canvas up/down\n"
				       " b            - visual browse things\n"
				       " c            - toggle graph cursor mode\n"
				       " C            - toggle scr.colors\n"
				       " d            - rename function\n"
				       " D            - toggle the mixed graph+disasm mode\n"
				       " e            - rotate graph.edges (show/hide edges)\n"
				       " E            - rotate graph.linemode (square/diagonal lines)\n"
				       " F            - enter flag selector\n"
				       " g            - go/seek to given offset\n"
				       " G            - debug trace callgraph (generated with dtc)\n"
				       " hjkl/HJKL    - scroll canvas or node depending on graph cursor (uppercase for faster)\n"
				       " i            - select input nodes by index\n"
				       " I            - select output node by index\n"
				       " m/M          - change mouse modes\n"
				       " n/N          - next/previous scr.nkey (function/flag..)\n"
				       " o([A-Za-z]*) - follow jmp/call identified by shortcut (like ;[oa])\n"
				       " O            - toggle asm.pseudo and asm.esil\n"
				       " p/P          - rotate graph modes (normal, display offsets, minigraph, summary)\n"
				       " q            - back to Visual mode\n"
				       " r            - toggle jmphints/leahints\n"
				       " R            - randomize colors\n"
				       " s/S          - step / step over\n"
				       " tab          - select next node\n"
				       " TAB          - select previous node\n"
				       " t/f          - follow true/false edges\n"
				       " u/U          - undo/redo seek\n"
				       " V            - toggle basicblock / call graphs\n"
				       " w            - toggle between movements speed 1 and graph.scroll\n"
				       " x/X          - jump to xref/ref\n"
				       " Y            - toggle tiny graph\n"
				       " z            - toggle node folding\n"
				       " Z            - toggle basic block folding");
			rz_cons_less();
			rz_cons_any_key(NULL);
			break;
		case '"':
			rz_config_toggle(core->config, "graph.refs");
			break;
		case '#':
			if (g->mode == RZ_AGRAPH_MODE_COMMENTS) {
				g->mode = RZ_AGRAPH_MODE_NORMAL;
			} else {
				g->mode = RZ_AGRAPH_MODE_COMMENTS;
			}
			g->need_reload_nodes = true;
			g->y_scroll = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			// rz_config_toggle (core->config, "graph.hints");
			break;
		case 'p':
			g->mode = next_mode(g->mode);
			g->need_reload_nodes = true;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'P':
			if (!fcn) {
				break;
			}
			g->mode = prev_mode(g->mode);
			g->need_reload_nodes = true;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'o':
			goto_asmqjmps(g, core);
			break;
		case 'g':
			showcursor(core, true);
			visual_offset(g, core);
			showcursor(core, false);
			break;
		case 'O':
			if (!fcn) {
				break;
			}
			disMode = (disMode + 1) % 3;
			applyDisMode(core);
			g->need_reload_nodes = true;
			get_bbupdate(g, core, fcn);
			break;
		case 'u': {
			if (!fcn) {
				break;
			}
			if (!rz_core_seek_undo(core)) {
				eprintf("Cannot undo\n");
			}
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		}
		case 'U': {
			if (!fcn) {
				break;
			}
			if (!rz_core_seek_redo(core)) {
				eprintf("Cannot redo\n");
			}
			break;
		}
		case 'r':
			if (fcn) {
				g->layout = rz_config_get_i(core->config, "graph.layout");
				g->need_reload_nodes = true;
			}
			// TODO: toggle shortcut hotkeys
			rz_core_visual_toggle_hints(core);
			break;
		case '$':
			if (core->print->cur_enabled) {
				rz_core_debug_reg_set(core, "PC", core->offset + core->print->cur, NULL);
			} else {
				rz_core_debug_reg_set(core, "PC", core->offset, NULL);
			}
			rz_core_seek_to_register(core, "PC", false);
			g->need_reload_nodes = true;
			break;
		case 'R':
			if (rz_config_get_i(core->config, "scr.randpal")) {
				rz_cons_pal_random();
			} else {
				rz_core_theme_nextpal(core, 'n');
			}
			if (!fcn) {
				break;
			}
			g->edgemode = rz_config_get_i(core->config, "graph.edges");
			get_bbupdate(g, core, fcn);
			break;
		case '!':
			rz_core_visual_panels_root(core, core->panels_root);
			break;
		case '\'':
			if (fcn) {
				rz_config_toggle(core->config, "graph.comments");
				g->need_reload_nodes = true;
			}
			break;
		case ';':
			if (fcn) {
				showcursor(core, true);
				char buf[256];
				rz_line_set_prompt("[comment]> ");
				if (rz_cons_fgets(buf, sizeof(buf), 0, NULL) > 0) {
					rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, core->offset, buf);
				}
				g->need_reload_nodes = true;
				showcursor(core, false);
			}
			break;
		case 'C':
			rotateColor(core);
			break;
		case 'm':
			mousemode++;
			if (!mousemodes[mousemode]) {
				mousemode = 0;
			}
			break;
		case 'M':
			mousemode--;
			if (mousemode < 0) {
				mousemode = 3;
			}
			break;
		case '(':
			if (fcn) {
				rz_core_cmd0(core, "wao recj@B:-1");
				g->need_reload_nodes = true;
			}
			break;
		case ')':
			if (fcn) {
				rotateAsmemu(core);
				g->need_reload_nodes = true;
			}
			break;
		case 'd': {
			showcursor(core, true);
			rz_core_visual_define(core, "", 0);
			get_bbupdate(g, core, fcn);
			showcursor(core, false);
		} break;
		case 'D':
			g->is_dis = !g->is_dis;
			break;
		case 'n':
			rz_core_seek_next(core, rz_config_get(core->config, "scr.nkey"), true);
			break;
		case 'N':
			rz_core_seek_prev(core, rz_config_get(core->config, "scr.nkey"), true);
			break;
		case 'Y':
			agraph_toggle_tiny(g);
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'z':
			agraph_toggle_mini(g);
			g->y_scroll = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'v':
			rz_core_visual_analysis(core, NULL);
			break;
		case 'J':
			// copypaste from 'j'
			if (g->cursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, 'j', speed * 2);
			} else {
				can->sy -= (5 * movspeed) * (invscroll ? -1 : 1);
			}
			break;
		case 'K':
			if (g->cursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, 'k', speed * 2);
			} else {
				can->sy += (5 * movspeed) * (invscroll ? -1 : 1);
			}
			break;
		case 'H':
			if (g->cursor) {
				// move node canvas faster
				graphNodeMove(g, 'h', movspeed * 2);
			} else {
				// scroll canvas faster
				if (okey == 27) {
					// handle home key
					const RzGraphNode *gn = find_near_of(g, NULL, true);
					g->update_seek_on = get_anode(gn);
				} else {
					can->sx += (5 * movspeed) * (invscroll ? -1 : 1);
				}
			}
			break;
		case 'L':
			if (g->cursor) {
				graphNodeMove(g, 'l', movspeed * 2);
			} else {
				can->sx -= (5 * movspeed) * (invscroll ? -1 : 1);
			}
			break;
		case 'c':
			g->cursor = !g->cursor;
			break;
		case 'j':
			if (g->is_dis) {
				rz_core_seek_opcode(core, 1, false);
			} else {
				if (g->cursor) {
					int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
					graphNodeMove(g, 'j', speed);
				} else {
					// scroll canvas
					can->sy -= movspeed * (invscroll ? -1 : 1);
				}
			}
			break;
		case 'k':
			if (g->is_dis) {
				rz_core_seek_opcode(core, -1, false);
			} else {
				if (g->cursor) {
					int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
					graphNodeMove(g, 'k', speed);
				} else {
					// scroll canvas
					can->sy += movspeed * (invscroll ? -1 : 1);
				}
			}
			break;
		case 'l':
			if (g->cursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, 'l', speed);
			} else {
				can->sx -= movspeed * (invscroll ? -1 : 1);
			}
			break;
		case 'h':
			if (g->cursor) {
				int speed = (okey == 27) ? PAGEKEY_SPEED : movspeed;
				graphNodeMove(g, 'h', speed);
			} else {
				can->sx += movspeed * (invscroll ? -1 : 1);
			}
			break;
		case '^': {
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			if (fcn) {
				rz_core_seek(core, fcn->addr, false);
			}
		}
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case ',':
			rz_config_toggle(core->config, "graph.few");
			g->need_reload_nodes = true;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case '.':
			g->y_scroll = 0;
			agraph_update_seek(g, get_anode(g->curnode), true);
			break;
		case 'i':
			agraph_follow_innodes(g, true);
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		case 'I':
			agraph_follow_innodes(g, false);
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		case 't':
			agraph_follow_true(g);
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		case 'T':
			// XXX WIP	agraph_merge_child (g, 0);
			break;
		case 'f':
			agraph_follow_false(g);
			if (rz_config_get_i(core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		case 'F':
			if (okey == 27) {
				// handle end key
				const RzGraphNode *gn = find_near_of(g, NULL, false);
				g->update_seek_on = get_anode(gn);
			} else {
				// agraph_merge_child (g, 1);
				rz_core_visual_trackflags(core);
			}
			break;
		case '/':
			showcursor(core, true);
			rz_core_cmd0(core, "?i highlight;e scr.highlight=`yp`");
			showcursor(core, false);
			break;
		case ':':
			core->cons->event_resize = (RzConsEvent)agraph_set_need_reload_nodes;
			rz_core_visual_prompt_input(core);
			core->cons->event_resize = (RzConsEvent)agraph_refresh_oneshot;
			if (!g) {
				g->need_reload_nodes = true; // maybe too slow and unnecessary sometimes? better be safe and reload
				get_bbupdate(g, core, fcn);
			}
			break;
		case 'w':
			agraph_toggle_speed(g, core);
			break;
		case '_':
			rz_core_visual_hudstuff(core);
			break;
		case RZ_CONS_KEY_F1:
			cmd = rz_config_get(core->config, "key.f1");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F2:
			cmd = rz_config_get(core->config, "key.f2");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			} else {
				graph_breakpoint(core);
			}
			break;
		case RZ_CONS_KEY_F3:
			cmd = rz_config_get(core->config, "key.f3");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F4:
			cmd = rz_config_get(core->config, "key.f4");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F5:
			cmd = rz_config_get(core->config, "key.f5");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F6:
			cmd = rz_config_get(core->config, "key.f6");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F7:
			cmd = rz_config_get(core->config, "key.f7");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			} else {
				graph_single_step_in(core, g);
			}
			break;
		case RZ_CONS_KEY_F8:
			cmd = rz_config_get(core->config, "key.f8");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			} else {
				graph_single_step_over(core, g);
			}
			break;
		case RZ_CONS_KEY_F9:
			cmd = rz_config_get(core->config, "key.f9");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			} else {
				graph_continue(core);
			}
			break;
		case RZ_CONS_KEY_F10:
			cmd = rz_config_get(core->config, "key.f10");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F11:
			cmd = rz_config_get(core->config, "key.f11");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case RZ_CONS_KEY_F12:
			cmd = rz_config_get(core->config, "key.f12");
			if (cmd && *cmd) {
				(void)rz_core_cmd0(core, cmd);
			}
			break;
		case -1: // EOF
		case ' ':
		case 'Q':
		case 'q':
			if (g->is_callgraph) {
				agraph_toggle_callgraph(g);
			} else {
				exit_graph = true;
			}
			break;
		case 27: // ESC
			if (rz_cons_readchar() == 91) {
				if (rz_cons_readchar() == 90) {
					agraph_prev_node(g);
				}
			}
			break;
		default:
			break;
		}
	}
	rz_vector_fini(&g->ghits.word_list);
	rz_cons_break_pop();
	rz_config_set(core->config, "asm.comments", rz_str_bool(asm_comments));
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->vmode = o_vmode;
	core->is_asmqjmps_letter = o_asmqjmps_letter;
	core->keep_asmqjmps = false;

	free(grd);
	if (graph_allocated) {
		rz_agraph_free(g);
	} else {
		rz_cons_canvas_free(g->can);
		g->can = o_can;
	}
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	if (update_seek) {
		return -1;
	}
	return !is_error;
}

/**
 * @brief Create RzAGraph from generic RzGraph with RzGraphNodeInfo as node data
 * 
 * @param graph <RzGraphNodeInfo>
 * @return RzAGraph* NULL if failure
 */
RZ_API RzAGraph *create_agraph_from_graph(const RzGraph /*<RzGraphNodeInfo>*/ *graph) {
	rz_return_val_if_fail(graph, NULL);

	RzAGraph *result_agraph = rz_agraph_new(rz_cons_canvas_new(1, 1));
	if (!result_agraph) {
		return NULL;
	}
	result_agraph->need_reload_nodes = false;
	// Cache lookup to build edges
	HtPPOptions pointer_options = { 0 };
	HtPP /*<RzGraphNode *node, RzANode *anode>*/ *hashmap = ht_pp_new_opt(&pointer_options);

	if (!hashmap) {
		rz_agraph_free(result_agraph);
		return NULL;
	}
	// List of the new RzANodes
	RzListIter *iter;
	RzGraphNode *node;
	// Traverse the list, create new ANode for each Node
	rz_list_foreach (graph->nodes, iter, node) {
		RzGraphNodeInfo *info = node->data;
		RzANode *a_node = rz_agraph_add_node(result_agraph, info->title, info->body);
		if (!a_node) {
			goto failure;
		}
		ht_pp_insert(hashmap, node, a_node);
	}

	// Traverse the nodes again, now build up the edges
	rz_list_foreach (graph->nodes, iter, node) {
		RzANode *a_node = ht_pp_find(hashmap, node, NULL);
		if (!a_node) {
			goto failure; // shouldn't happen in correct graph state
		}

		RzListIter *neighbour_iter;
		RzGraphNode *neighbour;
		rz_list_foreach (node->in_nodes, neighbour_iter, neighbour) {
			RzANode *a_neighbour = ht_pp_find(hashmap, neighbour, NULL);
			if (!a_neighbour) {
				goto failure;
			}
			rz_agraph_add_edge(result_agraph, a_neighbour, a_node);
		}
	}

	ht_pp_free(hashmap);
	return result_agraph;
failure:
	ht_pp_free(hashmap);
	rz_agraph_free(result_agraph);
	return NULL;
}
