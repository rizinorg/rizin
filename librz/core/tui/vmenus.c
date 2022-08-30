// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>

#include "../core_private.h"
#include "modes.h"

#define MAX_FORMAT 3

enum {
	RZ_BYTE_DATA = 1,
	RZ_WORD_DATA = 2,
	RZ_DWORD_DATA = 4,
	RZ_QWORD_DATA = 8
};

static char *print_rop(void *_core, void *_item, bool selected) {
	char *line = _item;
	// TODO: trim if too long
	return rz_str_newf("%c %s\n", selected ? '>' : ' ', line);
}

RZ_IPI int rz_core_visual_view_rop(RzCore *core) {
	RzListIter *iter;
	const int rows = 7;
	int cur = 0;

	rz_line_set_prompt("rop regexp: ");
	const char *line = rz_line_readline();

	int scr_h, scr_w = rz_cons_get_size(&scr_h);

	if (!line || !*line) {
		return false;
	}
	// maybe store in RzCore, so we can save it in project and use it outside visual

	eprintf("Searching ROP gadgets...\n");
	char *ropstr = rz_core_cmd_strf(core, "\"/Rl %s\" @e:scr.color=0", line);
	RzList *rops = rz_str_split_list(ropstr, "\n", 0);
	int delta = 0;
	bool show_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	bool forceaddr = false;
	ut64 addr = UT64_MAX;
	char *cursearch = strdup(line);
	while (true) {
		rz_cons_clear00();
		rz_cons_printf("[0x%08" PFMT64x "]-[visual-rzrop] %s (see pdp command)\n",
			(addr == UT64_MAX) ? 0 : addr + delta, cursearch);

		// compute chain
		RzStrBuf *sb = rz_strbuf_new("");
		char *msg;
		rz_list_foreach (core->ropchain, iter, msg) {
			if (core->rasm->bits == 64) {
				ut64 n = rz_num_get(NULL, msg);
				n = rz_read_be64(&n);
				rz_strbuf_appendf(sb, "%016" PFMT64x, n);
			} else {
				ut32 n = rz_num_get(NULL, msg);
				n = rz_read_be32(&n);
				rz_strbuf_appendf(sb, "%08x", n);
			}
		}
		char *chainstr = rz_strbuf_drain(sb);

		char *wlist = rz_str_widget_list(core, rops, rows, cur, print_rop);
		rz_cons_printf("%s", wlist);
		free(wlist);
		char *curline = rz_str_dup(NULL, rz_str_trim_head_ro(rz_str_widget_list(core, rops, rows, cur, print_rop)));
		if (curline) {
			char *sp = strchr(curline, ' ');
			if (sp) {
				*sp = 0;
				if (!forceaddr) {
					addr = rz_num_math(NULL, curline);
				}
				*sp = ' ';
			}
			if (addr != UT64_MAX) {
				rz_cons_printf("Gadget:");
				// get comment
				char *output = rz_core_cmd_strf(core, "piu 10 @ 0x%08" PFMT64x, addr + delta);
				if (output) {
					rz_cons_strcat_at(output, 0, 10, scr_w, 10);
					free(output);
				}
			}
		}
		int count = 0;
		rz_cons_flush();
		rz_cons_gotoxy(0, 20);
		rz_cons_printf("ROPChain:\n  %s\n", chainstr ? chainstr : "");
		int chainstrlen = chainstr ? strlen(chainstr) : 0;
		rz_list_foreach (core->ropchain, iter, msg) {
			int extra = chainstrlen / scr_w;
			rz_cons_gotoxy(0, extra + 22 + count);
			rz_cons_strcat(msg);
			const char *cmt = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, rz_num_get(NULL, msg));
			if (cmt) {
				rz_cons_strcat(cmt);
			}
			count++;
		}
		rz_cons_flush();
		int ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			free(curline);
			free(cursearch);
			RZ_FREE(chainstr);
			return false;
		}
#define NEWTYPE(x, y) rz_mem_dup(&(y), sizeof(x));
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 127:
			free(rz_list_pop(core->ropchain));
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf("[rzrop-visual] Help\n"
				       " jk - select next/prev rop gadget\n"
				       " JK - scroll next/prev page from list\n"
				       " hl - increase/decrease delta offset in disasm\n"
				       " \\n - enter key or dot will add the current offset into the chain\n"
				       " i  - enter a number to be pushed into the chain\n"
				       " :  - run rizin command\n"
				       " ;  - add comment in current offset\n"
				       " <- - backspace - delete last gadget from the chain\n"
				       " /  - highlight given word\n"
				       " y  - yank current rop chain into the clipboard (y?)\n"
				       " o  - seek to given offset\n"
				       " r  - run /R again\n"
				       " ?  - show this help message\n"
				       " q  - quit this view\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case ':': // TODO: move this into a separate helper function
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			while (true) {
				char cmd[1024];
				cmd[0] = '\0';
				rz_line_set_prompt(":> ");
				if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				if (!*cmd || *cmd == 'q') {
					break;
				}
				ut64 oseek = core->offset;
				rz_core_seek(core, addr + delta, false);
				rz_core_cmd(core, cmd, 1);
				rz_core_seek(core, oseek, false);
				rz_cons_flush();
			}
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			break;
		case 'y':
			rz_core_yank_hexpair(core, chainstr);
			break;
		case 'o': {
			rz_line_set_prompt("offset: ");
			const char *line = rz_line_readline();
			if (line && *line) {
				ut64 off = rz_num_math(core->num, line);
				rz_core_seek(core, off, true);
				addr = off;
				forceaddr = true;
				delta = 0;
			}
		} break;
		case 'r': {
			rz_line_set_prompt("rop regexp: ");
			const char *line = rz_line_readline();
			if (line && *line) {
				free(cursearch);
				delta = 0;
				addr = UT64_MAX;
				cur = 0;
				cursearch = strdup(line);
				free(ropstr);
				ropstr = rz_core_cmd_strf(core, "\"/Rl %s\" @e:scr.color=0", line);
				rz_list_free(rops);
				rops = rz_str_split_list(ropstr, "\n", 0);
			}
		} break;
		case '/':
			rz_core_cmd0(core, "?i highlight;e scr.highlight=`yp`");
			break;
		case 'i': {
			rz_line_set_prompt("insert value: ");
			const char *line = rz_line_readline();
			if (line && *line) {
				ut64 n = rz_num_math(core->num, line);
				rz_list_push(core->ropchain, rz_str_newf("0x%08" PFMT64x, n));
			}
		} break;
		case ';': {
			rz_line_set_prompt("comment: ");
			const char *line = rz_line_readline();
			if (line && *line) {
				rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr + delta, line);
			}
		} break;
		case '.':
		case '\n':
		case '\r':
			if (curline && *curline) {
				char *line = rz_core_cmd_strf(core, "piuq@0x%08" PFMT64x, addr + delta);
				rz_str_replace_char(line, '\n', ';');
				if (show_color) {
					// XXX parsing fails to read this ansi-offset
					// const char *offsetColor = rz_cons_singleton ()->context->pal.offset; // TODO etooslow. must cache
					// rz_list_push (core->ropchain, rz_str_newf ("%s0x%08"PFMT64x""Color_RESET"  %s", offsetColor, addr + delta, line));
					rz_list_push(core->ropchain, rz_str_newf("0x%08" PFMT64x "  %s", addr + delta, line));
				} else {
					rz_list_push(core->ropchain, rz_str_newf("0x%08" PFMT64x "  %s", addr + delta, line));
				}
				free(line);
			}
			break;
		case 'h':
			delta--;
			break;
		case 'l':
			delta++;
			break;
		case 'J':
			cur += 10;
			forceaddr = false;
			delta = 0;
			break;
		case 'K':
			delta = 0;
			forceaddr = false;
			if (cur > 10) {
				cur -= 10;
			} else {
				cur = 0;
			}
			break;
		case '0':
			delta = 0;
			cur = 0;
			break;
		case 'j':
			delta = 0;
			cur++;
			forceaddr = false;
			break;
		case 'k':
			delta = 0;
			forceaddr = false;
			if (cur > 0) {
				cur--;
			} else {
				cur = 0;
			}
			break;
		case 'q':
			free(curline);
			free(cursearch);
			RZ_FREE(chainstr);
			return true;
		}
		RZ_FREE(chainstr);
		free(curline);
	}
	free(cursearch);
	return false;
}

// helper
static void function_rename(RzCore *core, ut64 addr, const char *name) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;

	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		if (fcn->addr == addr) {
			rz_flag_unset_name(core->flags, fcn->name);
			free(fcn->name);
			fcn->name = strdup(name);
			rz_flag_set(core->flags, name, addr, rz_analysis_function_size_from_entry(fcn));
			break;
		}
	}
}

static void variable_rename(RzCore *core, ut64 addr, int vindex, const char *name) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	ut64 a_tmp = core->offset;
	int i = 0;
	RzListIter *iter;
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	RzAnalysisVar *var;

	rz_list_foreach (list, iter, var) {
		if (i == vindex) {
			rz_core_seek(core, addr, false);
			rz_core_analysis_var_rename(core, name, var->name);
			rz_core_seek(core, a_tmp, false);
			break;
		}
		++i;
	}
	rz_list_free(list);
}

static void variable_set_type(RzCore *core, ut64 addr, int vindex, const char *type) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	RzListIter *iter;
	RzAnalysisVar *var;

	RzType *ttype = rz_type_parse_string_single(core->analysis->typedb->parser, type, NULL);
	rz_list_foreach (list, iter, var) {
		if (vindex == 0) {
			rz_analysis_var_set_type(var, ttype, true);
			break;
		}
		vindex--;
	}
	rz_list_free(list);
}

/**
 * \brief Convert the string inputing to RzPVector, with WHITESPACE as separators
 *
 * \param inputing
 * \return return the pointer of RzPVector
 */
static RzPVector *capture_filter_keywords(char *inputing) {
	rz_return_val_if_fail(inputing, NULL);
	RzPVector *keywords = rz_pvector_new(free);

	if (!keywords) {
		return NULL;
	}
	char *processing = rz_str_trim_dup(inputing);
	char *buf = rz_str_new("");
	for (int i = 0; i < strlen(processing); i++) {
		if (IS_WHITESPACE(processing[i])) {
			if (strlen(buf)) {
				rz_pvector_push(keywords, buf);
				buf = rz_str_new("");
			}
		} else {
			buf = rz_str_appendch(buf, processing[i]);
		}
	}
	if (strlen(buf)) {
		rz_pvector_push(keywords, buf);
	} else {
		RZ_FREE(buf);
	}
	free(processing);
	return keywords;
}

/**
 * \brief Filter the functions in visual analysis mode (helper of command f)
 *
 * \param core
 * \param filter_fcn store the filtered functions
 * \return return the number of functions that conform to the keywords
 */
static ut32 filter_function(RzCore *core, RzList *filter_fcn, RzPVector *keywords) {
	rz_return_val_if_fail(core, 0);
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	size_t num = 0;

	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		bool contain = true;
		void **it;
		rz_pvector_foreach (keywords, it) {
			contain = contain && strstr(fcn->name, (char *)*it);
		}
		if (!contain) {
			continue;
		}
		if (filter_fcn) {
			rz_list_append(filter_fcn, fcn);
		}
		num++;
	}

	return num;
}

// In visual mode, display function list
static ut64 var_functions_show(RzCore *core, int idx, int show, int cols) {
	int wdelta = (idx > 5) ? idx - 5 : 0;
	char *var_functions;
	ut64 seek = core->offset;
	ut64 addr = core->offset;
	RzAnalysisFunction *fcn;
	RzList *filter_fcn = core->analysis->fcns, *visual_filter = NULL;
	int window, i = 0, print_full_func;
	RzListIter *iter;
	RzCoreVisual *visual = core->visual;

	// Adjust the windows size automaticaly
	(void)rz_cons_get_size(&window);
	window -= visual->inputing ? 10 : 8; // Size of printed things
	bool color = rz_config_get_i(core->config, "scr.color");
	const char *color_addr = core->cons->context->pal.offset;
	const char *color_fcn = core->cons->context->pal.fname;

	if (visual->inputing) {
		visual_filter = rz_list_newf(NULL);
		if (visual_filter) {
			RzPVector *keywords = capture_filter_keywords(visual->inputing);
			if (keywords) {
				filter_function(core, visual_filter, keywords);
				RZ_FREE_CUSTOM(keywords, rz_pvector_free);
				filter_fcn = visual_filter;
			}
		}
	}

	rz_list_foreach (filter_fcn, iter, fcn) {
		print_full_func = true;
		if (i >= wdelta) {
			if (i > window + wdelta - 1) {
				rz_cons_printf("...\n");
				break;
			}
			if (idx == i) {
				addr = fcn->addr;
			}
			if (show) {
				char *tmp;
				if (color) {
					var_functions = rz_str_newf("%c%c %s0x%08" PFMT64x "" Color_RESET " %4" PFMT64d " %s%s" Color_RESET "",
						(seek == fcn->addr) ? '>' : ' ',
						(idx == i) ? '*' : ' ',
						color_addr, fcn->addr, rz_analysis_function_realsize(fcn),
						color_fcn, fcn->name);
				} else {
					var_functions = rz_str_newf("%c%c 0x%08" PFMT64x " %4" PFMT64d " %s",
						(seek == fcn->addr) ? '>' : ' ',
						(idx == i) ? '*' : ' ',
						fcn->addr, rz_analysis_function_realsize(fcn), fcn->name);
				}
				if (var_functions) {
					if (!rz_cons_singleton()->show_vals) {
						int fun_len = rz_str_ansi_len(var_functions);
						int columns = fun_len > cols ? cols - 2 : cols;
						tmp = rz_str_ansi_crop(var_functions, 0, 0, columns, window);
						if (rz_str_ansi_len(tmp) < fun_len) {
							rz_cons_printf("%s..%s\n", tmp, Color_RESET);
							print_full_func = false;
						}
						rz_free(tmp);
					}
					if (print_full_func) {
						rz_cons_println(var_functions);
					}
					rz_free(var_functions);
				}
			}
		}
		i++;
	}
	if (filter_fcn != core->analysis->fcns) {
		rz_list_free(filter_fcn);
	}
	return addr;
}

// In visual mode, display the variables.
static ut64 var_variables_show(RzCore *core, int idx, int *vindex, int show, int cols) {
	int i = 0;
	const ut64 addr = var_functions_show(core, idx, 0, cols);
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	int window;
	int wdelta = (idx > 5) ? idx - 5 : 0;
	RzListIter *iter;
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	RzAnalysisVar *var;
	// Adjust the window size automatically.
	(void)rz_cons_get_size(&window);
	window -= 8; // Size of printed things.

	// A new line so this looks reasonable.
	rz_cons_newline();

	int llen = rz_list_length(list);
	if (*vindex >= llen) {
		*vindex = llen - 1;
	}

	rz_list_foreach (list, iter, var) {
		if (i >= wdelta) {
			if (i > window + wdelta) {
				rz_cons_printf("...\n");
				break;
			}
			if (show) {
				char *vartype = rz_type_as_string(core->analysis->typedb, var->type);
				switch (var->kind & 0xff) {
				case 'r': {
					RzRegItem *r = rz_reg_index_get(core->analysis->reg, var->delta);
					if (!r) {
						eprintf("Register not found");
						break;
					}
					rz_cons_printf("%sarg %s %s @ %s\n",
						i == *vindex ? "* " : "  ",
						vartype, var->name,
						r->name);
				} break;
				case 'b':
					rz_cons_printf("%s%s %s %s @ %s%s0x%x\n",
						i == *vindex ? "* " : "  ",
						var->delta < 0 ? "var" : "arg",
						vartype, var->name,
						core->analysis->reg->name[RZ_REG_NAME_BP],
						(var->kind == 'v') ? "-" : "+",
						var->delta);
					break;
				case 's':
					rz_cons_printf("%s%s %s %s @ %s%s0x%x\n",
						i == *vindex ? "* " : "  ",
						var->delta < 0 ? "var" : "arg",
						vartype, var->name,
						core->analysis->reg->name[RZ_REG_NAME_BP],
						(var->kind == 'v') ? "-" : "+",
						var->delta);
					break;
				}
				free(vartype);
			}
		}
		++i;
	}
	rz_list_free(list);
	return addr;
}

static int level = 0;
static st64 delta = 0;
static int option = 0;
static int variable_option = 0;
static int printMode = 0;
static bool selectPanel = false;

static void rz_core_visual_analysis_refresh_column(RzCore *core, int colpos) {
	const ut64 addr = (level != 0 && level != 1)
		? core->offset
		: var_functions_show(core, option, 0, colpos);
	// RzAnalysisFunction* fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	int h, w = rz_cons_get_size(&h);
	// int sz = (fcn)? RZ_MIN (rz_analysis_fcn_size (fcn), h * 15) : 16; // max instr is 15 bytes.

	const char *cmd;
	if (printMode > 0 && printMode < lastPrintMode) {
		cmd = printCmds[printMode];
	} else {
		cmd = printCmds[printMode = 0];
	}
	char *cmdf = rz_str_newf("%s @ 0x%" PFMT64x, cmd, addr + delta);
	if (!cmdf) {
		return;
	}
	char *output = rz_core_cmd_str(core, cmdf);
	if (output) {
		// 'h - 2' because we have two new lines in rz_cons_printf
		char *out = rz_str_ansi_crop(output, 0, 0, w - colpos, h - 2);
		rz_cons_printf("\n%s\n", out);
		free(out);
		RZ_FREE(output);
	}
	free(cmdf);
}

static const char *help_fun_visual[] = {
	"(a)", "analyze ", "(-)", "delete ", "(x)", "xrefs to ", "(X)", "xrefs from\n",
	"(r)", "rename ", "(c)", "calls ", "(d)", "define ", "(:)", "shell ", "(v)", "vars\n",
	"(j/k)", "next/prev ", "(tab)", "column ", "(_)", "hud ", "(?)", " help\n",
	"(f/F)", "set/reset filter ", "(s)", "function signature ", "(q)", "quit\n\n",
	NULL
};

static const char *help_var_visual[] = {
	"(a)", "add ", "(x)", "xrefs ", "(r)", "rename\n",
	"(t)", "type ", "(g)", "go ", "(-)", "delete\n",
	"(q)", "quit ", "(s)", "signature\n\n",
	NULL
};

static const char *help_vv_visual[] = {
	"j,k", "select next/prev item or scroll if tab pressed",
	"J,K", "scroll next/prev page \"\"",
	"f,F", "set/reset filter keyword",
	"h,q", "go back, quit",
	"p,P", "switch next/prev print mode",
	"v", "view selected function arguments and variables",
	"x,X", "see xrefs to the selected function",
	"tab", "toggle disasm column selection (to scroll in code)",
	"!", "run 'afls' to sort all functions by address",
	".", "seek to current function address",
	":", "run rizin commands",
	"_", "hud mode. same as: s $(afl~...)",
	"enter", "enter function view (variables), xrefs",
	NULL
};

static const char *help_vv_actions_visual[] = {
	" functions:", "Add, Modify, Delete, Xrefs Calls Vars",
	" variables:", "Add, Modify, Delete",
	NULL
};

static void rz_core_vmenu_append_help(RzStrBuf *p, const char **help) {
	int i;
	RzConsContext *cons_ctx = rz_cons_singleton()->context;
	const char *pal_args_color = cons_ctx->color_mode ? cons_ctx->pal.args : "",
		   *pal_help_color = cons_ctx->color_mode ? cons_ctx->pal.help : "",
		   *pal_reset = cons_ctx->color_mode ? cons_ctx->pal.reset : "";

	for (i = 0; help[i]; i += 2) {
		rz_strbuf_appendf(p, "%s%s %s%s%s",
			pal_args_color, help[i],
			pal_help_color, help[i + 1], pal_reset);
	}
}

static ut64 rz_core_visual_analysis_refresh(RzCore *core) {
	rz_return_val_if_fail(core, 0);
	RzCoreVisual *visual = core->visual;
	ut64 addr;
	RzStrBuf *buf;
	char old[1024];
	bool color = rz_config_get_i(core->config, "scr.color");
	int h, cols = rz_cons_get_size(&h);
	old[0] = '\0';
	addr = core->offset;
	cols -= 50;
	if (cols > 60) {
		cols = 60;
	}

	rz_cons_clear00();
	rz_core_visual_analysis_refresh_column(core, cols);
	if (cols > 30) {
		rz_cons_column(cols);
	}
	switch (level) {
	// Show functions list help in visual mode
	case 0: {
		buf = rz_strbuf_new("");
		if (color) {
			rz_cons_strcat(core->cons->context->pal.prompt);
		}
		if (selectPanel) {
			rz_cons_printf("-- functions -----------------[ %s ]-->>", printCmds[printMode]);
		} else {
			rz_cons_printf("-[ functions ]----------------- %s ---", printCmds[printMode]);
		}
		if (color) {
			rz_cons_strcat("\n" Color_RESET);
		}
		rz_core_vmenu_append_help(buf, help_fun_visual);
		char *drained = rz_strbuf_drain(buf);
		rz_cons_printf("%s", drained);
		free(drained);
		// hints for filtered keywords
		if (visual->inputing) {
			if (visual->is_inputing) {
				rz_cons_printf("input keywords: %s\n\n", visual->inputing);
			} else {
				rz_cons_printf("keywords: %s\n\n", visual->inputing);
			}
		}
		addr = var_functions_show(core, option, 1, cols);
		break;
	}
	case 1: {
		buf = rz_strbuf_new("");
		if (color) {
			rz_cons_strcat(core->cons->context->pal.prompt);
		}
		rz_cons_printf("-[ variables ]----- 0x%08" PFMT64x "", addr);
		if (color) {
			rz_cons_strcat("\n" Color_RESET);
		}
		rz_core_vmenu_append_help(buf, help_var_visual);
		char *drained = rz_strbuf_drain(buf);
		rz_cons_printf("%s", drained);
		addr = var_variables_show(core, option, &variable_option, 1, cols);
		free(drained);
		// var_index_show (core->analysis, fcn, addr, option);
		break;
	}
	case 2: {
		rz_cons_printf("Press 'q' to quit call refs\n");
		if (color) {
			rz_cons_strcat(core->cons->context->pal.prompt);
		}
		rz_cons_printf("-[ calls ]----------------------- 0x%08" PFMT64x " (TODO)\n", addr);
		if (color) {
			rz_cons_strcat("\n" Color_RESET);
		}
		// TODO: filter only the callrefs. but we cant grep here
		sprintf(old, "afi @ 0x%08" PFMT64x, addr);
		char *output = rz_core_cmd_str(core, old);
		if (output) {
			// 'h - 2' because we have two new lines in rz_cons_printf
			if (!rz_cons_singleton()->show_vals) {
				char *out = rz_str_ansi_crop(output, 0, 0, cols, h - 2);
				rz_cons_printf("\n%s\n", out);
				free(out);
				RZ_FREE(output);
			} else {
				rz_cons_printf("\n%s\n", output);
				RZ_FREE(output);
			}
		}
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
	rz_cons_flush();
	return addr;
}

static void rz_core_visual_analysis_refresh_oneshot(RzCore *core) {
	rz_core_task_enqueue_oneshot(&core->tasks, (RzCoreTaskOneShot)rz_core_visual_analysis_refresh, core);
}

static void rz_core_visual_debugtraces_help(RzCore *core) {
	rz_cons_clear00();
	rz_cons_printf(
		"vbd: Visual Browse Debugtraces:\n\n"
		" q     - quit the bit editor\n"
		" Q     - Quit (jump into the disasm view)\n"
		" j/k   - Select next/previous trace\n"
		" :     - enter command\n");
	rz_cons_flush();
	rz_cons_any_key(NULL);
}

RZ_IPI void rz_core_visual_debugtraces(RzCore *core, const char *input) {
	int i, delta = 0;
	for (;;) {
		char *trace_addr_str = rz_core_cmd_strf(core, "dtdq %d", delta);
		ut64 trace_addr = rz_num_get(NULL, trace_addr_str);
		free(trace_addr_str);
		rz_cons_printf("[0x%08" PFMT64x "]> %d dbg.trace\n", trace_addr, delta);
		for (i = 0; i < delta; i++) {
			rz_core_cmdf(core, ".dte %d", i);
		}
		rz_core_cmd0(core, "x 64@r:SP");
		rz_core_debug_ri(core);
		// limit by rows here
		// int rows = rz_cons_get_size (NULL);
		rz_core_cmdf(core, "dtd %d", delta);
		rz_cons_visual_flush();
		char ch;
		if (input && *input) {
			ch = *input;
			input++;
		} else {
			ch = rz_cons_readchar();
		}
		if (ch == 4 || ch == -1) {
			if (level == 0) {
				goto beach;
			}
			level--;
			continue;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'Q': // tab
		{
			ut64 oseek = core->offset;
			core->vmode = false;
			rz_core_seek(core, trace_addr, true);
			rz_core_visual(core, "");
			rz_core_seek(core, oseek, true);
		} break;
		case 'q':
			goto beach;
			break;
		case ']':
			rz_config_set_i(core->config, "hex.cols", rz_config_get_i(core->config, "hex.cols") + 1);
			break;
		case '[':
			rz_config_set_i(core->config, "hex.cols", rz_config_get_i(core->config, "hex.cols") - 1);
			break;
		case 'J':
			delta += 10;
			break;
		case 'K':
			delta -= 10;
			if (delta < 0) {
				delta = 0;
			}
			break;
		case 'j':
			delta++;
			break;
		case 'k':
			delta--;
			if (delta < 0) {
				delta = 0;
			}
			break;
		case ':':
			rz_core_visual_prompt(core);
			rz_cons_any_key(NULL);
			break;
		case '?':
			rz_core_visual_debugtraces_help(core);
			break;
		}
	}
beach:;
}

static char *__prompt(const char *msg, void *p) {
	char res[128];
	rz_cons_show_cursor(true);
	rz_cons_set_raw(false);
	rz_line_set_prompt(msg);
	res[0] = 0;
	if (!rz_cons_fgets(res, sizeof(res), 0, NULL)) {
		res[0] = 0;
	}
	return strdup(res);
}

static void addVar(RzCore *core, int ch, const char *msg) {
	char *src = __prompt(msg, NULL);
	char *name = __prompt("Variable Name: ", NULL);
	char *type = __prompt("Type of Variable (int32_t): ", NULL);
	char *cmd = rz_str_newf("afv%c %s %s %s", ch, src, name, type);
	rz_str_trim(cmd);
	rz_core_cmd0(core, cmd);
	free(cmd);
	free(src);
	free(name);
	free(type);
}

/* Like emenu but for real */
RZ_IPI void rz_core_visual_analysis(RzCore *core, const char *input) {
	char old[218];
	int nfcns, ch, _option = 0;

	RzCoreVisual *visual = core->visual;
	RzConsEvent olde = core->cons->event_resize;
	void *olde_user = core->cons->event_data;
	ut64 addr = core->offset;

	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = core;
	core->cons->event_resize = (RzConsEvent)rz_core_visual_analysis_refresh_oneshot;

	level = 0;

	int asmbytes = rz_config_get_i(core->config, "asm.bytes");
	rz_config_set_i(core->config, "asm.bytes", 0);
	for (;;) {
		nfcns = rz_list_length(core->analysis->fcns);
		if (visual->inputing) {
			RzPVector *keywords = capture_filter_keywords(visual->inputing);
			if (keywords) {
				nfcns = filter_function(core, NULL, keywords);
			}
			RZ_FREE_CUSTOM(keywords, rz_pvector_free);
		}
		addr = rz_core_visual_analysis_refresh(core);

		// for filter on the go
		if (level == 0 && visual->is_inputing) {
			int ch = rz_cons_readchar();
			switch (ch) {
			case 13: // CR
				visual->is_inputing = false;
				if (!strlen(visual->inputing)) {
					RZ_FREE(visual->inputing);
				}
				break;
			case 127: // Backspace
			case 8:
				if (strlen(visual->inputing) > 0) {
					visual->inputing[strlen(visual->inputing) - 1] = '\0';
				}
				break;
			default:
				if (!IS_PRINTABLE(ch)) {
					continue;
				}
				visual->inputing = rz_str_appendch(visual->inputing, ch);
				break;
			}
			// mute the following switch while inputing keyword
			continue;
		}

		if (input && *input) {
			ch = *input;
			input++;
		} else {
			ch = rz_cons_readchar();
		}
		if (ch == 4 || ch == -1) {
			if (level == 0) {
				goto beach;
			}
			level--;
			continue;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char

		switch (ch) {
		case 'f':
			if (level == 0) {
				// add new keyword
				visual->is_inputing = true;
				if (!visual->inputing) {
					visual->inputing = rz_str_new("");
				}
				option = 0;
			}
			break;
		case 'F':
			if (level == 0) {
				// reset all keywords
				RZ_FREE(visual->inputing);
			}
			break;
		case '[':
			rz_cons_singleton()->show_vals = true;
			break;
		case ']':
			rz_cons_singleton()->show_vals = false;
			break;
		case '?':
			rz_cons_clear00();
			RzStrBuf *buf = rz_strbuf_new("");
			rz_cons_println("|Usage: vv");
			rz_core_visual_append_help(buf, "Actions supported", help_vv_actions_visual);
			rz_core_visual_append_help(buf, "Keys", help_vv_visual);
			rz_cons_printf("%s", rz_strbuf_drain(buf));
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case 9:
			selectPanel = !selectPanel;
			if (!selectPanel) {
				delta = 0;
				printMode = 0;
			}
			break;
		case ':': {
			ut64 orig = core->offset;
			rz_core_seek(core, addr, false);
			while (rz_core_visual_prompt(core))
				;
			rz_core_seek(core, orig, false);
		}
			continue;
		case '/':
			rz_core_cmd0(core, "?i highlight;e scr.highlight=`yp`");
			break;
		case 'a':
			switch (level) {
			case 0:
				// Remove the old function information
				rz_core_analysis_undefine(core, core->offset);
				rz_analysis_fcn_del_locs(core->analysis, core->offset);
				rz_analysis_fcn_del(core->analysis, core->offset);
				// Reanalyze and create function from scratch
				rz_core_analysis_function_add(core, NULL, core->offset, false);
				break;
			case 1: {
				eprintf("Select variable source ('r'egister, 's'tackptr or 'b'aseptr): ");
				int type = rz_cons_readchar();
				switch (type) {
				case 'r':
					addVar(core, type, "Source Register Name: ");
					break;
				case 's':
					addVar(core, type, "BP Relative Delta: ");
					break;
				case 'b':
					addVar(core, type, "SP Relative Delta: ");
					break;
				}
			} break;
			}
			break;
		case 'r': {
			switch (level) {
			case 1:
				rz_cons_show_cursor(true);
				rz_cons_set_raw(false);
				rz_line_set_prompt("New name: ");
				if (rz_cons_fgets(old, sizeof(old), 0, NULL)) {
					if (*old) {
						// old[strlen (old)-1] = 0;
						variable_rename(core, addr, variable_option, old);
					}
				}
				break;
			default:
				rz_line_set_prompt("New name: ");
				if (rz_cons_fgets(old, sizeof(old), 0, NULL)) {
					if (*old) {
						// old[strlen (old)-1] = 0;
						function_rename(core, addr, old);
					}
				}
				break;
			}
			rz_cons_set_raw(true);
			rz_cons_show_cursor(false);
		} break;
		case 't':
			if (level == 1) {
				rz_cons_show_cursor(true);
				rz_cons_set_raw(false);
				rz_line_set_prompt("New type: ");
				if (rz_cons_fgets(old, sizeof(old), 0, NULL)) {
					if (*old) {
						// old[strlen (old)-1] = 0;
						variable_set_type(core, addr, variable_option, old);
					}
				}
				rz_cons_set_raw(true);
				rz_cons_show_cursor(false);
			}
			break;
		case '.':
			delta = 0;
			break;
		case 'R':
			rz_core_theme_nextpal(core, 'n');
			break;
		case 'p':
			printMode++;
			break;
		case 'P':
			if (printMode == 0) {
				printMode = lastPrintMode;
			} else {
				printMode--;
			}
			break;
		case 'd':
			rz_core_visual_define(core, "", 0);
			break;
		case '-':
			switch (level) {
			case 0:
				// Remove the old function information
				rz_core_analysis_undefine(core, addr);
				rz_analysis_fcn_del_locs(core->analysis, addr);
				rz_analysis_fcn_del(core->analysis, addr);
				break;
			}
			break;
		case 'x':
			rz_core_visual_xrefs(core, false, true);
			break;
		case 'X':
			rz_core_visual_xrefs(core, true, true);
			break;
		case 's':
			rz_core_analysis_function_signature_editor(core, addr);
			break;
		case 'c':
			level = 2;
			break;
		case 'v':
			level = 1;
			variable_option = 0;
			break;
		case '_': {
			rz_core_cmd0(core, "s $(afl~...)");
			int n = 0;
			RzListIter *iter;
			RzAnalysisFunction *fcn;
			rz_list_foreach (core->analysis->fcns, iter, fcn) {
				if (fcn->addr == core->offset) {
					option = n;
					break;
				}
				n++;
			}
		} break;
		case 'j':
			if (selectPanel) {
				printMode = 1;
				delta += 16;
			} else {
				delta = 0;
				switch (level) {
				case 1:
					variable_option++;
					break;
				default:
					option++;
					if (option >= nfcns) {
						--option;
					}
					break;
				}
			}
			break;
		case '!':
			// TODO: use aflsn/aflsb/aflss/...
			{
				static int sortMode = 0;
				const char *sortModes[4] = { "aflsa", "aflss", "aflsb", "aflsn" };
				rz_core_cmd0(core, sortModes[sortMode % 4]);
				sortMode++;
			}
			break;
		case 'k':
			if (selectPanel) {
				printMode = 1;
				delta -= 16;
			} else {
				delta = 0;
				switch (level) {
				case 1:
					variable_option = (variable_option <= 0) ? 0 : variable_option - 1;
					break;
				default:
					option = (option <= 0) ? 0 : option - 1;
					break;
				}
			}

			break;
		case 'J':
			if (selectPanel) {
				printMode = 1;
				delta += 40;
			} else {
				int rows = 0;
				rz_cons_get_size(&rows);
				option += (rows - 5);
				if (option >= nfcns) {
					option = nfcns - 1;
				}
			}
			break;
		case 'K':
			if (selectPanel) {
				printMode = 1;
				delta -= 40;
			} else {
				int rows = 0;
				rz_cons_get_size(&rows);
				option -= (rows - 5);
				if (option < 0) {
					option = 0;
				}
			}
			break;
		case 'g': {
			rz_core_visual_showcursor(core, true);
			rz_core_visual_offset(core); // change the seek to selected offset
			RzListIter *iter; // change the current option to selected seek
			RzAnalysisFunction *fcn;
			int i = 0;
			rz_list_foreach (core->analysis->fcns, iter, fcn) {
				if (core->offset == fcn->addr) {
					option = i;
				}
				i++;
			}
			rz_core_visual_showcursor(core, false);
		} break;
		case 'G':
			rz_core_seek(core, addr, SEEK_SET);
			goto beach;
		case ' ':
		case '\r':
		case '\n':
			level = 0;
			rz_core_seek(core, addr, SEEK_SET);
			goto beach;
			break;
		case 'l':
			level = 1;
			_option = option;
			break;
		case 'h':
		case 'b': // back
			level = 0;
			option = _option;
			break;
		case 'Q':
		case 'q':
			if (level == 0) {
				goto beach;
			}
			level--;
			break;
		}
	}
beach:
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = olde_user;
	core->cons->event_resize = olde;
	level = 0;
	rz_config_set_i(core->config, "asm.bytes", asmbytes);
}

// define the data at offset according to the type (byte, word...) n times
static void define_data_ntimes(RzCore *core, ut64 off, int times, int type) {
	int i = 0;
	rz_meta_del(core->analysis, RZ_META_TYPE_ANY, off, core->blocksize);
	if (times < 0) {
		times = 1;
	}
	for (i = 0; i < times; i++, off += type) {
		rz_meta_set(core->analysis, RZ_META_TYPE_DATA, off, type, "");
	}
}

static bool isDisasmPrint(int mode) {
	return (mode == 1 || mode == 2);
}

static void handleHints(RzCore *core) {
	// TODO extend for more analysis hints
	int i = 0;
	char ch[64] = RZ_EMPTY;
	const char *lines[] = { "[dh]- Define analysis hint:", " b [16,32,64]     set bits hint", NULL };
	for (i = 0; lines[i]; i++) {
		rz_cons_fill_line();
		rz_cons_printf("\r%s\n", lines[i]);
	}
	rz_cons_flush();
	rz_line_set_prompt("analysis hint: ");
	if (rz_cons_fgets(ch, sizeof(ch), 0, NULL) > 0) {
		switch (ch[0]) {
		case 'b': {
			char *arg = ch + 1;
			rz_str_trim(arg);
			int bits = atoi(arg);
			if (bits == 8 || bits == 16 || bits == 32 || bits == 64) {
				rz_analysis_hint_set_bits(core->analysis, core->offset, bits);
			}
		} break;
		default:
			break;
		}
	}
}

RZ_IPI void rz_core_visual_define(RzCore *core, const char *args, int distance) {
	RzCoreVisual *visual = core->visual;
	int plen = core->blocksize;
	ut64 off = core->offset;
	int i, h = 0, n, ch, ntotal = 0;
	ut8 *p = core->block;
	int rep = -1;
	char *name;
	int delta = 0;
	if (core->print->cur_enabled) {
		int cur = core->print->cur;
		if (core->print->ocur != -1) {
			plen = RZ_ABS(core->print->cur - core->print->ocur) + 1;
			if (core->print->ocur < cur) {
				cur = core->print->ocur;
			}
		}
		off += cur;
		p += cur;
	}
	(void)rz_cons_get_size(&h);
	h -= 19;
	if (h < 0) {
		h = 0;
		rz_cons_clear00();
	} else {
		rz_cons_gotoxy(0, 3);
	}
	const char *lines[] = { "", "[Vd]- Define current block as:", " $    define flag size", " 1    edit bits", " a    assembly", " b    as byte (1 byte)", " B    define half word (16 bit, 2 byte size)", " c    as code (unset any data / string / format) in here", " C    define flag color (fc)", " d    set as data", " e    end of function", " f    analyze function", " F    format", " h    define hint (for half-word, see 'B')", " i    (ahi) immediate base (b(in), o(ct), d(ec), h(ex), s(tr))", " I    (ahi1) immediate base (b(in), o(ct), d(ec), h(ex), s(tr))", " j    merge down (join this and next functions)", " k    merge up (join this and previous function)", " h    define analysis hint", " m    manpage for current call", " n    rename flag used at cursor", " N    edit function signature (afs!)", " o    opcode string", " r    rename function", " R    find references /r", " s    set string", " S    set strings in current block", " t    set opcode type via aht hints (call, nop, jump, ...)", " u    undefine metadata here", " v    rename variable at offset that matches some hex digits", " x    find xrefs to current address (./r)", " w    set as 32bit word", " W    set as 64bit word", " q    quit menu", " z    zone flag", NULL };
	for (i = 0; lines[i]; i++) {
		rz_cons_fill_line();
		rz_cons_printf("\r%s\n", lines[i]);
	}
	rz_cons_flush();
	int wordsize = 0;
	// get ESC+char, return 'hjkl' char
repeat:
	if (*args) {
		ch = *args;
		args++;
	} else {
		ch = rz_cons_arrow_to_hjkl(rz_cons_readchar());
	}

onemoretime:
	wordsize = 4;
	switch (ch) {
	case 'N':
		rz_core_analysis_function_signature_editor(core, off);
		break;
	case 'F': {
		char cmd[128];
		rz_cons_show_cursor(true);
		rz_core_cmd0(core, "pf?");
		rz_cons_flush();
		rz_line_set_prompt("format: ");
		strcpy(cmd, "Cf 0 ");
		if (rz_cons_fgets(cmd + 5, sizeof(cmd) - 5, 0, NULL) > 0) {
			rz_core_cmdf(core, "%s @ 0x%08" PFMT64x, cmd, off);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
		}
	} break;
	case '1':
		rz_core_visual_bit_editor(core);
		break;
	case 't':
	case 'o': {
		char str[128];
		rz_cons_show_cursor(true);
		rz_line_set_prompt(ch == 't' ? "type: " : "opstr: ");
		if (rz_cons_fgets(str, sizeof(str), 0, NULL) > 0) {
			rz_core_cmdf(core, "ah%c %s @ 0x%" PFMT64x, ch, str, off);
		}
	} break;
	case 'x':
		rz_core_cmd0(core, "/r $$");
		break;
	case 'i': {
		char str[128];
		rz_cons_show_cursor(true);
		rz_line_set_prompt("immbase: ");
		if (rz_cons_fgets(str, sizeof(str), 0, NULL) > 0) {
			int base = rz_num_base_of_string(core->num, str);
			rz_analysis_hint_set_immbase(core->analysis, off, base);
		}
	} break;
	case 'I': {
		char str[128];
		rz_cons_show_cursor(true);
		rz_line_set_prompt("immbase: ");
		if (rz_cons_fgets(str, sizeof(str), 0, NULL) > 0) {
			rz_core_cmdf(core, "ahi1 %s @ 0x%" PFMT64x, str, off);
		}
	} break;
	case 'a':
		rz_core_visual_asm(core, off);
		break;
	case 'b':
		if (plen != core->blocksize) {
			rep = plen / 2;
		}
		define_data_ntimes(core, off, rep, RZ_BYTE_DATA);
		wordsize = 1;
		break;
	case 'B': // "VdB"
		if (plen != core->blocksize) {
			rep = plen / 2;
		}
		define_data_ntimes(core, off, rep, RZ_WORD_DATA);
		wordsize = 2;
		break;
	case 'w':
		if (plen != core->blocksize) {
			rep = plen / 4;
		}
		define_data_ntimes(core, off, rep, RZ_DWORD_DATA);
		wordsize = 4;
		break;
	case 'W':
		if (plen != core->blocksize) {
			rep = plen / 8;
		}
		define_data_ntimes(core, off, rep, RZ_QWORD_DATA);
		wordsize = 8;
		break;
	case 'm': {
		char *man = NULL;
		/* check for manpage */
		RzAnalysisOp *op = rz_core_analysis_op(core, off, RZ_ANALYSIS_OP_MASK_BASIC);
		if (op) {
			if (op->jump != UT64_MAX) {
				RzFlagItem *item = rz_flag_get_i(core->flags, op->jump);
				if (item) {
					const char *ptr = rz_str_lchr(item->name, '.');
					if (ptr) {
						man = strdup(ptr + 1);
					}
				}
			}
			rz_analysis_op_free(op);
		}
		if (man) {
			char *p = strstr(man, "INODE");
			if (p) {
				*p = 0;
			}
			rz_cons_clear();
			rz_cons_flush();
			rz_sys_cmdf("man %s", man);
			free(man);
		}
		rz_cons_any_key(NULL);
	} break;
	case 'n': {
		RzAnalysisOp op;
		ut64 tgt_addr = UT64_MAX;
		if (!isDisasmPrint(visual->printidx)) {
			break;
		}
		// TODO: get the aligned instruction even if the cursor is in the middle of it.
		rz_analysis_op(core->analysis, &op, off,
			core->block + off - core->offset, 32, RZ_ANALYSIS_OP_MASK_BASIC);

		tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
		RzAnalysisVar *var = rz_analysis_get_used_function_var(core->analysis, op.addr);
		if (var) {
			char *newname = rz_cons_input(sdb_fmt("New variable name for '%s': ", var->name));
			if (newname && *newname) {
				rz_analysis_var_rename(var, newname, true);
				free(newname);
			}
		} else if (tgt_addr != UT64_MAX) {
			RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, tgt_addr);
			RzFlagItem *f = rz_flag_get_i(core->flags, tgt_addr);
			if (fcn) {
				char *msg = rz_str_newf("Rename function %s to: ", fcn->name);
				char *newname = rz_cons_input(msg);
				free(msg);
				rz_core_analysis_function_rename(core, tgt_addr, newname);
				free(newname);
			} else if (f) {
				char *msg = rz_str_newf("Rename flag %s to: ", f->name);
				char *newname = rz_cons_input(msg);
				free(msg);
				rz_flag_rename(core->flags, f, newname);
				free(newname);
			} else {
				char *msg = rz_str_newf("Create flag at 0x%" PFMT64x " named: ", tgt_addr);
				char *newname = rz_cons_input(msg);
				free(msg);
				rz_flag_set(core->flags, newname, tgt_addr, 1);
				free(newname);
			}
		}

		rz_analysis_op_fini(&op);
		break;
	}
	case 'C': {
		RzFlagItem *item = rz_flag_get_i(core->flags, off);
		if (item) {
			char cmd[128];
			rz_cons_show_cursor(true);
			rz_cons_flush();
			rz_line_set_prompt("color: ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) > 0) {
				rz_flag_item_set_color(item, cmd);
				rz_cons_set_raw(1);
				rz_cons_show_cursor(false);
			}
		} else {
			eprintf("Sorry. No flag here\n");
			rz_cons_any_key(NULL);
		}
	} break;
	case '$': {
		RzFlagItem *item = rz_flag_get_i(core->flags, off);
		if (item) {
			char cmd[128];
			rz_cons_printf("Current flag size is: %" PFMT64d "\n", item->size);
			rz_cons_show_cursor(true);
			rz_cons_flush();
			rz_line_set_prompt("new size: ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) > 0) {
				item->size = rz_num_math(core->num, cmd);
				rz_cons_set_raw(1);
				rz_cons_show_cursor(false);
			}
		} else {
			eprintf("Sorry. No flag here\n");
			rz_cons_any_key(NULL);
		}
	} break;
	case 'e':
		// set function size
		{
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
			if (!fcn) {
				fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			}
			if (fcn) {
				RzAnalysisOp op;
				ut64 size;
				if (rz_analysis_op(core->analysis, &op, off, core->block + delta,
					    core->blocksize - delta, RZ_ANALYSIS_OP_MASK_BASIC) > 0) {
					size = off - fcn->addr + op.size;
					rz_analysis_function_resize(fcn, size);
				}
			}
		}
		break;
	case 'j': {
		ut64 addr = rz_num_math(core->num, "$$+$F");
		rz_core_analysis_fcn_merge(core, off, addr);
	} break;
	case 'k':
		eprintf("TODO: merge up\n");
		rz_cons_any_key(NULL);
		break;
	// very weak and incomplete
	case 'h': // "Vdh"
		handleHints(core);
		break;
	case 'r': // "Vdr"
		rz_core_cmdf(core, "?i new function name;afn `yp` @ 0x%08" PFMT64x, off);
		break;
	case 'z': // "Vdz"
		rz_core_cmdf(core, "?i zone name;fz `yp` @ 0x%08" PFMT64x, off);
		break;
	case 'R': // "VdR"
		eprintf("Finding references to 0x%08" PFMT64x " ...\n", off);
		rz_core_cmdf(core, "./r 0x%08" PFMT64x " @ $S", off);
		break;
	case 'S': {
		int i, j;
		bool is_wide = false;
		do {
			n = rz_str_nlen_w((const char *)p + ntotal,
				    plen - ntotal) +
				1;
			if (n < 2) {
				break;
			}
			name = malloc(n + 10);
			strcpy(name, "str.");
			for (i = 0, j = 0; i < n; i++, j++) {
				name[4 + i] = p[j + ntotal];
				if (!p[j + ntotal]) {
					break;
				}
				if (!p[j + 1 + ntotal]) {
					// check if is still wide
					if (j + 3 + ntotal < n) {
						if (p[j + 3]) {
							break;
						}
					}
					is_wide = true;
					j++;
				}
			}
			name[4 + n] = '\0';
			if (is_wide) {
				rz_meta_set(core->analysis, RZ_META_TYPE_STRING,
					off + ntotal, (n * 2) + ntotal,
					(const char *)name + 4);
			} else {
				rz_meta_set(core->analysis, RZ_META_TYPE_STRING,
					off + ntotal, n + ntotal,
					(const char *)name + 4);
			}
			rz_name_filter(name, n + 10, true);
			rz_flag_set(core->flags, name, off + ntotal, n);
			free(name);
			if (is_wide) {
				ntotal += n * 2 - 1;
			} else {
				ntotal += n;
			}
		} while (ntotal < plen);
		wordsize = ntotal;
	} break;
	case 's': {
		int i, j;
		bool is_wide = false;
		if (core->print->ocur != -1) {
			n = plen;
		} else {
			n = rz_str_nlen_w((const char *)p, plen) + 1;
		}
		name = malloc(n + 10);
		if (!name) {
			break;
		}
		strcpy(name, "str.");
		for (i = 0, j = 0; i < n; i++, j++) {
			name[4 + i] = p[j];
			if (!p[j + 1]) {
				break;
			}
			if (!p[j + 1]) {
				if (j + 3 < n) {
					if (p[j + 3]) {
						break;
					}
				}
				is_wide = true;
				j++;
			}
		}
		name[4 + n] = '\0';
		// handle wide strings
		// memcpy (name + 4, (const char *)p, n);
		if (is_wide) {
			rz_meta_set(core->analysis, RZ_META_TYPE_STRING, off,
				n * 2, (const char *)name + 4);
		} else {
			rz_meta_set(core->analysis, RZ_META_TYPE_STRING, off,
				n, (const char *)name + 4);
		}
		rz_name_filter(name, n + 10, true);
		rz_flag_set(core->flags, name, off, n);
		wordsize = n;
		free(name);
	} break;
	case 'd': // TODO: check
		rz_meta_del(core->analysis, RZ_META_TYPE_ANY, off, plen);
		rz_meta_set(core->analysis, RZ_META_TYPE_DATA, off, plen, "");
		break;
	case 'c': // TODO: check
		rz_meta_del(core->analysis, RZ_META_TYPE_ANY, off, plen);
		rz_meta_set(core->analysis, RZ_META_TYPE_CODE, off, plen, "");
		break;
	case 'u':
		rz_core_analysis_undefine(core, off);
		break;
	case 'f': {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		if (fcn) {
			rz_analysis_function_resize(fcn, core->offset - fcn->addr);
		}
		rz_cons_break_push(NULL, NULL);
		// required for thumb autodetection
		rz_core_analysis_function_add(core, NULL, off, false);
		rz_cons_break_pop();
	} break;
	case 'v': {
		ut64 N;
		char *endptr = NULL;
		char *end_off = rz_cons_input("Last hexadecimal digits of instruction: ");
		if (end_off) {
			N = strtoull(end_off, &endptr, 16);
		}
		if (!end_off || end_off == endptr) {
			eprintf("Invalid numeric input\n");
			rz_cons_any_key(NULL);
			free(end_off);
			break;
		}
		free(end_off);

		ut64 incr = 0x10;
		ut64 tmp_N = N >> 4;
		while (tmp_N > 0) {
			tmp_N = tmp_N >> 4;
			incr = incr << 4;
		}
		ut64 mask = incr - 1;

		ut64 start_off = (off & ~mask) ^ N;
		if ((off & mask) > N) {
			if (start_off > incr) {
				start_off -= incr;
			} else {
				start_off = N;
			}
		}

		ut64 try_off;
		RzAnalysisOp *op = NULL;
		RzAnalysisVar *var = NULL;
		for (try_off = start_off; try_off < start_off + incr * 16; try_off += incr) {
			rz_analysis_op_free(op);
			op = rz_core_analysis_op(core, try_off, RZ_ANALYSIS_OP_MASK_ALL);
			if (!op) {
				break;
			}
			var = rz_analysis_get_used_function_var(core->analysis, op->addr);
			if (var) {
				break;
			}
		}

		if (var) {
			char *newname = rz_cons_input(sdb_fmt("New variable name for '%s': ", var->name));
			if (newname && *newname) {
				rz_analysis_var_rename(var, newname, true);
				free(newname);
			}
		} else {
			eprintf("Cannot find instruction with a variable\n");
			rz_cons_any_key(NULL);
		}

		rz_analysis_op_free(op);
		break;
	}
	case 'Q':
	case 'q':
	default:
		if (IS_DIGIT(ch)) {
			if (rep < 0) {
				rep = 0;
			}
			rep = rep * 10 + atoi((char *)&ch);
			goto repeat;
		}
		break;
	}
	if (distance > 0) {
		distance--;
		off += wordsize;
		goto onemoretime;
	}
}
