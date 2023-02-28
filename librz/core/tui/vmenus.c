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
	if (!fcn || vindex < 0 || vindex >= rz_pvector_len(&fcn->vars)) {
		return;
	}
	RzAnalysisVar *var = rz_pvector_at(&fcn->vars, vindex);
	rz_analysis_var_rename(var, name, true);
}

static void variable_set_type(RzCore *core, ut64 addr, int vindex, const char *type) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!fcn || vindex < 0 || vindex >= rz_pvector_len(&fcn->vars)) {
		return;
	}
	RzAnalysisVar *var = rz_pvector_at(&fcn->vars, vindex);
	RzType *ttype = rz_type_parse_string_single(core->analysis->typedb->parser, type, NULL);
	if (!ttype) {
		return;
	}
	rz_analysis_var_set_type(var, ttype, true);
}

/**
 * \brief Convert the string inputing to RzPVector, with WHITESPACE as separators
 *
 * \param inputing
 * \return return the pointer of RzPVector
 */
static RzPVector /*<char *>*/ *capture_filter_keywords(char *inputing) {
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
static ut32 filter_function(RzCore *core, RzList /*<RzAnalysisFunction *>*/ *filter_fcn, RzPVector /*<char *>*/ *keywords) {
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
	window -= 2; // size of command line in the bottom
	if (visual->inputing) {
		window -= 2; // filter size
	}
	if (!visual->hide_legend) {
		window -= 7; // legend size
	}
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
						free(tmp);
					}
					if (print_full_func) {
						rz_cons_println(var_functions);
					}
					free(var_functions);
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
	if (!fcn) {
		return addr;
	}
	int window;
	int wdelta = (idx > 5) ? idx - 5 : 0;
	// Adjust the window size automatically.
	(void)rz_cons_get_size(&window);
	window -= 8; // Size of printed things.

	// A new line so this looks reasonable.
	rz_cons_newline();

	int llen = rz_pvector_len(&fcn->vars);
	if (*vindex >= llen) {
		*vindex = llen - 1;
	}

	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (i >= wdelta) {
			if (i > window + wdelta) {
				rz_cons_printf("...\n");
				break;
			}
			if (show) {
				char *vartype = rz_type_as_string(core->analysis->typedb, var->type);
				switch (var->storage.type) {
				case RZ_ANALYSIS_VAR_STORAGE_REG: {
					rz_cons_printf("%sarg %s %s @ %s\n",
						i == *vindex ? "* " : "  ",
						vartype, var->name,
						var->storage.reg);
				} break;
				case RZ_ANALYSIS_VAR_STORAGE_STACK:
					rz_cons_printf("%s%s %s %s @ %s%s0x%" PFMT64x "\n",
						i == *vindex ? "* " : "  ",
						rz_analysis_var_is_arg(var) ? "arg" : "var",
						vartype, var->name,
						core->analysis->reg->name[RZ_REG_NAME_BP],
						"+",
						var->storage.stack_off);
					break;
				}
				free(vartype);
			}
		}
		++i;
	}
	return addr;
}

static int level = 0;
static st64 delta = 0;
// output is used to store the result of printCmds
// and avoid duplicated analysis while j and k is pressed
static char *output = NULL;
// output_mode labels which printCmds' result is stored in output
static int output_mode = -1;
static int output_addr = -1;
static int option = 0;
static int variable_option = 0;
static int printMode = 0;
static bool selectPanel = false;

static void rz_core_visual_analysis_refresh_column(RzCore *core, int colpos) {
	ut64 addr = (level != 0 && level != 1)
		? core->offset
		: var_functions_show(core, option, 0, colpos);
	int h, w = rz_cons_get_size(&h);

	if (printMode == 1) { // px $r
		addr += delta * 16;
	}
	if (output_mode != printMode || output_addr != addr) {
		const char *cmd;
		if (printMode > 0 && printMode < lastPrintMode) {
			cmd = printCmds[printMode];
		} else {
			cmd = printCmds[printMode = 0];
		}
		char *cmdf = rz_str_newf("%s @ 0x%" PFMT64x, cmd, addr);
		if (!cmdf) {
			return;
		}
		RZ_FREE(output); // free the result of the last printCmds
		output = rz_core_cmd_str(core, cmdf);
		output_mode = printMode;
		output_addr = addr;
		free(cmdf);
	}
	if (output) {
		// 'h - 2' because we have two new lines in rz_cons_printf
		char *out;
		if (printMode == 1) {
			out = rz_str_ansi_crop(output, 0, 0, w - colpos, h - 2);
		} else {
			out = rz_str_ansi_crop(output, 0, delta, w - colpos, h - 2 + delta);
		}
		rz_cons_printf("\n%s\n", out);
		free(out);
	}
}

static const char *help_fun_visual[] = {
	"(a)", "analyze ", "(-)", "delete ", "(x)", "xrefs to ", "(X)", "xrefs from\n",
	"(r)", "rename ", "(c)", "calls ", "(d)", "define ", "(:)", "shell ", "(v)", "vars\n",
	"(j/k)", "next/prev ", "(tab)", "column ", "(_)", "hud ", "(?)", " help\n",
	"(f/F)", "set/reset filter ", "(s)", "function signature ", "(q)", "quit\n",
	"(=)", "show/hide legend\n\n",
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
		if (!visual->hide_legend) {
			rz_core_vmenu_append_help(buf, help_fun_visual);
		}
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

static void set_current_option_to_seek(RzCore *core) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	int i = 0;
	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		if (core->offset == fcn->addr) {
			option = i;
		}
		i++;
	}
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

	set_current_option_to_seek(core);

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
		case '=':
			if (level == 0) {
				visual->hide_legend = visual->hide_legend ? false : true;
			}
			break;
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
				eprintf("Select variable source ('r'egister or 's'tack): ");
				int type = rz_cons_readchar();
				switch (type) {
				case 'r':
					addVar(core, type, "Source Register Name: ");
					break;
				case 's':
					addVar(core, type, "Stack Relative Delta: ");
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
			rz_core_theme_nextpal(core, RZ_CONS_PAL_SEEK_NEXT);
			break;
		case 'p':
			printMode++;
			delta = 0;
			break;
		case 'P':
			if (printMode == 0) {
				printMode = lastPrintMode;
			} else {
				printMode--;
			}
			delta = 0;
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
				delta += 1;
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
				if (delta > 0) {
					delta -= 1;
				}
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
			set_current_option_to_seek(core);
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
	RZ_FREE(output);
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = olde_user;
	core->cons->event_resize = olde;
	level = 0;
	rz_config_set_i(core->config, "asm.bytes", asmbytes);
}
