// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <stdbool.h>
#include "rz_core.h"

static const char *help_msg_ec[] = {
	"Usage ec[s?] [key][[=| ]fg] [bg]", "", "",
	"ec", " [key]", "list all/key color keys",
	"ec*", "", "same as above, but using rizin commands",
	"ecd", "", "set default palette",
	"ecr", "", "set random palette (see also scr.randpal)",
	"ecs", "", "show a colorful palette",
	"ecj", "", "show palette in JSON",
	"ecc", " [prefix]", "show palette in CSS",
	"eco", " [theme]", "load theme if provided (list available themes if not)",
	"ecp", "", "load previous color theme",
	"ecn", "", "load next color theme",
	"ecH", " [?]", "highlight word or instruction",
	"ec", " prompt red", "change color of prompt",
	"ec", " prompt red blue", "change color and background of prompt",
	"Vars:", "", "",
	"colors:", "", "rgb:000, red, green, blue, #ff0000, ...",
	"e scr.color", "=0", "use more colors (0: no color 1: ansi 16, 2: 256, 3: 16M)",
	"$DATADIR/rizin/cons", "", RZ_JOIN_2_PATHS("~", RZ_HOME_THEMES) " ./",
	NULL
};

static const char *help_msg_eco[] = {
	"Usage: eco[jc] [theme]", "", "load theme (cf. Path and dir.prefix)",
	"eco", "", "list available themes",
	"eco.", "", "display current theme name",
	"ecoo", "", "reload current theme",
	"ecoq", "", "list available themes without showing the current one",
	"ecoj", "", "list available themes in JSON",
	"Path:", "", "",
	"$DATADIR/rizin/cons", "", RZ_JOIN_2_PATHS("~", RZ_HOME_THEMES) " ./",
	NULL
};

static char *curtheme = "default";
static bool getNext = false;

RZ_IPI RzCmdStatus rz_env_handler(RzCore *core, int argc, const char **argv) {
	char *p, **e;
	switch (argc) {
	case 1:
		e = rz_sys_get_environ();
		while (!RZ_STR_ISEMPTY(e)) {
			rz_cons_println(*e);
			e++;
		}
		return RZ_CMD_STATUS_OK;
	case 2:
		p = rz_sys_getenv(argv[1]);
		if (!p) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_println(p);
		free(p);
		return RZ_CMD_STATUS_OK;
	case 3:
		rz_sys_setenv(argv[1], argv[2]);
		return RZ_CMD_STATUS_OK;
	default:
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
}

static bool load_theme(RzCore *core, const char *path) {
	if (!rz_file_exists(path)) {
		return false;
	}
	core->cmdfilter = "ec ";
	bool res = rz_core_cmd_file(core, path);
	if (res) {
		rz_cons_pal_update_event();
	}
	core->cmdfilter = NULL;
	return res;
}

static bool nextpal_item(RzCore *core, int mode, const char *file, int ctr) {
	const char *fn = rz_str_lchr(file, '/');
	if (!fn)
		fn = file;
	switch (mode) {
	case 'j': // json
		rz_cons_printf("%s\"%s\"", ctr ? "," : "", fn);
		break;
	case 'l': // list
		rz_cons_println(fn);
		break;
	case 'p': // previous
		// TODO: move logic here
		break;
	case 'n': // next
		if (getNext) {
			curtheme = rz_str_dup(curtheme, fn);
			getNext = false;
			return false;
		} else if (curtheme) {
			if (!strcmp(curtheme, fn)) {
				getNext = true;
			}
		} else {
			curtheme = rz_str_dup(curtheme, fn);
			return false;
		}
		break;
	}
	return true;
}

RZ_API bool rz_core_load_theme(RzCore *core, const char *name) {
	bool failed = false;
	char *path;
	if (!name || !*name) {
		return false;
	}
	if (!rz_str_cmp(name, "default", strlen(name))) {
		curtheme = strdup(name);
		rz_cons_pal_init(core->cons->context);
		return true;
	}

	char *tmp = rz_str_newf(RZ_JOIN_2_PATHS(RZ_HOME_THEMES, "%s"), name);
	char *home = tmp ? rz_str_home(tmp) : NULL;
	free(tmp);

	tmp = rz_str_newf(RZ_JOIN_2_PATHS(RZ_THEMES, "%s"), name);
	path = tmp ? rz_str_rz_prefix(tmp) : NULL;
	free(tmp);

	if (!load_theme(core, home)) {
		if (load_theme(core, path)) {
			curtheme = rz_str_dup(curtheme, name);
		} else {
			if (load_theme(core, name)) {
				curtheme = rz_str_dup(curtheme, name);
			} else {
				eprintf("eco: cannot open colorscheme profile (%s)\n", name);
				failed = true;
			}
		}
	}
	free(home);
	free(path);
	return !failed;
}

static void list_themes_in_path(RzList *list, const char *path) {
	RzListIter *iter;
	const char *fn;
	RzList *files = rz_sys_dir(path);
	rz_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.') {
			rz_list_append(list, strdup(fn));
		}
	}
	rz_list_free(files);
}

RZ_API char *rz_core_get_theme(void) {
	return curtheme;
}

RZ_API RzList *rz_core_list_themes(RzCore *core) {
	RzList *list = rz_list_newf(free);
	getNext = false;
	char *tmp = strdup("default");
	rz_list_append(list, tmp);
	char *path = rz_str_home(RZ_HOME_THEMES RZ_SYS_DIR);
	if (path) {
		list_themes_in_path(list, path);
		RZ_FREE(path);
	}

	path = rz_str_rz_prefix(RZ_THEMES RZ_SYS_DIR);
	if (path) {
		list_themes_in_path(list, path);
		RZ_FREE(path);
	}

	return list;
}

RZ_IPI void rz_core_theme_nextpal(RzCore *core, int mode) {
	// TODO: use rz_core_list_themes() here instead of rewalking all the time
	RzList *files = NULL;
	RzListIter *iter;
	const char *fn;
	char *path = NULL;
	int ctr = 0;
	char *home = rz_str_home(RZ_HOME_THEMES RZ_SYS_DIR);

	if (mode == 'j') {
		rz_cons_printf("[");
	}
	if (home) {
		files = rz_sys_dir(home);
		rz_list_foreach (files, iter, fn) {
			if (*fn && *fn != '.') {
				if (mode == 'p') {
					const char *nfn = iter->n ? iter->n->data : NULL;
					if (!curtheme) {
						free(home);
						rz_list_free(files);
						return;
					}
					eprintf("%s %s %s\n", rz_str_get_null(nfn), curtheme, fn);
					if (nfn && !strcmp(nfn, curtheme)) {
						free(curtheme);
						curtheme = strdup(fn);
						RZ_FREE(home);
						goto done;
					}
				} else {
					if (!nextpal_item(core, mode, fn, ctr++)) {
						RZ_FREE(home);
						goto done;
					}
				}
			}
		}
		RZ_FREE(home);
		rz_list_free(files);
		files = NULL;
	}

	path = rz_str_rz_prefix(RZ_THEMES RZ_SYS_DIR);
	if (path) {
		files = rz_sys_dir(path);
		rz_list_foreach (files, iter, fn) {
			if (*fn && *fn != '.') {
				if (mode == 'p') {
					const char *nfn = iter->n ? iter->n->data : NULL;
					if (!curtheme) {
						free(home);
						rz_list_free(files);
						return;
					}
					eprintf("%s %s %s\n", rz_str_get_null(nfn), curtheme, fn);
					if (nfn && !strcmp(nfn, curtheme)) {
						free(curtheme);
						curtheme = strdup(fn);
						goto done;
					}
				} else {
					if (!nextpal_item(core, mode, fn, ctr++)) {
						goto done;
					}
				}
			}
		}
	}

done:
	free(path);
	if (mode == 'l' && !curtheme && !rz_list_empty(files)) {
		//rz_core_theme_nextpal (core, mode);
	} else if (mode == 'n' || mode == 'p') {
		if (curtheme) {
			rz_core_load_theme(core, curtheme);
		}
	}
	rz_list_free(files);
	if (mode == 'j') {
		rz_cons_printf("]\n");
	}
}

RZ_API void rz_core_echo(RzCore *core, const char *input) {
	if (!strncmp(input, "64 ", 3)) {
		char *buf = strdup(input);
		rz_base64_decode((ut8 *)buf, input + 3, -1);
		if (*buf) {
			rz_cons_echo(buf);
		}
		free(buf);
	} else {
		if (input) {
			rz_cons_strcat(input);
			rz_cons_newline();
		}
	}
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_list_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {

	if (argc == 3) {
		if (rz_cons_pal_set(argv[1], argv[2])) {
			rz_cons_pal_update_event();
		}
		return RZ_CMD_STATUS_OK;
	} else if (argc == 2) {
		char color[32];
		RzColor rcolor = rz_cons_pal_get(argv[1]);
		rz_cons_rgb_str(color, sizeof(color), &rcolor);
		eprintf("(%s)(%sCOLOR" Color_RESET ")\n", argv[1], color);
		return RZ_CMD_STATUS_OK;
	}
	switch (mode) {
	case RZ_OUTPUT_MODE_RIZIN:
		rz_cons_pal_list(1, NULL);
		break;
	case RZ_OUTPUT_MODE_JSON:
		rz_cons_pal_list('j', NULL);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_pal_list(0, NULL);
		break;
	default:
		return RZ_CMD_STATUS_ERROR;
	};
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_display_palette_css_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_pal_list('c', argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_set_default_palette_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_pal_init(core->cons->context);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_set_random_palette_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_pal_random();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_set_colorful_palette_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_pal_show();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_load_previous_theme_handler(RzCore *core, int argc, const char **argv) {
	rz_core_theme_nextpal(core, 'p');
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_load_next_theme_handler(RzCore *core, int argc, const char **argv) {
	rz_core_theme_nextpal(core, 'n');
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_highlight_list_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (mode == RZ_OUTPUT_MODE_JSON) {
		rz_meta_print_list_all(core->analysis, RZ_META_TYPE_HIGHLIGHT, 'j');
	} else {
		rz_meta_print_list_all(core->analysis, RZ_META_TYPE_HIGHLIGHT, 0);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_load_theme_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {

	RzList *themes_list = NULL;
	RzListIter *th_iter;
	const char *th;
	if (argc == 2) {
		rz_core_load_theme(core, argv[1]);
		return RZ_CMD_STATUS_OK;
	}
	switch (mode) {
	case RZ_OUTPUT_MODE_JSON:
		rz_core_theme_nextpal(core, 'j');
		break;
	case RZ_OUTPUT_MODE_QUIET:
		themes_list = rz_core_list_themes(core);
		rz_list_foreach (themes_list, th_iter, th) {
			rz_cons_printf("%s\n", th);
		}
		break;
	default:
		themes_list = rz_core_list_themes(core);
		rz_list_foreach (themes_list, th_iter, th) {
			if (curtheme && !strcmp(curtheme, th)) {
				rz_cons_printf("> %s\n", th);
			} else {
				rz_cons_printf("  %s\n", th);
			}
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_list_current_theme_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%s\n", rz_core_get_theme());
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_list_reload_current_handler(RzCore *core, int argc, const char **argv) {
	rz_core_load_theme(core, rz_core_get_theme());
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_highlight_current_instruction_handler(RzCore *core, int argc, const char **argv) {
	char *dup = rz_str_newf("bgonly %s", argv[1]);
	char *color_code = NULL;
	color_code = rz_cons_pal_parse(dup, NULL);
	RZ_FREE(dup);
	if (!color_code) {
		eprintf("Unknown color %s\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_meta_set_string(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset, "");
	const char *str = rz_meta_get_string(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset);
	dup = rz_str_newf("%s \"%s\"", str ? str : "", color_code ? color_code : rz_cons_singleton()->context->pal.wordhl);
	rz_meta_set_string(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset, dup);
	RZ_FREE(color_code);
	RZ_FREE(dup);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_highlight_instruction_word_handler(RzCore *core, int argc, const char **argv) {
	char *dup = rz_str_newf("bgonly %s", argv[2]);
	char *color_code = NULL;
	color_code = rz_cons_pal_parse(dup, NULL);
	RZ_FREE(dup);
	if (!color_code) {
		eprintf("Unknown color %s\n", argv[2]);
		return true;
	}
	rz_meta_set_string(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset, "");
	const char *str = rz_meta_get_string(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset);
	dup = rz_str_newf("%s \"%s%s\"", str, argv[1], color_code ? color_code : rz_cons_singleton()->context->pal.wordhl);
	rz_meta_set_string(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset, dup);
	RZ_FREE(dup);
	RZ_FREE(color_code);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_highlight_list_current_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_print_list_in_function(core->analysis, RZ_META_TYPE_HIGHLIGHT, 0, core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_highlight_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_HIGHLIGHT, 0, UT64_MAX);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_highlight_remove_current_handler(RzCore *core, int argc, const char **argv) {
	rz_meta_del(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset, 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_echo_handler(RzCore *core, int argc, const char **argv) {
	if (argc >= 2) {
		rz_core_echo(core, argv[1]);
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI int rz_eval_color(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	switch (input[0]) {
	case 'd': // "ecd"
		rz_cons_pal_init(core->cons->context);
		break;
	case '?':
		rz_core_cmd_help(core, help_msg_ec);
		break;
	case 'o': // "eco"
		if (input[1] == 'j') {
			rz_core_theme_nextpal(core, 'j');
		} else if (input[1] == ' ') {
			rz_core_load_theme(core, input + 2);
		} else if (input[1] == 'o') {
			rz_core_load_theme(core, rz_core_get_theme());
		} else if (input[1] == 'c' || input[1] == '.') {
			rz_cons_printf("%s\n", rz_core_get_theme());
		} else if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_eco);
		} else if (input[1] == 'q') {
			RzList *themes_list = rz_core_list_themes(core);
			RzListIter *th_iter;
			const char *th;
			rz_list_foreach (themes_list, th_iter, th) {
				rz_cons_printf("%s\n", th);
			}
		} else {
			RzList *themes_list = rz_core_list_themes(core);
			RzListIter *th_iter;
			const char *th;
			rz_list_foreach (themes_list, th_iter, th) {
				if (curtheme && !strcmp(curtheme, th)) {
					rz_cons_printf("> %s\n", th);
				} else {
					rz_cons_printf("  %s\n", th);
				}
			}
		}
		break;
	case 's': rz_cons_pal_show(); break; // "ecs"
	case '*': rz_cons_pal_list(1, NULL); break; // "ec*"
	case 'h': // echo
		if (input[1] == 'o') {
			rz_core_echo(core, input + 2);
		} else {
			rz_cons_pal_list('h', NULL);
		}
		break;
	case 'j': // "ecj"
		rz_cons_pal_list('j', NULL);
		break;
	case 'c': // "ecc"
		rz_cons_pal_list('c', input + 1);
		break;
	case '\0': // "ec"
		rz_cons_pal_list(0, NULL);
		break;
	case 'r': // "ecr"
		rz_cons_pal_random();
		break;
	case 'n': // "ecn"
		rz_core_theme_nextpal(core, 'n');
		break;
	case 'p': // "ecp"
		rz_core_theme_nextpal(core, 'p');
		break;
	case 'H': { // "ecH"
		char *color_code = NULL;
		char *word = NULL;
		int argc = 0;
		int delta = (input[1]) ? 2 : 1;
		char **argv = rz_str_argv(rz_str_trim_head_ro(input + delta), &argc);
		switch (input[1]) {
		case '?': {
			const char *helpmsg[] = {
				"Usage ecH[iw-?]", "", "",
				"ecHi", "[color]", "highlight current instruction with 'color' background",
				"ecHw", "[word] [color]", "highlight 'word ' in current instruction with 'color' background",
				"ecH", "", "list all the highlight rules",
				"ecH.", "", "show highlight rule in current offset",
				"ecH-", "*", "remove all the highlight hints",
				"ecH-", "", "remove all highlights on current instruction",
				NULL
			};
			rz_core_cmd_help(core, helpmsg);
		}
			rz_str_argv_free(argv);
			return false;
		case '-': // ecH-
			if (input[2] == '*') {
				rz_meta_del(core->analysis, RZ_META_TYPE_HIGHLIGHT, 0, UT64_MAX);
			} else {
				rz_meta_del(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset, 1);
				// rz_meta_set_string (core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset, "");
			}
			rz_str_argv_free(argv);
			return false;
		case '.': {
			RzCmdStateOutput state = { 0 };
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD);
			rz_core_meta_print_list_in_function(core, RZ_META_TYPE_COMMENT, core->offset, &state);
			rz_cmd_state_output_print(&state);
			rz_cmd_state_output_fini(&state);
			rz_str_argv_free(argv);
			return false;
		}
		case '\0': {
			RzCmdStateOutput state = { 0 };
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD);
			rz_core_meta_print_list_all(core, RZ_META_TYPE_HIGHLIGHT, &state);
			rz_cmd_state_output_print(&state);
			rz_cmd_state_output_fini(&state);
			rz_str_argv_free(argv);
			return false;
		}
		case 'j': {
			RzCmdStateOutput state = { 0 };
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_JSON);
			rz_core_meta_print_list_all(core, RZ_META_TYPE_HIGHLIGHT, &state);
			rz_cmd_state_output_print(&state);
			rz_cmd_state_output_fini(&state);
			rz_str_argv_free(argv);
			return false;
		}
		case '*': {
			RzCmdStateOutput state = { 0 };
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_RIZIN);
			rz_core_meta_print_list_all(core, RZ_META_TYPE_HIGHLIGHT, &state);
			rz_cmd_state_output_print(&state);
			rz_cmd_state_output_fini(&state);
			rz_str_argv_free(argv);
			return false;
		}
		case ' ':
		case 'i': // "ecHi"
			if (argc) {
				char *dup = rz_str_newf("bgonly %s", argv[0]);
				color_code = rz_cons_pal_parse(dup, NULL);
				RZ_FREE(dup);
				if (!color_code) {
					eprintf("Unknown color %s\n", argv[0]);
					rz_str_argv_free(argv);
					return true;
				}
			}
			break;
		case 'w': // "ecHw"
			if (!argc) {
				eprintf("Usage: ecHw word [color]\n");
				rz_str_argv_free(argv);
				return true;
			}
			word = strdup(argv[0]);
			if (argc > 1) {
				char *dup = rz_str_newf("bgonly %s", argv[1]);
				color_code = rz_cons_pal_parse(dup, NULL);
				RZ_FREE(dup);
				if (!color_code) {
					eprintf("Unknown color %s\n", argv[1]);
					rz_str_argv_free(argv);
					free(word);
					return true;
				}
			}
			break;
		default:
			eprintf("See ecH?\n");
			rz_str_argv_free(argv);
			return true;
		}
		rz_meta_set_string(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset, "");
		const char *str = rz_meta_get_string(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset);
		char *dup = rz_str_newf("%s \"%s%s\"", str ? str : "", word ? word : "", color_code ? color_code : rz_cons_singleton()->context->pal.wordhl);
		rz_meta_set_string(core->analysis, RZ_META_TYPE_HIGHLIGHT, core->offset, dup);
		rz_str_argv_free(argv);
		RZ_FREE(word);
		RZ_FREE(dup);
		break;
	}
	default: {
		char *p = strdup(input + 1);
		char *q = strchr(p, '=');
		if (!q) {
			q = strchr(p, ' ');
		}
		if (q) {
			// Set color
			*q++ = 0;
			if (rz_cons_pal_set(p, q)) {
				rz_cons_pal_update_event();
			}
		} else {
			char color[32];
			RzColor rcolor = rz_cons_pal_get(p);
			rz_cons_rgb_str(color, sizeof(color), &rcolor);
			eprintf("(%s)(%sCOLOR" Color_RESET ")\n", p, color);
		}
		free(p);
		break;
	}
	}
	return 0;
}

RZ_IPI RzCmdStatus rz_eval_getset_handler(RzCore *core, int argc, const char **argv) {
	int i;
	for (i = 1; i < argc; i++) {
		RzList *l = rz_str_split_duplist_n(argv[i], "=", 1, false);
		if (!l) {
			return RZ_CMD_STATUS_ERROR;
		}
		size_t llen = rz_list_length(l);
		if (!llen) {
			return RZ_CMD_STATUS_ERROR;
		}
		char *key = rz_list_get_n(l, 0);
		if (RZ_STR_ISEMPTY(key)) {
			eprintf("No string specified before `=`. Make sure to use the format <key>=<value> without spaces.\n");
			continue;
		}

		if (llen == 1 && rz_str_endswith(key, ".")) {
			// no value was set, only key with ".". List possible sub-keys.
			RzCmdStateOutput state = { 0 };
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_QUIET);
			rz_core_config_print_all(core->config, key, &state);
			rz_cmd_state_output_print(&state);
			rz_cmd_state_output_fini(&state);
		} else if (llen == 1) {
			// no value was set, show the value of the key
			const char *v = rz_config_get(core->config, key);
			if (!v) {
				eprintf("Invalid config key '%s'\n", key);
				return RZ_CMD_STATUS_ERROR;
			}
			rz_cons_printf("%s\n", v);
		} else if (llen == 2) {
			char *value = rz_list_get_n(l, 1);
			rz_config_set(core->config, key, value);
		}
		rz_list_free(l);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *arg = argc > 1 ? argv[1] : "";
	rz_core_config_print_all(core->config, arg, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_reset_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_config_init(core) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_eval_bool_invert_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_config_toggle(core->config, argv[1])) {
		eprintf("Cannot toggle config key '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_editor_handler(RzCore *core, int argc, const char **argv) {
	const char *val = rz_config_get(core->config, argv[1]);
	if (!val) {
		eprintf("Invalid config key '%s'", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	char *p = rz_core_editor(core, NULL, val);
	if (!p) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_str_replace_char(p, '\n', ';');
	rz_config_set(core->config, argv[1], p);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_readonly_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_config_readonly(core->config, argv[1])) {
		eprintf("Cannot make eval '%s' readonly.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_spaces_handler(RzCore *core, int argc, const char **argv) {
	const char *arg = argc > 1 ? argv[1] : "";
	RzConfigNode *node;
	RzListIter *iter;
	char *oldSpace = NULL;
	rz_list_foreach (core->config->nodes, iter, node) {
		char *space = strdup(node->name);
		char *dot = strchr(space, '.');
		if (dot) {
			*dot = 0;
		}
		if (arg && *arg) {
			if (!strcmp(arg, space)) {
				rz_cons_println(dot + 1);
			}
			free(space);
			continue;
		} else if (oldSpace) {
			if (!strcmp(space, oldSpace)) {
				free(space);
				continue;
			}
			free(oldSpace);
			oldSpace = space;
		} else {
			oldSpace = space;
		}
		rz_cons_println(space);
	}
	free(oldSpace);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_type_handler(RzCore *core, int argc, const char **argv) {
	RzConfigNode *node = rz_config_node_get(core->config, argv[1]);
	if (!node) {
		eprintf("Cannot find eval '%s'.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}

	const char *type = rz_config_node_type(node);
	if (!type) {
		eprintf("Cannot find type of eval '%s'.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(type);
	return RZ_CMD_STATUS_OK;
}
