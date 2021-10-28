// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <stdbool.h>
#include "rz_core.h"

static char *curtheme = "default";
static bool getNext = false;

static RzCmdStatus bool2status(bool val) {
	return val ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
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

static bool pal_seek(RzCore *core, RzConsPalSeekMode mode, const char *file, RzListIter *iter) {
	const char *fn = rz_str_lchr(file, '/');
	if (!fn) {
		fn = file;
	}
	switch (mode) {
	case RZ_CONS_PAL_SEEK_PREVIOUS: {
		const char *next_fn = iter->n ? iter->n->data : NULL;
		if (!curtheme) {
			return true;
		}
		if (next_fn && !strcmp(next_fn, curtheme)) {
			free(curtheme);
			curtheme = strdup(fn);
			return false;
		}
		break;
	}
	case RZ_CONS_PAL_SEEK_NEXT:
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

RZ_API bool rz_core_theme_load(RzCore *core, const char *name) {
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

RZ_API char *rz_core_theme_get(void) {
	return curtheme;
}

RZ_API RZ_OWN RzList *rz_core_theme_list(RzCore *core) {
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

RZ_IPI void rz_core_theme_nextpal(RzCore *core, RzConsPalSeekMode mode) {
	RzListIter *iter;
	const char *fn;
	RzList *files = rz_core_theme_list(core);

	rz_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.') {
			if (!pal_seek(core, mode, fn, iter)) {
				goto done;
			}
		}
	}
	rz_list_free(files);
	files = NULL;
done:
	rz_core_theme_load(core, curtheme);
	rz_list_free(files);
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_list_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (argc == 3) {
		if (!rz_cons_pal_set(argv[1], argv[2])) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_cons_pal_update_event();
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
	rz_core_theme_nextpal(core, RZ_CONS_PAL_SEEK_PREVIOUS);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_load_next_theme_handler(RzCore *core, int argc, const char **argv) {
	rz_core_theme_nextpal(core, RZ_CONS_PAL_SEEK_NEXT);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_highlight_list_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzCmdStateOutput state = { 0 };
	rz_cmd_state_output_init(&state, mode);
	rz_core_meta_print_list_all(core, RZ_META_TYPE_HIGHLIGHT, &state);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_load_theme_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzList *themes_list = NULL;
	RzListIter *th_iter;
	const char *th;
	if (argc == 2) {
		return bool2status(rz_core_theme_load(core, argv[1]));
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON: {
		PJ *pj = state->d.pj;
		pj_a(pj);
		themes_list = rz_core_theme_list(core);
		if (!themes_list) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_list_foreach (themes_list, th_iter, th) {
			pj_s(pj, th);
		}
		pj_end(pj);
		break;
	}
	case RZ_OUTPUT_MODE_QUIET:
		themes_list = rz_core_theme_list(core);
		if (!themes_list) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_list_foreach (themes_list, th_iter, th) {
			rz_cons_printf("%s\n", th);
		}
		rz_list_free(themes_list);
		break;
	default:
		themes_list = rz_core_theme_list(core);
		if (!themes_list) {
			return RZ_CMD_STATUS_ERROR;
		}
		rz_list_foreach (themes_list, th_iter, th) {
			if (curtheme && !strcmp(curtheme, th)) {
				rz_cons_printf("> %s\n", th);
			} else {
				rz_cons_printf("  %s\n", th);
			}
		}
		rz_list_free(themes_list);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_list_current_theme_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_println(rz_core_theme_get());
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_list_reload_current_handler(RzCore *core, int argc, const char **argv) {
	rz_core_theme_load(core, rz_core_theme_get());
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_highlight_current_instruction_handler(RzCore *core, int argc, const char **argv) {
	char *dup = rz_str_newf("bgonly %s", argv[1]);
	char *color_code = rz_cons_pal_parse(dup, NULL);
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
	char *color_code = NULL, *dup = NULL;
	if (argc == 3) {
		dup = rz_str_newf("bgonly %s", argv[2]);
		color_code = rz_cons_pal_parse(dup, NULL);
		RZ_FREE(dup);
		if (!color_code) {
			eprintf("Unknown color %s\n", argv[2]);
			return RZ_CMD_STATUS_ERROR;
		}
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
	RzCmdStateOutput state = { 0 };
	rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD);
	rz_core_meta_print_list_in_function(core, RZ_META_TYPE_COMMENT, core->offset, &state);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
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
