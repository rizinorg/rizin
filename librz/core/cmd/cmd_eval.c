// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <stdbool.h>
#include <rz_core.h>
#include "../core_private.h"

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
		if (!core->curtheme) {
			return true;
		}
		if (next_fn && !strcmp(next_fn, core->curtheme)) {
			free(core->curtheme);
			core->curtheme = strdup(fn);
			return false;
		}
		break;
	}
	case RZ_CONS_PAL_SEEK_NEXT: {
		const char *prev_fn = iter->p ? iter->p->data : NULL;
		if (!core->curtheme) {
			return true;
		}
		if (prev_fn && !strcmp(prev_fn, core->curtheme)) {
			free(core->curtheme);
			core->curtheme = strdup(fn);
			return false;
		}
		break;
	}
	}
	return true;
}

RZ_API bool rz_core_theme_load(RzCore *core, const char *name) {
	bool failed = false;
	if (!name || !*name) {
		return false;
	}
	if (!rz_str_cmp(name, "default", strlen(name))) {
		core->curtheme = rz_str_dup(core->curtheme, name);
		rz_cons_pal_init(core->cons->context);
		return true;
	}

	char *home_themes = rz_path_home_prefix(RZ_THEMES);
	char *system_themes = rz_path_system(RZ_THEMES);
	char *home_file = rz_file_path_join(home_themes, name);
	char *system_file = rz_file_path_join(system_themes, name);
	free(system_themes);
	free(home_themes);

	if (!load_theme(core, home_file)) {
		if (load_theme(core, system_file)) {
			core->curtheme = rz_str_dup(core->curtheme, name);
		} else {
			if (load_theme(core, name)) {
				core->curtheme = rz_str_dup(core->curtheme, name);
			} else {
				eprintf("eco: cannot open colorscheme profile (%s)\n", name);
				failed = true;
			}
		}
	}
	free(home_file);
	free(system_file);
	return !failed;
}

static void list_themes_in_path(HtPU *themes, const char *path) {
	RzListIter *iter;
	const char *fn;
	RzList *files = rz_sys_dir(path);
	rz_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.') {
			ht_pu_insert(themes, fn, 1);
		}
	}
	rz_list_free(files);
}

RZ_API char *rz_core_theme_get(RzCore *core) {
	return core->curtheme;
}

static bool dict2keylist(void *user, const void *key, const ut64 value) {
	RzList *list = (RzList *)user;
	rz_list_append(list, strdup(key));
	return true;
}

RZ_API RZ_OWN RzList *rz_core_theme_list(RzCore *core) {
	HtPU *themes = ht_pu_new0();
	char *path = rz_path_home_prefix(RZ_THEMES);
	if (path) {
		list_themes_in_path(themes, path);
		RZ_FREE(path);
	}

	path = rz_path_system(RZ_THEMES);
	if (path) {
		list_themes_in_path(themes, path);
		RZ_FREE(path);
	}

	RzList *list = rz_list_newf(free);
	rz_list_append(list, strdup("default"));
	ht_pu_foreach(themes, dict2keylist, list);

	rz_list_sort(list, (RzListComparator)strcmp);
	ht_pu_free(themes);
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
	rz_core_theme_load(core, core->curtheme);
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
	PJ *pj = state->d.pj;
	const char *th;
	if (argc == 2) {
		return bool2status(rz_core_theme_load(core, argv[1]));
	}
	themes_list = rz_core_theme_list(core);
	if (!themes_list) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	rz_list_foreach (themes_list, th_iter, th) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON: {
			pj_s(pj, th);
			break;
		}
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%s\n", th);
			break;
		default:
			if (core->curtheme && !strcmp(core->curtheme, th)) {
				rz_cons_printf("> %s\n", th);
			} else {
				rz_cons_printf("  %s\n", th);
			}
		}
	}
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
	}
	rz_list_free(themes_list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_list_current_theme_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_println(rz_core_theme_get(core));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_eval_color_list_reload_current_handler(RzCore *core, int argc, const char **argv) {
	rz_core_theme_load(core, rz_core_theme_get(core));
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
