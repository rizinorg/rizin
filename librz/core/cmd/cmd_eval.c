// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <stdbool.h>
#include <rz_core.h>
#include <rz_util/rz_set.h>
#include <rz_util/rz_str.h>
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

RZ_API bool rz_core_theme_load(RzCore *core, const char *name) {
	bool failed = false;
	if (RZ_STR_ISEMPTY(name)) {
		return false;
	}
	if (!rz_str_cmp(name, "default", strlen(name))) {
		char *tmp = rz_str_dup(name);
		free(core->curtheme);
		core->curtheme = tmp;
		rz_cons_pal_init(core->cons->context);
		return true;
	}

	char *tmp = NULL;
	char *home_themes = rz_path_home_prefix(RZ_THEMES);
	char *system_themes = rz_path_system(RZ_THEMES);
	char *extra_themes = rz_path_extra(RZ_THEMES);
	char *home_file = rz_file_path_join(home_themes, name);
	char *system_file = rz_file_path_join(system_themes, name);
	char *extra_file = extra_themes ? rz_file_path_join(extra_themes, name) : NULL;
	free(system_themes);
	free(home_themes);
	free(extra_themes);

	if (load_theme(core, home_file)) {
		goto success;
	}

	if (load_theme(core, system_file)) {
		goto success;
	}

	if (load_theme(core, extra_file)) {
		goto success;
	}

	if (load_theme(core, name)) {
		goto success;
	}

	RZ_LOG_ERROR("core: cannot open colorscheme profile (%s)\n", name);
	failed = true;
	goto fail;

success:
	tmp = rz_str_dup(name);
	free(core->curtheme);
	core->curtheme = tmp;
fail:
	free(home_file);
	free(system_file);
	free(extra_file);
	return !failed;
}

static void list_themes_in_path(RzSetS *themes, const char *path) {
	RzListIter *iter;
	const char *fn;
	RzList *files = rz_sys_dir(path);
	rz_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.') {
			rz_set_s_add(themes, fn);
		}
	}
	rz_list_free(files);
}

RZ_API char *rz_core_theme_get(RzCore *core) {
	return core->curtheme;
}

static int compare_strings(const char *s1, const char *s2, RZ_UNUSED void *user) {
	return strcmp(s1, s2);
}

/**
 * \brief Get names of available rizin themes.
 *
 * \param core The RzCore struct to use
 * \return On success, an RzPVector pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzPVector /*<char *>*/ *rz_core_get_themes(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core, NULL);

	RzSetS *themes = rz_set_s_new(HT_STR_DUP);
	if (!themes) {
		return NULL;
	}

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

	path = rz_path_extra(RZ_THEMES);
	if (path) {
		list_themes_in_path(themes, path);
		RZ_FREE(path);
	}

	RzPVector *vec = rz_set_s_to_vector(themes);
	if (!vec) {
		rz_set_s_free(themes);
		return NULL;
	}
	rz_pvector_push(vec, rz_str_dup("default"));
	rz_pvector_sort(vec, (RzPVectorComparator)compare_strings, NULL);
	rz_set_s_free(themes);
	return vec;
}

RZ_API void rz_core_theme_nextpal(RzCore *core, RzConsPalSeekMode mode) {
	rz_return_if_fail(core && core->curtheme);

	void **iter;
	size_t idx;
	RzPVector *files = rz_core_get_themes(core);
	const char *new_theme = NULL;
	rz_pvector_enumerate (files, iter, idx) {
		const char *fn = *iter;
		if (strcmp(fn, core->curtheme)) {
			continue;
		}
		switch (mode) {
		case RZ_CONS_PAL_SEEK_PREVIOUS:
			if (idx > 0) {
				new_theme = rz_pvector_at(files, idx - 1);
			}
			break;
		case RZ_CONS_PAL_SEEK_NEXT:
			if (idx < rz_pvector_len(files) - 1) {
				new_theme = rz_pvector_at(files, idx + 1);
			}
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		break;
	}
	if (new_theme) {
		rz_core_theme_load(core, new_theme);
	}
	rz_pvector_free(files);
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
	PJ *pj = state->d.pj;
	if (argc == 2) {
		return bool2status(rz_core_theme_load(core, argv[1]));
	}
	RzPVector *themes = rz_core_get_themes(core);
	if (!themes) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_a(pj);
	}
	void **iter;
	rz_pvector_foreach (themes, iter) {
		const char *th = *iter;
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
	rz_pvector_free(themes);
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
		RZ_LOG_ERROR("core: Unknown color %s\n", argv[1]);
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
			RZ_LOG_ERROR("core: Unknown color %s\n", argv[2]);
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

static void print_all_plugin_configs(const RzCore *core) {
	// Incomplete plugin config key.
	RzConfig **cfg;
	RzCmdStateOutput state = { 0 };
	rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_QUIET);
	RzIterator *it = ht_sp_as_iter(core->plugin_configs);
	rz_iterator_foreach(it, cfg) {
		rz_core_config_print_all(*cfg, "", &state);
	}
	rz_iterator_free(it);
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
}

static RZ_BORROW RzConfig *eval_get_config_obj_by_key(const RzCore *core, const char *config_str) {
	rz_return_val_if_fail(core && config_str, NULL);
	RzConfig *cfg = NULL;
	if (!rz_str_startswith(config_str, "plugins")) {
		return core->config;
	}

	// Plugin config. Check for name.
	const char *first_dot = strchr(config_str, '.');
	if (!first_dot) {
		return NULL;
	}
	const char *second_dot = strchr(first_dot + 1, '.');
	bool cfg_found = false;
	if (!second_dot) {
		cfg = ht_sp_find(core->plugin_configs, first_dot + 1, &cfg_found);
	} else {
		char *config_name = rz_sub_str_ptr(config_str, first_dot + 1, second_dot - 1);
		cfg = ht_sp_find(core->plugin_configs, config_name, &cfg_found);
		free(config_name);
	}
	if (!cfg_found) {
		RZ_LOG_DEBUG("Did not find plugin config with name '%s'\n", config_str);
		return NULL;
	}
	return cfg;
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
			RZ_LOG_ERROR("core: No string specified before `=`. Make sure to use the format <key>=<value> without spaces.\n");
			rz_list_free(l);
			continue;
		}

		RzConfig *cfg = NULL;
		if (!(cfg = eval_get_config_obj_by_key(core, key))) {
			print_all_plugin_configs(core);
			return RZ_CMD_STATUS_OK;
		}
		if (llen == 1 && rz_str_endswith(key, ".")) {
			// no value was set, only key with ".". List possible sub-keys.
			RzCmdStateOutput state = { 0 };
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_QUIET);
			rz_core_config_print_all(cfg, key, &state);
			rz_cmd_state_output_print(&state);
			rz_cmd_state_output_fini(&state);
		} else if (llen == 1) {
			// no value was set, show the value of the key
			const char *v = rz_config_get(cfg, key);
			if (!v) {
				RZ_LOG_ERROR("core: Invalid config key '%s'\n", key);
				rz_list_free(l);
				return RZ_CMD_STATUS_ERROR;
			}
			rz_cons_printf("%s\n", v);
		} else if (llen == 2) {
			char *value = rz_list_get_n(l, 1);
			rz_config_set(cfg, key, value);
		}
		rz_list_free(l);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const char *arg = argc > 1 ? argv[1] : "";
	RzConfig *cfg = NULL;
	if (!(cfg = eval_get_config_obj_by_key(core, arg))) {
		print_all_plugin_configs(core);
		return RZ_CMD_STATUS_OK;
	}
	rz_core_config_print_all(cfg, arg, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_reset_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_config_init(core) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_eval_bool_invert_handler(RzCore *core, int argc, const char **argv) {
	RzConfig *cfg = NULL;
	if (!(cfg = eval_get_config_obj_by_key(core, argv[1]))) {
		print_all_plugin_configs(core);
		return RZ_CMD_STATUS_OK;
	}
	if (!rz_config_toggle(cfg, argv[1])) {
		RZ_LOG_ERROR("core: Cannot toggle config key '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_editor_handler(RzCore *core, int argc, const char **argv) {
	RzConfig *cfg = NULL;
	if (!(cfg = eval_get_config_obj_by_key(core, argv[1]))) {
		print_all_plugin_configs(core);
		return RZ_CMD_STATUS_OK;
	}
	const char *val = rz_config_get(cfg, argv[1]);
	if (!val) {
		RZ_LOG_ERROR("core: Invalid config key '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	char *p = rz_core_editor(core, NULL, val);
	if (!p) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_str_replace_char(p, '\n', ';');
	rz_config_set(cfg, argv[1], p);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_readonly_handler(RzCore *core, int argc, const char **argv) {
	RzConfig *cfg = NULL;
	if (!(cfg = eval_get_config_obj_by_key(core, argv[1]))) {
		print_all_plugin_configs(core);
		return RZ_CMD_STATUS_OK;
	}
	if (!rz_config_readonly(cfg, argv[1])) {
		RZ_LOG_ERROR("core: Cannot make eval '%s' readonly.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_spaces_handler(RzCore *core, int argc, const char **argv) {
	const char *arg = argc > 1 ? argv[1] : NULL;
	RzList *list = rz_core_config_in_space(core, arg);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	char *name;
	rz_list_foreach (list, iter, name) {
		rz_cons_println(name);
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_type_handler(RzCore *core, int argc, const char **argv) {
	RzConfig *cfg = NULL;
	if (!(cfg = eval_get_config_obj_by_key(core, argv[1]))) {
		print_all_plugin_configs(core);
		return RZ_CMD_STATUS_OK;
	}
	RzConfigNode *node = rz_config_node_get(cfg, argv[1]);
	if (!node) {
		RZ_LOG_ERROR("core: Cannot find eval '%s'.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}

	const char *type = rz_config_node_type(node);
	if (!type) {
		RZ_LOG_ERROR("core: Cannot find type of eval '%s'.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(type);
	return RZ_CMD_STATUS_OK;
}
