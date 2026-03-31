// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_strbuf.h>
#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_cons.h>
#include <rz_cmd.h>
#include <rz_search.h>

typedef struct _search_help {
	bool color;
	RzStrBuf *sb;
	PJ *pj;
	RzList /*<char *>*/ *detail_lines;
} RzHelpSearch;

static bool help_search_cmd_desc_summary(RzCmd *cmd, const RzCmdDesc *cd, void *user) {
	rz_return_val_if_fail(cd, false);
	RzHelpSearch *hs = (RzHelpSearch *)user;
	if (hs->pj) {
		rz_cmd_get_help_json(cmd, cd, hs->pj);
	} else {
		rz_cmd_get_help_strbuf(cmd, cd, hs->color, hs->sb, 0);
	}
	return true;
}

static bool help_search_interactive_cmd_desc_summary(RzCmd *cmd, const RzCmdDesc *cd, void *user) {
	rz_return_val_if_fail(cd, false);
	RzList *brief_lines = (RzList *)user;
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return false;
	}
	rz_cmd_get_help_strbuf(cmd, cd, cmd->core->print->flags & RZ_PRINT_FLAGS_COLOR, sb, 3);
	rz_list_append(brief_lines, rz_str_trim_tail(rz_strbuf_drain(sb)));
	return true;
}

static bool help_search_cmd_desc_details(RzCmd *cmd, const RzCmdDesc *cd, void *user) {
	rz_return_val_if_fail(cd, false);
	RzHelpSearch *hs = (RzHelpSearch *)user;
	if (!hs->detail_lines) {
		return false;
	}

	char *detail_help_command = rz_str_newf("%s??", cd->name);
	if (!detail_help_command) {
		return false;
	}
	RzCmdParsedArgs *pa = rz_cmd_parsed_args_newcmd(detail_help_command);
	free(detail_help_command);
	if (!pa) {
		return false;
	}

	const int hud_gutter_size = 3;
	bool ret = true;
	char *line_prefix = NULL;
	char *detailed_help = NULL;
	RzList *help_lines = NULL;

	line_prefix = rz_str_newf("%s | ", cd->name);
	if (!line_prefix) {
		goto error;
	}

	detailed_help = rz_cmd_get_help(cmd, pa, hs->color, hud_gutter_size + strlen(line_prefix));
	if (!detailed_help) {
		goto error;
	}

	help_lines = rz_str_split_list_regex(detailed_help, "\\n+", 0);
	if (!help_lines) {
		goto error;
	}

	while (!rz_list_empty(help_lines)) {
		char *line = (char *)rz_list_pop_head(help_lines);
		char *prefixed_line = NULL;
		if (*line == ' ') {
			prefixed_line = strdup(line);
			if (!prefixed_line) {
				goto error;
			}
			size_t prefixed_line_len = strlen(prefixed_line);
			if (prefixed_line_len >= hud_gutter_size) {
				// Currently, every line is handled separately by the hud, and this results
				// in a hud gutter being attached to every line and increasing its length.
				// However, wrapped lines already take the hud gutter into account and so
				// they need to be moved backwards.
				memmove(prefixed_line, prefixed_line + hud_gutter_size,
					prefixed_line_len - hud_gutter_size + 1);
			}
			memcpy(prefixed_line, line_prefix, strlen(line_prefix));
		} else {
			prefixed_line = rz_str_newf("%s%s", line_prefix, line);
			if (!prefixed_line) {
				goto error;
			}
		}
		rz_list_push(hs->detail_lines, prefixed_line);
	}

beach:
	rz_list_free(help_lines);
	free(detailed_help);
	free(line_prefix);
	rz_cmd_parsed_args_free(pa);
	return ret;

error:
	ret = false;
	goto beach;
}

// "?*"
RZ_IPI RzCmdStatus rz_cmd_help_search_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzCmdDesc *begin = NULL;

	if (argc == 2 && RZ_STR_ISNOTEMPTY(argv[1])) {
		begin = rz_cmd_get_desc(core->rcmd, argv[1]);
		if (!begin) {
			RZ_LOG_ERROR("Command '%s' does not exist.\n", argv[1]);
			status = RZ_CMD_STATUS_ERROR;
			goto exit_status;
		}
	}

	RzHelpSearch hs = {
		.color = core->print->flags & RZ_PRINT_FLAGS_COLOR,
		.pj = NULL,
		.sb = NULL,
		.detail_lines = NULL,
	};

	if (mode & RZ_OUTPUT_MODE_JSON) {
		hs.pj = pj_new();
		if (!hs.pj) {
			status = RZ_CMD_STATUS_ERROR;
			goto exit_status;
		}
		pj_o(hs.pj);
	} else {
		hs.sb = rz_strbuf_new(NULL);
		if (!hs.sb) {
			status = RZ_CMD_STATUS_ERROR;
			goto exit_status;
		}
	}

	rz_cmd_foreach_cmdname(core->rcmd, begin, help_search_cmd_desc_summary, &hs);

	if (mode & RZ_OUTPUT_MODE_JSON) {
		pj_end(hs.pj);
		rz_cons_printf("%s\n", pj_string(hs.pj));
		pj_free(hs.pj);
	} else {
		char *help = rz_strbuf_drain(hs.sb);
		rz_cons_printf("%s", help);
		free(help);
	}
exit_status:
	return status;
}

// "?**"
RZ_IPI RzCmdStatus rz_cmd_help_search_interactive_handler(RzCore *core, int argc, const char **argv) {
	RzList *brief_lines = rz_list_newf(free);
	if (!brief_lines) {
		return RZ_CMD_STATUS_ERROR;
	}
	// Get all summary descriptions of commands.
	rz_cmd_foreach_cmdname(core->rcmd, NULL, help_search_interactive_cmd_desc_summary, brief_lines);
	// Run it in the hub.
	free(rz_cons_hud(brief_lines, NULL));

	rz_list_free(brief_lines);
	return RZ_CMD_STATUS_OK;
}

// "?**e"
RZ_IPI RzCmdStatus rz_cmd_help_search_interactive_settings_handler(RzCore *core, int argc, const char **argv) {
	RzCmdStateOutput state = { 0 };
	rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STR_BUF, core);
	rz_core_config_print_all(core->config, "", &state);

	RzConfig **cfg;
	RzIterator *it = ht_sp_as_iter(core->plugin_configs);
	rz_iterator_foreach(it, cfg) {
		rz_core_config_print_all(*cfg, "", &state);
	}
	rz_iterator_free(it);

	// Run it in the hub.
	free(rz_cons_hud_string(rz_strbuf_get(state.d.sbuf)));
	rz_strbuf_free(state.d.sbuf);
	return RZ_CMD_STATUS_OK;
}

// "?***"
RZ_IPI RzCmdStatus rz_cmd_help_search_interactive_everything_handler(RzCore *core, int argc, const char **argv) {
	RzHelpSearch hs = {
		.color = core->print->flags & RZ_PRINT_FLAGS_COLOR,
		.pj = NULL,
		.sb = NULL,
		.detail_lines = NULL,
	};
	hs.detail_lines = rz_list_newf(free);
	if (!hs.detail_lines) {
		return RZ_CMD_STATUS_ERROR;
	}
	// Get all summary descriptions of commands.
	rz_cmd_foreach_cmdname(core->rcmd, NULL, help_search_cmd_desc_details, &hs);
	if (!hs.detail_lines) {
		return RZ_CMD_STATUS_ERROR;
	}
	// Run it in the hub.
	free(rz_cons_hud(hs.detail_lines, NULL));

	rz_list_free(hs.detail_lines);
	return RZ_CMD_STATUS_OK;
}
