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
		rz_cmd_get_help_strbuf(cmd, cd, hs->color, hs->sb);
	}
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

	char *detailed_help = rz_cmd_get_help(cmd, pa, hs->color);
	if (!detailed_help) {
		rz_cmd_parsed_args_free(pa);
		return false;
	}
	RzList *help_lines = rz_str_split_list_regex(detailed_help, "\\n+", 0);

	char *line_prefix = rz_str_newf("%s | ", cd->name);
	if (!help_lines || !line_prefix) {
		goto error;
	}
	while (!rz_list_empty(help_lines)) {
		char *line = (char *)rz_list_pop_head(help_lines);
		char *prefixed_line = rz_str_newf("%s%s", line_prefix, line);
		if (!prefixed_line) {
			goto error;
		}
		rz_list_push(hs->detail_lines, prefixed_line);
	}

	free(detailed_help);
	rz_list_free(help_lines);
	rz_cmd_parsed_args_free(pa);
	free(line_prefix);
	return true;

error:
	free(detailed_help);
	free(help_lines);
	free(line_prefix);
	rz_cmd_parsed_args_free(pa);
	return false;
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
	RzHelpSearch hs = {
		.color = core->print->flags & RZ_PRINT_FLAGS_COLOR,
		.pj = NULL,
		.sb = NULL,
		.detail_lines = NULL,
	};
	hs.sb = rz_strbuf_new("");
	if (!hs.sb) {
		return RZ_CMD_STATUS_ERROR;
	}
	// Get all summary descriptions of commands.
	rz_cmd_foreach_cmdname(core->rcmd, NULL, help_search_cmd_desc_summary, &hs);
	// Run it in the hub.
	free(rz_cons_hud_string(rz_strbuf_get(hs.sb)));

	rz_strbuf_free(hs.sb);
	return RZ_CMD_STATUS_OK;
}

// "?**e"
RZ_IPI RzCmdStatus rz_cmd_help_search_interactive_settings_handler(RzCore *core, int argc, const char **argv) {
	RzCmdStateOutput state = { 0 };
	rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STR_BUF);
	rz_core_config_print_all(core->config, "", &state);

	RzConfig **cfg;
	RzIterator *it = ht_sp_as_iter(core->plugin_configs);
	rz_iterator_foreach(it, cfg) {
		rz_core_config_print_all(*cfg, "", &state);
	}

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
