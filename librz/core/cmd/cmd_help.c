// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_strbuf.h"
#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_cons.h>
#include <rz_cmd.h>
#include <rz_search.h>

typedef struct _search_help {
	bool color;
	RzStrBuf *sb;
	PJ *pj;
} RzHelpSearch;

static bool help_search_cmd_desc_entry(RzCmd *cmd, const RzCmdDesc *cd, void *user) {
	rz_return_val_if_fail(cd, false);
	RzHelpSearch *hs = (RzHelpSearch *)user;
	if (hs->pj) {
		rz_cmd_get_help_json(cmd, cd, hs->pj);
	} else {
		rz_cmd_get_help_strbuf(cmd, cd, hs->color, hs->sb);
	}
	return true;
}

// "?*"
RZ_IPI RzCmdStatus rz_cmd_help_search_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzCmdDesc *begin = NULL;

	if (argc == 2) {
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

	rz_cmd_foreach_cmdname(core->rcmd, begin, help_search_cmd_desc_entry, &hs);

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
	};
	hs.sb = rz_strbuf_new("");
	if (!hs.sb) {
	  return RZ_CMD_STATUS_ERROR;
	}
	// Get all summary descriptions of commands.
	rz_cmd_foreach_cmdname(core->rcmd, NULL, help_search_cmd_desc_entry, &hs);
	// Run it in the hub.
	free(rz_cons_hud_string(rz_strbuf_get(hs.sb)));

	rz_strbuf_free(hs.sb);
	return RZ_CMD_STATUS_OK;
}

// "?***"
RZ_IPI RzCmdStatus rz_cmd_help_search_interactive_everything_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}
