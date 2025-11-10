// SPDX-FileCopyrightText: 2024 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_type.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_panels.h>

#include "../core_private.h"

RZ_IPI RzCmdStatus rz_interactive_visual_handler(RzCore *core, int argc, const char **argv) {
	if (core->http_up) {
		RZ_LOG_ERROR("core->http_up=false.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("Visual mode requires scr.interactive=true.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	const char *v_commands = argc > 1 ? argv[1] : "";
	rz_core_visual(core, v_commands);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_interactive_visual_disas_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_visual(core, "p");
}

RZ_IPI RzCmdStatus rz_interactive_visual_management_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_visual(core, "v");
}

RZ_IPI RzCmdStatus rz_interactive_visual_emu_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_visual(core, "pp");
}

RZ_IPI RzCmdStatus rz_interactive_visual_config_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_visual(core, "e");
}

RZ_IPI RzCmdStatus rz_interactive_visual_graph_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_visual(core, "V");
}

RZ_IPI RzCmdStatus rz_interactive_visual_help_handler(RzCore *core, int argc, const char **argv) {
	rz_core_cmd_help(core, rz_core_visual_get_short_help());
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_interactive_visual_help_detail_handler(RzCore *core, int argc, const char **argv) {
	rz_core_cmd_help(core, rz_core_visual_get_long_help());
	rz_cons_printf("%s\n", "Function Keys: (See 'e key.'), defaults to");
	rz_core_cmd_help(core, rz_core_visual_get_fcn_help());
	return RZ_CMD_STATUS_OK;
}
