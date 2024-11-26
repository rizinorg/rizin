// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_type.h>

#include "../core_private.h"

RZ_IPI RzCmdStatus rz_interactive_visual_handler(RzCore *core, int argc, const char **argv) {
	if (core->http_up) {
		return false;
	}
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Visual mode requires scr.interactive=true.\n");
		return false;
	}
	const char *v_commands = argc > 1 ? argv[1] : "";
	rz_core_visual(core, v_commands);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_interactive_panel_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_OK;
}
