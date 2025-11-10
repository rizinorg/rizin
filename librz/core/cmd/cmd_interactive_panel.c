// SPDX-FileCopyrightText: 2024 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_type.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_panels.h>

#include "../core_private.h"

RZ_IPI RzCmdStatus rz_interactive_panel_handler(RzCore *core, int argc, const char **argv) {
	if (core->vmode) {
		RZ_LOG_ERROR("core->vmode == false.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("Panel mode requires scr.interactive=true.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	RzCoreVisual *visual = core->visual;
	if (rz_core_visual_panels_root(core, visual->panels_root)) {
		return RZ_CMD_STATUS_OK;
	}
	RZ_LOG_ERROR("rz_core_visual_panels_root() failed\n");
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_interactive_panel_load_handler(RzCore *core, int argc, const char **argv) {
	RzCoreVisual *visual = core->visual;

	if (visual && visual->panels_root && visual->panels_root->active_tab) {
		rz_load_panels_layout(core, argv[1]);
	}
	rz_config_set(core->config, "scr.layout", argv[1]);
	RZ_LOG_INFO("Set scr.layout = %s", argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_interactive_panel_store_handler(RzCore *core, int argc, const char **argv) {
	rz_save_panels_layout(core, argv[1]);

	rz_return_val_if_fail(core->config, RZ_CMD_STATUS_ERROR);
	rz_config_set(core->config, "scr.layout", argv[1]);
	return RZ_CMD_STATUS_OK;
}
