// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_project.h>

RZ_IPI RzCmdStatus rz_project_save_handler(RzCore *core, int argc, const char **argv) {
	const char *file;
	if (argc == 1) {
		file = rz_config_get(core->config, "prj.file");
		if (RZ_STR_ISEMPTY(file)) {
			RZ_LOG_ERROR("core: There is no project file associated with the current session yet.\n"
				     "Specify the file explicitly as `Ps <file.rzdb>` or set it manually with `e prj.file=<project-path>`.\n");
			return RZ_CMD_STATUS_ERROR;
		}
	} else { // argc == 2 checked by the shell
		file = argv[1];
	}
	bool compress = rz_config_get_b(core->config, "prj.compress");
	RzProjectErr err = rz_project_save_file(core, file, compress);
	if (err != RZ_PROJECT_ERR_SUCCESS) {
		RZ_LOG_ERROR("core: Failed to save project to file %s: %s\n", file, rz_project_err_message(err));
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_project_open_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_project_load_for_cli(core, argv[1], true) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_project_open_no_bin_io_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_project_load_for_cli(core, argv[1], false) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
