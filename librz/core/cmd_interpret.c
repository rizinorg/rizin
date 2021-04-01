// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cmd.h>
#include <rz_core.h>
#include "cmd_descs/cmd_descs.h"

RZ_IPI RzCmdStatus rz_interpret_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 1) {
		lastcmd_repeat(core, 0);
		return RZ_CMD_STATUS_OK;
	} else if (argc == 2) {
		int tmp_html = rz_cons_singleton()->is_html;
		rz_cons_singleton()->is_html = 0;
		char *cmd_output = rz_core_cmd_str(core, argv[1]);
		rz_cons_singleton()->is_html = tmp_html;
		rz_core_cmd(core, cmd_output, 0);
		free(cmd_output);
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_interpret_output_handler(RzCore *core, int argc, const char **argv) {
	char *str = rz_core_cmd_str_pipe(core, argv[1]);
	if (!str) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_cmd(core, str, 0);
	free(str);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_repeat_forward_handler(RzCore *core, int argc, const char **argv) {
	lastcmd_repeat(core, 1);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_interpret_script_handler(RzCore *core, int argc, const char **argv) {
	const char *script_file = argv[1];
	if (*script_file == '$') {
		rz_core_cmd0(core, script_file);
	} else {
		if (!rz_core_run_script(core, script_file)) {
			eprintf("Cannot find script '%s'\n", script_file);
			core->num->value = 1;
		} else {
			core->num->value = 0;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_interpret_editor_2_handler(RzCore *core, int argc, const char **argv) {
	rz_core_run_script(core, "-");
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_interpret_pipe_handler(RzCore *core, int argc, const char **argv) {
	rz_core_run_script(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_interpret_system_handler(RzCore *core, int argc, const char **argv) {
	char *args = rz_str_array_join(argv + 1, argc - 1, " ");
	rz_core_cmd_command(core, args);
	free(args);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_interpret_macro_handler(RzCore *core, int argc, const char **argv) {
	rz_cmd_macro_call(&core->rcmd->macro, argv[1]);
	return RZ_CMD_STATUS_OK;
}
