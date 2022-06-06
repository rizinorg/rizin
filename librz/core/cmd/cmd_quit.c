// SPDX-FileCopyrightText: 2009-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_core.h"

#define RZ_QUIT_VALUE_KILL   5
#define RZ_QUIT_VALUE_NOKILL 1
#define RZ_QUIT_VALUE_SAVE   10
#define RZ_QUIT_VALUE_NOSAVE 2

RZ_IPI RzCmdStatus rz_cmd_quit_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = 0LL;
	return RZ_CMD_STATUS_EXIT;
}

RZ_IPI RzCmdStatus rz_quit_kill_save_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = RZ_QUIT_VALUE_KILL;
	core->num->value += RZ_QUIT_VALUE_SAVE;
	return RZ_CMD_STATUS_EXIT;
}
RZ_IPI RzCmdStatus rz_quit_kill_nosave_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = RZ_QUIT_VALUE_KILL;
	core->num->value += RZ_QUIT_VALUE_NOSAVE;
	return RZ_CMD_STATUS_EXIT;
}
RZ_IPI RzCmdStatus rz_quit_nokill_nosave_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = RZ_QUIT_VALUE_NOKILL;
	core->num->value += RZ_QUIT_VALUE_NOSAVE;
	return RZ_CMD_STATUS_EXIT;
}
RZ_IPI RzCmdStatus rz_quit_nokill_save_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = RZ_QUIT_VALUE_NOKILL;
	core->num->value += RZ_QUIT_VALUE_SAVE;
	return RZ_CMD_STATUS_EXIT;
}

static int cmd_Quit(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (input[0] == '!') {
		if (input[1] == '!') {
			exit(0);
			return -2;
		}
		rz_config_set(core->config, "scr.histsave", "false");
	}
	if (IS_DIGIT(input[0]) || input[0] == ' ') {
		core->num->value = rz_num_math(core->num, input);
	} else {
		core->num->value = -1;
	}
	return -2;
}

RZ_IPI RzCmdStatus rz_cmd_force_quit_handler(RzCore *core, int argc, const char **argv) {
	cmd_Quit(core, argv[0] + 1);
	return RZ_CMD_STATUS_EXIT;
}

RZ_IPI RzCmdStatus rz_cmd_force_quit_without_history_handler(RzCore *core, int argc, const char **argv) {
	cmd_Quit(core, argv[0] + 1);
	return RZ_CMD_STATUS_EXIT;
}
