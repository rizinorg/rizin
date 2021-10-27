// SPDX-FileCopyrightText: 2009-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_core.h"

#define RZ_QUIT_VALUE_KILL   5
#define RZ_QUIT_VALUE_NOKILL 1
#define RZ_QUIT_VALUE_SAVE   10
#define RZ_QUIT_VALUE_NOSAVE 2

static const char *help_msg_q[] = {
	"Usage:", "q[!][!] [retval]", "",
	"q", "", "quit program",
	"q!", "", "force quit (no questions)",
	"q!!", "", "force quit without saving history",
	"q!!!", "", "force quit without freeing anything",
	"q", " 1", "quit with return value 1",
	"q", " a-b", "quit with return value a-b",
	"q[y/n][y/n]", "", "quit, chose to kill process, chose to save project ",
	"Q", "", "same as q!!",
	NULL
};

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

RZ_IPI int rz_cmd_quit(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (input)
		switch (*input) {
		case '?':
			rz_core_cmd_help(core, help_msg_q);
			break;
		case '!':
			return cmd_Quit(core, input);
		case '\0':
			core->num->value = 0LL;
			return -2;
		default:
			while (*input == ' ') {
				input++;
			}
			if (*input) {
				rz_num_math(core->num, input);
			} else {
				core->num->value = 0LL;
			}

			if (*input == 'y') {
				core->num->value = 5;
			} else if (*input == 'n') {
				core->num->value = 1;
			}

			if (input[1] == 'y') {
				core->num->value += 10;
			} else if (input[1] == 'n') {
				core->num->value += 2;
			}
			return -2;
		}
	return false;
}
