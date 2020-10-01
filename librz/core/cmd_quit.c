/* radare - LGPL - Copyright 2009-2016 - pancake */

#include "rz_core.h"

static const char *help_msg_q[] = {
	"Usage:",  "q[!][!] [retval]", "",
	"q","","quit program",
	"q!","","force quit (no questions)",
	"q!!","","force quit without saving history",
	"q!!!","","force quit without freeing anything",
	"q"," 1","quit with return value 1",
	"q"," a-b","quit with return value a-b",
	"q[y/n][y/n]","","quit, chose to kill process, chose to save project ",
	"Q","", "same as q!!",
	NULL
};

static void cmd_quit_init(RzCore *core, RzCmdDesc *parent) {
	DEFINE_CMD_DESCRIPTOR (core, q);
}

static int cmd_Quit(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (input[0] == '!') {
		if (input[1] == '!') {
			if (!rz_sandbox_enable (false)) {
				exit (0);
			}
			return -2;
		}
		rz_config_set (core->config, "scr.histsave", "false");
	}
	if (IS_DIGIT (input[0]) || input[0] == ' ') {
		core->num->value = rz_num_math (core->num, input);
	} else {
		core->num->value = -1;
	}
	return -2;
}

static int cmd_quit(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (input)
	switch (*input) {
	case '?':
		rz_core_cmd_help (core, help_msg_q);
		break;
	case '!':
		return cmd_Quit (core, input);
	case '\0':
		core->num->value = 0LL;
		return -2;
	default:
		while (*input == ' ') {
			input++;
		}
		if (*input) {
			rz_num_math (core->num, input);
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
		//exit (*input?rz_num_math (core->num, input+1):0);
		//if (core->http_up) return false; // cancel quit when http is running
		return -2;
	}
	return false;
}
