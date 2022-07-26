// SPDX-FileCopyrightText: 2009-2014 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
#include "rz_cmd.h"
#include "rz_core.h"

static const char *help_msg_lparen[] = {
	"Usage:", "(foo args;cmd1;cmd2;..)", "Aliases",
	"(foo args;..;..)", "", "define macro foo",
	"(foo args;..;..)(args)", "", "define macro foo and call it",
	"(-foo)", "", "remove macro foo",
	".(foo args)", "", "call macro foo",
	"..(foo args1 args2 args3)", "", "call macro foo 3 times",
	"()", "", "break inside macro",
	"(*", "", "list all defined macros",
	"", "Argument support:", "",
	"(foo x y; $0 @ $1)", "", "define macro foo with args x($0) and y($1)",
	".(foo 128 0x804800)", "", "call it with args",
	"..(foo 128 0x804800 256 0x804801)", "", "call it with args twice",
	NULL
};

RZ_IPI int rz_cmd_macro(void *data, const char *input) {
	char *buf = NULL;
	RzCore *core = (RzCore *)data;

	switch (*input) {
	case '-':
		rz_cmd_macro_rm(&core->rcmd->macro, input + 1);
		break;
	case '*':
		rz_cmd_macro_meta(&core->rcmd->macro);
		break;
	case '\0':
		rz_cmd_macro_list(&core->rcmd->macro);
		break;
	case '(':
	case '?':
		rz_core_cmd_help(core, help_msg_lparen);
		break;
	default: {
		// XXX: stop at first ')'. if next is '(' and last
		// int lastiscp = input[strlen (input)-1] == ')';
		int mustcall = 0;
		int i, j = 0;
		buf = strdup(input);

		for (i = 0; buf[i]; i++) {
			switch (buf[i]) {
			case '(':
				j++;
				break;
			case ')':
				j--;
				if (buf[i + 1] == '(') {
					buf[i + 1] = 0;
					mustcall = i + 2;
				}
				break;
			}
		}
		buf[strlen(buf) - 1] = 0;
		rz_cmd_macro_add(&core->rcmd->macro, buf);
		if (mustcall) {
			char *comma = strchr(buf, ' ');
			if (!comma) {
				comma = strchr(buf, ';');
			}
			if (comma) {
				*comma = ' ';
				memmove(comma + 1, buf + mustcall, strlen(buf + mustcall) + 1);
				rz_cmd_macro_call(&core->rcmd->macro, buf);
			} else {
				eprintf("Invalid syntax for macro\n");
			}
		}
		free(buf);
	} break;
	}
	return 0;
}
