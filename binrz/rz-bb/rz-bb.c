// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

typedef char *(*CommandCallback)(const char *args);

typedef struct {
	const char *cmd;
	CommandCallback cb;
} BbCommands;

static BbCommands bbcmds[] = {
	{ "cat", rz_syscmd_cat },
	{ "ls", rz_syscmd_ls },
	NULL
};

static int run(int i, const char *arg) {
	char *res = bbcmds[i].cb(arg);
	if (res) {
		printf("%s", res);
		free(res);
		return 0;
	}
	return 1;
}

int main(int argc, char **argv) {
	int i;
	for (i = 0; bbcmds[i].cmd; i++) {
		if (!strcmp(bbcmds[i].cmd, argv[0])) {
			const char *arg = argc > 1 ? argv[1] : NULL;
			return run(i, arg);
		}
	}
	if (argc > 1) {
		for (i = 0; bbcmds[i].cmd; i++) {
			if (!strcmp(bbcmds[i].cmd, argv[1])) {
				const char *arg = argc > 2 ? argv[2] : NULL;
				return run(i, arg);
			}
		}
	}
	for (i = 0; bbcmds[i].cmd; i++) {
		printf("%s\n", bbcmds[i].cmd);
	}
	return 1;
}
