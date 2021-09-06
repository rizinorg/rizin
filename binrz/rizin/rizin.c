// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_main.h>
#include <rz_util.h>

static void rz_cmd(int in, int out, const char *cmd) {
	rz_xwrite(out, cmd, strlen(cmd) + 1);
	rz_xwrite(out, "\n", 1);
	int bufsz = (1024 * 64);
	unsigned char *buf = malloc(bufsz);
	if (!buf) {
		return;
	}
	while (1) {
		rz_xread(in, buf, bufsz);
		buf[bufsz - 1] = '\0';
		int len = strlen((const char *)buf);
		if (len < 1) {
			break;
		}
		rz_xwrite(1, buf, len);
		if (len != bufsz) {
			break;
		}
	}
	free(buf);
	rz_xwrite(1, "\n", 1);
}

static int rz_main_rzpipe(int argc, const char **argv) {
	int i, rc = 0;
	char *_in = rz_sys_getenv("RZ_PIPE_IN");
	char *_out = rz_sys_getenv("RZ_PIPE_OUT");
	if (_in && _out) {
		int in = atoi(_in);
		int out = atoi(_out);
		for (i = 1; i < argc; i++) {
			rz_cmd(in, out, argv[i]);
		}
	} else {
		eprintf("Error: RZ_PIPE_(IN|OUT) environment not set\n");
		eprintf("Usage: rizin -c '!*rzp x' # run commands via rzpipe\n");
		rc = 1;
	}
	free(_in);
	free(_out);
	return rc;
}

int MAIN_NAME(int argc, const ARGV_TYPE **argv) {
	char **utf8_argv = ARGV_TYPE_TO_UTF8(argc, argv);
	int ret;
	if (argc > 0 && strstr(utf8_argv[0], "rzp")) {
		ret = rz_main_rzpipe(argc, (const char **)utf8_argv);
	} else {
		ret = rz_main_rizin(argc, (const char **)utf8_argv);
	}
	FREE_UTF8_ARGV(argc, utf8_argv);
	return ret;
}
