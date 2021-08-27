// SPDX-FileCopyrightText: 2012-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_main.h>
#include <rz_util.h>

int MAIN_NAME(int argc, const ARGV_TYPE **argv) {
	char **utf8_argv = ARGV_TYPE_TO_UTF8(argc, argv);
	int rc = 1;
	const char *prog_name = rz_file_basename(utf8_argv[0]);
	RzMain *m = rz_main_new(prog_name);
	if (m) {
		rc = rz_main_run(m, argc, (const char **)utf8_argv);
		rz_main_free(m);
	}
	UTF8_ARGV_FREE(argc, utf8_argv);
	return rc;
}
