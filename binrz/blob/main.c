// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2012-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_main.h>
#include <rz_util.h>

int MAIN_NAME(int argc, const ARGV_TYPE **argv) {
	char **utf8_argv = ARGV_TYPE_TO_UTF8(argc, argv);
	const char *prog_name = rz_file_basename(utf8_argv[0]);
	RzMainCallback main_cb = rz_main_find(prog_name);
	if (!main_cb) {
		RZ_LOG_ERROR("rizin: Cannot find main for '%s'. using rizin instead\n", prog_name);
		main_cb = rz_main_rizin;
	}
	int rc = main_cb(argc, (const char **)utf8_argv);
	FREE_UTF8_ARGV(argc, utf8_argv);
	return rc;
}
