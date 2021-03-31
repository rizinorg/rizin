// SPDX-FileCopyrightText: 2012-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_main.h>
#include <rz_util.h>

int main(int argc, char **argv) {
	int rc = 1;
	const char *prog_name = rz_file_basename(argv[0]);
	RzMain *m = rz_main_new(prog_name);
	if (m) {
		rc = rz_main_run(m, argc, argv);
		rz_main_free(m);
	}
	return rc;
}
