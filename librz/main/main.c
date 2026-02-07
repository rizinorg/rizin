// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2012-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_main.h>
#include <rz_util.h>

RZ_LIB_VERSION(rz_main);

typedef struct main_entry_t {
	const char *name;
	RzMainCallback main;
} MainEntry;

static MainEntry main_prog[] = {
	{ "rizin", rz_main_rizin },
	{ "rz-asm", rz_main_rz_asm },
	{ "rz-ax", rz_main_rz_ax },
	{ "rz-bin", rz_main_rz_bin },
	{ "rz-diff", rz_main_rz_diff },
	{ "rz-find", rz_main_rz_find },
	{ "rz-gg", rz_main_rz_gg },
	{ "rz-hash", rz_main_rz_hash },
	{ "rz-run", rz_main_rz_run },
	{ "rz-sign", rz_main_rz_sign },
};

RZ_API RzMainCallback rz_main_find(const char *name) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(main_prog); i++) {
		if (!strcmp(name, main_prog[i].name)) {
			return main_prog[i].main;
		}
	}
	return NULL;
}

RZ_API int rz_main_version_print(RZ_BORROW RZ_NONNULL RzPath *sys_path, const char *progname) {
	rz_return_val_if_fail(sys_path, -1);
	char *s = rz_version_str(sys_path, progname);
	printf("%s\n", s);
	free(s);
	return 0;
}
