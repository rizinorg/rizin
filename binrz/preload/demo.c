// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
#include <stdio.h>
#include <dlfcn.h>

int main(int argc, char **argv) {
	void *a = dlopen(NULL, RTLD_LAZY);
	void *m = dlsym(a, "rz_main_rizin");
	if (m) {
		int (*rz_main)(int argc, char **argv) = m;
		return rz_main(argc, argv);
	}
	return 0;
}
