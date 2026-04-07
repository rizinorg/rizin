// SPDX-FileCopyrightText: 2024 z3phyr <giridh1337@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../unit/minunit.h"
#include <rz_heap_glibc.h>
#include <rz_core.h>

/* This is done to not link -lm for round(), only works for +ve integers*/
int int_round(double x) {
	return (int)(x + 0.5);
}

bool test_get_glibc_version(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	mu_assert_true(rz_core_file_open_load(core, "=", 0, RZ_PERM_R, false), "open =");

	double version = rz_get_glibc_version(core, "bins/elf/libc-2.27.so", NULL);
	int glibc_version = int_round((version * 100));
	mu_assert_eq(glibc_version, 227, "Incorrect libc version, expected 2.27");

	version = rz_get_glibc_version(core, "bins/elf/libc-2.31.so", NULL);
	glibc_version = int_round((version * 100));
	mu_assert_eq(glibc_version, 231, "Incorrect libc version, expected 2.31");

	version = rz_get_glibc_version(core, "bins/elf/libc-2.32.so", NULL);
	glibc_version = int_round((version * 100));
	mu_assert_eq(glibc_version, 232, "Incorrect libc version, expected 2.32");

	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_get_glibc_version);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
