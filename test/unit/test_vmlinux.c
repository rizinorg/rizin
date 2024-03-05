// SPDX-FileCopyrightText: 2017 Fangrui Song <i@maskray.me>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"
#include <vmlinux.h>
#include <stdbool.h>

int test_vmlinux_vercmp(void) {
    unsigned long v1[3] = {6, 7, 1};
    unsigned long v2[3] = {5, 17, 0};
	mu_assert("v1 > v2", vmlinux_vercmp(v1, v2) > 0);

	mu_assert("v1 > v2_str", vmlinux_vercmp_with_str(v1, "5.17") > 0);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_vmlinux_vercmp);
	return tests_passed != tests_run;
}

mu_main(all_tests)