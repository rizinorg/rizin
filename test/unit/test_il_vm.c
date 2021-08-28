// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"
static bool test_example() {
	int x = 1;
	return true;
}

bool all_tests() {
	mu_run_test(test_example);
	return tests_passed != tests_run;
}

mu_main(all_tests)