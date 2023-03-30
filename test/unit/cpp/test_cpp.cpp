// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util.h>

#include "../minunit.h"

/*
 * This is mostly just a test for ensuring all headers can be
 * compiled as C++.
 */

bool test_cpp(void) {
	RzCore *core = rz_core_new();
	char *r = rz_core_cmd_str(core, "echo Hello from C++!");
	mu_assert_streq(r, "Hello from C++!\n", "cmd");
	rz_core_free(core);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_cpp);
	return tests_passed != tests_run;
}

mu_main(all_tests)
