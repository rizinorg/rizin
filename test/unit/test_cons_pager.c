// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

#include "../../librz/cons/pager.c"

bool test_pager_splitlines(void) {
	char *s = strdup("line1\nline2\nline3");
	int count = 0;
	int *lines = pager_splitlines(s, &count);

	mu_assert_eq(count, 3, "Split 3 lines");
	mu_assert_eq(lines[0], 0, "First line offset");
	mu_assert_streq(s + lines[0], "line1", "First line content");
	mu_assert_streq(s + lines[1], "line2", "Second line content");
	mu_assert_streq(s + lines[2], "line3", "Third line content");

	free(lines);
	free(s);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_pager_splitlines);
	return tests_passed != tests_run;
}

mu_main(all_tests)
