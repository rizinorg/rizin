// SPDX-FileCopyrightText: 2025 answarck <answarc764@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_types.h>
#include "minunit.h"

bool test_rz_syscmd_uniq_pipe_basic(void) {
	const char *in = "a\na\na\n";
	char *out = rz_syscmd_uniq_pipe(in);
	mu_assert_streq(out, "a\n", "uniq basic");
	free(out);
	mu_end;
}

bool test_rz_syscmd_sort_pipe_basic(void) {
	const char *in = "c\na\nb\n";
	char *out = rz_syscmd_sort_pipe(in);
	mu_assert_streq(out, "a\nb\nc\n", "sort basic");
	free(out);
	mu_end;
}

bool test_rz_syscmd_uniq_pipe_empty(void) {
	char *out = rz_syscmd_uniq_pipe("");
	mu_assert_null(out, "empty -> NULL");
	mu_end;
}

bool test_rz_syscmd_sort_pipe_empty(void) {
	char *out = rz_syscmd_sort_pipe("");
	mu_assert_null(out, "empty -> NULL");
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_rz_syscmd_uniq_pipe_basic);
	mu_run_test(test_rz_syscmd_uniq_pipe_empty);
	mu_run_test(test_rz_syscmd_sort_pipe_basic);
	mu_run_test(test_rz_syscmd_sort_pipe_empty);
	return tests_passed != tests_run;
}

mu_main(all_tests);
