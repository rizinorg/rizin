// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_cons_pipe(void) {
	rz_cons_new();
	const char *test_file = "/tmp/rizin_test_pipe";
	// Redirect stdout (fd 1)
	RzConsPipe *cpipe = rz_cons_pipe_open(test_file, 1, false);
	if (!cpipe) {
		rz_cons_free();
		mu_end;
	}

	// This should go to the file now
	printf("Hello Pipe");
	fflush(stdout);

	rz_cons_pipe_close(cpipe);

	char *content = rz_file_slurp(test_file, NULL);
	mu_assert_notnull(content, "Pipe file should exist and have content");
	mu_assert_true(strstr(content, "Hello Pipe") != NULL, "Pipe file content check");
	free(content);

	unlink(test_file);
	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_cons_pipe);
	return tests_passed != tests_run;
}

mu_main(all_tests)
