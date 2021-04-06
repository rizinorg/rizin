// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_file_slurp(void) {

#ifdef __WINDOWS__
#define S_IRWXU _S_IREAD | _S_IWRITE
#endif

	const char *test_file = "./empty_file";
	size_t s;
	const char *some_words = "some words";

	int f = open(test_file, O_CREAT, S_IRWXU);
	mu_assert_neq(f, -1, "cannot create empty file");
	close(f);

	char *content = rz_file_slurp(test_file, &s);
	mu_assert_eq(s, 0, "size should be zero");
	mu_assert_eq(strlen(content), 0, "returned buffer should be empty");
	free(content);

	f = open(test_file, O_WRONLY, S_IRWXU);
	mu_assert_neq(f, -1, "cannot reopen empty file");
	rz_xwrite(f, some_words, strlen(some_words));
	close(f);

	content = rz_file_slurp(test_file, &s);
	mu_assert_eq(s, strlen(some_words), "size should be correct");
	mu_assert_eq(strlen(content), strlen(some_words), "size for the buffer should be correct");
	mu_assert_streq(content, some_words, "content should match");
	free(content);

	unlink(test_file);

	mu_end;
}

int all_tests() {
	mu_run_test(test_file_slurp);
	return tests_passed != tests_run;
}

mu_main(all_tests)
