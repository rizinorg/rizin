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
	mu_assert_notnull(content, "content should not be NULL");
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

#define test_leading_zeros_case(x, expect) \
	mu_assert_eq(rz_bits_leading_zeros(x), expect, "should be " #expect)

bool test_leading_zeros(void) {
	test_leading_zeros_case(0ULL, 64);
	test_leading_zeros_case(1ULL, 63);

	test_leading_zeros_case(0xffffffffffffffffULL, 0);
	test_leading_zeros_case(0xffffffffULL, 32);
	test_leading_zeros_case(0x80000000ULL, 32);
	test_leading_zeros_case(0x100000000ULL, 31);
	test_leading_zeros_case(0x40000000ULL, 33);
	test_leading_zeros_case(0x400000000ULL, 29);

	test_leading_zeros_case(0x1000000000000, 15);
	test_leading_zeros_case(0x800000000000, 16);
	test_leading_zeros_case(0x400000000000, 17);
	test_leading_zeros_case(0x200000000000, 18);
	test_leading_zeros_case(0x100000000000, 19);
	mu_end;
}

bool test_path_prefix(void) {
	size_t equal;
	RzPath *sys_path = rz_path_new();
	if (!sys_path) {
		mu_assert_eq(1, 0, "initialization error");
	}
	const char *output = rz_path_prefix(sys_path);
	equal = strcmp(output, RZ_PREFIX);
	mu_assert_eq(equal, 0, "not equal");
	rz_path_free(sys_path);
	mu_end;
}

bool test_path_normalize_expand(void) {
	char *out;

	out = rz_path_normalize_expand("", strlen(""));
	mu_assert_notnull(out, "result should not be NULL");
	mu_assert_streq(out, ".", "empty input should normalize to '.'");
	free(out);

	out = rz_path_normalize_expand("foo/bar", strlen("foo/bar"));
	mu_assert_notnull(out, "result should not be NULL");
#ifdef __WINDOWS__
	mu_assert_streq(out, ".\\foo\\bar", "relative path should be prefixed with '.\\'");
#else
	mu_assert_streq(out, "./foo/bar", "relative path should be prefixed with './'");
#endif
	free(out);
	out = rz_path_normalize_expand(".hidden_dir", strlen(".hidden_dir"));
	mu_assert_notnull(out, "result should not be NULL");
	mu_assert_streq(out, ".hidden_dir", "dotfile should be preserved");
	free(out);

	out = rz_path_normalize_expand("/home/user/.././etc", strlen("/home/user/.././etc"));
	mu_assert_notnull(out, "result should not be NULL");
#ifdef __WINDOWS__
	free(out);
	out = rz_path_normalize_expand("C:\\Users\\Test", strlen("C:\\Users\\Test"));
	mu_assert_notnull(out, "result should not be NULL");
	mu_assert_streq(out, "C:\\Users\\Test", "Windows absolute path should be unchanged");
#else
	mu_assert_notnull(out, "result should not be NULL");
	mu_assert_streq(out, "/home/user/.././etc", "absolute path should be unchanged");
#endif
	free(out);

	out = rz_path_normalize_expand("/home/user/./doc/././", strlen("/home/user/./doc/././"));
	mu_assert_notnull(out, "result should not be NULL");
#ifdef __WINDOWS__
	free(out);
	out = rz_path_normalize_expand("C:\\Users\\Test\\.\\.\\", strlen("C:\\Users\\Test\\.\\.\\"));
	mu_assert_notnull(out, "result should not be NULL");
	mu_assert_streq(out, "C:\\Users\\Test\\.\\.\\", "should preserve . in absolute paths");
#else
	mu_assert_streq(out, "/home/user/./doc/././", "should preserve . in absolute paths");
#endif
	free(out);

	mu_end;
}

int all_tests() {
	mu_run_test(test_file_slurp);
	mu_run_test(test_leading_zeros);
	mu_run_test(test_path_prefix);
	mu_run_test(test_path_normalize_expand);
	return tests_passed != tests_run;
}

mu_main(all_tests)
