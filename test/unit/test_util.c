// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_util/set.h>
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

bool test_set_u(void) {
	SetU *set_u = set_u_new();
	set_u_add(set_u, 0x5050505);
	set_u_add(set_u, 0x5050505);
	set_u_add(set_u, 0x6060606);
	set_u_add(set_u, 0x7070707);
	set_u_add(set_u, 0x7070707);
	mu_assert_eq(set_u_size(set_u), 3, "Length wrong.");
	mu_assert_true(set_u_contains(set_u, 0x5050505), "Value was not added.");
	mu_assert_true(set_u_contains(set_u, 0x6060606), "Value was not added.");
	mu_assert_true(set_u_contains(set_u, 0x7070707), "Value was not added.");

	set_u_delete(set_u, 0x7070707);
	mu_assert_false(set_u_contains(set_u, 0x7070707), "Value was not deleted.");
	mu_assert_eq(set_u_size(set_u), 2, "Length wrong.");

	// Double delete
	set_u_delete(set_u, 0x7070707);
	mu_assert_eq(set_u_size(set_u), 2, "Length wrong.");

	size_t x = 0;
	SetUIter it;
	set_u_foreach (set_u, it) {
		x++;
		bool matches = it.v == 0x5050505 || it.v == 0x6060606;
		mu_assert_true(matches, "Set contained ill-formed value.");
	}
	mu_assert_eq(x, 2, "Foreach hasn't iterated the correct number of times.");

	set_u_delete(set_u, 0x6060606);
	mu_assert_eq(set_u_size(set_u), 1, "Length wrong.");
	set_u_delete(set_u, 0x5050505);
	mu_assert_eq(set_u_size(set_u), 0, "Length wrong.");

	set_u_foreach (set_u, it) {
		mu_assert("Should not be reached.", false);
	}
	set_u_add(set_u, 0x53e0);
	set_u_add(set_u, 0x53bc);
	x = 0;
	set_u_foreach (set_u, it) {
		x++;
	}
	mu_assert_eq(x, 2, "Foreach hasn't iterated the correct number of times.");
	set_u_delete(set_u, 0x53e0);
	set_u_delete(set_u, 0x53bc);

	set_u_add(set_u, 0);
	set_u_add(set_u, 1);
	set_u_add(set_u, 2);
	set_u_add(set_u, 3);

	// Add an address as key which is far away from the heap addresses.
	set_u_add(set_u, 100000000);
	mu_assert_true(set_u_contains(set_u, 100000000), "Not contained.");
	mu_assert_eq(set_u->count, 5, "count");
	mu_assert_false(set_u_contains(set_u, 6), "should not be here.");

	x = 0;
	set_u_foreach (set_u, it) {
		x++;
	}
	mu_assert_eq(x, 5, "Foreach hasn't iterated the correct number of times.");

	set_u_free(set_u);
	mu_end;
}

int all_tests() {
	mu_run_test(test_set_u);
	mu_run_test(test_file_slurp);
	mu_run_test(test_leading_zeros);
	return tests_passed != tests_run;
}

mu_main(all_tests)
