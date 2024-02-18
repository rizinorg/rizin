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


bool test_htpp_anomaly(void) {
	HtPP *ht = ht_pp_new0();
	void *p1 = malloc(0x10);
	void *p2 = malloc(0x20);
	void *p3 = malloc(0x30);
	ut64 p4 = 0x50505050505;
	ht_pp_insert(ht, p1, (void *) 1);
	ht_pp_insert(ht, p2, (void *) 1);
	printf("\nht->count should be 2, but is = %d\n", ht->count);

	// Add an address as key which is far away from the heap addresses.
	ht_pp_insert(ht, &p4, (void *) 1);
	printf("ht->count should be 3, but is = %d (stack addr is treaded as unique key)\n", ht->count);
	bool found = false;
	ht_pp_find(ht, p3, &found);
	mu_assert_false(found, "p3 should not be here.");
	mu_end;
}

int all_tests() {
	mu_run_test(test_htpp_anomaly);
	mu_run_test(test_file_slurp);
	mu_run_test(test_leading_zeros);
	return tests_passed != tests_run;
}

mu_main(all_tests)
