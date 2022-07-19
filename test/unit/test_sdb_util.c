// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include "minunit.h"
#include <sdb.h>
#include <fcntl.h>
#include <stdio.h>

bool test_sdb_itoa_null_arg() {
	mu_assert_streq_free(sdb_itoa(0, NULL, 10), "0", "0 is converted");
	mu_assert_streq_free(sdb_itoa(10, NULL, 10), "10", "10 is converted");
	mu_assert_streq_free(sdb_itoa(3, NULL, 10), "3", "3 is converted");
	mu_assert_streq_free(sdb_itoa(100, NULL, 16), "0x64", "100 is converted");
	mu_assert_streq_free(sdb_itoa(100, NULL, 10), "100", "100 is converted");
	mu_end;
}

bool test_sdb_itoa() {
	char s[64];
	mu_assert_streq(sdb_itoa(0, s, 10), "0", "0 is converted");
	mu_assert_streq(sdb_itoa(10, s, 10), "10", "10 is converted");
	mu_assert_streq(sdb_itoa(3, s, 10), "3", "3 is converted");
	mu_assert_streq(sdb_itoa(100, s, 16), "0x64", "100 is converted");
	mu_assert_streq(sdb_itoa(100, s, 10), "100", "100 is converted");
	mu_end;
}

int all_tests() {
	mu_run_test(test_sdb_itoa_null_arg);
	mu_run_test(test_sdb_itoa);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
