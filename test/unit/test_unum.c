// SPDX-FileCopyrightText: 2017 kriw <kotarou777775@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static RzNum *num;

bool test_rz_num_units() {
	char humansz[8];
	const struct {
		const char *expected_res;
		const char *message;
		ut64 num;
	} test_cases[] = {
		{ "0", "B", 0ULL },
		{ "512", "B", 512ULL },
		{ "1K", "K", 1ULL << 10 },
		{ "1M", "M", 1ULL << 20 },
		{ "1G", "G", 1ULL << 30 },
		{ "1T", "T", 1ULL << 40 },
		{ "1P", "P", 1ULL << 50 },
		{ "1E", "E", 1ULL << 60 },
		/* Decimal test */
		{ "1.0K", "K", 1025 },
		{ "994K", "K", 994 * (1ULL << 10) },
		{ "999K", "K", 999 * (1ULL << 10) },
		{ "1.0M", "M", 1025 * (1ULL << 10) },
		{ "1.5M", "M", 1536 * (1ULL << 10) },
		{ "1.9M", "M", 1996 * (1ULL << 10) },
		{ "2.0M", "M", 1997 * (1ULL << 10) },
		{ "2.0M", "M", 2047 * (1ULL << 10) },
		{ "2M", "M", 2048 * (1ULL << 10) },
		{ "2.0M", "M", 2099 * (1ULL << 10) },
		{ "2.1M", "M", 2100 * (1ULL << 10) },
		{ "9.9G", "G", 10188 * (1ULL << 20) },
		/* Biggest units */
		{ "82P", "P", 82 * (1ULL << 50) },
		{ "16E", "E", UT64_MAX }
	};
	size_t nitems = sizeof(test_cases) / sizeof(test_cases[0]);
	size_t i;
	for (i = 0; i < nitems; i++) {
		rz_num_units(humansz, sizeof(humansz), test_cases[i].num);
		mu_assert_streq(humansz, test_cases[i].expected_res, test_cases[i].message);
	}
	mu_end;
}

bool test_rz_num_minmax_swap_i() {
	int a = -1, b = 2;
	rz_num_minmax_swap_i(&a, &b);
	mu_assert_eq(a == -1 && b == 2, 1, "a < b -> a < b");
	a = 2, b = -1;
	rz_num_minmax_swap_i(&a, &b);
	mu_assert_eq(a == -1 && b == 2, 1, "b < a -> a < b");
	mu_end;
}

bool test_rz_num_minmax_swap() {
	ut64 a = 1, b = 2;
	rz_num_minmax_swap(&a, &b);
	mu_assert_eq(a == 1 && b == 2, 1, "a < b -> a < b");
	a = 2, b = 1;
	rz_num_minmax_swap(&a, &b);
	mu_assert_eq(a == 1 && b == 2, 1, "b < a -> a < b");
	mu_end;
}

bool test_rz_num_between() {
	mu_assert_eq(rz_num_between(num, "1 2 3"), 1, "1 <= 2 <= 3");
	mu_assert_eq(rz_num_between(num, "3 2 1"), 0, "3 <= 2 <= 1");
	mu_assert_eq(rz_num_between(num, "1 1 1"), 1, "1 <= 1 <= 1");
	mu_assert_eq(rz_num_between(num, "2 1 3"), 0, "2 <= 1 <= 3");
	mu_assert_eq(rz_num_between(num, "1 2 1+2"), 1, "1 <= 2 <= 1+2");
	mu_assert_eq(rz_num_between(num, "2 3 1+2+3"), 1, "2 <= 3 <= 1+2+3");
	mu_assert_eq(rz_num_between(num, "1+2 2 1+1"), 0, "1+2 <= 2 <= 1+1");
	mu_assert_eq(rz_num_between(num, "1 + 2 2 1 + 1"), 0, "1 + 2 <= 2 <= 1 + 1");
	mu_end;
}

bool test_rz_num_str_len() {
	mu_assert_eq(rz_num_str_len("1"), 1, "\"1\"");
	mu_assert_eq(rz_num_str_len("1+1"), 3, "\"1+1\"");
	mu_assert_eq(rz_num_str_len("1 + 1"), 5, "\"1 + 1\"");
	mu_assert_eq(rz_num_str_len("1 + 1 "), 5, "\"1 + 1 \"");
	mu_assert_eq(rz_num_str_len("1 + 1  "), 5, "\"1 + 1  \"");
	mu_assert_eq(rz_num_str_len("1 + 1 1"), 5, "\"1 + 1 1\"");
	mu_assert_eq(rz_num_str_len("1 + 1 1 + 1"), 5, "\"1 + 1 1 + 1\"");
	mu_assert_eq(rz_num_str_len("1 + (1 + 1) 1"), 11, "\"1 + (1 + 1) 1\"");
	mu_assert_eq(rz_num_str_len("1 + (1 + (1 + 1)) 1"), 17, "\"1 + (1 + (1 + 1)) 1\"");
	mu_assert_eq(rz_num_str_len("1+(1+(1+1)) 1"), 11, "\"1+(1+(1+1)) 1\"");
	mu_assert_eq(rz_num_str_len("(1 + 1) + (1 + 1) 1"), 17, "\"(1 + 1) + (1 + 1) 1\"");
	mu_assert_eq(rz_num_str_len("(1+1)+(1+1) 1"), 11, "\"(1+1)+(1+1) 1\"");
	mu_end;
}

bool test_rz_num_str_split() {
	char *str = malloc(0x20);
	strcpy(str, "1 1 + 2 1 + (2 + 3) 4 ");
	// expected "1\01 + 2\01 + (2 + 3)\04\0"
	int count = rz_num_str_split(str);
	mu_assert_eq(count, 4, "rz_num_str_split (str) == 4");
	mu_assert_streq(str + 0, "1", "1");
	mu_assert_streq(str + 2, "1 + 2", "1 + 2");
	mu_assert_streq(str + 8, "1 + (2 + 3)", "1 + (2 + 3)");
	mu_assert_streq(str + 20, "4", "4");
	free(str);
	mu_end;
}

bool test_rz_num_str_split_list() {
	char *s;
	char *str = malloc(0x20);
	strcpy(str, "1 1 + 2 1 + (2 + 3) 4 ");
	// expected {"1", "1 + 2", "1 + (2 + 3)", "4"} as list
	RzList *list = rz_num_str_split_list(str);
	mu_assert_eq(rz_list_length(list), 4, "rz_list_length (list) == 4");
	s = (char *)rz_list_pop_head(list);
	mu_assert_streq(s, "1", "1");
	s = (char *)rz_list_pop_head(list);
	mu_assert_streq(s, "1 + 2", "1 + 2");
	s = (char *)rz_list_pop_head(list);
	mu_assert_streq(s, "1 + (2 + 3)", "1 + (2 + 3)");
	s = (char *)rz_list_pop_head(list);
	mu_assert_streq(s, "4", "4");
	free(str);
	rz_list_free(list);
	mu_end;
}

bool test_rz_num_align_delta() {
	ut64 d = rz_num_align_delta(0, 8);
	mu_assert_eq(d, 0, "align delta");
	d = rz_num_align_delta(3, 8);
	mu_assert_eq(d, 5, "align delta");
	d = rz_num_align_delta(0x10, 8);
	mu_assert_eq(d, 0, "align delta");
	d = rz_num_align_delta(0x11, 8);
	mu_assert_eq(d, 7, "align delta");
	d = rz_num_align_delta(0x42, 0);
	mu_assert_eq(d, 0, "align delta");
	mu_end;
}

bool test_rz_num_bitmask() {
	static const ut64 expect_masks[] = {
		0x0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff,
		0xfff, 0x1fff, 0x3fff, 0x7fff, 0xffff, 0x1ffff, 0x3ffff, 0x7ffff,
		0xfffff, 0x1fffff, 0x3fffff, 0x7fffff, 0xffffff, 0x1ffffffLL, 0x3ffffffLL,
		0x7ffffffLL, 0xfffffffLL, 0x1fffffffLL, 0x3fffffffLL, 0x7fffffffLL, 0xffffffffLL,
		0x1ffffffffLL, 0x3ffffffffLL, 0x7ffffffffLL, 0xfffffffffLL, 0x1fffffffffLL,
		0x3fffffffffLL, 0x7fffffffffLL, 0xffffffffffLL, 0x1ffffffffffLL, 0x3ffffffffffLL,
		0x7ffffffffffLL, 0xfffffffffffLL, 0x1fffffffffffLL, 0x3fffffffffffLL, 0x7fffffffffffLL,
		0xffffffffffffLL, 0x1ffffffffffffLL, 0x3ffffffffffffLL, 0x7ffffffffffffLL,
		0xfffffffffffffLL, 0x1fffffffffffffLL, 0x3fffffffffffffLL, 0x7fffffffffffffLL,
		0xffffffffffffffLL, 0x1ffffffffffffffLL, 0x3ffffffffffffffLL, 0x7ffffffffffffffLL,
		0xfffffffffffffffLL, 0x1fffffffffffffffLL, 0x3fffffffffffffffLL, 0x7fffffffffffffffLL, 0xffffffffffffffffLL
	};

	for (ut16 width = 0; width < 256; width++) {
		ut64 actual = rz_num_bitmask((ut8)width);
		ut64 expect = expect_masks[RZ_MIN(width, 64)];
		char msg[0x100];
		snprintf(msg, sizeof(msg), "bitmask of %u bits\n", (unsigned int)width);
		mu_assert_eq(actual, expect, msg);
	}

	mu_end;
}

bool test_rz_num_abs() {
	mu_assert_eq(rz_num_abs(ST64_MAX), ST64_MAX, "rz_num_abs(2^63 - 1) = 2^63 - 1");
	mu_assert_eq(rz_num_abs(0), 0, "rz_num_abs(0) = 0");
	mu_assert_eq(rz_num_abs(ST64_MIN), UT64_GT0, "rz_num_abs(-2^63) = 2^63");
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_num_units);
	mu_run_test(test_rz_num_minmax_swap_i);
	mu_run_test(test_rz_num_minmax_swap);
	mu_run_test(test_rz_num_between);
	mu_run_test(test_rz_num_str_len);
	mu_run_test(test_rz_num_str_split);
	mu_run_test(test_rz_num_str_split_list);
	mu_run_test(test_rz_num_align_delta);
	mu_run_test(test_rz_num_bitmask);
	mu_run_test(test_rz_num_abs);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	num = rz_num_new(NULL, NULL, NULL);
	return all_tests();
}
