// SPDX-FileCopyrightText: 2021 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_itv_overlap(void) {
	RzInterval a = { 0 }, b = { 0 };
	mu_assert_true(rz_itv_overlap(a, b), "at same address a and b overlap, both size = 0");
	mu_assert_true(rz_itv_overlap(b, a), "at same address b and a overlap, both size = 0");
	a.size = 1;
	mu_assert_true(rz_itv_overlap(a, b), "at same address a and b overlap, a size = 1");
	mu_assert_true(rz_itv_overlap(b, a), "at same address b and a overlap, a size = 1");
	b.size = 1;
	mu_assert_true(rz_itv_overlap(a, b), "at same address a and b overlap, both size = 1");
	mu_assert_true(rz_itv_overlap(b, a), "at same address b and a overlap, both size = 1");
	a.size = 2;
	mu_assert_true(rz_itv_overlap(a, b), "at same address a and b overlap, a size > b size");
	mu_assert_true(rz_itv_overlap(b, a), "at same address b and a overlap, a size > b size");
	a.size = 3;
	b.addr = 2;
	mu_assert_true(rz_itv_overlap(a, b), "a contains b, so they overlap");
	mu_assert_true(rz_itv_overlap(b, a), "b is contained by a, so they overlap");
	a.addr = 1;
	b.size = 4;
	mu_assert_true(rz_itv_overlap(a, b), "a is before b, the end of a overlaps the start of b");
	mu_assert_true(rz_itv_overlap(b, a), "b is after a, the start of b overlaps the end of a");
	b.addr = 4;
	mu_assert_false(rz_itv_overlap(a, b), "a ends where b starts, no overlap");
	mu_assert_false(rz_itv_overlap(b, a), "b starts where a ends, no overlap");
	b.addr = 10;
	mu_assert_false(rz_itv_overlap(a, b), "theres a gap between a and b, no overlap");
	mu_assert_false(rz_itv_overlap(b, a), "theres a gap between b and a, no overlap");
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_rz_itv_overlap);
	return tests_passed != tests_run;
}

mu_main(all_tests)
