// SPDX-FileCopyrightText: 2021 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include "rz_util/rz_itv.h"

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

bool test_rz_itv_overlap_bounded(void) {
	RzIntervalBoundedUt64 right_open = { .a = 1, .b = 4, .bound = RZ_INTERVAL_BOUND_RIGHT_OPEN };
	RzIntervalBoundedUt64 left_open = { .a = 1, .b = 4, .bound = RZ_INTERVAL_BOUND_LEFT_OPEN };
	RzIntervalBoundedUt64 open = { .a = 1, .b = 4, .bound = RZ_INTERVAL_BOUND_OPEN };
	RzIntervalBoundedUt64 closed = { .a = 1, .b = 4, .bound = RZ_INTERVAL_BOUND_CLOSED };

	mu_assert_eq(rz_itv_bound_contains_ut64(&right_open, 0), RZ_INTERVAL_OUT, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&right_open, 1), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&right_open, 2), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&right_open, 3), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&right_open, 4), RZ_INTERVAL_OUT, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&right_open, 5), RZ_INTERVAL_OUT, "Affiliation mismatch");

	mu_assert_eq(rz_itv_bound_contains_ut64(&left_open, 0), RZ_INTERVAL_OUT, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&left_open, 1), RZ_INTERVAL_OUT, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&left_open, 2), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&left_open, 3), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&left_open, 4), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&left_open, 5), RZ_INTERVAL_OUT, "Affiliation mismatch");

	mu_assert_eq(rz_itv_bound_contains_ut64(&open, 0), RZ_INTERVAL_OUT, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&open, 1), RZ_INTERVAL_OUT, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&open, 2), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&open, 3), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&open, 4), RZ_INTERVAL_OUT, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&open, 5), RZ_INTERVAL_OUT, "Affiliation mismatch");

	mu_assert_eq(rz_itv_bound_contains_ut64(&closed, 0), RZ_INTERVAL_OUT, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&closed, 1), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&closed, 2), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&closed, 3), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&closed, 4), RZ_INTERVAL_IN, "Affiliation mismatch");
	mu_assert_eq(rz_itv_bound_contains_ut64(&closed, 5), RZ_INTERVAL_OUT, "Affiliation mismatch");
	mu_end;
}

bool test_rz_itv_str_to_bounded(void) {
	RzIntervalBoundedUt64 itv = { 0 };
	itv.a = UT64_MAX;
	itv.b = UT64_MAX;
	itv.bound = RZ_INTERVAL_BOUND_UNDEF;

	mu_assert_false(rz_itv_str_to_bounded_itv_ut64("", &itv), "Parsing should have failed");
	mu_assert_eq(itv.a, UT64_MAX, "Invalid value was not set.");
	mu_assert_eq(itv.b, UT64_MAX, "Invalid value was not set.");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_UNDEF, "Invalid value was not set.");

	mu_assert_false(rz_itv_str_to_bounded_itv_ut64("{0x111,1]", &itv), "Parsing should have failed");
	mu_assert_eq(itv.a, UT64_MAX, "Invalid value was not set.");
	mu_assert_eq(itv.b, UT64_MAX, "Invalid value was not set.");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_UNDEF, "Invalid value was not set.");

	// a must be smaller than b.
	mu_assert_false(rz_itv_str_to_bounded_itv_ut64("[0x111,1]", &itv), "Parsing should have failed");
	mu_assert_eq(itv.a, UT64_MAX, "Invalid value was not set.");
	mu_assert_eq(itv.b, UT64_MAX, "Invalid value was not set.");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_UNDEF, "Invalid value was not set.");

	mu_assert_true(rz_itv_str_to_bounded_itv_ut64("1", &itv), "parsing failed");
	mu_assert_eq(itv.a, 1, "Left limit was not set");
	mu_assert_eq(itv.b, 1, "Right limit was not set");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_CLOSED, "Bound was not set.");

	mu_assert_true(rz_itv_str_to_bounded_itv_ut64("0", &itv), "parsing failed");
	mu_assert_eq(itv.a, 0, "Left limit was not set");
	mu_assert_eq(itv.b, 0, "Right limit was not set");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_CLOSED, "Bound was not set.");

	// The empty interval is valid.
	mu_assert_true(rz_itv_str_to_bounded_itv_ut64("(1,1)", &itv), "parsing failed");
	mu_assert_eq(itv.a, 1, "Left limit was not set");
	mu_assert_eq(itv.b, 1, "Right limit was not set");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_OPEN, "Bound was not set.");

	mu_assert_true(rz_itv_str_to_bounded_itv_ut64("[0,1]", &itv), "Parsing failed");
	mu_assert_eq(itv.a, 0, "Left limit was not set");
	mu_assert_eq(itv.b, 1, "Right limit was not set.");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_CLOSED, "Bound was not set.");

	mu_assert_true(rz_itv_str_to_bounded_itv_ut64("[0,0xffFfffFfff)", &itv), "Parsing failed");
	mu_assert_eq(itv.a, 0, "Left limit was not set");
	mu_assert_eq(itv.b, 0xffffffffff, "Right limit was not set.");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_RIGHT_OPEN, "Bound was not set.");

	mu_assert_true(rz_itv_str_to_bounded_itv_ut64("[0,0xA)", &itv), "Parsing failed");
	mu_assert_eq(itv.a, 0, "Left limit was not set");
	mu_assert_eq(itv.b, 10, "Right limit was not set.");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_RIGHT_OPEN, "Bound was not set.");

	mu_assert_true(rz_itv_str_to_bounded_itv_ut64("(2,10]", &itv), "Parsing failed");
	mu_assert_eq(itv.a, 2, "Left limit was not set");
	mu_assert_eq(itv.b, 10, "Right limit was not set.");
	mu_assert_eq(itv.bound, RZ_INTERVAL_BOUND_LEFT_OPEN, "Bound was not set.");

	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_rz_itv_overlap);
	mu_run_test(test_rz_itv_overlap_bounded);
	mu_run_test(test_rz_itv_str_to_bounded);
	return tests_passed != tests_run;
}

mu_main(all_tests)
