// SPDX-FileCopyrightText: 2026 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_interrupt.h>
#include "minunit.h"

static void dummy_callback(void *user) {
	int *count = (int *)user;
	if (count) {
		(*count)++;
	}
}

static void dummy_callback_2(void *user) {
	int *count = (int *)user;
	if (count) {
		*count += 10;
	}
}

bool test_rz_interrupt_new_free(void) {
	RzInterrupt *intr = rz_interrupt_new();
	mu_assert_notnull(intr, "rz_interrupt_new failed");
	rz_interrupt_free(intr);
	rz_interrupt_free(NULL);
	mu_end;
}

bool test_rz_interrupt_raise_and_callbacks(void) {
	RzInterrupt *intr = rz_interrupt_new();
	mu_assert_notnull(intr, "rz_interrupt_new failed");

	int counter = 0;
	rz_interrupt_break_push(intr, dummy_callback, &counter);
	mu_assert_false(rz_interrupt_is_breaked(intr), "should not be breaked initially");

	rz_interrupt_raise(intr);
	mu_assert_true(rz_interrupt_is_breaked(intr), "should be breaked after raise");
	mu_assert_eq(counter, 1, "callback should have executed once");

	rz_interrupt_free(intr);
	mu_end;
}

bool test_rz_interrupt_push_pop(void) {
	RzInterrupt *intr = rz_interrupt_new();
	mu_assert_notnull(intr, "rz_interrupt_new failed");

	int count1 = 0;
	int count2 = 0;

	rz_interrupt_break_push(intr, dummy_callback, &count1);
	rz_interrupt_break_push(intr, dummy_callback_2, &count2);

	rz_interrupt_raise(intr);
	mu_assert_eq(count1, 0, "first callback should not run");
	mu_assert_eq(count2, 10, "second callback should run");

	rz_interrupt_break_pop(intr);

	rz_interrupt_raise(intr);
	mu_assert_eq(count1, 1, "first callback should now run");
	mu_assert_eq(count2, 10, "second callback should not run again");

	rz_interrupt_break_pop(intr);
	rz_interrupt_free(intr);
	mu_end;
}

bool test_rz_interrupt_break_clear_and_end(void) {
	RzInterrupt *intr = rz_interrupt_new();
	mu_assert_notnull(intr, "rz_interrupt_new failed");

	rz_interrupt_raise(intr);
	mu_assert_true(rz_interrupt_is_breaked(intr), "should be breaked");

	rz_interrupt_break_clear(intr);
	mu_assert_false(rz_interrupt_is_breaked(intr), "should not be breaked after clear");

	int counter = 0;
	rz_interrupt_break_push(intr, dummy_callback, &counter);
	rz_interrupt_raise(intr);
	mu_assert_true(rz_interrupt_is_breaked(intr), "should be breaked");

	rz_interrupt_break_end(intr);
	mu_assert_false(rz_interrupt_is_breaked(intr), "should not be breaked after end");

	rz_interrupt_free(intr);
	mu_end;
}

bool test_rz_interrupt_timeout(void) {
	RzInterrupt *intr = rz_interrupt_new();
	mu_assert_notnull(intr, "rz_interrupt_new failed");

	rz_interrupt_timeout(intr, 0);
	mu_assert_false(rz_interrupt_is_breaked(intr), "timeout 0 should not break immediately");

	rz_interrupt_break_timeout(intr, 0);
	mu_assert_false(rz_interrupt_is_breaked(intr), "break_timeout 0 should not break");

	rz_interrupt_free(intr);
	mu_end;
}

bool test_rz_interrupt_null_inputs(void) {
	rz_interrupt_free(NULL);
	rz_interrupt_raise(NULL);
	rz_interrupt_break_push(NULL, NULL, NULL);
	rz_interrupt_break_pop(NULL);
	rz_interrupt_timeout(NULL, 10);
	rz_interrupt_break_end(NULL);
	rz_interrupt_break_timeout(NULL, 10);
	mu_assert_false(rz_interrupt_is_breaked(NULL), "null intr is not breaked");
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_rz_interrupt_new_free);
	mu_run_test(test_rz_interrupt_raise_and_callbacks);
	mu_run_test(test_rz_interrupt_push_pop);
	mu_run_test(test_rz_interrupt_break_clear_and_end);
	mu_run_test(test_rz_interrupt_timeout);
	mu_run_test(test_rz_interrupt_null_inputs);
	return tests_passed != tests_run;
}

mu_main(all_tests);
