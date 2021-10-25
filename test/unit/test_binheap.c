// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

int basic_cmp(const void *a, const void *b) {
	size_t sa = (size_t)a;
	size_t sb = (size_t)b;
	return sa >= sb ? sa - sb : -1;
}

bool test_basic(void) {
	RzBinHeap *bh = rz_binheap_new(basic_cmp);
	mu_assert_notnull(bh, "binheap is created");
	mu_assert_true(rz_binheap_empty(bh), "binheap is empty");
	rz_binheap_push(bh, (void *)(size_t)10);
	mu_assert_false(rz_binheap_empty(bh), "binheap is not empty anymore");
	rz_binheap_clear(bh);
	mu_assert_true(rz_binheap_empty(bh), "binheap is empty again after clear");
	rz_binheap_free(bh);
	mu_end;
}

bool test_pushpop(void) {
	RzBinHeap *bh = rz_binheap_new(basic_cmp);
	rz_binheap_push(bh, (void *)(size_t)10);
	mu_assert_eq((size_t)rz_binheap_top(bh), (size_t)10, "10 is the top");
	mu_assert_eq((size_t)rz_binheap_pop(bh), (size_t)10, "10 is popped");
	mu_assert_true(rz_binheap_empty(bh), "the only element has been popped out");
	rz_binheap_push(bh, (void *)(size_t)10);
	rz_binheap_push(bh, (void *)(size_t)2);
	rz_binheap_push(bh, (void *)(size_t)5);
	rz_binheap_push(bh, (void *)(size_t)4);
	rz_binheap_push(bh, (void *)(size_t)11);
	mu_assert_eq((size_t)rz_binheap_top(bh), (size_t)2, "2 is the top");
	mu_assert_eq((size_t)rz_binheap_pop(bh), (size_t)2, "2 is popped");
	mu_assert_eq((size_t)rz_binheap_pop(bh), (size_t)4, "4 is popped");
	mu_assert_eq((size_t)rz_binheap_pop(bh), (size_t)5, "5 is popped");
	mu_assert_eq((size_t)rz_binheap_pop(bh), (size_t)10, "10 is popped");
	mu_assert_eq((size_t)rz_binheap_pop(bh), (size_t)11, "11 is popped");
	rz_binheap_free(bh);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_basic);
	mu_run_test(test_pushpop);
	return tests_passed != tests_run;
}

mu_main(all_tests)