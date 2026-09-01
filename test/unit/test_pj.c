// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util/rz_pj.h>
#include "minunit.h"

bool test_pj_reset() {
	PJ *j = pj_new();
	pj_o(j);
	pj_ks(j, "test", "object");
	pj_end(j);
	mu_assert_streq(pj_string(j), "{\"test\":\"object\"}", "before reset");
	pj_reset(j);
	mu_assert_streq(pj_string(j), "", "empty after reset");
	pj_a(j);
	pj_s(j, "test");
	pj_s(j, "array");
	pj_end(j);
	mu_assert_streq(pj_string(j), "[\"test\",\"array\"]", "reuse after reset");
	pj_free(j);
	mu_end;
}

bool test_depth_limit() {
	PJ *j = pj_new();
	for (int i = 0; i < RZ_PRINT_JSON_DEPTH_LIMIT + 1; i++) {
		pj_o(j);
	}
	mu_assert_null(pj_string(j), "pj_string should be null after exceeding depth limit");

	// writing after overflow is suppressed (level<0 path)
	pj_ks(j, "key", "val");
	mu_assert_null(pj_string(j), "pj_string still null after writing in overflow state");

	// pj_end is a nop after overflow (level<1 path)
	pj_end(j);
	mu_assert_null(pj_string(j), "pj_string still null after pj_end in overflow state");
	pj_free(j);

	mu_end;
}

bool test_pj_drain() {
	// pj_drain returns NULL and frees when level != 0 (overflow)
	PJ *j = pj_new();
	for (int i = 0; i < RZ_PRINT_JSON_DEPTH_LIMIT + 1; i++) {
		pj_o(j);
	}
	char *res = pj_drain(j); // j is consumed
	mu_assert_null(res, "pj_drain should return NULL on overflow");

	mu_assert_null(pj_drain(NULL), "pj_drain(NULL) should return NULL");

	// pj_drain suceed when level=0
	j = pj_new();
	pj_o(j);
	pj_ki(j, "a", 1);
	pj_end(j);
	res = pj_drain(j);
	mu_assert_notnull(res, "pj_drain should succeed on valid json");
	mu_assert_streq(res, "{\"a\":1}", "pj_drain result");
	free(res);

	mu_end;
}

int all_tests() {
	mu_run_test(test_pj_reset);
	mu_run_test(test_depth_limit);
	mu_run_test(test_pj_drain);
	return tests_passed != tests_run;
}

mu_main(all_tests)
