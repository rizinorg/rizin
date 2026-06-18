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
	pj_free(j);
	mu_end;
}

int all_tests() {
	mu_run_test(test_pj_reset);
	mu_run_test(test_depth_limit);
	return tests_passed != tests_run;
}

mu_main(all_tests)
