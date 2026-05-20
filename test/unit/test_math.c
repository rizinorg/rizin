// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_vector.h>
#include "minunit.h"

static bool test_welford(void) {
	RzMathWelfordSums wf = { 0 };
	rz_math_welford_init(&wf);
	rz_math_welford_push(&wf, 10.0);
	rz_math_welford_push(&wf, 17.0);
	rz_math_welford_push(&wf, 37.0);
	rz_math_welford_push(&wf, 45.0);
	rz_math_welford_push(&wf, 76.0);
	rz_math_welford_push(&wf, 98.0);
	rz_math_welford_push(&wf, 99.0);
	rz_math_welford_push(&wf, 100.0);

	mu_assert_eq(rz_math_welford_n(&wf), 8, "n");
	char val[16] = { 0 };
	rz_strf(val, "%.4f", rz_math_welford_variance(&wf));
	mu_assert_streq(val, "1417.6429", "variance");

	rz_strf(val, "%.4f", rz_math_welford_std_deviation(&wf));
	mu_assert_streq(val, "37.6516", "std deviation");

	rz_strf(val, "%.4f", rz_math_welford_mean(&wf));
	mu_assert_streq(val, "60.2500", "mean");

	rz_strf(val, "%.4f", rz_math_welford_sum_of_squares(&wf));
	mu_assert_streq(val, "9923.5000", "sum of squares");

	rz_math_welford_clear(&wf);

	mu_end;
}

static int all_tests(void) {

	mu_run_test(test_welford);

	return tests_passed != tests_run;
}

mu_main(all_tests)
