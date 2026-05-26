// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_vector.h>
#include "minunit.h"

static bool test_welford_arithmetic(void) {
	RzMathWelfordSums wf = { 0 };
	rz_math_welford_init(&wf, 0.0);
	rz_math_welford_push(&wf, 0.49671415);
	rz_math_welford_push(&wf, -0.1382643);
	rz_math_welford_push(&wf, 0.64768854);
	rz_math_welford_push(&wf, 1.52302986);
	rz_math_welford_push(&wf, -0.23415337);
	rz_math_welford_push(&wf, -0.23413696);
	rz_math_welford_push(&wf, 1.57921282);
	rz_math_welford_push(&wf, 0.76743473);
	rz_math_welford_push(&wf, -0.46947439);
	rz_math_welford_push(&wf, 0.54256004);
	rz_math_welford_push(&wf, -0.46341769);
	rz_math_welford_push(&wf, -0.46572975);
	rz_math_welford_push(&wf, 0.24196227);
	rz_math_welford_push(&wf, -1.91328024);
	rz_math_welford_push(&wf, -1.72491783);
	rz_math_welford_push(&wf, -0.56228753);
	rz_math_welford_push(&wf, -1.01283112);
	rz_math_welford_push(&wf, 0.31424733);
	rz_math_welford_push(&wf, -0.90802408);
	rz_math_welford_push(&wf, -1.4123037);

	mu_assert_eq(rz_math_welford_n(&wf), 20, "n");

	char val[16] = { 0 };
	rz_strf(val, "%.6f", rz_math_welford_avar(&wf));
	mu_assert_streq(val, "0.875572", "variance");

	rz_strf(val, "%.6f", rz_math_welford_astddev(&wf));
	mu_assert_streq(val, "0.935720", "std deviation");

	rz_strf(val, "%.6f", rz_math_welford_amean(&wf));
	mu_assert_streq(val, "-0.171299", "mean");

	rz_math_welford_clear(&wf);

	mu_end;
}

static bool test_welford_geometric(void) {
	RzMathWelfordSums wf = { 0 };
	rz_math_welford_init(&wf, 0.0);

	rz_math_welford_push(&wf, 131.5502965);
	rz_math_welford_push(&wf, 47.68105836);
	rz_math_welford_push(&wf, 56.85572523);
	rz_math_welford_push(&wf, 23.22318396);
	rz_math_welford_push(&wf, 39.38442231);
	rz_math_welford_push(&wf, 58.35549654);
	rz_math_welford_push(&wf, 27.36880479);
	rz_math_welford_push(&wf, 68.40314554);
	rz_math_welford_push(&wf, 38.0772422);
	rz_math_welford_push(&wf, 45.8320556);
	rz_math_welford_push(&wf, 38.05285189);
	rz_math_welford_push(&wf, 165.8969663);
	rz_math_welford_push(&wf, 54.15778147);
	rz_math_welford_push(&wf, 28.94430432);
	rz_math_welford_push(&wf, 89.43632748);
	rz_math_welford_push(&wf, 26.24548069);
	rz_math_welford_push(&wf, 61.88749606);
	rz_math_welford_push(&wf, 16.84742668);
	rz_math_welford_push(&wf, 24.60841286);
	rz_math_welford_push(&wf, 61.4434194);

	mu_assert_eq(rz_math_welford_n(&wf), 20, "n");

	char val[16] = { 0 };
	rz_strf(val, "%.6f", rz_math_welford_gmean(&wf));
	mu_assert_streq(val, "46.544783", "mean");

	rz_strf(val, "%.6f", rz_math_welford_gstddev(&wf));
	mu_assert_streq(val, "1.787509", "std deviation");

	rz_math_welford_clear(&wf);

	mu_end;
}

#define ITER 20000000

static bool test_welford_geometric_overflows(void) {
	RzMathWelfordSums wf = { 0 };
	rz_math_welford_init(&wf, 0.0);
	// Values don't matter. All we want is to ensure it doesn't overflow.
	for (size_t i = 0; i < ITER; i++) {
		// Sample random not negative double
		double v = rz_time_now_mono() + rz_num_rand64(0x20000);
		rz_math_welford_push(&wf, v);
	}
	char val[16] = { 0 };
	rz_strf(val, "%.f", rz_math_welford_gmean(&wf));
	mu_assert_false(RZ_STR_EQ(val, "0.0"), "Should not be 0.0");
	rz_strf(val, "%.f", rz_math_welford_gmean(&wf));
	mu_assert_false(RZ_STR_EQ(val, "-nan"), "Should not be -nan");
	rz_strf(val, "%.f", rz_math_welford_gmean(&wf));
	mu_assert_false(RZ_STR_EQ(val, "nan"), "Should not be nan");
	rz_strf(val, "%.f", rz_math_welford_gstddev(&wf));
	mu_assert_false(RZ_STR_EQ(val, "0.0"), "Should not be 0.0");
	rz_strf(val, "%.f", rz_math_welford_gstddev(&wf));
	mu_assert_false(RZ_STR_EQ(val, "-nan"), "Should not be -nan");
	rz_strf(val, "%.f", rz_math_welford_gstddev(&wf));
	mu_assert_false(RZ_STR_EQ(val, "nan"), "Should not be nan");
	rz_math_welford_clear(&wf);

	mu_end;
}

static int all_tests(void) {

	mu_run_test(test_welford_arithmetic);
	mu_run_test(test_welford_geometric);
	mu_run_test(test_welford_geometric_overflows);

	return tests_passed != tests_run;
}

mu_main(all_tests)
