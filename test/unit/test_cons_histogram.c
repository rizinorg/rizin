// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_histogram_horizontal(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = true;

	ut8 data[] = { 50, 200 };
	RzStrBuf *buf = rz_histogram_horizontal(&opts, data, 2, 2);

	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "255|") != NULL, "Ruler 255 present");
	mu_assert_true(strstr(res, "128|") != NULL, "Ruler 128 present");
	mu_assert_true(strstr(res, "_") != NULL, "Base line present");
	free(res);
	rz_cons_free();
	mu_end;
}

bool test_histogram_vertical(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;

	ut8 data[] = { 255, 0 };
	RzStrBuf *buf = rz_histogram_vertical(&opts, data, 2, 5);

	char *res = rz_strbuf_drain(buf);
	// Vertical histogram for 255 and 0 should have one full column and one empty
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "#") != NULL, "Blocks present for data 255");
	free(res);
	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_histogram_horizontal);
	mu_run_test(test_histogram_vertical);
	return tests_passed != tests_run;
}

mu_main(all_tests)
