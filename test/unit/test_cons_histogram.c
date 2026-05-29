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
	mu_assert_true(strstr(res, "200 |") != NULL, "Ruler 200 present");
	free(res);
	rz_cons_free();
	mu_end;
}

bool test_histogram_entropy(void) {
	rz_cons_new();
	RzHistogramOptions opts = { 0 };
	opts.color = false;
	opts.unicode = false;
	opts.ruler = true;

	double entropy_data[] = { 3.14 };
	RzStrBuf *buf = rz_histogram_horizontal_f64(&opts, entropy_data, 1, 2);
	char *res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "3.14 |") != NULL, "Ruler entropy present");
	mu_assert_true(strstr(res, "0.00 |") != NULL, "Baseline present");
	free(res);

	double entropy_fract_data[] = { 0.39 };
	buf = rz_histogram_horizontal_f64(&opts, entropy_fract_data, 1, 2);
	res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "0.39 |") != NULL, "Ruler entropy_fract present");
	mu_assert_true(strstr(res, "0.00 |") != NULL, "Baseline present");
	free(res);

	double temperature_data[] = { 0.18 };
	buf = rz_histogram_horizontal_f64(&opts, temperature_data, 1, 2);
	res = rz_strbuf_drain(buf);
	mu_assert_notnull(res, "Histogram buffer should not be null");
	mu_assert_true(strstr(res, "0.18 |") != NULL, "Ruler temperature present");
	mu_assert_true(strstr(res, "0.00 |") != NULL, "Baseline present");
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
	mu_run_test(test_histogram_entropy);
	mu_run_test(test_histogram_vertical);
	return tests_passed != tests_run;
}

mu_main(all_tests)
