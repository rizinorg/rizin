// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util/rz_pj.h>
#include <rz_util/rz_float.h>
#include <float.h>
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

static const char *float_json(PJ *j, double d, bool single) {
	pj_reset(j);
	if (single) {
		pj_f(j, (float)d);
	} else {
		pj_d(j, d);
	}
	return pj_string(j);
}

bool test_pj_d() {
	// Not static: F64_NAN and F64_PINF are function calls
	const struct {
		double d;
		const char *json;
	} cases[] = {
		{ 1e-9, "1.0e-09" },
		{ 1.2345678901234567, "1.2345678901234567" },
		{ 1e100, "1.0e+100" },
		{ 0.1, "0.1" },
		{ 1.0, "1.0" },
		{ -0.0, "-0.0" },
		{ DBL_MAX, "1.7976931348623157e+308" },
		{ 4.9406564584124654e-324, "4.94065645841247e-324" },
		{ F64_NAN, "\"NaN\"" },
		{ -F64_NAN, "\"NaN\"" },
		{ F64_PINF, "\"Infinity\"" },
		{ F64_NINF, "\"-Infinity\"" },
	};
	PJ *j = pj_new();
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		mu_assert_streq(float_json(j, cases[i].d, false), cases[i].json, "pj_d");
	}
	pj_reset(j);
	pj_a(j);
	pj_d(j, 0.5);
	pj_d(j, F64_NAN);
	pj_o(j);
	pj_kd(j, "inf", F64_PINF);
	pj_kf(j, "f", 2.0f);
	pj_end(j);
	pj_end(j);
	mu_assert_streq(pj_string(j), "[0.5,\"NaN\",{\"inf\":\"Infinity\",\"f\":2.0}]", "separators around floats");
	pj_free(j);
	mu_end;
}

bool test_pj_f() {
	const struct {
		float f;
		const char *json;
	} cases[] = {
		{ 0.1f, "0.1" },
		{ 1e-9f, "1.0e-09" },
		{ 16777216.0f, "16777216.0" },
		{ FLT_MAX, "3.4028235e+38" },
		{ F32_NAN, "\"NaN\"" },
		{ F32_PINF, "\"Infinity\"" },
		{ F32_NINF, "\"-Infinity\"" },
	};
	PJ *j = pj_new();
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		mu_assert_streq(float_json(j, cases[i].f, true), cases[i].json, "pj_f");
	}
	pj_free(j);
	mu_end;
}

int all_tests() {
	mu_run_test(test_pj_reset);
	mu_run_test(test_depth_limit);
	mu_run_test(test_pj_drain);
	mu_run_test(test_pj_d);
	mu_run_test(test_pj_f);
	return tests_passed != tests_run;
}

mu_main(all_tests)
