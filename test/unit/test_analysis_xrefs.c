// SPDX-FileCopyrightText: 2020 xvilka
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "minunit.h"

bool test_rz_analysis_xrefs_count() {
	RzAnalysis *analysis = rz_analysis_new();

	mu_assert_eq(rz_analysis_xrefs_count(analysis), 0, "xrefs count");

	rz_analysis_xrefs_set(analysis, 0x1337, 42, RZ_ANALYSIS_REF_TYPE_NULL);
	rz_analysis_xrefs_set(analysis, 0x1337, 43, RZ_ANALYSIS_REF_TYPE_CODE);
	rz_analysis_xrefs_set(analysis, 1234, 43, RZ_ANALYSIS_REF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 12345, 43, RZ_ANALYSIS_REF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 4321, 4242, RZ_ANALYSIS_REF_TYPE_CALL);

	mu_assert_eq(rz_analysis_xrefs_count(analysis), 5, "xrefs count");

	rz_analysis_free(analysis);
	mu_end;
}

static bool dummy_count_cb(RzAnalysisXRef *xref, void *user) {
	(*(size_t *)user)++;
	return true;
}

bool test_rz_analysis_xrefs_foreach() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_analysis_xrefs_set(analysis, 1234, UT64_MAX, RZ_ANALYSIS_REF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, 12345, UT64_MAX, RZ_ANALYSIS_REF_TYPE_CODE);
	rz_analysis_xrefs_set(analysis, 4321, UT64_MAX, RZ_ANALYSIS_REF_TYPE_CALL);

	rz_analysis_xrefs_set(analysis, UT64_MAX, 1337, RZ_ANALYSIS_REF_TYPE_CALL);
	rz_analysis_xrefs_set(analysis, UT64_MAX, 101, RZ_ANALYSIS_REF_TYPE_NULL);

	size_t cnt = 0;
	rz_analysis_xrefs_foreach(analysis, dummy_count_cb, &cnt);
	mu_assert_eq(cnt, 5, "xrefs count");

	RzList *xrefs = rz_analysis_xrefs_get_to(analysis, UT64_MAX);
	mu_assert_eq(rz_list_length(xrefs), 3, "xrefs to count");
	rz_list_free(xrefs);

	xrefs = rz_analysis_xrefs_get_from(analysis, UT64_MAX);
	mu_assert_eq(rz_list_length(xrefs), 2, "xrefs from count");
	rz_list_free(xrefs);

	rz_analysis_free(analysis);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_xrefs_count);
	mu_run_test(test_rz_analysis_xrefs_foreach);
	return tests_passed != tests_run;
}

mu_main(all_tests)