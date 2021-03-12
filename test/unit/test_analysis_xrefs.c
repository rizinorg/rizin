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

int all_tests() {
	mu_run_test(test_rz_analysis_xrefs_count);
	return tests_passed != tests_run;
}

mu_main(all_tests)