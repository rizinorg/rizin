// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_project.h>

#include "minunit.h"

bool test_v1_noreturn() {
	RzCore *core = rz_core_new();
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	mu_assert_notnull(res, "result info new");
	RzProjectErr err = rz_project_load_file(core, "prj/v1-noreturn.rzdb", true, res);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err");
	mu_assert_eq(rz_list_length(res), 1, "info");
	mu_assert_streq(rz_list_get_n(res, 0), "project migrated from version 1 to 2.", "info");

	mu_assert_true(rz_analysis_noreturn_at_addr(core->analysis, 0x4242), "noreturn");
	mu_assert_true(rz_analysis_noreturn_at_addr(core->analysis, 0x1337), "noreturn");
	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x12345), "nono");

	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, 0x4242);
	mu_assert_notnull(fcn, "has the function");
	mu_assert_true(!fcn->is_noreturn, "deleted from analysis/types db");

	rz_serialize_result_info_free(res);

	rz_core_free(core);
	mu_end;
}

bool test_v1_noreturn_empty() {
	RzCore *core = rz_core_new();
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	mu_assert_notnull(res, "result info new");
	RzProjectErr err = rz_project_load_file(core, "prj/v1-noreturn-empty.rzdb", true, res);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err");
	mu_assert_eq(rz_list_length(res), 1, "info");
	mu_assert_streq(rz_list_get_n(res, 0), "project migrated from version 1 to 2.", "info");

	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x4242), "nono");
	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x1337), "nono");
	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x12345), "nono");

	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, 0x4242);
	mu_assert_notnull(fcn, "has the function");
	mu_assert_true(!fcn->is_noreturn, "nono in analysis function db");

	rz_serialize_result_info_free(res);

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_v1_noreturn);
	mu_run_test(test_v1_noreturn_empty);
	return tests_passed != tests_run;
}

mu_main(all_tests)
