// SPDX-FileCopyrightText: 2021 Siddharth Mishra <misra.cxx@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_project.h>

#include "../unit/minunit.h"

bool test_auto_analysis() {
	// new core
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");

    // load test file
	ut64 loadaddr = 0;
	const char *fpath = "bins/elf/ls";
	rz_core_bin_load(core, fpath, loadaddr);

	// aa
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_SIMPLE);
	RzList *simple_fcn_list = rz_analysis_function_list(core->analysis);
    mu_assert_notnull(simple_fcn_list, "simple function list");
    ut32 simple_fcn_list_length = rz_list_length(simple_fcn_list);
	eprintf("functions count = %d\n", simple_fcn_list_length);

    // aaa
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_DEEP);
	RzList *deep_fcn_list = rz_analysis_function_list(core->analysis);
    mu_assert_notnull(deep_fcn_list, "simple function list");
    ut32 deep_fcn_list_length = rz_list_length(deep_fcn_list);
	eprintf("functions count = %d\n", deep_fcn_list_length);

    // more function should be detected in deep analysis
    // not true for all binaries but for most it must be true
    mu_assert("deep analysis success", deep_fcn_list_length >= simple_fcn_list_length);

    // aaa
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
	RzList *experimental_fcn_list = rz_analysis_function_list(core->analysis);
    mu_assert_notnull(experimental_fcn_list, "simple function list");
    ut32 experimental_fcn_list_length = rz_list_length(experimental_fcn_list);
	eprintf("functions count = %d\n", experimental_fcn_list_length);

    // again more in experimental
    mu_assert("deep analysis success", experimental_fcn_list_length >= deep_fcn_list_length);

    // free core and end test
	rz_core_free(core);
    mu_end;
}

int all_tests() {
	mu_run_test(test_auto_analysis);
	return tests_passed != tests_run;
}

mu_main(all_tests)
