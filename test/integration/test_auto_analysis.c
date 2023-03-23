// SPDX-FileCopyrightText: 2023 Siddharth Mishra <misra.cxx@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_project.h>

#include "../unit/minunit.h"

bool test_detected_functions_list_size(const char* fpath) {
	// new core
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");

	// load test file
	ut64 loadaddr = 0;
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

	// aaaa
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

// new functions can be found at analysis levels DEEP(aaa) and EXPERIMENTAL(aaaa)
bool test_new_functions_detected_at_level(RzCoreAnalysisType analysis_type, const char* fpath, const char* fcn_name) {
	// new core
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");

	// load test file
	ut64 loadaddr = 0;
	rz_core_bin_load(core, fpath, loadaddr);

	// perform analysis and get function list
	rz_core_perform_auto_analysis(core, analysis_type);
	RzList *fcn_list = rz_analysis_function_list(core->analysis);
	ut32 fcn_list_len = rz_list_length(fcn_list);
	mu_assert_notnull(fcn_list, "function list retrieved");

	// find requested function
	bool found = false;
	for(ut32 i = 0; i < fcn_list_len; ++i) {
		RzAnalysisFunction *fcn = (RzAnalysisFunction*)rz_list_pop_head(fcn_list);
		if(!strcmp(fcn->name, fcn_name)) {
			found = true;
			break;
		}
	}
	mu_assert_true(found, "new detected function found");

	// free core and end test
	rz_core_free(core);
	mu_end;
}

struct test_bin_fcn_level {
	const char* fpath;
	const char* fcn_name;
	RzCoreAnalysisType analysis_type;
};

struct test_bin_fcn_level bin_fcn_list[] = {
	{"bins/arm/elf/hello-world", "fcn.00000522", RZ_CORE_ANALYSIS_EXPERIMENTAL},

	{"bins/arm/elf/hello-world-buildroot-201402", "fcn.00008300", RZ_CORE_ANALYSIS_DEEP},
	{"bins/arm/elf/hello-world-buildroot-201402", "fcn.00008274", RZ_CORE_ANALYSIS_DEEP},
	{"bins/arm/elf/hello-world-buildroot-201402", "fcn.00008200", RZ_CORE_ANALYSIS_DEEP},

	{"bins/arm/elf/hello-world-linaro-201201", "fcn.00008334", RZ_CORE_ANALYSIS_DEEP},
	{"bins/arm/elf/hello-world-linaro-201201", "fcn.00008298", RZ_CORE_ANALYSIS_DEEP},
	{"bins/arm/elf/hello-world-linaro-201201", "fcn.000082a4", RZ_CORE_ANALYSIS_DEEP},
	{"bins/arm/elf/hello-world-linaro-201201", "fcn.000083bc", RZ_CORE_ANALYSIS_EXPERIMENTAL},

	{"bins/elf/ls", "fcn.00016530", RZ_CORE_ANALYSIS_DEEP},
	{"bins/elf/ls", "fcn.0000f1b0", RZ_CORE_ANALYSIS_DEEP},
	{"bins/elf/ls", "fcn.00010be0", RZ_CORE_ANALYSIS_DEEP},
	{"bins/elf/ls", "fcn.00016320", RZ_CORE_ANALYSIS_DEEP},
};

const ut32 bin_fcn_list_size = RZ_ARRAY_SIZE(bin_fcn_list);

bool test_fcn_list_size() {
	for(ut32 i = 0; i < bin_fcn_list_size; ++i) {
		test_detected_functions_list_size(bin_fcn_list[i].fpath);
	}
	mu_end;
}

bool test_new_fcn_detected() {
	for(ut32 i = 0; i < bin_fcn_list_size; ++i) {
		test_new_functions_detected_at_level(bin_fcn_list[i].analysis_type, bin_fcn_list[i].fpath, bin_fcn_list[i].fcn_name);
	}
	mu_end;
}

int all_tests() {
	mu_run_test(test_fcn_list_size);
	mu_run_test(test_new_fcn_detected);
	return tests_passed != tests_run;
}

mu_main(all_tests)
