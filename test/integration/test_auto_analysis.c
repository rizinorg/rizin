// SPDX-FileCopyrightText: 2023 Siddharth Mishra <misra.cxx@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_project.h>

#include "../unit/minunit.h"

typedef struct test_fcn_level {
	const char *fcn_name; ///< name of function
	RzCoreAnalysisType analysis_type; ///< analysis level to test presence at
} TestFcnLevel;

typedef struct test_bin_fcn_level {
	const char *fpath;
	TestFcnLevel test_fcns[5]; ///< maximum of 5 functions (can be expanded)
} TestBinFcnLevel;

bool test_detected_functions_list_size(const char *fpath) {
	// new core
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");

	// load test file
	ut64 loadaddr = 0;
	rz_core_bin_load(core, fpath, loadaddr);

	// aa
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_SIMPLE);
	RzPVector *simple_fcn_list = rz_analysis_function_list(core->analysis);
	mu_assert_notnull(simple_fcn_list, "simple function list");
	ut32 simple_fcn_list_length = rz_pvector_len(simple_fcn_list);
	eprintf("functions count = %d\n", simple_fcn_list_length);

	// aaa
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_DEEP);
	RzPVector *deep_fcn_list = rz_analysis_function_list(core->analysis);
	mu_assert_notnull(deep_fcn_list, "simple function list");
	ut32 deep_fcn_list_length = rz_pvector_len(deep_fcn_list);
	eprintf("functions count = %d\n", deep_fcn_list_length);

	// more function should be detected in deep analysis
	// not true for all binaries but for most it must be true
	mu_assert("deep analysis success", deep_fcn_list_length >= simple_fcn_list_length);

	// aaaa
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_EXPERIMENTAL);
	RzPVector *experimental_fcn_list = rz_analysis_function_list(core->analysis);
	mu_assert_notnull(experimental_fcn_list, "simple function list");
	ut32 experimental_fcn_list_length = rz_pvector_len(experimental_fcn_list);
	eprintf("functions count = %d\n", experimental_fcn_list_length);

	// again more in experimental
	mu_assert("deep analysis success", experimental_fcn_list_length >= deep_fcn_list_length);

	// free core and end test
	rz_core_free(core);
	mu_end;
}

// compare function for rz_list_find
int cmp_fcn_name(const void *value, const void *list_data, void *user) {
	RzAnalysisFunction *fcn = (RzAnalysisFunction *)list_data;
	return strcmp((const char *)value, fcn->name);
}

// new functions can be found at analysis levels DEEP(aaa) and EXPERIMENTAL(aaaa)
bool test_new_functions_detected_at_level(TestBinFcnLevel testbin) {
	// new core
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");

	// load test file
	ut64 loadaddr = 0;
	rz_core_bin_load(core, testbin.fpath, loadaddr);

	// simple analyis will always be performed
	RzCoreAnalysisType last_analysis_type = RZ_CORE_ANALYSIS_SIMPLE;
	rz_core_perform_auto_analysis(core, last_analysis_type);
	RzPVector *fcn_list = rz_analysis_function_list(core->analysis);
	mu_assert_notnull(fcn_list, "function list retrieved");

	for (ut32 i = 0; i < 5; i++) {
		const char *fcn_name = testbin.test_fcns[i].fcn_name;
		RzCoreAnalysisType analysis_type = testbin.test_fcns[i].analysis_type;
		if (fcn_name == NULL) {
			break;
		}

		// perform analysis and get function list
		if (analysis_type != last_analysis_type) {
			rz_core_perform_auto_analysis(core, analysis_type);
			fcn_list = rz_analysis_function_list(core->analysis);
			mu_assert_notnull(fcn_list, "function list retrieved");

			last_analysis_type = analysis_type;
		}

		// search function
		bool fcn_found = rz_pvector_find(fcn_list, fcn_name, cmp_fcn_name, NULL) != NULL;
		mu_assert("function not found at given analysis level", fcn_found);
	}

	// free core and end test
	rz_core_free(core);
	mu_end;
}

TestBinFcnLevel bin_fcn_list[] = {
	{ "bins/arm/elf/hello-world",
		{
			/* fun name */ /* analysis level */
			{ "fcn.00000522", RZ_CORE_ANALYSIS_EXPERIMENTAL },
			{ "entry.init0", RZ_CORE_ANALYSIS_SIMPLE },
			{ NULL, 0 } /* ending entry */
		} },

	{ "bins/arm/elf/hello-world-buildroot-201402",
		{
			/* fun name */ /* analysis level */
			{ "fcn.00008300", RZ_CORE_ANALYSIS_DEEP },
			{ "fcn.00008274", RZ_CORE_ANALYSIS_DEEP },
			{ "fcn.00008200", RZ_CORE_ANALYSIS_DEEP },
			{ NULL, 0 } /* ending entry */
		} },

	{ "bins/arm/elf/hello-world-linaro-201201",
		{
			/* fun name */ /* analysis level */
			{ "fcn.00008334", RZ_CORE_ANALYSIS_DEEP },
			{ "fcn.00008298", RZ_CORE_ANALYSIS_DEEP },
			{ "fcn.000082a4", RZ_CORE_ANALYSIS_DEEP },
			{ "fcn.000083bc", RZ_CORE_ANALYSIS_EXPERIMENTAL },
			{ NULL, 0 } /* ending entry */
		} },

	{ "bins/elf/ls",
		{
			/* fun name */ /* analysis level */
			{ "fcn.00016530", RZ_CORE_ANALYSIS_DEEP },
			{ "fcn.0000f1b0", RZ_CORE_ANALYSIS_DEEP },
			{ "fcn.00010be0", RZ_CORE_ANALYSIS_DEEP },
			{ "fcn.00016320", RZ_CORE_ANALYSIS_DEEP },
			{ NULL, 0 } /* ending entry */
		} },
};

const ut32 bin_fcn_list_size = RZ_ARRAY_SIZE(bin_fcn_list);

bool test_fcn_list_size() {
	for (ut32 i = 0; i < bin_fcn_list_size; ++i) {
		test_detected_functions_list_size(bin_fcn_list[i].fpath);
	}
	mu_end;
}

bool test_new_fcn_detected() {
	for (ut32 i = 0; i < bin_fcn_list_size; ++i) {
		test_new_functions_detected_at_level(bin_fcn_list[i]);
	}
	mu_end;
}

int all_tests() {
	mu_run_test(test_fcn_list_size);
	mu_run_test(test_new_fcn_detected);
	return tests_passed != tests_run;
}

mu_main(all_tests)
