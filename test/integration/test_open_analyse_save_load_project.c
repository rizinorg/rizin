// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_project.h>

#include "../unit/minunit.h"

bool test_open_analyse_save() {
	// 1. Open the file
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	ut64 loadaddr = 0;
	const char *fpath = "bins/elf/ls";
	RzCoreFile *file = rz_core_file_open(core, fpath, RZ_PERM_R, loadaddr);
	mu_assert_notnull(file, "open file");
	rz_core_bin_load(core, fpath, loadaddr);

	// 2. Analyse the file
	rz_core_analysis_all(core);
	rz_core_analysis_everything(core, false, "esil");

	RzList *functionsold = rz_analysis_function_list(core->analysis);
	mu_assert_notnull(functionsold, "export functions list");
	eprintf("functions count = %d\n", rz_list_length(functionsold));

	// 3. Remove the function
	const char* fcnname = "fcn.0000ebe0";
	RzAnalysisFunction *fcn = rz_analysis_get_function_byname(core->analysis, fcnname);
	mu_assert_notnull(fcn, "find function");
	rz_analysis_function_delete(fcn);

	// 3. Export the function list
	RzList *functions = rz_analysis_function_list(core->analysis);
	mu_assert_notnull(functions, "export functions list");
	size_t functions_count_expect = rz_list_length(functions);

	// 4. Save into the project
	if (!rz_file_exists(".tmp/")) {
		mu_assert_true(rz_sys_mkdir(".tmp/"), "create tmp directory");
	}
	RzProjectErr err = rz_project_save_file(core, ".tmp/test_open_analyse.rzdb");
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project save err");

	// 5. Close the file
	rz_core_file_free(file);
	rz_core_free(core);

	// 6. Open the file again
	core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	file = rz_core_file_open(core, fpath, RZ_PERM_R, loadaddr);
	mu_assert_notnull(file, "open file");
	rz_core_bin_load(core, fpath, loadaddr);

	// 7. Load the previously saved project
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	mu_assert_notnull(res, "result info new");
	err = rz_project_load_file(core, ".tmp/test_open_analyse.rzdb", true, res);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err");

	// 8. Export the function list
	RzList *functions_load = rz_analysis_function_list(core->analysis);
	mu_assert_notnull(functions_load, "export functions list");

	// 9. Compare with the previously saved one
	mu_assert_eq(rz_list_length(functions_load), functions_count_expect, "compare functions list");

	// 10. Exit
	rz_serialize_result_info_free(res);
	rz_core_file_free(file);
	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_open_analyse_save);
	return tests_passed != tests_run;
}

mu_main(all_tests)
