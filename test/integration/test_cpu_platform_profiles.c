// SPDX-FileCopyrightText: 2020 Aswin C (officialcjunior) <realc@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_platform.h>
#include <rz_project.h>

#include "../unit/minunit.h"
#include "../unit/rz_arch_buffer.h"

bool test_cpu_profiles() {
	// 1. Open the file
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	ut64 loadaddr = 0;
	const char *fpath = "bins/firmware/arduino_avr.bin";
	RzCoreFile *file = rz_core_file_open(core, fpath, RZ_PERM_R, loadaddr);
	mu_assert_notnull(file, "opening the firmware");
	rz_core_bin_load(core, fpath, loadaddr);

	const char *tempfile = rz_file_temp(".sdb");
	rz_file_dump(tempfile, cpu_buffer, sizeof(cpu_buffer), false);
	rz_platform_load_profile_sdb(core->analysis->arch_target, tempfile);

	// 2. Analyse the file
	rz_platform_profile_add_flag_every_io(core->analysis->arch_target->profile, core->flags);

	RzFlagItem *item = rz_flag_get(core->flags, "DDRB");
	mu_assert_eq(rz_flag_item_get_offset(item), 0x00000004, "Flag DDRB not found");
	item = rz_flag_get(core->flags, "PORTB");
	mu_assert_eq(rz_flag_item_get_offset(item), 0x00000005, "Flag PORTB not found");

	// 3. Save into the project
	char *tmpdir = rz_file_tmpdir();
	char *project_file = rz_file_path_join(tmpdir, "cpu_profile.rzdb");
	RzProjectErr err = rz_project_save_file(core, project_file, true);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project save err");
	free(project_file);

	// 4. Close the file
	rz_core_file_close(file);
	rz_core_free(core);

	// 5. Create a new core
	core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");

	// 6. Load the previously saved project
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	mu_assert_notnull(res, "result info new");
	project_file = rz_file_path_join(tmpdir, "cpu_profile.rzdb");
	err = rz_project_load_file(core, project_file, true, res);
	free(project_file);
	rz_serialize_result_info_free(res);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err");

	// 7. Check the values again
	item = rz_flag_get(core->flags, "DDRB");
	mu_assert_eq(rz_flag_item_get_offset(item), 0x00000004, "Flag DDRB not found");
	item = rz_flag_get(core->flags, "PORTB");
	mu_assert_eq(rz_flag_item_get_offset(item), 0x00000005, "Flag PORTB not found");

	free(tmpdir);
	rz_core_free(core);
	mu_end;
}

bool test_platform_profiles() {
	// 1. Open the file
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	ut64 loadaddr = 0;
	const char *fpath = "bins/arm/elf/hello_world";
	RzCoreFile *file = rz_core_file_open(core, fpath, RZ_PERM_R, loadaddr);
	mu_assert_notnull(file, "opening the binary");
	rz_core_bin_load(core, fpath, loadaddr);

	const char *tempfile = rz_file_temp(".sdb");
	rz_file_dump(tempfile, platform_buffer, sizeof(platform_buffer), false);
	rz_platform_target_index_load_sdb(core->analysis->platform_target, tempfile);

	// 2. Analyse the file
	rz_platform_index_add_flags_comments(core);

	RzFlagItem *item = rz_flag_get(core->flags, "AUX_MU_IER_REG");
	mu_assert_eq(rz_flag_item_get_offset(item), 0x7e215044, "Flag AUX_MU_IER_REG not found");
	const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, 0x7e804000);
	mu_assert_streq(comment, "Broadcom Serial Controller 1 (BSC)", "Comment unequal!");

	// 3. Save into the project
	char *tmpdir = rz_file_tmpdir();
	char *project_file = rz_file_path_join(tmpdir, "cpu_platform.rzdb");
	RzProjectErr err = rz_project_save_file(core, project_file, true);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project save err");
	free(project_file);

	// 4. Close the file
	rz_core_file_close(file);
	rz_core_free(core);

	// 5. Create a new core
	core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");

	// 6. Load the previously saved project
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	mu_assert_notnull(res, "result info new");
	project_file = rz_file_path_join(tmpdir, "cpu_platform.rzdb");
	err = rz_project_load_file(core, project_file, true, res);
	free(project_file);
	rz_serialize_result_info_free(res);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err");

	// 7. Check the values again
	comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, 0x7e804000);
	mu_assert_streq(comment, "Broadcom Serial Controller 1 (BSC)", "Comment not found");
	item = rz_flag_get(core->flags, "AUX_MU_IER_REG");
	mu_assert_eq(rz_flag_item_get_offset(item), 0x7e215044, "Flag AUX_MU_IER_REG not found");

	free(tmpdir);
	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_cpu_profiles);
	mu_run_test(test_platform_profiles);
	return tests_passed != tests_run;
}

mu_main(all_tests)
