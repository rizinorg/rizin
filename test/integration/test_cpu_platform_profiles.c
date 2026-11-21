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
	RzPlatformTarget *arch_target = rz_analysis_get_arch_target(core->analysis);
	rz_platform_load_profile_sdb(arch_target, tempfile);

	// 2. Analyse the file
	rz_platform_profile_add_flag_every_io(arch_target->profile, core->flags);

	RzFlagItem *item = rz_flag_get(core->flags, "DDRB");
	mu_assert_eq(item->offset, 0x00000004, "Flag DDRB not found");
	item = rz_flag_get(core->flags, "PORTB");
	mu_assert_eq(item->offset, 0x00000005, "Flag PORTB not found");

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
	mu_assert_eq(item->offset, 0x00000004, "Flag DDRB not found");
	item = rz_flag_get(core->flags, "PORTB");
	mu_assert_eq(item->offset, 0x00000005, "Flag PORTB not found");

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

	RzPlatformTargetIndex *platform_target = rz_analysis_get_platform_target(core->analysis);
	rz_platform_target_index_load_sdb(platform_target, tempfile);

	// 2. Analyse the file
	rz_platform_index_add_flags_comments(core);

	RzFlagItem *item = rz_flag_get(core->flags, "AUX_MU_IER_REG");
	mu_assert_eq(item->offset, 0x7e215044, "Flag AUX_MU_IER_REG not found");
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
	mu_assert_eq(item->offset, 0x7e215044, "Flag AUX_MU_IER_REG not found");

	free(tmpdir);
	rz_core_free(core);
	mu_end;
}

static bool test_platform_profile_edge_cases(void) {
	RzPlatformTargetIndex *target = rz_platform_target_index_new();
	mu_assert_notnull(target, "new platform target index");

	// First SDB: one entry with comment and one without comment.
	char *path1 = rz_file_temp(".sdb");
	mu_assert_notnull(path1, "temp sdb 1");
	Sdb *db1 = sdb_new(NULL, path1, 0);
	mu_assert_notnull(db1, "sdb_new 1");
	sdb_set(db1, "REG_A", "name");
	sdb_num_set(db1, "REG_A.address", 0x1000);
	sdb_set(db1, "REG_A.comment", "First reg");
	sdb_set(db1, "REG_B", "name");
	sdb_num_set(db1, "REG_B.address", 0x2000);
	mu_assert_true(sdb_sync(db1), "sync db1");
	sdb_close(db1);
	sdb_free(db1);

	mu_assert_true(rz_platform_target_index_load_sdb(target, path1), "load db1");
	RzPlatformItem *item_a = ht_up_find(target->platforms, 0x1000, NULL);
	mu_assert_notnull(item_a, "REG_A loaded");
	mu_assert_streq(item_a->name, "REG_A", "REG_A name");
	mu_assert_streq(item_a->comment, "First reg", "REG_A comment");
	RzPlatformItem *item_b = ht_up_find(target->platforms, 0x2000, NULL);
	mu_assert_notnull(item_b, "REG_B loaded");
	mu_assert_streq(item_b->name, "REG_B", "REG_B name");
	mu_assert_null(item_b->comment, "REG_B has no comment");

	// Second SDB: duplicate address must be ignored without leaking the new item.
	char *path2 = rz_file_temp(".sdb");
	mu_assert_notnull(path2, "temp sdb 2");
	Sdb *db2 = sdb_new(NULL, path2, 0);
	mu_assert_notnull(db2, "sdb_new 2");
	sdb_set(db2, "REG_DUP", "name");
	sdb_num_set(db2, "REG_DUP.address", 0x1000);
	sdb_set(db2, "REG_DUP.comment", "Duplicate reg");
	mu_assert_true(sdb_sync(db2), "sync db2");
	sdb_close(db2);
	sdb_free(db2);

	mu_assert_true(rz_platform_target_index_load_sdb(target, path2), "load db2 with dup addr");
	item_a = ht_up_find(target->platforms, 0x1000, NULL);
	mu_assert_notnull(item_a, "existing entry retained");
	mu_assert_streq(item_a->name, "REG_A", "duplicate did not overwrite REG_A");

	// Third SDB: missing address must fail cleanly without leaking items vector.
	char *path3 = rz_file_temp(".sdb");
	mu_assert_notnull(path3, "temp sdb 3");
	Sdb *db3 = sdb_new(NULL, path3, 0);
	mu_assert_notnull(db3, "sdb_new 3");
	sdb_set(db3, "REG_NOADDR", "name");
	mu_assert_true(sdb_sync(db3), "sync db3");
	sdb_close(db3);
	sdb_free(db3);

	bool loaded = rz_platform_target_index_load_sdb(target, path3);
	mu_assert_false(loaded, "missing address returns false");

	rz_file_rm(path1);
	rz_file_rm(path2);
	rz_file_rm(path3);
	free(path1);
	free(path2);
	free(path3);
	rz_platform_target_index_free(target);
	mu_end;
}

int all_tests() {
	mu_run_test(test_cpu_profiles);
	mu_run_test(test_platform_profiles);
	mu_run_test(test_platform_profile_edge_cases);
	return tests_passed != tests_run;
}

mu_main(all_tests)
