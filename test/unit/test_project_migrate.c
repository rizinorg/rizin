// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_project.h>

#include "minunit.h"

/**
 * \file
 * About Project Migration Tests:
 *
 * Every migration from version A to version B has to come with two kinds of tests,
 * of which both cover all changes performed by this migration:
 *
 * * **Individual tests for only the single migration from A to B.**
 *   These are written against the sdb directly and test changes made by a single call to the
 *   respective `rz_project_migrate_vA_vB` function. No RzCore is involved in these tests.
 *   They should be written once and ideally never change in the future as they are not affected
 *   by later project versions.
 *   They are called `test_migrate_vA_vB_<...>` here.
 * * **Loading tests from version A to the current version.**
 *   These load a project of version A completely into an RzCore. Then they test if the data
 *   migrated has eventually been correctly deserialized into the core.
 *   They make sure that the results produced by the migration and tested by the individual tests
 *   are actually valid for the deserialization.
 *   As the feature set and architecture of RzCore and all descendants may change, these tests
 *   can be adapted in the future and in extreme cases even be removed if the migrated data simply
 *   is not used anymore.
 *   These are called `test_load_vA_<...>` here.
 *
 * See also `librz/core/project_migrate.c` for general info on implementing project migrations.
 *
  */

bool test_migrate_v1_v2_noreturn() {
	RzProject *prj = rz_project_load_file_raw("prj/v1-noreturn.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v1_v2(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");
	Sdb *types_db = sdb_ns(analysis_db, "types", false);
	mu_assert_notnull(types_db, "types ns");

	mu_assert_null(sdb_get(types_db, "addr.1337.noreturn", 0), "old noreturn deleted");
	mu_assert_null(sdb_get(types_db, "addr.4242.noreturn", 0), "old noreturn deleted");

	Sdb *noreturn_db = sdb_ns(analysis_db, "noreturn", false);
	mu_assert_notnull(noreturn_db, "noreturn ns");

	mu_assert_streq(sdb_get(noreturn_db, "addr.1337.noreturn", 0), "true", "new noreturn added");
	mu_assert_streq(sdb_get(noreturn_db, "addr.4242.noreturn", 0), "true", "new noreturn added");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

bool test_migrate_v1_v2_noreturn_empty() {
	RzProject *prj = rz_project_load_file_raw("prj/v1-noreturn-empty.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v1_v2(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");
	Sdb *types_db = sdb_ns(analysis_db, "types", false);
	mu_assert_notnull(types_db, "types ns");

	Sdb *noreturn_db = sdb_ns(analysis_db, "noreturn", false);
	// not more to test here, just assert the existence of the noreturn ns
	mu_assert_notnull(noreturn_db, "noreturn ns");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

bool test_migrate_v2_v3() {
	// TODO: like above
	mu_end;
}

bool test_load_v1_noreturn() {
	RzCore *core = rz_core_new();
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	mu_assert_notnull(res, "result info new");
	RzProjectErr err = rz_project_load_file(core, "prj/v1-noreturn.rzdb", true, res);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err");
	mu_assert_eq(rz_list_length(res), 2, "info");
	mu_assert_streq(rz_list_get_n(res, 0), "project migrated from version 1 to 2.", "info");
	mu_assert_streq(rz_list_get_n(res, 1), "project migrated from version 2 to 3.", "info");

	mu_assert_true(rz_analysis_noreturn_at_addr(core->analysis, 0x4242), "noreturn");
	mu_assert_true(rz_analysis_noreturn_at_addr(core->analysis, 0x1337), "noreturn");
	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x12345), "nono");

	rz_serialize_result_info_free(res);

	rz_core_free(core);
	mu_end;
}

bool test_load_v1_noreturn_empty() {
	RzCore *core = rz_core_new();
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	mu_assert_notnull(res, "result info new");
	RzProjectErr err = rz_project_load_file(core, "prj/v1-noreturn-empty.rzdb", true, res);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err");
	mu_assert_eq(rz_list_length(res), 2, "info");
	mu_assert_streq(rz_list_get_n(res, 0), "project migrated from version 1 to 2.", "info");
	mu_assert_streq(rz_list_get_n(res, 1), "project migrated from version 2 to 3.", "info");

	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x4242), "nono");
	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x1337), "nono");
	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x12345), "nono");

	rz_serialize_result_info_free(res);

	rz_core_free(core);
	mu_end;
}

bool test_load_v2_typelink() {
	RzCore *core = rz_core_new();
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	mu_assert_notnull(res, "result info new");
	RzProjectErr err = rz_project_load_file(core, "prj/v2-typelink.rzdb", true, res);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err");
	mu_assert_eq(rz_list_length(res), 1, "info");
	mu_assert_streq(rz_list_get_n(res, 0), "project migrated from version 2 to 3.", "info");

	// 4. Save into the project
	if (!rz_file_is_directory(".tmp" RZ_SYS_DIR)) {
		mu_assert_true(rz_sys_mkdir(".tmp/"), "create tmp directory");
	}
	err = rz_project_save_file(core, ".tmp/test_v2_typelink_v3_migrated.rzdb");
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project save err");

	mu_assert_true(rz_analysis_type_link_exists(core->analysis, 0x80484b0), "has typelink");
	RzType *typelink = rz_analysis_type_link_at(core->analysis, 0x80484b0);
	mu_assert_notnull(typelink, "has typelink");
	mu_assert_eq(RZ_TYPE_KIND_POINTER, typelink->kind, "typelink is a pointer");
	mu_assert_true(rz_type_atomic_str_eq(core->analysis->typedb, typelink->pointer.type, "char"), "typelink is char *");

	rz_serialize_result_info_free(res);

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_migrate_v1_v2_noreturn);
	mu_run_test(test_migrate_v1_v2_noreturn_empty);
	mu_run_test(test_migrate_v2_v3);
	mu_run_test(test_load_v1_noreturn);
	mu_run_test(test_load_v1_noreturn_empty);
	mu_run_test(test_load_v2_typelink);
	return tests_passed != tests_run;
}

mu_main(all_tests)
