// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_project.h>

#include "../unit/minunit.h"

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

static bool test_migrate_v1_v2_noreturn() {
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

	mu_assert_streq_free(sdb_get(noreturn_db, "addr.1337.noreturn", 0), "true", "new noreturn added");
	mu_assert_streq_free(sdb_get(noreturn_db, "addr.4242.noreturn", 0), "true", "new noreturn added");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v1_v2_noreturn_empty() {
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

static bool test_migrate_v2_v3_typelink_callables() {
	RzProject *prj = rz_project_load_file_raw("prj/v2-typelink-callables.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v2_v3(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");

	Sdb *types_db = sdb_ns(analysis_db, "types", false);
	mu_assert_notnull(types_db, "types ns");
	mu_assert_null(sdb_get(types_db, "func._Exit.args", 0), "old function deleted");
	mu_assert_null(sdb_get(types_db, "_Exit", 0), "old function deleted");
	mu_assert_null(sdb_get(types_db, "link.080484b0", 0), "old typelink deleted");

	Sdb *callables_db = sdb_ns(analysis_db, "callables", false);
	mu_assert_notnull(callables_db, "callables ns");
	mu_assert_streq_free(sdb_get(callables_db, "func._Exit.args", 0), "1", "new callable added");
	mu_assert_streq_free(sdb_get(callables_db, "_Exit", 0), "func", "new callable added");

	Sdb *typelinks_db = sdb_ns(analysis_db, "typelinks", false);
	mu_assert_notnull(typelinks_db, "typelinks ns");
	mu_assert_streq_free(sdb_get(typelinks_db, "0x080484b0", 0), "char *", "new typelink added");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v2_v3_types_empty() {
	RzProject *prj = rz_project_load_file_raw("prj/v2-types-empty.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v2_v3(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");

	// All empty, but should exist
	Sdb *types_db = sdb_ns(analysis_db, "types", false);
	mu_assert_notnull(types_db, "types ns");
	Sdb *callables_db = sdb_ns(analysis_db, "callables", false);
	mu_assert_notnull(callables_db, "callables ns");
	Sdb *typelinks_db = sdb_ns(analysis_db, "typelinks", false);
	mu_assert_notnull(typelinks_db, "typelinks ns");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v3_v4_typelink() {
	RzProject *prj = rz_project_load_file_raw("prj/v3-typelink.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v3_v4(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");

	// Empty, but should exist
	Sdb *types_db = sdb_ns(analysis_db, "types", false);
	mu_assert_notnull(types_db, "types ns");
	Sdb *callables_db = sdb_ns(analysis_db, "vars", false);
	mu_assert_notnull(callables_db, "callables ns");

	// Typelinks still exist too
	Sdb *typelinks_db = sdb_ns(analysis_db, "typelinks", false);
	mu_assert_notnull(typelinks_db, "typelinks ns");
	mu_assert_streq_free(sdb_get(typelinks_db, "0x08048660", 0), "uint32_t", "new callable added");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v4_v5_types() {
	RzProject *prj = rz_project_load_file_raw("prj/v4-types.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v4_v5(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");

	Sdb *types_db = sdb_ns(analysis_db, "types", false);
	mu_assert_notnull(types_db, "types ns");
	mu_assert_streq_free(sdb_get(types_db, "unknown_t", 0), "type", "unknown_t added");
	mu_assert_streq_free(sdb_get(types_db, "type.unknown_t", 0), "d", "unknown_t added");
	mu_assert_streq_free(sdb_get(types_db, "type.unknown_t.size", 0), "32", "unknown_t added");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v5_v6() {
	RzProject *prj = rz_project_load_file_raw("prj/v5-empty.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v5_v6(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *debug_db = sdb_ns(core_db, "debug", false);
	mu_assert_notnull(debug_db, "debug ns");
	Sdb *breakpoints_db = sdb_ns(debug_db, "breakpoints", false);
	mu_assert_notnull(breakpoints_db, "breakpoints ns");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v6_v7_esil_pins() {
	RzProject *prj = rz_project_load_file_raw("prj/v6-esil-pins.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v6_v7(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");
	Sdb *pins_db = sdb_ns(analysis_db, "pins", false);
	mu_assert_null(pins_db, "pins");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v7_v8_zignatures() {
	RzProject *prj = rz_project_load_file_raw("prj/v7-zignatures.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v7_v8(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");

	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");
	Sdb *zigns_db = sdb_ns(analysis_db, "zigns", false);
	mu_assert_null(zigns_db, "zigns ns");

	Sdb *config_db = sdb_ns(core_db, "config", false);
	mu_assert_notnull(config_db, "analysis ns");
	mu_assert_streq_free(sdb_get(config_db, "analysis.apply.signature", 0), "true", "config");
	mu_assert_null(sdb_get(config_db, "zign.autoload", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.diff.bthresh", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.diff.gthresh", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.bytes", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.graph", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.hash", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.offset", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.refs", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.types", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.maxsz", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.mincc", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.minsz", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.prefix", 0), "config");
	mu_assert_null(sdb_get(config_db, "zign.threshold", 0), "config");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v8_v9_fingerprint() {
	RzProject *prj = rz_project_load_file_raw("prj/v8-fingerprint.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v8_v9(prj, res);
	mu_assert_true(s, "migrate success");
	// No changes, success result is enough for us
	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v9_v10_stackptr() {
	RzProject *prj = rz_project_load_file_raw("prj/v9-stackptr.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v9_v10(prj, res);
	mu_assert_true(s, "migrate success");
	// No changes, success result is enough for us
	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v10_v11_stack_vars_bp() {
	RzProject *prj = rz_project_load_file_raw("prj/v10-bp-vars.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v10_v11(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");
	Sdb *functions_db = sdb_ns(analysis_db, "functions", false);
	mu_assert_notnull(functions_db, "functions ns");

	// bp vars
	const char *val = sdb_const_get(functions_db, "0x113c", 0);
	const char *varfunc_expect =
		"{\"name\":\"dbg.varfunc\",\"bits\":64,\"type\":4,\"cc\":\"amd64\",\"stack\":-8,\"maxstack\":24,\"ninstr\":14,"
		"\"bp_frame\":true,\"bp_off\":8,\"bbs\":[4412],"
		"\"vars\":["
			"{\"name\":\"lightbulb\",\"type\":\"int\",\"accs\":["
				"{\"off\":8,\"type\":\"w\",\"sp\":-16,\"reg\":\"rbp\"},"
				"{\"off\":52,\"type\":\"r\",\"sp\":-16,\"reg\":\"rbp\"}],\"stack\":-24},"
			"{\"name\":\"sun\",\"type\":\"int\",\"accs\":["
				"{\"off\":15,\"type\":\"w\",\"sp\":-12,\"reg\":\"rbp\"},"
				"{\"off\":49,\"type\":\"w\",\"sp\":-12,\"reg\":\"rbp\"}],\"stack\":-20},"
			"{\"name\":\"last\",\"type\":\"int\",\"accs\":["
				"{\"off\":22,\"type\":\"w\",\"sp\":-8,\"reg\":\"rbp\"}],\"stack\":-16},"
			"{\"name\":\"chance\",\"type\":\"int\",\"accs\":["
				"{\"off\":29,\"type\":\"w\",\"sp\":-4,\"reg\":\"rbp\"},"
				"{\"off\":46,\"type\":\"r\",\"sp\":-4,\"reg\":\"rbp\"}],\"stack\":-12}"
		"]}";
	mu_assert_streq(val, varfunc_expect, "varfunc");

	// also some reg vars
	val = sdb_const_get(functions_db, "0x1175", 0);
	const char *main_expect =
		"{\"name\":\"dbg.main\",\"bits\":64,\"type\":4,\"cc\":\"amd64\",\"stack\":-8,\"maxstack\":24,\"ninstr\":15,"
		"\"bp_frame\":true,\"bp_off\":8,\"bbs\":[4469],"
		"\"vars\":["
			"{\"name\":\"var_4h\",\"type\":\"int\",\"accs\":["
				"{\"off\":8,\"type\":\"w\",\"sp\":-4,\"reg\":\"rbp\"}],\"stack\":-12},"
			"{\"name\":\"var_10h\",\"type\":\"char **\",\"accs\":["
				"{\"off\":11,\"type\":\"w\",\"sp\":-16,\"reg\":\"rbp\"}],\"stack\":-24},"
			"{\"name\":\"argc\",\"type\":\"int\",\"reg\":\"rdi\",\"accs\":["
				"{\"off\":8,\"type\":\"r\",\"reg\":\"rdi\"}]},"
			"{\"name\":\"argv\",\"type\":\"char **\",\"reg\":\"rsi\",\"accs\":["
				"{\"off\":11,\"type\":\"r\",\"reg\":\"rsi\"}]}"
		"]}";
	mu_assert_streq(val, main_expect, "main");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v10_v11_stack_vars_sp() {
	RzProject *prj = rz_project_load_file_raw("prj/v10-sp-vars.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v10_v11(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");
	Sdb *functions_db = sdb_ns(analysis_db, "functions", false);
	mu_assert_notnull(functions_db, "functions ns");

	// sp vars
	const char *val = sdb_const_get(functions_db, "0x1137", 0);
	const char *varfunc_expect =
		"{\"name\":\"sym.varfunc\",\"bits\":64,\"type\":4,\"cc\":\"amd64\",\"stack\":-8,\"maxstack\":16,\"ninstr\":12,"
		"\"bp_frame\":true,\"bbs\":[4407],"
		"\"vars\":["
			"{\"name\":\"sun\",\"type\":\"int\",\"accs\":["
				"{\"off\":11,\"type\":\"w\",\"sp\":4,\"reg\":\"rsp\"},"
				"{\"off\":49,\"type\":\"w\",\"sp\":4,\"reg\":\"rsp\"}],"
				"\"stack\":-12},"
			"{\"name\":\"last\",\"type\":\"int\",\"accs\":["
				"{\"off\":19,\"type\":\"w\",\"sp\":8,\"reg\":\"rsp\"}],"
				"\"stack\":-8},"
			"{\"name\":\"chance\",\"type\":\"int\",\"accs\":["
				"{\"off\":27,\"type\":\"w\",\"sp\":12,\"reg\":\"rsp\"},"
				"{\"off\":45,\"type\":\"r\",\"sp\":12,\"reg\":\"rsp\"}],"
				"\"stack\":-4},"
			"{\"name\":\"lightbulb\",\"type\":\"int\",\"stack\":-16}]}";
	mu_assert_streq(val, varfunc_expect, "varfunc");

	// also some reg vars
	val = sdb_const_get(functions_db, "0x1174", 0);
	const char *main_expect =
		"{\"name\":\"main\",\"bits\":64,\"type\":4,\"cc\":\"amd64\",\"stack\":-8,\"maxstack\":24,\"ninstr\":13,"
		"\"bp_frame\":true,\"bbs\":[4468],\"vars\":["
			"{\"name\":\"var_ch\",\"type\":\"int64_t\",\"accs\":["
				"{\"off\":4,\"type\":\"w\",\"sp\":12,\"reg\":\"rsp\"}],"
				"\"stack\":-12},"
			"{\"name\":\"argc\",\"type\":\"int\",\"reg\":\"rdi\",\"accs\":["
				"{\"off\":4,\"type\":\"r\",\"reg\":\"rdi\"}]},"
			"{\"name\":\"argv\",\"type\":\"char **\",\"reg\":\"rsi\",\"accs\":["
				"{\"off\":8,\"type\":\"r\",\"reg\":\"rsi\"}]}]}";
	mu_assert_streq(val, main_expect, "main");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

// Also test v9 -> v10 -> v11 because v9 will generally have less stackpointer info than v10 may
// have, but the vars should still be converted as good as possible.
static bool test_migrate_v9_v10_v11_stack_vars_bp() {
	RzProject *prj = rz_project_load_file_raw("prj/v9-bp-vars.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v10_v11(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");
	Sdb *functions_db = sdb_ns(analysis_db, "functions", false);
	mu_assert_notnull(functions_db, "functions ns");

	// bp vars
	const char *val = sdb_const_get(functions_db, "0x113c", 0);
	const char *varfunc_expect =
		"{\"name\":\"dbg.varfunc\",\"bits\":64,\"type\":4,\"cc\":\"amd64\",\"stack\":8,\"maxstack\":24,\"ninstr\":14,"
		"\"bp_frame\":true,\"bp_off\":8,\"bbs\":[4412],"
		"\"vars\":["
			"{\"name\":\"lightbulb\",\"type\":\"int\",\"accs\":["
				"{\"off\":8,\"type\":\"w\",\"sp\":-16,\"reg\":\"rbp\"},"
				"{\"off\":52,\"type\":\"r\",\"sp\":-16,\"reg\":\"rbp\"}],\"stack\":-24},"
			"{\"name\":\"sun\",\"type\":\"int\",\"accs\":["
				"{\"off\":15,\"type\":\"w\",\"sp\":-12,\"reg\":\"rbp\"},"
				"{\"off\":49,\"type\":\"w\",\"sp\":-12,\"reg\":\"rbp\"}],\"stack\":-20},"
			"{\"name\":\"last\",\"type\":\"int\",\"accs\":["
				"{\"off\":22,\"type\":\"w\",\"sp\":-8,\"reg\":\"rbp\"}],\"stack\":-16},"
			"{\"name\":\"chance\",\"type\":\"int\",\"accs\":["
				"{\"off\":29,\"type\":\"w\",\"sp\":-4,\"reg\":\"rbp\"},"
				"{\"off\":46,\"type\":\"r\",\"sp\":-4,\"reg\":\"rbp\"}],\"stack\":-12}"
		"]}";
	mu_assert_streq(val, varfunc_expect, "varfunc");

	// also some reg vars
	val = sdb_const_get(functions_db, "0x1175", 0);
	const char *main_expect =
		"{\"name\":\"dbg.main\",\"bits\":64,\"type\":4,\"cc\":\"amd64\",\"stack\":8,\"maxstack\":24,\"ninstr\":15,"
		"\"bp_frame\":true,\"bp_off\":8,\"bbs\":[4469],"
		"\"vars\":["
			"{\"name\":\"var_4h\",\"type\":\"int\",\"accs\":["
				"{\"off\":8,\"type\":\"w\",\"sp\":-4,\"reg\":\"rbp\"}],\"stack\":-12},"
			"{\"name\":\"var_10h\",\"type\":\"char **\",\"accs\":["
				"{\"off\":11,\"type\":\"w\",\"sp\":-16,\"reg\":\"rbp\"}],\"stack\":-24},"
			"{\"name\":\"argc\",\"type\":\"int\",\"reg\":\"rdi\",\"accs\":["
				"{\"off\":8,\"type\":\"r\",\"reg\":\"rdi\"}]},"
			"{\"name\":\"argv\",\"type\":\"char **\",\"reg\":\"rsi\",\"accs\":["
				"{\"off\":11,\"type\":\"r\",\"reg\":\"rsi\"}]}"
		"]}";
	mu_assert_streq(val, main_expect, "main");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v9_v10_v11_stack_vars_sp() {
	RzProject *prj = rz_project_load_file_raw("prj/v9-sp-vars.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v10_v11(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *analysis_db = sdb_ns(core_db, "analysis", false);
	mu_assert_notnull(analysis_db, "analysis ns");
	Sdb *functions_db = sdb_ns(analysis_db, "functions", false);
	mu_assert_notnull(functions_db, "functions ns");

	// sp vars
	const char *val = sdb_const_get(functions_db, "0x1137", 0);
	const char *varfunc_expect =
		"{\"name\":\"sym.varfunc\",\"bits\":64,\"type\":4,\"cc\":\"amd64\",\"stack\":-8,\"maxstack\":16,\"ninstr\":12,"
		"\"bp_frame\":true,\"bbs\":[4407],"
		"\"vars\":["
			"{\"name\":\"sun\",\"type\":\"int\",\"accs\":["
				"{\"off\":11,\"type\":\"w\",\"sp\":4,\"reg\":\"rsp\"},"
				"{\"off\":49,\"type\":\"w\",\"sp\":4,\"reg\":\"rsp\"}],"
				"\"stack\":-12},"
			"{\"name\":\"last\",\"type\":\"int\",\"accs\":["
				"{\"off\":19,\"type\":\"w\",\"sp\":8,\"reg\":\"rsp\"}],"
				"\"stack\":-8},"
			"{\"name\":\"chance\",\"type\":\"int\",\"accs\":["
				"{\"off\":27,\"type\":\"w\",\"sp\":12,\"reg\":\"rsp\"},"
				"{\"off\":45,\"type\":\"r\",\"sp\":12,\"reg\":\"rsp\"}],"
				"\"stack\":-4},"
			"{\"name\":\"lightbulb\",\"type\":\"int\",\"stack\":-16}]}";
	mu_assert_streq(val, varfunc_expect, "varfunc");

	// also some reg vars
	val = sdb_const_get(functions_db, "0x1174", 0);
	const char *main_expect =
		"{\"name\":\"main\",\"bits\":64,\"type\":4,\"cc\":\"amd64\",\"stack\":-8,\"maxstack\":24,\"ninstr\":13,"
		"\"bp_frame\":true,\"bbs\":[4468],\"vars\":["
			"{\"name\":\"var_ch\",\"type\":\"int64_t\",\"accs\":["
				"{\"off\":4,\"type\":\"w\",\"sp\":12,\"reg\":\"rsp\"}],"
				"\"stack\":-12},"
			"{\"name\":\"argc\",\"type\":\"int\",\"reg\":\"rdi\",\"accs\":["
				"{\"off\":4,\"type\":\"r\",\"reg\":\"rdi\"}]},"
			"{\"name\":\"argv\",\"type\":\"char **\",\"reg\":\"rsi\",\"accs\":["
				"{\"off\":8,\"type\":\"r\",\"reg\":\"rsi\"}]}]}";
	mu_assert_streq(val, main_expect, "main");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

/// Load project of given version from file into core and check the log for migration success messages
#define BEGIN_LOAD_TEST(core, version, file) \
	do { \
		RzSerializeResultInfo *res = rz_serialize_result_info_new(); \
		mu_assert_notnull(res, "result info new"); \
		RzProjectErr err = rz_project_load_file(core, file, true, res); \
		if (err != RZ_PROJECT_ERR_SUCCESS) { \
			RzListIter *it; \
			char *s; \
			rz_list_foreach (res, it, s) { \
				eprintf("%s\n", s); \
			} \
		} \
		mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err"); \
		mu_assert_eq(rz_list_length(res), RZ_PROJECT_VERSION - version, "migration log"); \
		for (int i = version; i < RZ_PROJECT_VERSION; i++) { \
			char expect[256]; \
			snprintf(expect, sizeof(expect), "project migrated from version %d to %d.", i, i + 1); \
			mu_assert_streq(rz_list_get_n(res, i - version), expect, "migration log"); \
		} \
		rz_serialize_result_info_free(res); \
	} while (0)


static bool test_load_v1_noreturn() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 1, "prj/v1-noreturn.rzdb");

	mu_assert_true(rz_analysis_noreturn_at_addr(core->analysis, 0x4242), "noreturn");
	mu_assert_true(rz_analysis_noreturn_at_addr(core->analysis, 0x1337), "noreturn");
	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x12345), "nono");

	rz_core_free(core);
	mu_end;
}

static bool test_load_v1_noreturn_empty() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 1, "prj/v1-noreturn-empty.rzdb");

	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x4242), "nono");
	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x1337), "nono");
	mu_assert_false(rz_analysis_noreturn_at_addr(core->analysis, 0x12345), "nono");

	rz_core_free(core);
	mu_end;
}

static bool test_load_v1_unknown_type() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 1, "prj/v1-noreturn.rzdb");

	mu_assert_true(rz_type_exists(core->analysis->typedb, "unknown_t"), "has unknown_t");
	RzBaseType *unknown = rz_type_db_get_base_type(core->analysis->typedb, "unknown_t");
	mu_assert_notnull(unknown, "has unknown_t");
	mu_assert_eq(RZ_BASE_TYPE_KIND_ATOMIC, unknown->kind, "unknown_t is atomic");
	mu_assert_eq(32, unknown->size, "unknown_t is 32-bit wide");

	rz_core_free(core);
	mu_end;
}

static bool test_load_v2_typelink() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 2, "prj/v2-typelink-callables.rzdb");

	mu_assert_true(rz_analysis_type_link_exists(core->analysis, 0x80484b0), "has typelink");
	RzType *typelink = rz_analysis_type_link_at(core->analysis, 0x80484b0);
	mu_assert_notnull(typelink, "has typelink");
	mu_assert_eq(RZ_TYPE_KIND_POINTER, typelink->kind, "typelink is a pointer");
	mu_assert_true(rz_type_atomic_str_eq(core->analysis->typedb, typelink->pointer.type, "char"), "typelink is char *");

	rz_core_free(core);
	mu_end;
}

static bool test_load_v2_callables() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 2, "prj/v2-typelink-callables.rzdb");

	RzAnalysisFunction *fcn = rz_analysis_get_function_byname(core->analysis, "entry0");
	mu_assert_notnull(fcn, "find \"entry0\" function");
	fcn = rz_analysis_get_function_byname(core->analysis, "main");
	mu_assert_notnull(fcn, "find \"entry0\" function");

	RzTypeDB *typedb = core->analysis->typedb;
	RzCallable *chmod = rz_type_func_get(typedb, "chmod");
	mu_assert_notnull(chmod, "func \"chmod\" callable type");
	mu_assert_streq(chmod->name, "chmod", "is chmod() function");
	mu_assert_eq(2, rz_type_func_args_count(typedb, "chmod"), "chmod() has 2 arguments");
	mu_assert_false(chmod->noret, "func \"chmod\" returns");
	RzCallableArg *arg0 = *rz_pvector_index_ptr(chmod->args, 0);
	mu_assert_notnull(arg0, "func \"chmod\" has 1st argument");
	mu_assert_streq(arg0->name, "path", "has \"path\" argument");
	RzCallableArg *arg1 = *rz_pvector_index_ptr(chmod->args, 1);
	mu_assert_notnull(arg1, "func \"chmod\" has 2nd argument");
	mu_assert_streq(arg1->name, "mode", "has \"mode\" argument");
	mu_assert_true(rz_type_atomic_str_eq(typedb, chmod->ret, "int"), "chmod() returns \"int\"");

	rz_core_free(core);
	mu_end;
}

static bool test_load_v2_types_empty() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 2, "prj/v2-types-empty.rzdb");

	RzAnalysisFunction *fcn = rz_analysis_get_function_byname(core->analysis, "entry0");
	mu_assert_notnull(fcn, "find \"entry0\" function");
	fcn = rz_analysis_get_function_byname(core->analysis, "main");
	mu_assert_notnull(fcn, "find \"entry0\" function");

	// typedb empty

	rz_core_free(core);
	mu_end;
}

static bool test_load_v3_typelink() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 3, "prj/v3-typelink.rzdb");

	RzType *tl = rz_analysis_type_link_at(core->analysis, 0x08048660);
	mu_assert_notnull(tl, "typelink still exists");
	mu_assert_streq_free(rz_type_as_string(core->analysis->typedb, tl), "uint32_t", "typelink");

	rz_core_free(core);
	mu_end;
}

static bool test_load_v4_types() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 4, "prj/v4-types.rzdb");

	RzBaseType *unk = rz_type_db_get_base_type(core->analysis->typedb, "unknown_t");
	mu_assert_notnull(unk, "unknown_t exists");
	mu_assert_eq(unk->kind, RZ_BASE_TYPE_KIND_ATOMIC, "unknown_t kind");
	mu_assert_eq(unk->size, 32, "unknown_t size");

	rz_core_free(core);
	mu_end;
}

static bool test_load_v5() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 5, "prj/v5-empty.rzdb");
	// No new or changed info here
	rz_core_free(core);
	mu_end;
}

static bool test_load_v6_esil_pins() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 6, "prj/v6-esil-pins.rzdb");
	// No new or changed info here
	rz_core_free(core);
	mu_end;
}

static bool test_load_v7_zignatures() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 7, "prj/v7-zignatures.rzdb");
	// No new or changed info here
	rz_core_free(core);
	mu_end;
}

static bool test_load_v8_fingerprint() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 8, "prj/v8-fingerprint.rzdb");

	RzAnalysisBlock *block = rz_analysis_get_block_at(core->analysis, 0x8048374);
	mu_assert_notnull(block, "block");
	mu_assert_eq(block->size, 6, "block");
	block = rz_analysis_get_block_at(core->analysis, 0x80484c8);
	mu_assert_notnull(block, "block");
	mu_assert_eq(block->size, 20, "block");
	block = rz_analysis_get_block_at(core->analysis, 0x8048540);
	mu_assert_notnull(block, "block");
	mu_assert_eq(block->size, 92, "block");

	// Theoretically, we should also check a project that contains "fingerprint" keys
	// in some RzAnalysisFunction, but it seems saving such a project was never even
	// possible since that field was only set in the rz-diff executable.

	rz_core_free(core);
	mu_end;
}

static bool test_load_v9_stackptr() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 9, "prj/v9-stackptr.rzdb");

	// Old stackptr/parent_stackptr is useless, thus make sure our new sp_entry/sp_delta
	// values are all empty.

	RzAnalysisBlock *block = rz_analysis_get_block_at(core->analysis, 0x8048394);
	mu_assert_notnull(block, "block");
	mu_assert_eq(block->sp_entry, RZ_STACK_ADDR_INVALID, "sp_entry");
	mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, 0), ST16_MAX, "sp_delta");

	block = rz_analysis_get_block_at(core->analysis, 0x8048484);
	mu_assert_notnull(block, "block");
	mu_assert_eq(block->sp_entry, RZ_STACK_ADDR_INVALID, "sp_entry");
	mu_assert_eq(block->ninstr, 18, "ninstr");
	for (size_t i = 0; i < block->ninstr; i++) {
		mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, i), ST16_MAX, "sp_delta");
	}

	block = rz_analysis_get_block_at(core->analysis, 0x8048526);
	mu_assert_notnull(block, "block");
	mu_assert_eq(block->sp_entry, RZ_STACK_ADDR_INVALID, "sp_entry");
	mu_assert_eq(block->ninstr, 4, "ninstr");
	for (size_t i = 0; i < block->ninstr; i++) {
		mu_assert_eq(rz_analysis_block_get_op_sp_delta(block, i), ST16_MAX, "sp_delta");
	}

	rz_core_free(core);
	mu_end;
}

static bool test_load_v9_v10_stack_vars_bp(int version, const char *prj_file) {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, version, prj_file);

	RzAnalysisFunction *f = rz_analysis_get_function_byname(core->analysis, "dbg.varfunc");
	mu_assert_notnull(f, "function");
	mu_assert_eq(rz_pvector_len(&f->vars), 4, "vars count");
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(f, "lightbulb");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0x18, "var storage");
	var = rz_analysis_function_get_var_byname(f, "sun");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0x14, "var storage");
	var = rz_analysis_function_get_var_byname(f, "last");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0x10, "var storage");
	var = rz_analysis_function_get_var_byname(f, "chance");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0xc, "var storage");

	f = rz_analysis_get_function_byname(core->analysis, "dbg.main");
	mu_assert_notnull(f, "function");
	mu_assert_eq(rz_pvector_len(&f->vars), 4, "vars count");
	var = rz_analysis_function_get_var_byname(f, "argc");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "var storage");
	mu_assert_streq(var->storage.reg, "rdi", "var storage");
	var = rz_analysis_function_get_var_byname(f, "argv");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "var storage");
	mu_assert_streq(var->storage.reg, "rsi", "var storage");
	var = rz_analysis_function_get_var_byname(f, "var_10h");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0x18, "var storage");
	var = rz_analysis_function_get_var_byname(f, "var_4h");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0xc, "var storage");

	rz_core_free(core);
	mu_end;
	mu_end;
}

static bool test_load_v9_v10_stack_vars_sp(int version, const char *prj_file) {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, version, prj_file);

	RzAnalysisFunction *f = rz_analysis_get_function_byname(core->analysis, "sym.varfunc");
	mu_assert_notnull(f, "function");
	mu_assert_eq(rz_pvector_len(&f->vars), 4, "vars count");
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(f, "lightbulb");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0x10, "var storage");
	var = rz_analysis_function_get_var_byname(f, "sun");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0xc, "var storage");
	var = rz_analysis_function_get_var_byname(f, "last");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0x8, "var storage");
	var = rz_analysis_function_get_var_byname(f, "chance");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0x4, "var storage");

	f = rz_analysis_get_function_byname(core->analysis, "main");
	mu_assert_notnull(f, "function");
	mu_assert_eq(rz_pvector_len(&f->vars), 3, "vars count");
	var = rz_analysis_function_get_var_byname(f, "argc");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "var storage");
	mu_assert_streq(var->storage.reg, "rdi", "var storage");
	var = rz_analysis_function_get_var_byname(f, "argv");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "var storage");
	mu_assert_streq(var->storage.reg, "rsi", "var storage");
	var = rz_analysis_function_get_var_byname(f, "var_ch");
	mu_assert_notnull(var, "var");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage");
	mu_assert_eq(var->storage.stack_off, -0xc, "var storage");

	rz_core_free(core);
	mu_end;
	mu_end;
}

int all_tests() {
	mu_run_test(test_migrate_v1_v2_noreturn);
	mu_run_test(test_migrate_v1_v2_noreturn_empty);
	mu_run_test(test_migrate_v2_v3_typelink_callables);
	mu_run_test(test_migrate_v2_v3_types_empty);
	mu_run_test(test_migrate_v3_v4_typelink);
	mu_run_test(test_migrate_v4_v5_types);
	mu_run_test(test_migrate_v5_v6);
	mu_run_test(test_migrate_v6_v7_esil_pins);
	mu_run_test(test_migrate_v7_v8_zignatures);
	mu_run_test(test_migrate_v8_v9_fingerprint);
	mu_run_test(test_migrate_v9_v10_stackptr);
	mu_run_test(test_migrate_v10_v11_stack_vars_bp);
	mu_run_test(test_migrate_v10_v11_stack_vars_sp);
	mu_run_test(test_migrate_v9_v10_v11_stack_vars_bp);
	mu_run_test(test_migrate_v9_v10_v11_stack_vars_sp);
	mu_run_test(test_load_v1_noreturn);
	mu_run_test(test_load_v1_noreturn_empty);
	mu_run_test(test_load_v1_unknown_type);
	mu_run_test(test_load_v2_callables);
	mu_run_test(test_load_v2_typelink);
	mu_run_test(test_load_v2_types_empty);
	mu_run_test(test_load_v3_typelink);
	mu_run_test(test_load_v4_types);
	mu_run_test(test_load_v5);
	mu_run_test(test_load_v6_esil_pins);
	mu_run_test(test_load_v7_zignatures);
	mu_run_test(test_load_v8_fingerprint);
	mu_run_test(test_load_v9_stackptr);
	mu_run_test(test_load_v9_v10_stack_vars_bp, 9, "prj/v9-bp-vars.rzdb");
	mu_run_test(test_load_v9_v10_stack_vars_sp, 9, "prj/v9-sp-vars.rzdb");
	mu_run_test(test_load_v9_v10_stack_vars_bp, 10, "prj/v10-bp-vars.rzdb");
	mu_run_test(test_load_v9_v10_stack_vars_sp, 10, "prj/v10-sp-vars.rzdb");
	return tests_passed != tests_run;
}

mu_main(all_tests)
