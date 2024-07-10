// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_project.h>

#include "../unit/minunit.h"
#include "rz_config.h"
#include "sdb.h"

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

	mu_assert_null(sdb_get(types_db, "addr.1337.noreturn"), "old noreturn deleted");
	mu_assert_null(sdb_get(types_db, "addr.4242.noreturn"), "old noreturn deleted");

	Sdb *noreturn_db = sdb_ns(analysis_db, "noreturn", false);
	mu_assert_notnull(noreturn_db, "noreturn ns");

	mu_assert_streq_free(sdb_get(noreturn_db, "addr.1337.noreturn"), "true", "new noreturn added");
	mu_assert_streq_free(sdb_get(noreturn_db, "addr.4242.noreturn"), "true", "new noreturn added");

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
	mu_assert_null(sdb_get(types_db, "func._Exit.args"), "old function deleted");
	mu_assert_null(sdb_get(types_db, "_Exit"), "old function deleted");
	mu_assert_null(sdb_get(types_db, "link.080484b0"), "old typelink deleted");

	Sdb *callables_db = sdb_ns(analysis_db, "callables", false);
	mu_assert_notnull(callables_db, "callables ns");
	mu_assert_streq_free(sdb_get(callables_db, "func._Exit.args"), "1", "new callable added");
	mu_assert_streq_free(sdb_get(callables_db, "_Exit"), "func", "new callable added");

	Sdb *typelinks_db = sdb_ns(analysis_db, "typelinks", false);
	mu_assert_notnull(typelinks_db, "typelinks ns");
	mu_assert_streq_free(sdb_get(typelinks_db, "0x080484b0"), "char *", "new typelink added");

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
	mu_assert_streq_free(sdb_get(typelinks_db, "0x08048660"), "uint32_t", "new callable added");

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
	mu_assert_streq_free(sdb_get(types_db, "unknown_t"), "type", "unknown_t added");
	mu_assert_streq_free(sdb_get(types_db, "type.unknown_t"), "d", "unknown_t added");
	mu_assert_streq_free(sdb_get(types_db, "type.unknown_t.size"), "32", "unknown_t added");

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
	mu_assert_notnull(config_db, "config ns");
	mu_assert_streq_free(sdb_get(config_db, "analysis.apply.signature"), "true", "config");
	mu_assert_null(sdb_get(config_db, "zign.autoload"), "config");
	mu_assert_null(sdb_get(config_db, "zign.diff.bthresh"), "config");
	mu_assert_null(sdb_get(config_db, "zign.diff.gthresh"), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.bytes"), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.graph"), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.hash"), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.offset"), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.refs"), "config");
	mu_assert_null(sdb_get(config_db, "zign.match.types"), "config");
	mu_assert_null(sdb_get(config_db, "zign.maxsz"), "config");
	mu_assert_null(sdb_get(config_db, "zign.mincc"), "config");
	mu_assert_null(sdb_get(config_db, "zign.minsz"), "config");
	mu_assert_null(sdb_get(config_db, "zign.prefix"), "config");
	mu_assert_null(sdb_get(config_db, "zign.threshold"), "config");

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
	const char *val = sdb_const_get(functions_db, "0x113c");
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
	val = sdb_const_get(functions_db, "0x1175");
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
	const char *val = sdb_const_get(functions_db, "0x1137");
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
	val = sdb_const_get(functions_db, "0x1174");
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

static bool test_migrate_v2_v12() {
	RzProject *prj = rz_project_load_file_raw("prj/v2-types-empty.rzdb");
	mu_assert_notnull(prj, "load raw project");

	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate(prj, 2, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *config_db = sdb_ns(core_db, "config", false);
	mu_assert_notnull(config_db, "debug ns");
	mu_assert_notnull(sdb_const_get(config_db, "asm.debuginfo"), "asm.debuginfo");
	mu_assert_notnull(sdb_const_get(config_db, "asm.debuginfo.abspath"), "asm.debuginfo.abspath");
	mu_assert_notnull(sdb_const_get(config_db, "asm.debuginfo.file"), "asm.debuginfo.file");

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
	const char *val = sdb_const_get(functions_db, "0x113c");
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
	val = sdb_const_get(functions_db, "0x1175");
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
	const char *val = sdb_const_get(functions_db, "0x1137");
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
	val = sdb_const_get(functions_db, "0x1174");
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

static bool test_migrate_v14_v15() {
	RzProject *prj = rz_project_load_file_raw("prj/v14-float_ex1_hightec.rzdb.gz");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v14_v15(prj, res);
	mu_assert_true(s, "migrate success");

	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *seek_db = sdb_ns(core_db, "seek", false);
	mu_assert_notnull(seek_db, "seek ns");

	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v15_v16_str_config() {
	RzProject *prj = rz_project_load_file_raw("prj/v15-str-config.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v15_v16(prj, res);
	mu_assert_true(s, "migrate success");
	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *config_db = sdb_ns(core_db, "config", false);
	mu_assert_notnull(config_db, "config ns");
	mu_assert_null(sdb_get(config_db, "bin.maxstr"), "config");
	mu_assert_null(sdb_get(config_db, "bin.minstr"), "config");
	mu_assert_null(sdb_get(config_db, "bin.str.enc"), "config");
	mu_assert_null(sdb_get(config_db, "bin.maxstrbuf"), "config");
	mu_assert_streq_free(sdb_get(config_db, "str.search.min_length"), "6", "config");
	mu_assert_streq_free(sdb_get(config_db, "str.search.encoding"), "utf8", "config");
	mu_assert_streq_free(sdb_get(config_db, "str.search.buffer_size"), "0x00b00123", "config");
	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v16_v17_flags_base() {
	RzProject *prj = rz_project_load_file_raw("prj/v16-flags-base.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v16_v17(prj, res);
	mu_assert_true(s, "migrate success");
	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *config_db = sdb_ns(core_db, "flags", false);
	mu_assert_notnull(config_db, "config ns");
	mu_assert_null(sdb_get(config_db, "base"), "flags base");
	rz_serialize_result_info_free(res);
	rz_project_free(prj);
	mu_end;
}

static bool test_migrate_v17_v18_rop_config() {
	RzProject *prj = rz_project_load_file_raw("prj/v17-rop-config.rzdb");
	mu_assert_notnull(prj, "load raw project");
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	bool s = rz_project_migrate_v17_v18(prj, res);
	mu_assert_true(s, "migrate success");
	Sdb *core_db = sdb_ns(prj, "core", false);
	mu_assert_notnull(core_db, "core ns");
	Sdb *config_db = sdb_ns(core_db, "config", false);
	mu_assert_null(sdb_get(config_db, "rop.sdb"), "config");
	mu_assert_null(sdb_get(config_db, "rop.db"), "config");
	mu_assert_streq_free(sdb_get(config_db, "rop.cache"), "false", "config");
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

	RzAnalysisVarGlobal *gv = rz_analysis_var_global_get_byaddr_at(core->analysis, 0x80484b0);
	mu_assert_notnull(gv, "typelink converted to a global var");
	mu_assert_eq(RZ_TYPE_KIND_POINTER, gv->type->kind, "typelink is a pointer");
	mu_assert_true(rz_type_atomic_str_eq(core->analysis->typedb, gv->type->pointer.type, "char"), "typelink is char *");

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
	RzCallableArg *arg0 = rz_pvector_at(chmod->args, 0);
	mu_assert_notnull(arg0, "func \"chmod\" has 1st argument");
	mu_assert_streq(arg0->name, "path", "has \"path\" argument");
	RzCallableArg *arg1 = rz_pvector_at(chmod->args, 1);
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

	RzAnalysisVarGlobal *gv = rz_analysis_var_global_get_byaddr_at(core->analysis, 0x08048660);
	mu_assert_notnull(gv, "typelink converted to a global var");
	mu_assert_streq_free(rz_type_as_string(core->analysis->typedb, gv->type), "uint32_t", "typelink");

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
}

static bool test_load_v12() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 12, "prj/v12-types-empty.rzdb");

	mu_assert_notnull(rz_config_get(core->config, "asm.debuginfo"), "asm.debuginfo");
	mu_assert_notnull(rz_config_get(core->config, "asm.debuginfo.abspath"), "asm.debuginfo.abspath");
	mu_assert_notnull(rz_config_get(core->config, "asm.debuginfo.file"), "asm.debuginfo.file");
	mu_assert_notnull(rz_config_get(core->config, "asm.debuginfo.lines"), "asm.debuginfo.lines");

	rz_core_free(core);
	mu_end;
}

static bool test_load_v14() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 14, "prj/v14-float_ex1_hightec.rzdb.gz");
	RzAnalysisFunction *f = rz_analysis_get_function_byname(core->analysis, "dbg.printf");
	mu_assert_notnull(f, "function");
	mu_assert_eq(rz_pvector_len(&f->vars), 3, "vars count");
	mu_assert_eq(rz_analysis_arg_count(f), 1, "args count");

	RzAnalysisVar *v = rz_analysis_function_get_var_byname(f, "ans");
	mu_assert_notnull(v, "var");
	mu_assert_eq(v->storage.type, RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING, "var storage");
	mu_assert_eq(v->storage.dw_var_off, 14178, "var storage dw_var_off");
	rz_core_free(core);
	mu_end;
}

static bool test_load_v15_seek_history() {
	RzCore *core = rz_core_new();

	// enable the cursor so we can check the deserialized value
	rz_print_set_cursor(core->print, true, 0, 0);

	BEGIN_LOAD_TEST(core, 15, "prj/v15-seek-history.rzdb");

	mu_assert_eq(rz_vector_len(&core->seek_history.undos), 1, "bad number of undos");
	RzCoreSeekItem *item = rz_vector_index_ptr(&core->seek_history.undos, 0);
	mu_assert_eq(item->offset, 0x5ae0, "bad undo offset");
	mu_assert_eq(item->cursor, 1, "bad undo cursor");

	mu_assert_eq(rz_vector_len(&core->seek_history.redos), 2, "bad number of redos");
	item = rz_vector_index_ptr(&core->seek_history.redos, 1);
	mu_assert_eq(item->offset, 0x5b00, "bad first redo offset");
	mu_assert_eq(item->cursor, 3, "bad first redo cursor");
	item = rz_vector_index_ptr(&core->seek_history.redos, 0);
	mu_assert_eq(item->offset, 0x5b10, "bad second redo offset");
	mu_assert_eq(item->cursor, 4, "bad second redo cursor");

	// core offset not restored from current seek history item, so not checked
	mu_assert_eq(rz_print_get_cursor(core->print), 2, "bad current cursor");

	rz_core_free(core);
	mu_end;
}

static bool test_load_v15_str_config() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 15, "prj/v15-str-config.rzdb");
	mu_assert_eq(rz_config_get_i(core->config, "str.search.min_length"), 6, "str.search.min_length");
	mu_assert_streq(rz_config_get(core->config, "str.search.encoding"), "utf8", "str.search.encoding");
	mu_assert_eq(rz_config_get_i(core->config, "str.search.buffer_size"), 0x00b00123, "str.search.buffer_size");
	rz_core_free(core);
	mu_end;
}

static bool test_load_v16() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 16, "prj/v16-flags-base.rzdb");
	// No new or changed info here
	rz_core_free(core);
	mu_end;
}

static bool test_load_v17() {
	RzCore *core = rz_core_new();
	BEGIN_LOAD_TEST(core, 17, "prj/v17-rop-config.rzdb");
	mu_assert_eq(rz_config_get_b(core->config, "rop.cache"), false, "rop.cache");
	rz_core_free(core);
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
	mu_run_test(test_migrate_v2_v12);
	mu_run_test(test_migrate_v14_v15);
	mu_run_test(test_migrate_v15_v16_str_config);
	mu_run_test(test_migrate_v16_v17_flags_base);
	mu_run_test(test_migrate_v17_v18_rop_config);
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
	mu_run_test(test_load_v12);
	mu_run_test(test_load_v14);
	mu_run_test(test_load_v15_seek_history);
	mu_run_test(test_load_v15_str_config);
	mu_run_test(test_load_v16);
	mu_run_test(test_load_v17);
	return tests_passed != tests_run;
}

mu_main(all_tests)
