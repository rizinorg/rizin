// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "test_config.h"
#include "../unit/minunit.h"

bool test_rz_analysis_global_var() {
	RzCore *core = rz_core_new();
	RzAnalysis *analysis = core->analysis;
	rz_type_db_init(analysis->typedb, TEST_BUILD_TYPES_DIR, NULL, 0, NULL);

	RzAnalysisVarGlobal *glob = rz_analysis_var_global_new("foo", 0x1337);
	mu_assert_notnull(glob, "create a global variable");
	mu_assert_streq(glob->name, "foo", "global var name");
	mu_assert_eq(glob->addr, 0x1337, "global var address");
	mu_assert_null(glob->analysis, "global var analysis");
	RzTypeParser *parser = rz_type_parser_new();
	mu_assert_notnull(parser, "create type parser");
	char *errmsg = NULL;
	RzType *typ = rz_type_parse_string_single(parser, "int", &errmsg);
	mu_assert_notnull(typ, "parsed type");
	rz_analysis_var_global_set_type(glob, typ);
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");
	RzFlagItem *flag = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_null(flag, "no flag yet");

	bool added = rz_analysis_var_global_add(analysis, glob);
	mu_assert_true(added, "add global var");
	flag = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_notnull(flag, "global var flag_item");
	mu_assert_eq(flag->offset, glob->addr, "flag item addr");
	mu_assert_streq(flag->name, "foo", "flag item name");
	mu_assert_streq(flag->space->name, RZ_FLAGS_FS_GLOBALS, "flag space");

	glob = NULL;
	glob = rz_analysis_var_global_get_byaddr_at(analysis, 0x1337);
	mu_assert_notnull(glob, "get global var by addr");
	mu_assert_streq(glob->name, "foo", "global var name");
	mu_assert_eq(glob->addr, 0x1337, "global var address");
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	glob = NULL;
	glob = rz_analysis_var_global_get_byname(analysis, "foo");
	mu_assert_notnull(glob, "get global var by addr");
	mu_assert_streq(glob->name, "foo", "global var name");
	mu_assert_eq(glob->addr, 0x1337, "global var address");
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	glob = NULL;
	glob = rz_analysis_var_global_get_byaddr_in(analysis, 0x1339); // test RBTree
	mu_assert_notnull(glob, "get global var by addr");
	mu_assert_streq(glob->name, "foo", "global var name");
	mu_assert_eq(glob->addr, 0x1337, "global var address");
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	RzFlagItem *flag_exists = rz_flag_get(analysis->flb.f, glob->name);
	mu_assert_notnull(flag_exists, "flag not found");

	bool rename = rz_analysis_var_global_rename(analysis, "foo", "bar");
	mu_assert_true(rename, "rename global var");
	glob = NULL;
	glob = rz_analysis_var_global_get_byname(analysis, "bar");
	mu_assert_notnull(glob, "get global var by addr");
	mu_assert_streq(glob->name, "bar", "global var name");
	mu_assert_streq(flag->name, "bar", "global flag_item name");
	RzFlagItem *flag2 = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_ptreq(flag2, flag, "still same flag");

	bool deleted = rz_analysis_var_global_delete_byaddr_at(analysis, 0x1337);
	mu_assert_true(deleted, "delete global var");
	glob = NULL;
	glob = rz_analysis_var_global_get_byaddr_at(analysis, 0x1337);
	mu_assert_null(glob, "get deleted global var");
	RzFlagItem *flag_deleted = rz_flag_get_i(analysis->flb.f, 0x1337);
	mu_assert_null(flag_deleted, "get deleted flag");

	// re add
	glob = rz_analysis_var_global_new("foo", 0x1337);
	mu_assert_notnull(glob, "create a global variable");
	mu_assert_streq(glob->name, "foo", "global var name");
	mu_assert_eq(glob->addr, 0x1337, "global var address");
	mu_assert_null(glob->analysis, "global var flags");
	errmsg = NULL;
	typ = rz_type_parse_string_single(parser, "int", &errmsg);
	mu_assert_notnull(typ, "parsed type");
	rz_analysis_var_global_set_type(glob, typ);
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	added = rz_analysis_var_global_add(analysis, glob);
	mu_assert_true(added, "add global var");

	glob = NULL;
	glob = rz_analysis_var_global_get_byaddr_at(analysis, 0x1337);
	mu_assert_notnull(glob, "get readded global var");

	flag_exists = rz_flag_get(analysis->flb.f, glob->name);
	mu_assert_notnull(flag_exists, "flag not found");

	deleted = rz_analysis_var_global_delete_byaddr_in(analysis, 0x133A); // test RBTree again
	mu_assert_true(deleted, "delete global var");
	glob = NULL;
	glob = rz_analysis_var_global_get_byaddr_in(analysis, 0x133A);
	mu_assert_null(glob, "get deleted global var");

	// re add
	glob = rz_analysis_var_global_new("bar", 0x114514);
	mu_assert_notnull(glob, "create a global variable");
	mu_assert_streq(glob->name, "bar", "global var name");
	mu_assert_eq(glob->addr, 0x114514, "global var address");
	mu_assert_null(glob->analysis, "global var flags");
	typ = rz_type_parse_string_single(parser, "int", &errmsg);
	mu_assert_notnull(typ, "parsed type");
	rz_analysis_var_global_set_type(glob, typ);
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	added = rz_analysis_var_global_add(analysis, glob);
	mu_assert_true(added, "add global var");
	flag = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_notnull(flag, "global var flag_item");
	mu_assert_eq(flag->offset, glob->addr, "flag item addr");
	mu_assert_streq(flag->name, "bar", "flag item name");

	glob = NULL;
	glob = rz_analysis_var_global_get_byname(analysis, "bar");
	mu_assert_notnull(glob, "get readded global var");

	flag_exists = rz_flag_get(analysis->flb.f, glob->name);
	mu_assert_notnull(flag_exists, "flag not found");

	deleted = rz_analysis_var_global_delete_byname(analysis, "bar");
	glob = NULL;
	glob = rz_analysis_var_global_get_byname(analysis, "bar");
	mu_assert_null(glob, "get deleted global var");

	// create global
	typ = rz_type_parse_string_single(parser, "int", &errmsg);
	mu_assert_notnull(typ, "parsed type");
	mu_assert_true(rz_analysis_var_global_create(analysis, "crab", typ, 0x125418),
		"create global var");

	glob = rz_analysis_var_global_get_byname(analysis, "crab");
	mu_assert_notnull(glob, "create a global variable");
	mu_assert_streq(glob->name, "crab", "global var name");
	mu_assert_eq(glob->addr, 0x125418, "global var address");
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	flag = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_notnull(flag, "global var flag_item");
	mu_assert_eq(flag->offset, glob->addr, "flag item addr");
	mu_assert_streq(flag->name, "crab", "flag item name");

	rz_type_parser_free(parser);
	rz_core_free(core);
	mu_end;
}

bool test_flag_confusion_space_name() {
	RzCore *core = rz_core_new();
	RzAnalysis *analysis = core->analysis;

	rz_flag_space_set(core->flags, "mire");
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_new("foo", 0x1337);
	RzTypeParser *parser = rz_type_parser_new();
	mu_assert_notnull(parser, "create type parser");
	RzType *typ = rz_type_parse_string_single(parser, "int", NULL);
	rz_analysis_var_global_set_type(glob, typ);
	rz_analysis_var_global_add(analysis, glob);
	RzFlagItem *fi = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_notnull(fi, "global var flag_item");
	mu_assert_eq(fi->offset, glob->addr, "flag item addr");
	mu_assert_streq(fi->name, "foo", "flag item name");
	mu_assert_streq(fi->space->name, RZ_FLAGS_FS_GLOBALS, "flag space");

	rz_flag_space_set(core->flags, "ulu-mulu");
	RzFlagItem *fii = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_ptreq(fii, fi, "unaffected by space change");

	rz_flag_rename(core->flags, fi, "bar");
	fi = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_null(fi, "flag lost");

	rz_type_parser_free(parser);
	rz_core_free(core);
	mu_end;
}

bool test_flag_confusion_addr() {
	RzCore *core = rz_core_new();
	RzAnalysis *analysis = core->analysis;

	RzAnalysisVarGlobal *glob = rz_analysis_var_global_new("foo", 0x1337);
	RzTypeParser *parser = rz_type_parser_new();
	mu_assert_notnull(parser, "create type parser");
	RzType *typ = rz_type_parse_string_single(parser, "int", NULL);
	rz_analysis_var_global_set_type(glob, typ);
	rz_analysis_var_global_add(analysis, glob);
	RzFlagItem *fi = rz_analysis_var_global_get_flag_item(glob);

	rz_flag_set(core->flags, fi->name, 0x31337, fi->size);
	fi = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_null(fi, "flag lost");

	rz_type_parser_free(parser);
	rz_core_free(core);
	mu_end;
}

bool test_global_vars_from_symbols() {
	RzCore *core = rz_core_new();
	rz_type_db_init(core->analysis->typedb, TEST_BUILD_TYPES_DIR, NULL, 0, NULL);

	const char *fpath = "bins/elf/dectest64";
	mu_assert_notnull(rz_core_file_open(core, fpath, RZ_PERM_R, 0), "open file");
	rz_core_bin_load(core, fpath, 0);
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_SIMPLE);

	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(core->analysis, "global_var");
	mu_assert_notnull(glob, "global_var populated from symbol table");
	mu_assert_eq(glob->addr, 0x00404050, "global_var address");
	mu_assert_null(glob->type, "global_var type is NULL (no DWARF)");

	glob = rz_analysis_var_global_get_byname(core->analysis, "global_array");
	mu_assert_notnull(glob, "global_array populated from symbol table");
	mu_assert_eq(glob->addr, 0x00404058, "global_array address");
	mu_assert_null(glob->type, "global_array type is NULL (no DWARF)");

	rz_core_free(core);
	mu_end;
}

bool test_global_var_null_type_output() {
	RzCore *core = rz_core_new();
	rz_type_db_init(core->analysis->typedb, TEST_BUILD_TYPES_DIR, NULL, 0, NULL);

	RzAnalysisVarGlobal *glob = rz_analysis_var_global_new("test_null_type", 0x1234);
	mu_assert_notnull(glob, "create global with NULL type");
	rz_analysis_var_global_add(core->analysis, glob);

	char *output = rz_core_cmd_str(core, "avgl");
	mu_assert_notnull(output, "avgl output");
	mu_assert_true(strstr(output, "test_null_type") != NULL, "standard shows name");
	mu_assert_true(strstr(output, "unknown") != NULL, "standard shows unknown type");
	free(output);

	output = rz_core_cmd_str(core, "avglq");
	mu_assert_notnull(output, "avglq output");
	mu_assert_true(strstr(output, "test_null_type") != NULL, "quiet shows name");
	free(output);

	output = rz_core_cmd_str(core, "avglj");
	mu_assert_notnull(output, "avglj output");
	mu_assert_true(strstr(output, "\"type\":\"unknown\"") != NULL, "json shows unknown type");
	mu_assert_true(strstr(output, "\"size\":0") != NULL, "json shows size 0");
	free(output);

	output = rz_core_cmd_str(core, "avglt");
	mu_assert_notnull(output, "avglt output");
	mu_assert_true(strstr(output, "unknown") != NULL, "table shows unknown type");
	free(output);

	rz_core_free(core);
	mu_end;
}

bool test_global_var_no_duplicate() {
	RzCore *core = rz_core_new();
	RzAnalysis *analysis = core->analysis;
	rz_type_db_init(analysis->typedb, TEST_BUILD_TYPES_DIR, NULL, 0, NULL);

	RzAnalysisVarGlobal *glob = rz_analysis_var_global_new("existing_global", 0x404050);
	mu_assert_notnull(glob, "create existing global");
	RzTypeParser *parser = rz_type_parser_new();
	RzType *typ = rz_type_parse_string_single(parser, "int", NULL);
	rz_analysis_var_global_set_type(glob, typ);
	rz_analysis_var_global_add(analysis, glob);

	const char *fpath = "bins/elf/dectest64";
	mu_assert_notnull(rz_core_file_open(core, fpath, RZ_PERM_R, 0), "open file");
	rz_core_bin_load(core, fpath, 0);
	rz_core_perform_auto_analysis(core, RZ_CORE_ANALYSIS_SIMPLE);

	RzAnalysisVarGlobal *check = rz_analysis_var_global_get_byaddr_at(analysis, 0x404050);
	mu_assert_notnull(check, "global at address still exists");
	mu_assert_streq(check->name, "existing_global", "original global preserved");
	mu_assert_notnull(check->type, "original type preserved");

	mu_assert_null(rz_analysis_var_global_get_byname(analysis, "global_var"), "global_var not created (duplicate address)");

	rz_type_parser_free(parser);
	rz_core_free(core);
	mu_end;
}

bool test_flag_confusion_delete() {
	RzCore *core = rz_core_new();
	RzAnalysis *analysis = core->analysis;
	rz_type_db_init(analysis->typedb, TEST_BUILD_TYPES_DIR, NULL, 0, NULL);

	RzAnalysisVarGlobal *glob = rz_analysis_var_global_new("foo", 0x1337);
	RzTypeParser *parser = rz_type_parser_new();
	mu_assert_notnull(parser, "create type parser");
	RzType *typ = rz_type_parse_string_single(parser, "int", NULL);
	rz_analysis_var_global_set_type(glob, typ);
	rz_analysis_var_global_add(analysis, glob);
	RzFlagItem *fi = rz_analysis_var_global_get_flag_item(glob);

	rz_flag_unset(core->flags, fi);
	fi = rz_analysis_var_global_get_flag_item(glob);
	mu_assert_null(fi, "flag lost");

	rz_analysis_var_global_rename(analysis, "foo", "bar");
	mu_assert_streq(glob->name, "bar", "rename without flag");
	mu_assert_eq(glob->addr, 0x1337, "addr");

	glob = NULL;
	glob = rz_analysis_var_global_get_byaddr_at(analysis, 0x1337);
	mu_assert_notnull(glob, "get global var by addr");
	mu_assert_streq(glob->name, "bar", "global var name");
	mu_assert_eq(glob->addr, 0x1337, "global var address");
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	glob = NULL;
	glob = rz_analysis_var_global_get_byname(analysis, "bar");
	mu_assert_notnull(glob, "get global var by addr");
	mu_assert_streq(glob->name, "bar", "global var name");
	mu_assert_eq(glob->addr, 0x1337, "global var address");
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	glob = NULL;
	glob = rz_analysis_var_global_get_byaddr_in(analysis, 0x1339); // test RBTree
	mu_assert_notnull(glob, "get global var by addr");
	mu_assert_streq(glob->name, "bar", "global var name");
	mu_assert_eq(glob->addr, 0x1337, "global var address");
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	rz_type_parser_free(parser);
	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_global_var);
	mu_run_test(test_flag_confusion_space_name);
	mu_run_test(test_flag_confusion_addr);
	mu_run_test(test_flag_confusion_delete);
	mu_run_test(test_global_vars_from_symbols);
	mu_run_test(test_global_var_null_type_output);
	mu_run_test(test_global_var_no_duplicate);
	return tests_passed != tests_run;
}

mu_main(all_tests)
