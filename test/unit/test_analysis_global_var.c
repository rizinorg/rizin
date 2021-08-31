// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "minunit.h"

bool test_rz_analysis_global_var() {
	RzCore *core = rz_core_new();
	RzAnalysis *analysis = core->analysis;

	RzAnalysisVarGlobal *glob = rz_analysis_var_global_new("foo", 0x1337);
	mu_assert_notnull(glob, "create a global variable");
	mu_assert_streq(glob->name, "foo", "global var name");
	mu_assert_eq(glob->addr, 0x1337, "global var address");
	mu_assert_null(glob->flag_item, "global var flag_item");
	mu_assert_null(glob->flags, "global var flags");
	RzTypeParser *parser = rz_type_parser_new();
	mu_assert_notnull(parser, "create type parser");
	char *errmsg = NULL;
	RzType *typ = rz_type_parse_string_single(parser, "int", &errmsg);
	mu_assert_notnull(typ, "parsed type");
	rz_analysis_var_global_set_type(glob, typ, analysis->typedb);
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	bool added = rz_analysis_var_global_add(analysis, glob);
	mu_assert_true(added, "add global var");
	mu_assert_notnull(glob->flag_item, "flag_item null");
	mu_assert_notnull(glob->flags, "flags null");

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

	RzFlagItem *flag_exists = rz_flag_get(glob->flags, glob->name);
	mu_assert_notnull(flag_exists, "flag not found");

	bool rename = rz_analysis_var_global_rename(analysis, "foo", "bar");
	mu_assert_true(rename, "rename global var");
	glob = NULL;
	glob = rz_analysis_var_global_get_byname(analysis, "bar");
	mu_assert_notnull(glob, "get global var by addr");
	mu_assert_streq(glob->name, "bar", "global var name");
	mu_assert_streq(glob->flag_item->name, "bar", "global flag_item name");

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
	mu_assert_null(glob->flag_item, "global var flag_item");
	mu_assert_null(glob->flags, "global var flags");
	errmsg = NULL;
	typ = rz_type_parse_string_single(parser, "int", &errmsg);
	mu_assert_notnull(typ, "parsed type");
	rz_analysis_var_global_set_type(glob, typ, analysis->typedb);
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	added = rz_analysis_var_global_add(analysis, glob);
	mu_assert_true(added, "add global var");
	mu_assert_notnull(glob->flag_item, "flag_item null");
	mu_assert_notnull(glob->flags, "flags null");

	glob = NULL;
	glob = rz_analysis_var_global_get_byaddr_at(analysis, 0x1337);
	mu_assert_notnull(glob, "get readded global var");

	flag_exists = rz_flag_get(glob->flags, glob->name);
	mu_assert_notnull(flag_exists, "flag not found");

	deleted = rz_analysis_var_global_delete_byaddr_in(analysis, 0x133A); //test RBTree again
	mu_assert_true(deleted, "delete global var");
	glob = NULL;
	glob = rz_analysis_var_global_get_byaddr_in(analysis, 0x133A);
	mu_assert_null(glob, "get deleted global var");

	// re add
	glob = rz_analysis_var_global_new("bar", 0x114514);
	mu_assert_notnull(glob, "create a global variable");
	mu_assert_streq(glob->name, "bar", "global var name");
	mu_assert_eq(glob->addr, 0x114514, "global var address");
	mu_assert_null(glob->flag_item, "global var flag_item");
	mu_assert_null(glob->flags, "global var flags");
	typ = rz_type_parse_string_single(parser, "int", &errmsg);
	mu_assert_notnull(typ, "parsed type");
	rz_analysis_var_global_set_type(glob, typ, analysis->typedb);
	mu_assert_streq(glob->type->identifier.name, "int", "global var type");

	added = rz_analysis_var_global_add(analysis, glob);
	mu_assert_true(added, "add global var");
	mu_assert_notnull(glob->flag_item, "flag_item null");
	mu_assert_notnull(glob->flags, "flags null");

	glob = NULL;
	glob = rz_analysis_var_global_get_byname(analysis, "bar");
	mu_assert_notnull(glob, "get readded global var");

	flag_exists = rz_flag_get(glob->flags, glob->name);
	mu_assert_notnull(flag_exists, "flag not found");

	deleted = rz_analysis_var_global_delete_byname(analysis, "bar");
	glob = NULL;
	glob = rz_analysis_var_global_get_byname(analysis, "bar");
	mu_assert_null(glob, "get deleted global var");

	rz_type_parser_free(parser);
	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_global_var);
	return tests_passed != tests_run;
}

mu_main(all_tests)
