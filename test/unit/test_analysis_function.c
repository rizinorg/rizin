// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "minunit.h"

#include "test_analysis_block_invars.inl"

static void setup_types_db(RzTypeDB *typedb) {
	RzBaseType *b_int_t = rz_type_base_type_new(RZ_BASE_TYPE_KIND_ATOMIC);
	if (!b_int_t) {
		return;
	}
	b_int_t->name = strdup("int");
	b_int_t->size = 32;
	rz_type_db_save_base_type(typedb, b_int_t);
}

static void setup_sdb_for_function(Sdb *res) {
	sdb_set(res, "ExitProcess", "func", 0);
	sdb_num_set(res, "func.ExitProcess.args", 0, 0);
	sdb_set(res, "func.ExitProcess.ret", "void", 0);
	sdb_set(res, "ReadFile", "func", 0);
	sdb_num_set(res, "func.ReadFile.args", 0, 0);
	sdb_set(res, "func.ReadFile.ret", "void", 0);
	sdb_set(res, "memcpy", "func", 0);
	sdb_num_set(res, "func.memcpy.args", 0, 0);
	sdb_set(res, "func.memcpy.ret", "void", 0);
	sdb_set(res, "strchr", "func", 0);
	sdb_num_set(res, "func.strchr.args", 0, 0);
	sdb_set(res, "func.strchr.ret", "void", 0);
	sdb_set(res, "__stack_chk_fail", "func", 0);
	sdb_num_set(res, "func.__stack_chk_fail.args", 0, 0);
	sdb_set(res, "func.__stack_chk_fail.ret", "void", 0);
	sdb_set(res, "WSAStartup", "func", 0);
	sdb_num_set(res, "func.WSAStartup.args", 0, 0);
	sdb_set(res, "func.WSAStartup.ret", "void", 0);
}

bool ht_up_count(void *user, const ut64 k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

bool ht_pp_count(void *user, const void *k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

static bool function_check_invariants(RzAnalysis *analysis) {
	if (!block_check_invariants(analysis)) {
		return false;
	}

	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (analysis->fcns, it, fcn) {
		mu_assert_ptreq(ht_up_find(analysis->ht_addr_fun, fcn->addr, NULL), fcn, "function in addr ht");
		mu_assert_ptreq(ht_pp_find(analysis->ht_name_fun, fcn->name, NULL), fcn, "function in name ht");
	}

	size_t addr_count = 0;
	ht_up_foreach(analysis->ht_addr_fun, ht_up_count, &addr_count);
	mu_assert_eq(addr_count, rz_list_length(analysis->fcns), "function addr ht count");

	size_t name_count = 0;
	ht_pp_foreach(analysis->ht_name_fun, ht_pp_count, &name_count);
	mu_assert_eq(name_count, rz_list_length(analysis->fcns), "function name ht count");

	return true;
}

#define check_invariants function_check_invariants
#define check_leaks      block_check_leaks

#define assert_invariants(analysis) \
	do { \
		if (!check_invariants(analysis)) { \
			return false; \
		} \
	} while (0)
#define assert_leaks(analysis) \
	do { \
		if (!check_leaks(analysis)) { \
			return false; \
		} \
	} while (0)

bool test_rz_analysis_function_relocate() {
	RzAnalysis *analysis = rz_analysis_new();
	assert_invariants(analysis);

	RzAnalysisFunction *fa = rz_analysis_create_function(analysis, "do_something", 0x1337, 0, NULL);
	assert_invariants(analysis);
	RzAnalysisFunction *fb = rz_analysis_create_function(analysis, "do_something_else", 0xdeadbeef, 0, NULL);
	assert_invariants(analysis);
	rz_analysis_create_function(analysis, "do_something_different", 0xc0ffee, 0, NULL);
	assert_invariants(analysis);

	bool success = rz_analysis_function_relocate(fa, fb->addr);
	assert_invariants(analysis);
	mu_assert_false(success, "failed relocate");
	mu_assert_eq(fa->addr, 0x1337, "failed relocate addr");

	success = rz_analysis_function_relocate(fa, 0x1234);
	assert_invariants(analysis);
	mu_assert_true(success, "successful relocate");
	mu_assert_eq(fa->addr, 0x1234, "successful relocate addr");

	assert_leaks(analysis);
	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_function_labels() {
	RzAnalysis *analysis = rz_analysis_new();

	RzAnalysisFunction *f = rz_analysis_create_function(analysis, "do_something", 0x1337, 0, NULL);

	bool s = rz_analysis_function_set_label(f, "smartfriend", 0x1339);
	mu_assert_true(s, "set label");
	s = rz_analysis_function_set_label(f, "stray", 0x133c);
	mu_assert_true(s, "set label");
	s = rz_analysis_function_set_label(f, "the", 0x1340);
	mu_assert_true(s, "set label");
	s = rz_analysis_function_set_label(f, "stray", 0x1234);
	mu_assert_false(s, "set label (existing name)");
	s = rz_analysis_function_set_label(f, "henlo", 0x133c);
	mu_assert_false(s, "set label (existing addr)");

	ut64 addr = rz_analysis_function_get_label(f, "smartfriend");
	mu_assert_eq(addr, 0x1339, "get label");
	addr = rz_analysis_function_get_label(f, "stray");
	mu_assert_eq(addr, 0x133c, "get label");
	addr = rz_analysis_function_get_label(f, "skies");
	mu_assert_eq(addr, UT64_MAX, "get label (unknown)");

	const char *name = rz_analysis_function_get_label_at(f, 0x1339);
	mu_assert_streq(name, "smartfriend", "get label at");
	name = rz_analysis_function_get_label_at(f, 0x133c);
	mu_assert_streq(name, "stray", "get label at");
	name = rz_analysis_function_get_label_at(f, 0x1234);
	mu_assert_null(name, "get label at (unknown)");

	rz_analysis_function_delete_label(f, "stray");
	addr = rz_analysis_function_get_label(f, "stray");
	mu_assert_eq(addr, UT64_MAX, "get label (deleted)");
	name = rz_analysis_function_get_label_at(f, 0x133c);
	mu_assert_null(name, "get label at (deleted)");
	addr = rz_analysis_function_get_label(f, "smartfriend");
	mu_assert_eq(addr, 0x1339, "get label (unaffected by delete)");
	name = rz_analysis_function_get_label_at(f, 0x1339);
	mu_assert_streq(name, "smartfriend", "get label at (unaffected by delete)");

	rz_analysis_function_delete_label_at(f, 0x1340);
	addr = rz_analysis_function_get_label(f, "the");
	mu_assert_eq(addr, UT64_MAX, "get label (deleted)");
	name = rz_analysis_function_get_label_at(f, 0x340);
	mu_assert_null(name, "get label at (deleted)");
	addr = rz_analysis_function_get_label(f, "smartfriend");
	mu_assert_eq(addr, 0x1339, "get label (unaffected by delete)");
	name = rz_analysis_function_get_label_at(f, 0x1339);
	mu_assert_streq(name, "smartfriend", "get label at (unaffected by delete)");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_dll_names(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");

	setup_types_db(typedb);
	Sdb *sdb = sdb_new0();
	setup_sdb_for_function(sdb);
	rz_serialize_callables_load(sdb, typedb, NULL);
	sdb_free(sdb);

	char *s;

	s = rz_analysis_function_name_guess(typedb, "sub.KERNEL32.dll_ExitProcess");
	mu_assert_notnull(s, "dll_ should be ignored");
	mu_assert_streq(s, "ExitProcess", "dll_ should be ignored");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "sub.dll_ExitProcess_32");
	mu_assert_notnull(s, "number should be ignored");
	mu_assert_streq(s, "ExitProcess", "number should be ignored");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "sym.imp.KERNEL32.dll_ReadFile");
	mu_assert_notnull(s, "dll_ and number should be ignored case 1");
	mu_assert_streq(s, "ReadFile", "dll_ and number should be ignored case 1");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "sub.VCRUNTIME14.dll_memcpy");
	mu_assert_notnull(s, "dll_ and number should be ignored case 2");
	mu_assert_streq(s, "memcpy", "dll_ and number should be ignored case 2");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "sub.KERNEL32.dll_ExitProcess_32");
	mu_assert_notnull(s, "dll_ and number should be ignored case 3");
	mu_assert_streq(s, "ExitProcess", "dll_ and number should be ignored case 3");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "WS2_32.dll_WSAStartup");
	mu_assert_notnull(s, "dll_ and number should be ignored case 4");
	mu_assert_streq(s, "WSAStartup", "dll_ and number should be ignored case 4");
	free(s);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_ignore_prefixes(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");

	setup_types_db(typedb);
	Sdb *sdb = sdb_new0();
	setup_sdb_for_function(sdb);
	rz_serialize_callables_load(sdb, typedb, NULL);
	sdb_free(sdb);

	char *s;

	s = rz_analysis_function_name_guess(typedb, "fcn.KERNEL32.dll_ExitProcess_32");
	mu_assert_null(s, "fcn. names should be ignored");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "loc.KERNEL32.dll_ExitProcess_32");
	mu_assert_null(s, "loc. names should be ignored");
	free(s);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_remove_rz_prefixes(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");

	setup_types_db(typedb);
	Sdb *sdb = sdb_new0();
	setup_sdb_for_function(sdb);
	rz_serialize_callables_load(sdb, typedb, NULL);
	sdb_free(sdb);

	char *s;

	s = rz_analysis_function_name_guess(typedb, "sym.imp.ExitProcess");
	mu_assert_notnull(s, "sym.imp should be ignored");
	mu_assert_streq(s, "ExitProcess", "sym.imp should be ignored");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "sym.imp.fcn.ExitProcess");
	mu_assert_notnull(s, "sym.imp.fcn should be ignored");
	mu_assert_streq(s, "ExitProcess", "sym.imp.fcn should be ignored");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "longprefix.ExitProcess");
	mu_assert_null(s, "prefixes longer than 3 should not be ignored");
	free(s);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_autonames(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");

	setup_types_db(typedb);
	Sdb *sdb = sdb_new0();
	setup_sdb_for_function(sdb);
	rz_serialize_callables_load(sdb, typedb, NULL);
	sdb_free(sdb);

	char *s;

	s = rz_analysis_function_name_guess(typedb, "sub.strchr_123");
	mu_assert_null(s, "function that calls common fcns shouldn't be identified as such");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "sub.__strchr_123");
	mu_assert_null(s, "initial _ should not confuse the api");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "sub.__stack_chk_fail_740");
	mu_assert_null(s, "initial _ should not confuse the api");
	free(s);

	s = rz_analysis_function_name_guess(typedb, "sym.imp.strchr");
	mu_assert_notnull(s, "sym.imp. should be ignored");
	mu_assert_streq(s, "strchr", "strchr should be identified");
	free(s);

	rz_type_db_free(typedb);
	mu_end;
}

bool test_initial_underscore(void) {
	RzTypeDB *typedb = rz_type_db_new();
	mu_assert_notnull(typedb, "Couldn't create new RzTypeDB");

	setup_types_db(typedb);
	Sdb *sdb = sdb_new0();
	setup_sdb_for_function(sdb);
	rz_serialize_callables_load(sdb, typedb, NULL);
	sdb_free(sdb);

	char *s;

	s = rz_analysis_function_name_guess(typedb, "sym._strchr");
	mu_assert_notnull(s, "sym._ should be ignored");
	mu_assert_streq(s, "strchr", "strchr should be identified");
	free(s);

	rz_type_db_free(typedb);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_function_relocate);
	mu_run_test(test_rz_analysis_function_labels);
	mu_run_test(test_ignore_prefixes);
	mu_run_test(test_remove_rz_prefixes);
	mu_run_test(test_dll_names);
	mu_run_test(test_autonames);
	mu_run_test(test_initial_underscore);
	return tests_passed != tests_run;
}

mu_main(all_tests)
