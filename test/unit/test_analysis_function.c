// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "minunit.h"
#include "test_config.h"

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
	sdb_set(res, "ExitProcess", "func");
	sdb_num_set(res, "func.ExitProcess.args", 0);
	sdb_set(res, "func.ExitProcess.ret", "void");
	sdb_set(res, "ReadFile", "func");
	sdb_num_set(res, "func.ReadFile.args", 0);
	sdb_set(res, "func.ReadFile.ret", "void");
	sdb_set(res, "memcpy", "func");
	sdb_num_set(res, "func.memcpy.args", 0);
	sdb_set(res, "func.memcpy.ret", "void");
	sdb_set(res, "strchr", "func");
	sdb_num_set(res, "func.strchr.args", 0);
	sdb_set(res, "func.strchr.ret", "void");
	sdb_set(res, "__stack_chk_fail", "func");
	sdb_num_set(res, "func.__stack_chk_fail.args", 0);
	sdb_set(res, "func.__stack_chk_fail.ret", "void");
	sdb_set(res, "WSAStartup", "func");
	sdb_num_set(res, "func.WSAStartup.args", 0);
	sdb_set(res, "func.WSAStartup.ret", "void");
}

bool ht_up_count(void *user, const ut64 k, const void *v) {
	size_t *count = user;
	(*count)++;
	return true;
}

bool ht_sp_count(void *user, const char *k, const void *v) {
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
		mu_assert_ptreq(ht_sp_find(analysis->ht_name_fun, fcn->name, NULL), fcn, "function in name ht");
	}

	size_t addr_count = 0;
	ht_up_foreach_cb(analysis->ht_addr_fun, ht_up_count, &addr_count);
	mu_assert_eq(addr_count, rz_list_length(analysis->fcns), "function addr ht count");

	size_t name_count = 0;
	ht_sp_foreach_cb(analysis->ht_name_fun, ht_sp_count, &name_count);
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

	RzAnalysisFunction *fa = rz_analysis_create_function(analysis, "do_something", 0x1337, RZ_ANALYSIS_FCN_TYPE_NULL);
	assert_invariants(analysis);
	RzAnalysisFunction *fb = rz_analysis_create_function(analysis, "do_something_else", 0xdeadbeef, RZ_ANALYSIS_FCN_TYPE_NULL);
	assert_invariants(analysis);
	rz_analysis_create_function(analysis, "do_something_different", 0xc0ffee, RZ_ANALYSIS_FCN_TYPE_NULL);
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

	RzAnalysisFunction *f = rz_analysis_create_function(analysis, "do_something", 0x1337, RZ_ANALYSIS_FCN_TYPE_NULL);

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

bool test_rz_analysis_function_set_type() {
	RzAnalysis *analysis = rz_analysis_new();
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 32);
	rz_analysis_cc_set(analysis, "eax sectarian(ecx, edx, stack)");
	rz_type_db_purge(analysis->typedb);
	const char *types_dir = TEST_BUILD_TYPES_DIR;
	rz_type_db_init(analysis->typedb, types_dir, "x86", 32, "linux");

	// Only setup here
	RzAnalysisFunction *f = rz_analysis_create_function(analysis, "postcard", 0x100, RZ_ANALYSIS_FCN_TYPE_NULL);
	RzAnalysisVarStorage stor = { 0 };
	stor.type = RZ_ANALYSIS_VAR_STORAGE_REG;
	stor.reg = "edx";
	rz_analysis_function_set_var(f, &stor, NULL, 4, "oldarg0");
	stor.type = RZ_ANALYSIS_VAR_STORAGE_REG;
	stor.reg = "ecx";
	rz_analysis_function_set_var(f, &stor, NULL, 4, "oldarg1");
	stor.type = RZ_ANALYSIS_VAR_STORAGE_STACK;
	stor.stack_off = 1000;
	rz_analysis_function_set_var(f, &stor, NULL, 4, "oldarg2");
	stor.type = RZ_ANALYSIS_VAR_STORAGE_STACK;
	stor.stack_off = -8;
	rz_analysis_function_set_var(f, &stor, NULL, 4, "oldvar");
	mu_assert_eq(rz_pvector_len(&f->vars), 4, "initial vars");
	// The order in the vars vector is allowed to be different. It is only assumed here because
	// it is currently deterministic and this simplifies the test code.
	RzAnalysisVar *var = rz_pvector_at(&f->vars, 0);
	mu_assert_streq(var->name, "oldarg0", "var name");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "var storage type");
	mu_assert_streq(var->storage.reg, "edx", "var storage reg");
	mu_assert_eq(var->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type kind");
	mu_assert_streq(var->type->identifier.name, "int32_t", "var type");
	var = rz_pvector_at(&f->vars, 1);
	mu_assert_streq(var->name, "oldarg1", "var name");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "var storage type");
	mu_assert_streq(var->storage.reg, "ecx", "var storage reg");
	mu_assert_eq(var->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type kind");
	mu_assert_streq(var->type->identifier.name, "int32_t", "var type");
	var = rz_pvector_at(&f->vars, 2);
	mu_assert_streq(var->name, "oldarg2", "var name");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage type");
	mu_assert_eq(var->storage.stack_off, 1000, "var storage stack");
	mu_assert_eq(var->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type kind");
	mu_assert_streq(var->type->identifier.name, "int32_t", "var type");
	var = rz_pvector_at(&f->vars, 3);
	mu_assert_streq(var->name, "oldvar", "var name");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage type");
	mu_assert_eq(var->storage.stack_off, -8, "var storage stack");
	mu_assert_eq(var->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type kind");
	mu_assert_streq(var->type->identifier.name, "int32_t", "var type");
	f->is_noreturn = true;

	RzCallable *c = rz_type_callable_new("nopartofme");
	rz_type_callable_arg_add(c, rz_type_callable_arg_new(analysis->typedb, "arg0", rz_type_identifier_of_base_type_str(analysis->typedb, "uint8_t")));
	rz_type_callable_arg_add(c, rz_type_callable_arg_new(analysis->typedb, "arg1", rz_type_identifier_of_base_type_str(analysis->typedb, "uint32_t")));
	rz_type_callable_arg_add(c, rz_type_callable_arg_new(analysis->typedb, "arg2", rz_type_identifier_of_base_type_str(analysis->typedb, "int64_t")));
	rz_type_callable_arg_add(c, rz_type_callable_arg_new(analysis->typedb, "arg3", rz_type_identifier_of_base_type_str(analysis->typedb, "uint32_t")));
	c->noret = false;
	c->ret = rz_type_identifier_of_base_type_str(analysis->typedb, "uint16_t");
	c->cc = rz_str_constpool_get(&analysis->constpool, "sectarian");

	// Actual testing
	rz_analysis_function_set_type(analysis, f, c);
	rz_type_callable_free(c);
	mu_assert_streq(f->cc, "sectarian", "cc");
	mu_assert_eq(rz_pvector_len(&f->vars), 5, "initial vars");
	// Expected: only the var that was not an arg from before still exists, all
	// args have been replaced by the ones from the callable.
	// See note about the ordering above
	var = rz_pvector_at(&f->vars, 0);
	mu_assert_streq(var->name, "oldvar", "var name");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage type");
	mu_assert_eq(var->storage.stack_off, -8, "var storage stack");
	mu_assert_eq(var->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type kind");
	mu_assert_streq(var->type->identifier.name, "int32_t", "var type");
	var = rz_pvector_at(&f->vars, 1);
	mu_assert_streq(var->name, "arg0", "var name");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "var storage type");
	mu_assert_streq(var->storage.reg, "ecx", "var storage reg");
	mu_assert_eq(var->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type kind");
	mu_assert_streq(var->type->identifier.name, "uint8_t", "var type");
	var = rz_pvector_at(&f->vars, 2);
	mu_assert_streq(var->name, "arg1", "var name");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "var storage type");
	mu_assert_streq(var->storage.reg, "edx", "var storage reg");
	mu_assert_eq(var->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type kind");
	mu_assert_streq(var->type->identifier.name, "uint32_t", "var type");
	var = rz_pvector_at(&f->vars, 3);
	mu_assert_streq(var->name, "arg2", "var name");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage type");
	mu_assert_eq(var->storage.stack_off, 4, "var storage stack");
	mu_assert_eq(var->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type kind");
	mu_assert_streq(var->type->identifier.name, "int64_t", "var type");
	var = rz_pvector_at(&f->vars, 4);
	mu_assert_streq(var->name, "arg3", "var name");
	mu_assert_eq(var->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "var storage type");
	mu_assert_eq(var->storage.stack_off, 12, "var storage stack");
	mu_assert_eq(var->type->kind, RZ_TYPE_KIND_IDENTIFIER, "var type kind");
	mu_assert_streq(var->type->identifier.name, "uint32_t", "var type");

	mu_assert_notnull(f->ret_type, "ret type");
	mu_assert_eq(f->ret_type->kind, RZ_TYPE_KIND_IDENTIFIER, "ret type kind");
	mu_assert_streq(f->ret_type->identifier.name, "uint16_t", "ret type");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_noreturn_functions_list() {
	RzAnalysis *analysis = rz_analysis_new();

	rz_analysis_noreturn_add(analysis, NULL, 0x800800);

	RzList *noret = rz_analysis_noreturn_functions(analysis);
	mu_assert_eq(rz_list_length(noret), 1, "Num functions");
	mu_assert_streq(rz_list_first(noret), "0x800800", "Addr");
	rz_list_free(noret);

	rz_analysis_noreturn_drop(analysis, "0x800800");
	rz_analysis_noreturn_add(analysis, NULL, 0xdeadbeeff000bad1);

	noret = rz_analysis_noreturn_functions(analysis);
	mu_assert_eq(rz_list_length(noret), 1, "Num functions");
	mu_assert_streq(rz_list_first(noret), "0xdeadbeeff000bad1", "Long addr");
	rz_list_free(noret);

	rz_analysis_noreturn_drop(analysis, "0xdeadbeeff000bad1");
	rz_analysis_noreturn_add(analysis, "foobar", UT64_MAX);

	noret = rz_analysis_noreturn_functions(analysis);
	mu_assert_eq(rz_list_length(noret), 1, "Num functions");
	mu_assert_streq(rz_list_first(noret), "foobar", "Name");
	rz_list_free(noret);

	rz_analysis_noreturn_drop(analysis, "foobar");

	noret = rz_analysis_noreturn_functions(analysis);
	mu_assert_eq(rz_list_length(noret), 0, "Num functions");
	rz_list_free(noret);

	rz_analysis_free(analysis);
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
	mu_run_test(test_rz_analysis_function_set_type);
	mu_run_test(test_noreturn_functions_list);
	return tests_passed != tests_run;
}

mu_main(all_tests)
