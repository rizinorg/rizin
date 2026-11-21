// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include <rz_util.h>
#include "minunit.h"
#include "test_config.h"
#include "analysis_private.h"

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
	ht_up_foreach(analysis->ht_addr_fun, ht_up_count, &addr_count);
	mu_assert_eq(addr_count, rz_list_length(analysis->fcns), "function addr ht count");

	size_t name_count = 0;
	ht_sp_foreach(analysis->ht_name_fun, ht_sp_count, &name_count);
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
	RzAnalysis *analysis = rz_analysis_new(NULL);
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
	RzAnalysis *analysis = rz_analysis_new(NULL);

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
	RzAnalysis *analysis = rz_analysis_new(NULL);
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
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_noreturn_add(analysis, NULL, 0x800800);

	RzList *noret = rz_analysis_noreturn_functions(analysis);
	mu_assert_eq(rz_list_length(noret), 1, "Num functions");
	mu_assert_streq(rz_list_first_val(noret), "0x800800", "Addr");
	rz_list_free(noret);

	rz_analysis_noreturn_drop(analysis, "0x800800");
	rz_analysis_noreturn_add(analysis, NULL, 0xdeadbeeff000bad1);

	noret = rz_analysis_noreturn_functions(analysis);
	mu_assert_eq(rz_list_length(noret), 1, "Num functions");
	mu_assert_streq(rz_list_first_val(noret), "0xdeadbeeff000bad1", "Long addr");
	rz_list_free(noret);

	rz_analysis_noreturn_drop(analysis, "0xdeadbeeff000bad1");
	rz_analysis_noreturn_add(analysis, "foobar", UT64_MAX);

	noret = rz_analysis_noreturn_functions(analysis);
	mu_assert_eq(rz_list_length(noret), 1, "Num functions");
	mu_assert_streq(rz_list_first_val(noret), "foobar", "Name");
	rz_list_free(noret);

	rz_analysis_noreturn_drop(analysis, "foobar");

	noret = rz_analysis_noreturn_functions(analysis);
	mu_assert_eq(rz_list_length(noret), 0, "Num functions");
	rz_list_free(noret);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_analysis_function_rename() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	// we know b does not exist, rename a to b
	RzAnalysisFunction *a = rz_analysis_create_function(analysis, "a", 0xcafe, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_true(rz_analysis_function_rename(a, "b"), "rename a to b");
	mu_assert_streq(a->name, "b", "rename a to b failed");

	// we know b does exist, so rename must fail
	RzAnalysisFunction *c = rz_analysis_create_function(analysis, "c", 0xbbbb, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_false(rz_analysis_function_rename(c, "b"), "rename c to b"); // try renaming
	mu_assert_streq(c->name, "c", "c rename succeded"); // whether it actually failed

	rz_analysis_free(analysis);

	mu_end;
}

bool test_analysis_function_force_rename() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	RzAnalysisFunction *a = rz_analysis_create_function(analysis, "a", 0xcafe, RZ_ANALYSIS_FCN_TYPE_FCN);
	rz_analysis_create_function(analysis, "b", 0xbabe, RZ_ANALYSIS_FCN_TYPE_FCN);

	// rename a to b, but b already exists, so we force rename
	const char *expected_name = "b_cafe";
	const char *new_name = rz_analysis_function_force_rename(a, "b");
	mu_assert_notnull(new_name, "function force rename");
	mu_assert_streq(new_name, expected_name, "incorrect force rename result");
	mu_assert_streq(a->name, expected_name, "incorrenct force rename");

	rz_analysis_free(analysis);

	mu_end;
}

bool test_rz_analysis_function_set_cc() {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 32);

	rz_analysis_cc_set(analysis, "eax testcc(ecx, edx, stack)");
	mu_assert_true(rz_analysis_cc_exist(analysis, "testcc"), "testcc should exist");

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "testfunc", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(fcn, "function should be created");

	bool ret = rz_analysis_function_set_cc(analysis, fcn, "testcc");
	mu_assert_true(ret, "setting valid cc should succeed");
	mu_assert_streq(fcn->cc, "testcc", "cc should be set to testcc");

	ret = rz_analysis_function_set_cc(analysis, fcn, "nonexistent");
	mu_assert_false(ret, "setting invalid cc should fail");
	mu_assert_streq(fcn->cc, "testcc", "cc should remain unchanged after failed set");

	ret = rz_analysis_function_set_cc(analysis, fcn, NULL);
	mu_assert_true(ret, "setting NULL cc should succeed");
	mu_assert_null(fcn->cc, "cc should be NULL after clearing");

	ret = rz_analysis_function_set_cc(analysis, fcn, "testcc");
	mu_assert_true(ret, "setting cc back to testcc should succeed");
	ret = rz_analysis_function_set_cc(analysis, fcn, "");
	mu_assert_true(ret, "setting empty string cc should succeed");
	mu_assert_null(fcn->cc, "cc should be NULL after setting empty string");

	ret = rz_analysis_function_set_cc(analysis, fcn, "testcc");
	mu_assert_true(ret, "setting cc to testcc should succeed");
	ret = rz_analysis_function_set_cc(analysis, fcn, "testcc");
	mu_assert_true(ret, "setting same cc again should succeed");
	mu_assert_streq(fcn->cc, "testcc", "cc should still be testcc");

	rz_analysis_cc_set(analysis, "eax anothercc(edx, stack)");
	mu_assert_true(rz_analysis_cc_exist(analysis, "anothercc"), "anothercc should exist");
	ret = rz_analysis_function_set_cc(analysis, fcn, "anothercc");
	mu_assert_true(ret, "setting cc to anothercc should succeed");
	mu_assert_streq(fcn->cc, "anothercc", "cc should be set to anothercc");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_function_get_ret_var() {
	RzAnalysis *analysis = rz_analysis_new(NULL);

	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 32);

	// x86 standard cases
	rz_analysis_cc_set(analysis, "eax test_reg()");
	rz_analysis_cc_set(analysis, "stack+8 test_stack()");
	rz_analysis_cc_set(analysis, "eax,edx,stack+8 test_comp()");

	// ARM64
	rz_analysis_cc_set(analysis, "x0 test_arm64()");

	// fcn Return multiple locations
	rz_analysis_cc_set(analysis, "eax,ebx test_mul_reg()");
	rz_analysis_cc_set(analysis, "stack+8,stack+16 test_mul_stack()");

	// Register pairs
	rz_analysis_cc_set(analysis, "d2,d3 test_tricore()");

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "testfunc", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(fcn, "function should be created");

	bool cc_set1 = rz_analysis_function_set_cc(analysis, fcn, "test_reg");
	mu_assert_true(cc_set1, "failed to set test_reg cc");
	RzAnalysisVar *var_reg_ret = rz_analysis_function_get_ret_var(fcn);
	mu_assert_notnull(var_reg_ret, "should get ret var for reg cc");
	mu_assert_eq(var_reg_ret->storage.type, RZ_ANALYSIS_VAR_STORAGE_REG, "storage type should be REG");
	mu_assert_streq(var_reg_ret->storage.reg, "eax", "reg should be eax");
	rz_analysis_var_free(var_reg_ret);

	bool cc_set2 = rz_analysis_function_set_cc(analysis, fcn, "test_stack");
	mu_assert_true(cc_set2, "failed to set test_stack cc");
	RzAnalysisVar *var_stack = rz_analysis_function_get_ret_var(fcn);
	mu_assert_notnull(var_stack, "should get ret var for stack cc");
	mu_assert_eq(var_stack->storage.type, RZ_ANALYSIS_VAR_STORAGE_STACK, "storage type should be STACK");
	mu_assert_eq(var_stack->storage.stack_off, 8, "stack offset should be 8");
	rz_analysis_var_free(var_stack);

	bool cc_set3 = rz_analysis_function_set_cc(analysis, fcn, "test_comp");
	mu_assert_true(cc_set3, "failed to set test_comp cc");
	RzAnalysisVar *var_comp = rz_analysis_function_get_ret_var(fcn);
	mu_assert_notnull(var_comp, "should get ret var for composite cc");
	mu_assert_eq(var_comp->storage.type, RZ_ANALYSIS_VAR_STORAGE_COMPOSITE, "storage type should be COMPOSITE");
	mu_assert_eq((int)rz_vector_len(var_comp->storage.composite), 3, "composite should have 3 pieces");

	RzAnalysisVarStoragePiece *p0 = (RzAnalysisVarStoragePiece *)rz_vector_index_ptr(var_comp->storage.composite, 0);
	mu_assert_eq(p0->storage->type, RZ_ANALYSIS_VAR_STORAGE_REG, "piece 0 storage should be REG");
	mu_assert_streq(p0->storage->reg, "eax", "piece 0 reg should be eax");

	RzAnalysisVarStoragePiece *p1 = (RzAnalysisVarStoragePiece *)rz_vector_index_ptr(var_comp->storage.composite, 1);
	mu_assert_eq(p1->storage->type, RZ_ANALYSIS_VAR_STORAGE_REG, "piece 1 storage should be REG");
	mu_assert_streq(p1->storage->reg, "edx", "piece 1 reg should be edx");

	RzAnalysisVarStoragePiece *p2 = (RzAnalysisVarStoragePiece *)rz_vector_index_ptr(var_comp->storage.composite, 2);
	mu_assert_eq(p2->storage->type, RZ_ANALYSIS_VAR_STORAGE_STACK, "piece 2 storage should be STACK");
	mu_assert_eq(p2->storage->stack_off, 8, "piece 2 stack offset should be 8");
	rz_analysis_var_free(var_comp);

	bool cc_set4 = rz_analysis_function_set_cc(analysis, fcn, "test_arm64");
	mu_assert_true(cc_set4, "failed to set test_arm64 cc");
	RzAnalysisVar *var_arm64 = rz_analysis_function_get_ret_var(fcn);
	mu_assert_notnull(var_arm64, "should get ret var for arm64 cc");
	mu_assert_streq(var_arm64->storage.reg, "x0", "reg should be x0");
	rz_analysis_var_free(var_arm64);

	bool cc_set5 = rz_analysis_function_set_cc(analysis, fcn, "test_mul_reg");
	mu_assert_true(cc_set5, "failed to set test_mul_reg cc");
	RzAnalysisVar *var_mul_reg = rz_analysis_function_get_ret_var(fcn);
	mu_assert_notnull(var_mul_reg, "should get ret var for mul reg cc");
	mu_assert_eq(var_mul_reg->storage.type, RZ_ANALYSIS_VAR_STORAGE_COMPOSITE, "storage type should be COMPOSITE");
	mu_assert_eq((int)rz_vector_len(var_mul_reg->storage.composite), 2, "reg should have 2 pieces");

	RzAnalysisVarStoragePiece *p_r0 = (RzAnalysisVarStoragePiece *)rz_vector_index_ptr(var_mul_reg->storage.composite, 0);
	mu_assert_streq(p_r0->storage->reg, "eax", "piece 0 should be eax");
	mu_assert_eq(p_r0->offset_in_bits, 0, "piece 0 offset should be 0");

	RzAnalysisVarStoragePiece *p_r1 = (RzAnalysisVarStoragePiece *)rz_vector_index_ptr(var_mul_reg->storage.composite, 1);
	mu_assert_streq(p_r1->storage->reg, "ebx", "piece 1 should be ebx");
	mu_assert_eq(p_r1->offset_in_bits, 32, "piece 1 offset should be 32"); // Assuming 32-bit fallback
	rz_analysis_var_free(var_mul_reg);

	bool cc_set6 = rz_analysis_function_set_cc(analysis, fcn, "test_mul_stack");
	mu_assert_true(cc_set6, "failed to set test_mul_stack cc");
	RzAnalysisVar *var_mul_stack = rz_analysis_function_get_ret_var(fcn);
	mu_assert_notnull(var_mul_stack, "should get ret var for stack cc");
	mu_assert_eq((int)rz_vector_len(var_mul_stack->storage.composite), 2, "stack should have 2 pieces");

	RzAnalysisVarStoragePiece *p_mul_s0 = (RzAnalysisVarStoragePiece *)rz_vector_index_ptr(var_mul_stack->storage.composite, 0);
	mu_assert_eq(p_mul_s0->storage->stack_off, 8, "stack piece 0 offset 8");

	RzAnalysisVarStoragePiece *p_mul_s1 = (RzAnalysisVarStoragePiece *)rz_vector_index_ptr(var_mul_stack->storage.composite, 1);
	mu_assert_eq(p_mul_s1->storage->stack_off, 16, "stack piece 1 offset 16");
	rz_analysis_var_free(var_mul_stack);

	bool cc_set7 = rz_analysis_function_set_cc(analysis, fcn, "test_tricore");
	mu_assert_true(cc_set7, "failed to set test_tricore cc");
	RzAnalysisVar *var_tricore = rz_analysis_function_get_ret_var(fcn);
	mu_assert_notnull(var_tricore, "should get ret var for tricore cc");
	mu_assert_eq(var_tricore->storage.type, RZ_ANALYSIS_VAR_STORAGE_COMPOSITE, "storage type should be COMPOSITE");

	RzAnalysisVarStoragePiece *p_tri0 = (RzAnalysisVarStoragePiece *)rz_vector_index_ptr(var_tricore->storage.composite, 0);
	mu_assert_streq(p_tri0->storage->reg, "d2", "tricore piece 0 should be d2");

	RzAnalysisVarStoragePiece *p_tri1 = (RzAnalysisVarStoragePiece *)rz_vector_index_ptr(var_tricore->storage.composite, 1);
	mu_assert_streq(p_tri1->storage->reg, "d3", "tricore piece 1 should be d3");
	rz_analysis_var_free(var_tricore);

	rz_analysis_function_set_cc(analysis, fcn, NULL);
	RzAnalysisVar *var_null = rz_analysis_function_get_ret_var(fcn);
	mu_assert_null(var_null, "should safely return NULL when CC is not set");

	rz_analysis_free(analysis);
	mu_end;
}

static bool run_indirect_branch_test(const ut8 *img, size_t img_size,
	ut64 exp_jump, ut64 exp_fail, size_t exp_bbs) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	RzCoreFile *cf = rz_core_file_open(core, "malloc://0x200", RZ_PERM_RWX, 0x1000);
	mu_assert_notnull(cf, "open malloc://0x200");
	rz_io_map_add(core->io, cf->fd, RZ_PERM_RWX, 0, 0x1000, 0x200);
	rz_config_set(core->config, "asm.arch", "x86");
	rz_config_set_i(core->config, "asm.bits", 64);
	core->analysis->opt.jmptbl = true;
	mu_assert_true(rz_io_write_at(core->io, 0x1000, img, img_size), "write code");

	RzAnalysisFunction *fcn = rz_analysis_create_function(
		core->analysis, "fcn_ind", 0x1000, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(fcn, "create function");
	rz_analysis_fcn(core->analysis, fcn, 0x1000, img_size, RZ_ANALYSIS_XREF_TYPE_NULL);

	RzAnalysisBlock *entry = rz_analysis_get_block_at(core->analysis, 0x1000);
	mu_assert_notnull(entry, "entry block exists");
	mu_assert_eq(entry->jump, exp_jump, "expected jump target");
	mu_assert_eq(entry->fail, exp_fail, "expected fail target");
	mu_assert_eq(rz_pvector_len(fcn->bbs), exp_bbs, "expected basic block count");

	rz_core_free(core);
	return true;
}

bool test_indirect_reg_branch_resolution(void) {
	ut8 img[0x200];

	// Case 1: 2-way CMOV + signed 32-bit delta table load + add + jmp reg
	memset(img, 0x90, sizeof(img));
	const ut8 cmov_delta[] = {
		0x48, 0x8d, 0x05, 0x39, 0x00, 0x00, 0x00, // lea rax, [rip + 0x39] -> 0x1040
		0x85, 0xff, // test edi, edi
		0x48, 0x63, 0x48, 0x00, // movsxd rcx, dword [rax + 0]
		0x48, 0x63, 0x50, 0x04, // movsxd rdx, dword [rax + 4]
		0x48, 0x0f, 0x44, 0xca, // cmove rcx, rdx
		0x48, 0x01, 0xc8, // add rax, rcx
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, cmov_delta, sizeof(cmov_delta));
	rz_write_at_le32(img, 0x40, 0x40); // 0x1040 + 0x40 = 0x1080
	rz_write_at_le32(img, 0x50, 0x44); // 0x1040 + 0x50 = 0x1090
	img[0x80] = 0xc3;
	img[0x90] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), 0x1080, 0x1090, 3),
		"2-way cmov delta branch");

	// Case 2: 2-way 64-bit pointer table load + mov reg, reg + sub + cmov
	memset(img, 0x90, sizeof(img));
	const ut8 ptr64_sub[] = {
		0x48, 0x8d, 0x05, 0x39, 0x00, 0x00, 0x00, // lea rax, [rip + 0x39] -> 0x1040
		0x48, 0x8b, 0x48, 0x00, // mov rcx, qword [rax + 0]
		0x48, 0x8b, 0x50, 0x08, // mov rdx, qword [rax + 8]
		0x48, 0x89, 0xce, // mov rsi, rcx
		0x48, 0x0f, 0x44, 0xf2, // cmove rsi, rdx
		0x48, 0xc7, 0xc7, 0x10, 0x00, 0x00, 0x00, // mov rdi, 0x10
		0x48, 0x29, 0xfe, // sub rsi, rdi
		0xff, 0xe6 // jmp rsi
	};
	memcpy(img, ptr64_sub, sizeof(ptr64_sub));
	rz_write_at_le64(img, 0x1090, 0x40); // 0x1090 - 0x10 = 0x1080
	rz_write_at_le64(img, 0x10a0, 0x48); // 0x10a0 - 0x10 = 0x1090
	img[0x80] = 0xc3;
	img[0x90] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), 0x1080, 0x1090, 3),
		"2-way 64-bit pointer table + sub");

	// Case 3: 1-way 32-bit zero-ext load + movsxd reg, reg + add + stack store
	memset(img, 0x90, sizeof(img));
	const ut8 zext_sxd[] = {
		0x48, 0x8d, 0x05, 0x39, 0x00, 0x00, 0x00, // lea rax, [rip + 0x39] -> 0x1040
		0x8b, 0x48, 0x00, // mov ecx, dword [rax + 0]
		0x48, 0x63, 0xd1, // movsxd rdx, ecx
		0x48, 0x89, 0x54, 0x24, 0x08, // mov qword [rsp + 8], rdx
		0x48, 0x01, 0xd0, // add rax, rdx
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, zext_sxd, sizeof(zext_sxd));
	rz_write_at_le32(img, 0x40, 0x40); // 0x1040 + 0x40 = 0x1080
	img[0x80] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), 0x1080, UT64_MAX, 2),
		"1-way mov32 + movsxd reg + store");

	// Case 4: 2-way direct LEA + CMOV + dedup CMOV + jmp reg
	memset(img, 0x90, sizeof(img));
	const ut8 cmov_lea[] = {
		0x48, 0x8d, 0x05, 0x79, 0x00, 0x00, 0x00, // lea rax, [rip + 0x79] -> 0x1080
		0x48, 0x8d, 0x0d, 0x82, 0x00, 0x00, 0x00, // lea rcx, [rip + 0x82] -> 0x1090
		0x85, 0xff, // test edi, edi
		0x48, 0x0f, 0x45, 0xc1, // cmovne rax, rcx
		0x48, 0x0f, 0x44, 0xc1, // cmove rax, rcx (dedup)
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, cmov_lea, sizeof(cmov_lea));
	img[0x80] = 0xc3;
	img[0x90] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), 0x1080, 0x1090, 3),
		"2-way cmov lea with dedup");

	// Case 5: negative tests — out-of-range delta, >2-way CMOV overflow,
	// clobbering ops (call, xor, imul, xchg, partial al write), gs: load, SIB UJMP
	memset(img, 0x90, sizeof(img));
	memcpy(img, cmov_delta, sizeof(cmov_delta));
	rz_write_at_le32(img, 0x40, 0x40);
	rz_write_at_le32(img, 0x70000000, 0x44);
	img[0x80] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"out-of-range cmov delta rejected");

	// 3-way CMOV exceeds max 2 values -> cleared
	memset(img, 0x90, sizeof(img));
	const ut8 cmov_three[] = {
		0x48, 0x8d, 0x05, 0x79, 0x00, 0x00, 0x00, // lea rax, [0x1080]
		0x48, 0x8d, 0x0d, 0x82, 0x00, 0x00, 0x00, // lea rcx, [0x1090]
		0x48, 0x8d, 0x15, 0x8b, 0x00, 0x00, 0x00, // lea rdx, [0x10a0]
		0x48, 0x0f, 0x44, 0xc1, // cmove rax, rcx
		0x48, 0x0f, 0x45, 0xc2, // cmovne rax, rdx (>2 -> clear)
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, cmov_three, sizeof(cmov_three));
	img[0x80] = img[0x90] = img[0xa0] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"3-way cmov overflow rejected");

	// Call clobber
	memset(img, 0x90, sizeof(img));
	const ut8 call_clobber[] = {
		0x48, 0x8d, 0x05, 0x79, 0x00, 0x00, 0x00, // lea rax, [0x1080]
		0xe8, 0x84, 0x00, 0x00, 0x00, // call 0x1090
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, call_clobber, sizeof(call_clobber));
	img[0x80] = img[0x90] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"call clobber invalidates tracked jump target");

	// Partial register write (xor al, al) clears rax
	memset(img, 0x90, sizeof(img));
	const ut8 partial_clobber[] = {
		0x48, 0x8d, 0x05, 0x79, 0x00, 0x00, 0x00, // lea rax, [0x1080]
		0x30, 0xc0, // xor al, al
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, partial_clobber, sizeof(partial_clobber));
	img[0x80] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"partial register write invalidates rax");

	// Unhandled op (imul) resets tracked state
	memset(img, 0x90, sizeof(img));
	const ut8 imul_clobber[] = {
		0x48, 0x8d, 0x05, 0x79, 0x00, 0x00, 0x00, // lea rax, [0x1080]
		0x48, 0x0f, 0xaf, 0xc1, // imul rax, rcx
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, imul_clobber, sizeof(imul_clobber));
	img[0x80] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"imul resets tracked state");

	// Memory-indirect SIB jump (jmp qword [rax + rcx*8]) must not resolve to rax
	memset(img, 0x90, sizeof(img));
	const ut8 sib_ujmp[] = {
		0x48, 0x8d, 0x05, 0x79, 0x00, 0x00, 0x00, // lea rax, [0x1080]
		0xff, 0x24, 0xc8 // jmp qword [rax + rcx*8]
	};
	memcpy(img, sib_ujmp, sizeof(sib_ujmp));
	img[0x80] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"memory-indirect SIB ujmp not misresolved to base reg");

	// Segment-prefixed load (mov rax, qword gs:[rax + 0]) rejected
	memset(img, 0x90, sizeof(img));
	const ut8 gs_load[] = {
		0x48, 0x8d, 0x05, 0x39, 0x00, 0x00, 0x00, // lea rax, [0x1040]
		0x65, 0x48, 0x8b, 0x40, 0x00, // mov rax, qword gs:[rax]
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, gs_load, sizeof(gs_load));
	rz_write_at_le64(img, 0x1080, 0x40);
	img[0x80] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"segment-prefixed memory load rejected");

	// Tracked rbp store must reset state (not skipped as frame spill)
	memset(img, 0x90, sizeof(img));
	const ut8 tracked_bp_store[] = {
		0x48, 0x8d, 0x2d, 0x39, 0x00, 0x00, 0x00, // lea rbp, [0x1040]
		0x48, 0x89, 0x55, 0x00, // mov qword [rbp + 0], rdx
		0x48, 0x8b, 0x45, 0x00, // mov rax, qword [rbp + 0]
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, tracked_bp_store, sizeof(tracked_bp_store));
	rz_write_at_le64(img, 0x1080, 0x40);
	img[0x80] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"tracked rbp store invalidates tracked state");

	// Non-allowlisted reg-dst op (xchg) resets tracked state
	memset(img, 0x90, sizeof(img));
	const ut8 xchg_clobber[] = {
		0x48, 0x8d, 0x05, 0x79, 0x00, 0x00, 0x00, // lea rax, [0x1080]
		0x48, 0x91, // xchg rax, rcx
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, xchg_clobber, sizeof(xchg_clobber));
	img[0x80] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"xchg resets tracked state");

	// 32-bit truncation deduplicates colliding low-32-bit values
	memset(img, 0x90, sizeof(img));
	const ut8 trunc32_dedup[] = {
		0x48, 0xb9, 0x80, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rcx, 0x100001080
		0x48, 0xba, 0x80, 0x10, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov rdx, 0x200001080
		0x0f, 0x44, 0xca, // cmove ecx, edx -> 0x1080 (dedup)
		0xff, 0xe1 // jmp rcx
	};
	memcpy(img, trunc32_dedup, sizeof(trunc32_dedup));
	img[0x80] = 0xc3;
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), 0x1080, UT64_MAX, 2),
		"32-bit truncation deduplicates values");

	// Indirect jump to function prelude (push rbp; mov rbp, rsp) rejected as tail call
	memset(img, 0x90, sizeof(img));
	const ut8 jmp_tail[] = {
		0x48, 0x8d, 0x05, 0x79, 0x00, 0x00, 0x00, // lea rax, [rip + 0x79] -> 0x1080
		0x85, 0xff, // test edi, edi
		0xff, 0xe0 // jmp rax
	};
	memcpy(img, jmp_tail, sizeof(jmp_tail));
	img[0x80] = 0x55; // push rbp
	img[0x81] = 0x48;
	img[0x82] = 0x89;
	img[0x83] = 0xe5; // mov rbp, rsp
	img[0x84] = 0xc3; // ret
	mu_assert_true(run_indirect_branch_test(img, sizeof(img), UT64_MAX, UT64_MAX, 1),
		"indirect jump to function prelude rejected");

	// Indirect jump to an existing external function is not absorbed into caller
	{
		memset(img, 0x90, sizeof(img));
		memcpy(img, jmp_tail, sizeof(jmp_tail));
		img[0x80] = 0xc3;
		RzCore *core = rz_core_new();
		mu_assert_notnull(core, "core");
		RzCoreFile *cf = rz_core_file_open(core, "malloc://0x200", RZ_PERM_RWX, 0x1000);
		mu_assert_notnull(cf, "open malloc://0x200");
		rz_io_map_add(core->io, cf->fd, RZ_PERM_RWX, 0, 0x1000, 0x200);
		rz_config_set(core->config, "asm.arch", "x86");
		rz_config_set_i(core->config, "asm.bits", 64);
		core->analysis->opt.jmptbl = true;
		mu_assert_true(rz_io_write_at(core->io, 0x1000, img, sizeof(img)), "write code");

		RzAnalysisFunction *callee = rz_analysis_create_function(
			core->analysis, "fcn_callee", 0x1080, RZ_ANALYSIS_FCN_TYPE_FCN);
		mu_assert_notnull(callee, "create callee");
		RzAnalysisFunction *fcn = rz_analysis_create_function(
			core->analysis, "fcn_caller", 0x1000, RZ_ANALYSIS_FCN_TYPE_FCN);
		mu_assert_notnull(fcn, "create caller");
		rz_analysis_fcn(core->analysis, fcn, 0x1000, sizeof(img), RZ_ANALYSIS_XREF_TYPE_NULL);

		RzAnalysisBlock *entry = rz_analysis_get_block_at(core->analysis, 0x1000);
		mu_assert_notnull(entry, "entry block exists");
		mu_assert_eq(entry->jump, UT64_MAX, "external function target not resolved as intra-fcn jump");
		mu_assert_eq(entry->fail, UT64_MAX, "external function target fail unset");
		mu_assert_eq(rz_pvector_len(fcn->bbs), 1, "caller does not absorb external function");
		rz_core_free(core);
	}

	// 32-bit address-size override (0x67) memory load masks upper 32 bits of base reg
	{
		memset(img, 0x90, sizeof(img));
		const ut8 addr32_load[] = {
			0x48, 0xb8, 0x40, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rax, 0x100001040
			0x67, 0x48, 0x8b, 0x00, // mov rax, qword [eax]
			0xff, 0xe0 // jmp rax
		};
		memcpy(img, addr32_load, sizeof(addr32_load));
		rz_write_at_le64(img, 0x1080, 0x40); // low 32-bit addr 0x1040 -> 0x1080
		img[0x80] = 0xc3;
		img[0x90] = 0xc3;

		ut8 hi_img[0x200];
		memset(hi_img, 0, sizeof(hi_img));
		rz_write_at_le64(hi_img, 0x1090, 0x40); // unmasked 64-bit addr 0x100001040 -> 0x1090

		RzCore *core = rz_core_new();
		mu_assert_notnull(core, "core");
		RzCoreFile *cf_lo = rz_core_file_open(core, "malloc://0x200", RZ_PERM_RWX, 0x1000);
		mu_assert_notnull(cf_lo, "open low map");
		rz_io_map_add(core->io, cf_lo->fd, RZ_PERM_RWX, 0, 0x1000, 0x200);
		RzCoreFile *cf_hi = rz_core_file_open(core, "malloc://0x200", RZ_PERM_RW, 0x100001000ULL);
		mu_assert_notnull(cf_hi, "open high map");
		rz_io_map_add(core->io, cf_hi->fd, RZ_PERM_RW, 0, 0x100001000ULL, 0x200);
		rz_config_set(core->config, "asm.arch", "x86");
		rz_config_set_i(core->config, "asm.bits", 64);
		core->analysis->opt.jmptbl = true;
		mu_assert_true(rz_io_write_at(core->io, 0x1000, img, sizeof(img)), "write low image");
		mu_assert_true(rz_io_write_at(core->io, 0x100001000ULL, hi_img, sizeof(hi_img)), "write high image");

		RzAnalysisFunction *fcn = rz_analysis_create_function(
			core->analysis, "fcn_addr32", 0x1000, RZ_ANALYSIS_FCN_TYPE_FCN);
		mu_assert_notnull(fcn, "create addr32 function");
		rz_analysis_fcn(core->analysis, fcn, 0x1000, sizeof(img), RZ_ANALYSIS_XREF_TYPE_NULL);

		RzAnalysisBlock *entry = rz_analysis_get_block_at(core->analysis, 0x1000);
		mu_assert_notnull(entry, "entry block exists");
		mu_assert_eq(entry->jump, 0x1080, "32-bit addr-size load reads masked 0x1040, not 0x100001040");
		mu_assert_eq(entry->fail, UT64_MAX, "addr32 fail unset");
		mu_assert_eq(rz_pvector_len(fcn->bbs), 2, "addr32 resolves only masked target");
		rz_core_free(core);
	}

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
	mu_run_test(test_rz_analysis_function_set_cc);
	mu_run_test(test_noreturn_functions_list);
	mu_run_test(test_analysis_function_rename);
	mu_run_test(test_analysis_function_force_rename);
	mu_run_test(test_rz_analysis_function_get_ret_var);
	mu_run_test(test_indirect_reg_branch_resolution);
	return tests_passed != tests_run;
}

mu_main(all_tests)
