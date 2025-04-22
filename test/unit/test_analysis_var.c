// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "test_config.h"
#include "minunit.h"

static bool sanitize_instr_acc(void *user, const ut64 k, const void *v) {
	RzPVector *vec = (RzPVector *)v;
	void **it;
	rz_pvector_foreach (vec, it) {
		RzAnalysisVar *var = *it;
		RzAnalysisVarAccess *acc;
		bool found = false;
		rz_vector_foreach (&var->accesses, acc) {
			if (acc->offset == (st64)k) {
				found = true;
				break;
			}
		}
		mu_assert("instr refs var, but var does not ref instr", found);
	}
	return true;
}

static bool sanitize(RzAnalysisFunction *fcn) {
	ht_up_foreach(fcn->inst_vars, sanitize_instr_acc, NULL);

	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		RzAnalysisVarAccess *acc;
		rz_vector_foreach (&var->accesses, acc) {
			RzPVector *iaccs = ht_up_find(fcn->inst_vars, acc->offset, NULL);
			mu_assert("var refs instr but instr does not ref var", rz_pvector_contains(iaccs, var));
		}
	}
	return true;
}

#define assert_sane(analysis) \
	do { \
		RzListIter *ass_it; \
		RzAnalysisFunction *ass_fcn; \
		rz_list_foreach ((analysis)->fcns, ass_it, ass_fcn) { \
			if (!sanitize(ass_fcn)) { \
				return false; \
			} \
		} \
	} while (0);

static RzAnalysisVar *set_var_str(RzAnalysisFunction *fcn, RzAnalysisVarStorage *stor, const char *type, int size, const char *name) {
	RzType *ttype = rz_type_parse_string_single(fcn->analysis->typedb->parser, type, NULL);
	if (!ttype) {
		return NULL;
	}
	RzAnalysisVar *ret = rz_analysis_function_set_var(fcn, stor, ttype, size, name);
	rz_type_free(ttype);
	return ret;
}

bool test_rz_analysis_var() {
	RzAnalysis *analysis = rz_analysis_new();
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "fcn", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	assert_sane(analysis);

	// creating variables and renaming

	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_stack(&stor, -0x10);
	RzAnalysisVar *a = set_var_str(fcn, &stor, "char *", 8, "random_name");
	mu_assert_notnull(a, "create a var");
	mu_assert_streq(a->name, "random_name", "var name");
	mu_assert_false(rz_analysis_var_is_arg(a), "negative stack offset is local var");
	bool succ = rz_analysis_var_rename(a, "var_a", false);
	mu_assert("rename success", succ);
	mu_assert_streq(a->name, "var_a", "var name after rename");

	rz_analysis_var_storage_init_stack(&stor, 8);
	RzAnalysisVar *b = set_var_str(fcn, &stor, "char *", 8, "var_a");
	mu_assert_null(b, "create a var with the same name");
	b = set_var_str(fcn, &stor, "char *", 8, "new_var");
	mu_assert_notnull(b, "create a var with another name");
	mu_assert_streq(b->name, "new_var", "var name");
	mu_assert_true(rz_analysis_var_is_arg(b), "positive stack offset is arg");
	succ = rz_analysis_var_rename(b, "random_name", false);
	mu_assert("rename success", succ);
	mu_assert_streq(b->name, "random_name", "var name after rename");
	succ = rz_analysis_var_rename(b, "var_a", false);
	mu_assert("rename failed", !succ);
	mu_assert_streq(b->name, "random_name", "var name after failed rename");
	succ = rz_analysis_var_rename(b, "var_b", false);
	mu_assert("rename success", succ);
	mu_assert_streq(b->name, "var_b", "var name after rename");

	rz_analysis_var_storage_init_reg(&stor, "rax");
	RzAnalysisVar *c = set_var_str(fcn, &stor, "int64_t", 8, "arg42");
	mu_assert_notnull(c, "create a var");
	mu_assert_false(rz_analysis_var_is_arg(c), "rz_analysis_var_is_arg based on call conversion");

	// querying variables

	RzAnalysisVar *v = rz_analysis_function_get_reg_var_at(fcn, "rbx");
	mu_assert_null(v, "get no var (reg)");
	v = rz_analysis_function_get_reg_var_at(fcn, "rax");
	mu_assert_ptreq(v, c, "get var (reg)");
	v = rz_analysis_function_get_stack_var_at(fcn, -0xf);
	mu_assert_null(v, "get no var (stack)");
	v = rz_analysis_function_get_stack_var_at(fcn, -0x10);
	mu_assert_ptreq(v, a, "get var (stack)");

	v = rz_analysis_function_get_var_byname(fcn, "random_name");
	mu_assert_null(v, "nonsense name");
	v = rz_analysis_function_get_var_byname(fcn, "var_a");
	mu_assert_ptreq(v, a, "get var by name");

	// accesses

	rz_analysis_var_set_access(a, "rsp", 0x120, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 42);
	rz_analysis_var_set_access(a, "rbp", 0x130, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, 13);
	rz_analysis_var_set_access(b, "rsp", 0x120, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, 123);
	rz_analysis_var_set_access(b, "rbp", 0x10, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, -100);

	RzPVector *used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x130);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x120);
	mu_assert_eq(rz_pvector_len(used_vars), 2, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	mu_assert("used vars", rz_pvector_contains(used_vars, b));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x10);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, b));

	assert_sane(analysis);

	// relocate function

	rz_analysis_function_relocate(fcn, 0xffffffffffff0100UL);
	assert_sane(analysis);

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0xffffffffffff0130UL); // addresses should stay the same
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	rz_analysis_var_set_access(a, "rbp", 0xffffffffffff0130UL, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 42);
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0xffffffffffff0130UL);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	rz_analysis_var_set_access(a, "rbp", 0x123, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 42);
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x130);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x120);
	mu_assert_eq(rz_pvector_len(used_vars), 2, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	mu_assert("used vars", rz_pvector_contains(used_vars, b));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x10);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, b));

	rz_analysis_function_relocate(fcn, 0x8000000000000010);
	assert_sane(analysis);

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x8000000000000100);
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	rz_analysis_var_set_access(a, "rbp", 0x8000000000000100, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 987321);
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x8000000000000100);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x7ffffffffffffe00);
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	rz_analysis_var_set_access(a, "rbp", 0x7ffffffffffffe00, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 777);
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x7ffffffffffffe00);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0xffffffffffff0130UL);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x130);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x120);
	mu_assert_eq(rz_pvector_len(used_vars), 2, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	mu_assert("used vars", rz_pvector_contains(used_vars, b));

	assert_sane(analysis);

	rz_analysis_var_delete(a);
	assert_sane(analysis);

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0xffffffffffff0130UL);
	mu_assert("used vars count", !used_vars || !rz_pvector_len(used_vars));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert("used vars count", !used_vars || !rz_pvector_len(used_vars));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x130);
	mu_assert("used vars count", !used_vars || !rz_pvector_len(used_vars));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x120);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, b));

	rz_analysis_var_delete(b);
	rz_analysis_var_delete(c);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_function_get_stack_var_in() {
	RzAnalysis *analysis = rz_analysis_new();
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "fcn", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	assert_sane(analysis);

	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_stack(&stor, -0x10);
	RzAnalysisVar *a = set_var_str(fcn, &stor, "char *", 8, "var_10h");
	mu_assert_notnull(a, "create var");
	rz_analysis_var_storage_init_stack(&stor, -0x18);
	RzAnalysisVar *b = set_var_str(fcn, &stor, "uint64_t", 8, "var_18h");
	mu_assert_notnull(b, "create var");
	rz_analysis_var_storage_init_stack(&stor, 8);
	RzAnalysisVar *c = set_var_str(fcn, &stor, "char *", 8, "arg_8h");
	mu_assert_notnull(c, "create var");
	assert_sane(analysis);

	RzAnalysisVar *var = rz_analysis_function_get_stack_var_in(fcn, -0x10);
	mu_assert_ptreq(var, a, "var_in");
	var = rz_analysis_function_get_stack_var_at(fcn, -0x10);
	mu_assert_ptreq(var, a, "var_at");

	var = rz_analysis_function_get_stack_var_in(fcn, -0xf);
	mu_assert_ptreq(var, a, "var_in");
	var = rz_analysis_function_get_stack_var_at(fcn, -0xf);
	mu_assert_null(var, "var_at");

	var = rz_analysis_function_get_stack_var_in(fcn, 7);
	mu_assert_ptreq(var, a, "var_in");
	var = rz_analysis_function_get_stack_var_at(fcn, 7);
	mu_assert_null(var, "var_at");

	var = rz_analysis_function_get_stack_var_in(fcn, 8);
	mu_assert_ptreq(var, c, "var_in");
	var = rz_analysis_function_get_stack_var_at(fcn, 8);
	mu_assert_ptreq(var, c, "var_at");

	var = rz_analysis_function_get_stack_var_in(fcn, 99999);
	mu_assert_ptreq(var, c, "var_in");
	var = rz_analysis_function_get_stack_var_at(fcn, 99999);
	mu_assert_null(var, "var_at");

	var = rz_analysis_function_get_stack_var_in(fcn, -0x17);
	mu_assert_ptreq(var, b, "var_in");
	var = rz_analysis_function_get_stack_var_at(fcn, -0x17);
	mu_assert_null(var, "var_at");

	var = rz_analysis_function_get_stack_var_in(fcn, -0x18);
	mu_assert_ptreq(var, b, "var_in");
	var = rz_analysis_function_get_stack_var_at(fcn, -0x18);
	mu_assert_ptreq(var, b, "var_at");

	var = rz_analysis_function_get_stack_var_in(fcn, -0x19);
	mu_assert_null(var, "var_in");
	var = rz_analysis_function_get_stack_var_at(fcn, -0x19);
	mu_assert_null(var, "var_at");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_function_var_expr_for_reg_access_at() {
	RzAnalysis *analysis = rz_analysis_new();
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	rz_type_db_init(analysis->typedb, TEST_BUILD_TYPES_DIR, NULL, 64, NULL);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "fcn", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	fcn->bp_off = 8;
	assert_sane(analysis);

	RzType *struct_type = rz_type_parse_string_single(analysis->typedb->parser, "struct MyStruct { uint32_t a; uint32_t b; };", NULL);
	mu_assert_notnull(struct_type, "parse struct");

	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_stack(&stor, -0x10);
	RzAnalysisVar *a = set_var_str(fcn, &stor, "char *", 0, "var_10h");
	mu_assert_notnull(a, "create var");
	ut64 a_size = rz_analysis_var_size(analysis, a);
	mu_assert_eq(a_size, 64, "var size");
	rz_analysis_var_storage_init_stack(&stor, -0x18);
	RzAnalysisVar *b = rz_analysis_function_set_var(fcn, &stor, struct_type, 0, "var_18h");
	mu_assert_notnull(b, "create var");
	ut64 b_size = rz_analysis_var_size(analysis, b);
	mu_assert_eq(b_size, 64, "var size");
	rz_analysis_var_storage_init_stack(&stor, 8);
	RzAnalysisVar *c = set_var_str(fcn, &stor, "char *", 0, "arg_8h");
	mu_assert_notnull(c, "create var");
	ut64 c_size = rz_analysis_var_size(analysis, c);
	mu_assert_eq(c_size, 64, "var size");
	rz_type_free(struct_type);
	assert_sane(analysis);

	// bp-based access, uses fcn->bp_off

	char *s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rbp", -8);
	mu_assert_streq_free(s, "var_10h", "expr from stack for bp");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rbp", -3);
	mu_assert_streq_free(s, "var_10h + 0x5", "expr from stack for bp with offset");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rbp", -42);
	mu_assert_null(s, "expr from stack for bp oob");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rbp", -0x10);
	mu_assert_streq_free(s, "var_18h.a", "expr from stack for bp in struct");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rbp", -0xc);
	mu_assert_streq_free(s, "var_18h.b", "expr from stack for bp in struct");

	// sp-based access, needing sp tracking info

	RzAnalysisBlock *block = rz_analysis_create_block(analysis, 0x100, 0x10);
	rz_analysis_function_add_block(fcn, block);
	rz_analysis_block_unref(block);
	block->sp_entry = 0;
	block->ninstr = 4;
	rz_analysis_block_set_op_sp_delta(block, 0, 0);
	rz_analysis_block_set_op_offset(block, 1, 3);
	rz_analysis_block_set_op_sp_delta(block, 1, -0x20);
	rz_analysis_block_set_op_offset(block, 2, 5);
	rz_analysis_block_set_op_sp_delta(block, 2, -0x28);
	rz_analysis_block_set_op_offset(block, 3, 0xa);
	rz_analysis_block_set_op_sp_delta(block, 3, 0);

	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rsp", 0x10);
	mu_assert_streq_free(s, "var_10h", "expr from stack for sp");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rsp", 0x13);
	mu_assert_streq_free(s, "var_10h + 0x3", "expr from stack for sp with offset");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rsp", 0);
	mu_assert_null(s, "expr from stack for sp oob");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x10a, "rsp", 0x10);
	mu_assert_streq_free(s, "var_18h.a", "expr from stack for sp in struct");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x10a, "rsp", 0x13);
	mu_assert_streq_free(s, "var_18h + 0x3", "expr from stack for sp with offset");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x10a, "rsp", 0x14);
	mu_assert_streq_free(s, "var_18h.b", "expr from stack for sp in struct");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x10a, "rsp", 0);
	mu_assert_null(s, "expr from stack for sp oob");

	// arbitrary reg accesses from explicit RzAnalysisVarAccesses

	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rax", 6);
	mu_assert_null(s, "expr from access");
	rz_analysis_var_set_access(a, "rax", 0x105, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 6);
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rax", 6);
	mu_assert_streq_free(s, "var_10h", "expr from access");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rax", 5);
	mu_assert_null(s, "expr from access");
	s = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x105, "rbx", 6);
	mu_assert_null(s, "expr from access");

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_analysis_var_is_arg() {
	RzCore *core = rz_core_new();
	RzAnalysis *analysis = core->analysis;
	rz_config_set(core->config, "analysis.arch", "x86");
	rz_analysis_set_bits(core->analysis, 64);
	rz_core_analysis_cc_init_by_path(core, TEST_BUILD_TYPES_DIR, NULL);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "fcn", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	assert_sane(core->analysis);

	RzAnalysisVarStorage stor = { 0 };
	rz_analysis_var_storage_init_reg(&stor, "rdi");
	RzAnalysisVar *var = set_var_str(fcn, &stor, "int64_t", 8, "arg0");
	mu_assert_notnull(var, "create a var");
	mu_assert_true(rz_analysis_var_is_arg(var), "rz_analysis_var_is_arg based on call conversion rdi");

	rz_analysis_var_storage_init_reg(&stor, "r10");
	var = set_var_str(fcn, &stor, "int64_t", 8, "arg10");
	mu_assert_notnull(var, "create a var");
	mu_assert_false(rz_analysis_var_is_arg(var), "rz_analysis_var_is_arg based on call conversion r10");

	var = RZ_NEW0(RzAnalysisVar);
	var->kind = RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER;
	mu_assert_true(rz_analysis_var_is_arg(var), "rz_analysis_var_is_arg based on var->kind");
	var->kind = RZ_ANALYSIS_VAR_KIND_VARIABLE;
	mu_assert_false(rz_analysis_var_is_arg(var), "rz_analysis_var_is_arg based on var->kind");
	free(var);

	rz_core_free(core);
	mu_end;
}

int all_tests() {
#if !ASAN
	mu_run_test(test_rz_analysis_var);
#endif
	mu_run_test(test_rz_analysis_function_get_stack_var_in);
	mu_run_test(test_rz_analysis_function_var_expr_for_reg_access_at);
	mu_run_test(test_rz_analysis_var_is_arg);
	return tests_passed != tests_run;
}

mu_main(all_tests)
