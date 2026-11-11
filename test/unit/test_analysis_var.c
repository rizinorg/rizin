// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "analysis_private.h"
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
	RzAnalysis *analysis = rz_analysis_new(NULL);
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
	RzAnalysis *analysis = rz_analysis_new(NULL);
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
	RzAnalysis *analysis = rz_analysis_new(NULL);
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

static bool test_extract_vars_stack_pointer(void) {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	mu_assert_notnull(analysis, "analysis");
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "stack_vars", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(fcn, "function");
	fcn->stack = 0x100;
	RzAnalysisOp op = { 0 };
	// mov rax, [rsp + 8]
	const ut8 bytes[] = { 0x48, 0x8b, 0x44, 0x24, 0x08 };
	mu_assert_eq(rz_analysis_op(analysis, &op, 0x100, bytes, sizeof(bytes), RZ_ANALYSIS_OP_MASK_VAL), sizeof(bytes), "decode stack load");
	rz_analysis_extract_vars(analysis, fcn, &op, -16);
	RzAnalysisVar *var = rz_analysis_function_get_stack_var_at(fcn, -8);
	mu_assert_notnull(var, "local uses the instruction's stack pointer");
	mu_assert_false(rz_analysis_var_is_arg(var), "local is not an argument");
	op.addr++;
	rz_analysis_extract_vars(analysis, fcn, &op, 0);
	var = rz_analysis_function_get_stack_var_at(fcn, 8);
	mu_assert_notnull(var, "genuine stack argument");
	mu_assert_true(rz_analysis_var_is_arg(var), "positive offset is an argument");
	op.addr++;
	rz_analysis_extract_vars(analysis, fcn, &op, RZ_STACK_ADDR_INVALID);
	rz_analysis_extract_vars(analysis, fcn, &op, ST64_MAX - 4);
	mu_assert_eq(rz_pvector_len(&fcn->vars), 2, "unknown and overflowing stack addresses create no variables");
	fcn->bp_frame = false;
	char *expr = rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x110, "rbp", 8);
	mu_assert_null(expr, "repurposed frame pointer does not name a stack argument");
	rz_analysis_op_fini(&op);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_arm_frame_pointer_vars(void) {
	const struct {
		const char *bytes;
		bool frame;
	} cases[] = {
		// mov fp, sp; accesses a local at fp - 4 and an argument at fp + 12.
		{ "00482de90db0a0e110d04de204000be50c009be510d08de20088bde8", true },
		// add fp, sp, 4; the same local and argument have different displacements.
		{ "00482de904b08de210d04de208000be508009be510d08de20088bde8", true },
		// ldr fp, [pc, 16]; fp addresses global data, while sp still addresses a local.
		{ "00482de910d04de20c008de510b09fe50c009be510d08de20088bde8", false },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		RzCore *core = rz_core_new();
		mu_assert_notnull(core, "core");
		rz_config_set(core->config, "asm.arch", "arm");
		rz_config_set_i(core->config, "asm.bits", 32);
		mu_assert_true(rz_core_file_open_load(core, "malloc://64", 0, RZ_PERM_RWX, true), "file");
		rz_core_cmdf(core, "wx %s", cases[i].bytes);
		rz_core_cmd0(core, "af");
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, 0);
		mu_assert_notnull(fcn, "analyzed function");
		mu_assert_eq(fcn->bp_frame, cases[i].frame, "recognize frame setup and global-data loads");
		for (int pass = 0; pass < 2; pass++) {
			RzAnalysisVar *local = rz_analysis_function_get_stack_var_at(fcn, -12);
			mu_assert_notnull(local, "preserve stack local");
			mu_assert_false(rz_analysis_var_is_arg(local), "local classification");
			RzList *vars = rz_analysis_var_list(fcn, RZ_ANALYSIS_VAR_STORAGE_STACK);
			mu_assert_eq(rz_list_length(vars), cases[i].frame ? 2 : 1, "only real stack variables");
			rz_list_free(vars);
			if (cases[i].frame) {
				RzAnalysisVar *arg = rz_analysis_function_get_stack_var_at(fcn, 4);
				mu_assert_notnull(arg, "preserve stack argument");
				mu_assert_true(rz_analysis_var_is_arg(arg), "argument classification");
			}
			if (!pass) {
				rz_core_cmd0(core, "afva");
			}
		}
		if (!cases[i].frame) {
			RzAnalysisVar *local = rz_analysis_function_get_stack_var_at(fcn, -12);
			rz_analysis_var_set_access(local, "fp", 0x30, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, -12);
			rz_analysis_function_check_bp_use(fcn);
			mu_assert_null(rz_analysis_var_get_access_at(local, 0x30), "remove the invalid fp access");
			mu_assert_notnull(rz_analysis_var_get_access_at(local, 8), "retain the valid sp access");
			assert_sane(core->analysis);
		}
		rz_core_free(core);
	}
	mu_end;
}

static bool test_x86_stack_var_recovery(void) {
	const struct {
		const char *bytes;
		st64 locals[2];
		bool frame;
	} cases[] = {
		// Saving esp to [ebp - 8] must not change the frame base.
		{ "5589e583ec208965f88b45fc8b4508c9c3", { -12, -8 }, true },
		// Each branch accesses [esp + 4] after a different stack allocation.
		{ "83ec2085c074098b4c240483c420c39083ec108b54240483c430c3", { -44, -28 }, false },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		RzCore *core = rz_core_new();
		mu_assert_notnull(core, "core");
		rz_config_set(core->config, "asm.arch", "x86");
		rz_config_set_i(core->config, "asm.bits", 32);
		mu_assert_true(rz_core_file_open_load(core, "malloc://64", 0, RZ_PERM_RWX, true), "file");
		rz_core_cmdf(core, "wx %s", cases[i].bytes);
		rz_core_cmd0(core, "af");
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, 0);
		mu_assert_notnull(fcn, "analyzed function");
		for (int pass = 0; pass < 2; pass++) {
			for (size_t j = 0; j < RZ_ARRAY_SIZE(cases[i].locals); j++) {
				RzAnalysisVar *local = rz_analysis_function_get_stack_var_at(fcn, cases[i].locals[j]);
				mu_assert_notnull(local, "preserve stack local");
				mu_assert_false(rz_analysis_var_is_arg(local), "local classification");
			}
			if (cases[i].frame) {
				mu_assert_eq(fcn->bp_off, 4, "store through ebp preserves the frame base");
				RzAnalysisVar *arg = rz_analysis_function_get_stack_var_at(fcn, 4);
				mu_assert_notnull(arg, "preserve stack argument");
				mu_assert_true(rz_analysis_var_is_arg(arg), "argument classification");
			} else {
				RzList *vars = rz_analysis_var_list(fcn, RZ_ANALYSIS_VAR_STORAGE_STACK);
				mu_assert_eq(rz_list_length(vars), 2, "both branches contain locals only");
				rz_list_free(vars);
			}
			assert_sane(core->analysis);
			if (!pass) {
				rz_core_cmd0(core, "afva");
			}
		}
		rz_core_free(core);
	}
	mu_end;
}

int all_tests() {
	mu_run_test(test_extract_vars_stack_pointer);
	mu_run_test(test_arm_frame_pointer_vars);
	mu_run_test(test_x86_stack_var_recovery);
#if !ASAN
	mu_run_test(test_rz_analysis_var);
#endif
	mu_run_test(test_rz_analysis_function_get_stack_var_in);
	mu_run_test(test_rz_analysis_function_var_expr_for_reg_access_at);
	mu_run_test(test_rz_analysis_var_is_arg);
	return tests_passed != tests_run;
}

mu_main(all_tests)
