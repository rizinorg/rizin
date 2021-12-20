// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool test_rzil_vm_init() {
	RzILVM *vm = rz_il_vm_new(0, 8, 8);
	mu_assert_eq(vm->addr_size, 8, "VM Init");
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_basic_operation() {
	RzILVM *vm = rz_il_vm_new(0, 8, 16);

	// 1. create variables
	RzILVar *var_r1 = rz_il_vm_create_global_variable(vm, "r1", RZIL_VAR_TYPE_UNK, true);
	RzILVar *var_r2 = rz_il_vm_create_global_variable(vm, "r2", RZIL_VAR_TYPE_UNK, false);
	mu_assert_notnull(var_r1, "Create var 1");
	mu_assert_notnull(var_r2, "Create var 2");

	// check name
	mu_assert_streq(var_r1->var_name, "r1", "var r1 name");
	mu_assert_streq(var_r2->var_name, "r2", "var r2 name");

	// check type
	mu_assert_eq(var_r1->type, RZIL_VAR_TYPE_UNK, "var r1 type unk");
	mu_assert_eq(var_r2->type, RZIL_VAR_TYPE_UNK, "var r2 type unk");

	// check mutablity
	mu_assert_eq(var_r1->is_mutable, true, "var r1 is mutable");
	mu_assert_eq(var_r2->is_mutable, false, "var r2 is not mutable");

	// 2. find vars from vm
	RzILVar *find_var_r1 = rz_il_find_var_by_name(vm, "r1");
	RzILVar *find_var_r2 = rz_il_find_var_by_name(vm, "r2");
	mu_assert_eq(var_r1, find_var_r1, "Store and find r1");
	mu_assert_eq(var_r2, find_var_r2, "Store and find r2");

	// 3. create value
	RzILVal *val_r1 = rz_il_vm_create_value_bitv(vm, rz_bv_new_zero(32));
	RzILVal *val_r2 = rz_il_vm_create_value_bool(vm, false);
	mu_assert_notnull(val_r1, "Create val 1");
	mu_assert_notnull(val_r2, "Create val 2");

	// check type
	mu_assert_eq(val_r1->type, RZIL_VAR_TYPE_BV, "val 1 has type bitv");
	mu_assert_eq(val_r2->type, RZIL_VAR_TYPE_BOOL, "val 2 has type bool");

	// 4. bind value to var
	rz_il_hash_bind(vm, var_r1, val_r1);
	rz_il_hash_bind(vm, var_r2, val_r2);
	RzILVal *find_val_r1 = rz_il_hash_find_val_by_name(vm, "r1");
	RzILVal *find_val_r2 = rz_il_hash_find_val_by_name(vm, "r2");
	mu_assert_eq(val_r1, find_val_r1, "Bind and find");
	mu_assert_eq(val_r2, find_val_r2, "Bind and find");

	// 5. cancel binding
	rz_il_hash_cancel_binding(vm, var_r1);
	RzILVal *null_val = rz_il_hash_find_val_by_name(vm, "r1");
	mu_assert_null(null_val, "Cancel binding");

	// 6. bind to another one
	rz_il_hash_bind(vm, var_r1, val_r2);
	RzILVal *cur_var_r1_value = rz_il_hash_find_val_by_name(vm, "r1");
	RzILVal *cur_var_r2_value = rz_il_hash_find_val_by_name(vm, "r2");
	mu_assert_eq(cur_var_r1_value, cur_var_r2_value, "Bind to the same value");

	// 7. create label
	RzBitVector *addr = rz_bv_new_from_ut64(16, 233);
	RzILEffectLabel *blackhole = rz_il_vm_create_label(vm, "blackhole", addr);

	// default type is LABEL_ADDR
	mu_assert_eq(blackhole->type, EFFECT_LABEL_ADDR, "Label type");
	mu_assert_streq(blackhole->label_id, "blackhole", "Label name");

	bool is_equal_bv = rz_bv_cmp(blackhole->addr, addr) == 0 ? true : false;
	mu_assert("Label address correct", is_equal_bv);

	// find label
	RzILEffectLabel *find_blackhole = rz_il_vm_find_label_by_name(vm, "blackhole");
	mu_assert_eq(blackhole, find_blackhole, "Find Label");

	RzBitVector *find_addr = rz_il_hash_find_addr_by_lblname(vm, "blackhole");
	is_equal_bv = rz_bv_cmp(find_addr, addr) == 0 ? true : false;
	mu_assert("Find address equal", is_equal_bv);

	// 8. create label lazy (without giving an address)
	RzILEffectLabel *lazy = rz_il_vm_create_label_lazy(vm, "lazy");
	RzILEffectLabel *find_lazy = rz_il_vm_find_label_by_name(vm, "lazy");
	mu_assert_eq(lazy, find_lazy, "Find lazy label");

	RzBitVector *lazy_addr = rz_il_hash_find_addr_by_lblname(vm, "lazy");
	mu_assert_null(lazy_addr, "Lazy label have NULL address");

	// 9. update the address of lazy label
	rz_il_vm_update_label(vm, "lazy", addr);
	lazy_addr = rz_il_hash_find_addr_by_lblname(vm, "lazy");
	is_equal_bv = rz_bv_cmp(lazy_addr, addr) == 0 ? true : false;
	mu_assert_true(is_equal_bv, "Update lazy label successfully");

	rz_bv_free(addr);
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_operation() {
	RzILVM *vm = rz_il_vm_new(0, 8, 16);

	// 1. create register r0 and r1
	rz_il_vm_add_reg(vm, "r0", 8);
	rz_il_vm_add_reg(vm, "r1", 8);

	RzILVar *reg_r0 = rz_il_find_var_by_name(vm, "r0");
	RzILVar *reg_r1 = rz_il_find_var_by_name(vm, "r1");
	mu_assert_streq(reg_r0->var_name, "r0", "register name r0");
	mu_assert_streq(reg_r1->var_name, "r1", "register name r1");

	RzILVal *val_r0 = rz_il_hash_find_val_by_name(vm, "r0");
	RzILVal *val_r1 = rz_il_hash_find_val_by_name(vm, "r1");
	mu_assert_eq(val_r0->type, RZIL_VAR_TYPE_BV, "r0 is bitvector");
	mu_assert_eq(val_r1->type, RZIL_VAR_TYPE_BV, "r1 is bitvector");

	RzILVal *r0 = rz_il_hash_find_val_by_name(vm, "r0");
	RzILVal *r1 = rz_il_hash_find_val_by_name(vm, "r1");

	bool is_zero = rz_bv_is_zero_vector(r0->data.bv);
	mu_assert("Init r0 as all zero bitvector", is_zero);

	is_zero = rz_bv_is_zero_vector(r1->data.bv);
	mu_assert("Init r1 as all zero bitvector", is_zero);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_root_evaluation() {
	RzILVM *vm = rz_il_vm_new(0, 8, 16);

	// (ite (add 23 19)
	//	true
	//	false)
	// evaluate (add 23 19) will get a bitvector, but condition require a bool
	RzILOp *arg1 = rz_il_op_new_bitv_from_st64(16, 23);
	RzILOp *arg2 = rz_il_op_new_bitv_from_st64(16, 19);
	RzILOp *add = rz_il_op_new_add(arg1, arg2);
	RzILOp *true_val = rz_il_op_new_b1();
	RzILOp *false_val = rz_il_op_new_b0();
	RzILOp *ite_root = rz_il_op_new_ite(add, true_val, false_val);

	// Partially evaluate `condition` only
	RzILOpArgType type_checker = RZIL_OP_ARG_INIT;
	RzILBool *condition = rz_il_evaluate_bool(vm, ite_root->op.ite->condition, &type_checker);
	mu_assert_eq(type_checker, RZIL_OP_ARG_BOOL, "Evaluate a bool expression");
	mu_assert_eq(condition->b, true, "Correctly convert bitv to bool");
	rz_il_bool_free(condition);

	// Evaluate the whole ite expression
	RzILVal *ite_val = rz_il_evaluate_val(vm, ite_root, &type_checker);
	mu_assert_eq(type_checker, RZIL_OP_ARG_VAL, "Correctly get a RzILVal");
	mu_assert_eq(ite_val->type, RZIL_VAR_TYPE_BOOL, "Return a Bool Val");
	mu_assert_eq(ite_val->data.b->b, true, "Return a True");
	rz_il_value_free(ite_val);

	rz_il_op_free(ite_root);
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_set() {
	RzILVM *vm = rz_il_vm_new(0, 8, 16);

	RzILVar *var_r1 = rz_il_vm_create_global_variable(vm, "r1", RZIL_VAR_TYPE_UNK, true);
	RzILVar *var_r2 = rz_il_vm_create_global_variable(vm, "r2", RZIL_VAR_TYPE_UNK, false);
	rz_il_hash_bind(vm, var_r1, rz_il_vm_create_value_bitv(vm, rz_bv_new_zero(32)));
	rz_il_hash_bind(vm, var_r2, rz_il_vm_create_value_bitv(vm, rz_bv_new_zero(32)));

	// try to set immutable and fail
	RzILOp *op = rz_il_op_new_set("r2", rz_il_op_new_bitv_from_ut64(24, 42));
	RzILOpArgType tret = RZIL_OP_ARG_INIT;
	rz_il_evaluate_effect(vm, op, &tret);
	rz_il_op_free(op);
	RzILVal *val = rz_il_hash_find_val_by_name(vm, var_r2->var_name);
	mu_assert_notnull(val, "get val");
	mu_assert_eq(val->type, RZIL_VAR_TYPE_BV, "unchanged bv");
	mu_assert_eq(rz_bv_len(val->data.bv), 32, "unchanged bv len");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 0, "unchanged bv val");

	// set mutable
	op = rz_il_op_new_set("r1", rz_il_op_new_bitv_from_ut64(24, 42));
	tret = RZIL_OP_ARG_INIT;
	rz_il_evaluate_effect(vm, op, &tret);
	rz_il_op_free(op);
	val = rz_il_hash_find_val_by_name(vm, var_r1->var_name);
	mu_assert_notnull(val, "get val");
	mu_assert_eq(val->type, RZIL_VAR_TYPE_BV, "set bv");
	mu_assert_eq(rz_bv_len(val->data.bv), 24, "set bv len");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 42, "set bv val");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_jmp() {
	RzILVM *vm = rz_il_vm_new(0, 8, 16);

	RzILOp *op = rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(8, 0x42));
	RzILOpArgType tret = RZIL_OP_ARG_INIT;
	rz_il_evaluate_effect(vm, op, &tret);
	rz_il_op_free(op);
	mu_assert_eq(rz_bv_to_ut64(vm->pc), 0x42, "jumped");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_goto_addr() {
	RzILVM *vm = rz_il_vm_new(0, 8, 16);

	RzBitVector *dst = rz_bv_new_from_ut64(8, 0x42);
	rz_il_vm_create_label(vm, "beach", dst);
	rz_bv_free(dst);

	RzILOp *op = rz_il_op_new_goto("beach");
	RzILOpArgType tret = RZIL_OP_ARG_INIT;
	rz_il_evaluate_effect(vm, op, &tret);
	rz_il_op_free(op);
	mu_assert_eq(rz_bv_to_ut64(vm->pc), 0x42, "wentto");

	rz_il_vm_free(vm);
	mu_end;
}

static void hook_test(RzILVM *vm, RzILOp *op) {
	RzILVar *var = rz_il_find_var_by_name(vm, "myvar");
	rz_il_hash_bind(vm, var, rz_il_vm_create_value_bitv(vm, rz_bv_new_from_ut64(32, 0xc0ffee)));
}

static bool test_rzil_vm_op_goto_hook() {
	RzILVM *vm = rz_il_vm_new(0, 8, 16);

	RzILVar *var = rz_il_vm_create_global_variable(vm, "myvar", RZIL_VAR_TYPE_UNK, true);
	rz_il_hash_bind(vm, var, rz_il_vm_create_value_bitv(vm, rz_bv_new_zero(32)));

	RzBitVector *dst = rz_bv_new_from_ut64(8, 0x42);
	RzILEffectLabel *label = rz_il_vm_create_label_lazy(vm, "beach");
	label->type = EFFECT_LABEL_HOOK;
	label->hook = hook_test;
	rz_bv_free(dst);

	RzILOp *op = rz_il_op_new_goto("beach");
	RzILOpArgType tret = RZIL_OP_ARG_INIT;
	rz_il_evaluate_effect(vm, op, &tret);
	rz_il_op_free(op);

	// check the effect we implemented in hook_test
	RzILVal *val = rz_il_hash_find_val_by_name(vm, "myvar");
	mu_assert_eq(val->type, RZIL_VAR_TYPE_BV, "val type");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 0xc0ffee, "val contents");

	rz_il_vm_free(vm);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rzil_vm_init);
	mu_run_test(test_rzil_vm_basic_operation);
	mu_run_test(test_rzil_vm_operation);
	mu_run_test(test_rzil_vm_root_evaluation);
	mu_run_test(test_rzil_vm_op_set);
	mu_run_test(test_rzil_vm_op_jmp);
	mu_run_test(test_rzil_vm_op_goto_addr);
	mu_run_test(test_rzil_vm_op_goto_hook);
	return tests_passed != tests_run;
}

mu_main(all_tests)
