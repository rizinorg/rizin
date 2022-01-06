// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool test_rzil_vm_init() {
	RzILVM *vm = rz_il_vm_new(0, 8, true);
	mu_assert_eq(vm->addr_size, 8, "VM Init");
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_global_vars() {
	RzILVM *vm = rz_il_vm_new(0, 8, true);

	// 1. create variables
	RzILVar *var_r1 = rz_il_vm_create_global_var(vm, "r1", rz_il_sort_pure_bool());
	RzILVar *var_r2 = rz_il_vm_create_global_var(vm, "r2", rz_il_sort_pure_bv(32));
	mu_assert_notnull(var_r1, "Create var 1");
	mu_assert_notnull(var_r2, "Create var 2");

	// check name
	mu_assert_streq(var_r1->name, "r1", "var r1 name");
	mu_assert_streq(var_r2->name, "r2", "var r2 name");

	// check type
	mu_assert_true(rz_il_sort_pure_eq(var_r1->sort, rz_il_sort_pure_bool()), "var r1 sort");
	mu_assert_true(rz_il_sort_pure_eq(var_r2->sort, rz_il_sort_pure_bv(32)), "var r2 sort");

	// find vars from vm
	RzILVar *find_var_r1 = rz_il_vm_get_var(vm, RZ_IL_VAR_KIND_GLOBAL, "r1");
	RzILVar *find_var_r2 = rz_il_vm_get_var(vm, RZ_IL_VAR_KIND_GLOBAL, "r2");
	mu_assert_eq(var_r1, find_var_r1, "Store and find r1");
	mu_assert_eq(var_r2, find_var_r2, "Store and find r2");

	// initial contents
	RzILVal *val_r1 = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, "r1");
	mu_assert_eq(val_r1->type, RZ_IL_TYPE_PURE_BOOL, "val type");
	mu_assert_false(val_r1->data.b->b, "val content");
	RzILVal *val_r2 = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, "r2");
	mu_assert_eq(val_r2->type, RZ_IL_TYPE_PURE_BITVECTOR, "val type");
	mu_assert_eq(rz_bv_len(val_r2->data.bv), 32, "val bv len");
	mu_assert_eq(rz_bv_to_ut64(val_r2->data.bv), 0, "val bv content");

	// bind value to var
	rz_il_vm_set_global_var(vm, "r1", rz_il_value_new_bool(rz_il_bool_new(true)));
	rz_il_vm_set_global_var(vm, "r2", rz_il_value_new_bitv(rz_bv_new_from_ut64(32, 123)));
	val_r1 = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, "r1");
	mu_assert_eq(val_r1->type, RZ_IL_TYPE_PURE_BOOL, "val type");
	mu_assert_true(val_r1->data.b->b, "val content");
	val_r2 = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, "r2");
	mu_assert_eq(val_r2->type, RZ_IL_TYPE_PURE_BITVECTOR, "val type");
	mu_assert_eq(rz_bv_len(val_r2->data.bv), 32, "val bv len");
	mu_assert_eq(rz_bv_to_ut64(val_r2->data.bv), 123, "val bv content");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_labels() {
	RzILVM *vm = rz_il_vm_new(0, 8, true);
	// create label
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

	// create label lazy (without giving an address)
	RzILEffectLabel *lazy = rz_il_vm_create_label_lazy(vm, "lazy");
	RzILEffectLabel *find_lazy = rz_il_vm_find_label_by_name(vm, "lazy");
	mu_assert_eq(lazy, find_lazy, "Find lazy label");

	RzBitVector *lazy_addr = rz_il_hash_find_addr_by_lblname(vm, "lazy");
	mu_assert_null(lazy_addr, "Lazy label have NULL address");

	// update the address of lazy label
	rz_il_vm_update_label(vm, "lazy", addr);
	lazy_addr = rz_il_hash_find_addr_by_lblname(vm, "lazy");
	is_equal_bv = rz_bv_cmp(lazy_addr, addr) == 0 ? true : false;
	mu_assert_true(is_equal_bv, "Update lazy label successfully");

	rz_bv_free(addr);
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_root_evaluation() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	// (ite (add 23 19)
	//	true
	//	false)
	// evaluate (add 23 19) will get a bitvector, but condition require a bool
	RzILOpBitVector *arg1 = rz_il_op_new_bitv_from_st64(16, 23);
	RzILOpBitVector *arg2 = rz_il_op_new_bitv_from_st64(16, 19);
	RzILOpBitVector *add = rz_il_op_new_add(arg1, arg2);
	RzILOpBool *condition = rz_il_op_new_bool_inv(rz_il_op_new_eq(add, rz_il_op_new_bitv_from_ut64(16, 0)));
	RzILOpBool *true_val = rz_il_op_new_b1();
	RzILOpBool *false_val = rz_il_op_new_b0();
	RzILOpBitVector *ite_root = rz_il_op_new_ite(condition, true_val, false_val);

	// Partially evaluate `condition` only
	RzILBool *condition_res = rz_il_evaluate_bool(vm, ite_root->op.ite.condition);
	mu_assert_notnull(condition_res, "boolean eval success");
	mu_assert_eq(condition_res->b, true, "Evaluate boolean condition");
	rz_il_bool_free(condition_res);

	// Evaluate the whole ite expression
	RzILVal *ite_val = rz_il_evaluate_val(vm, ite_root);
	mu_assert_eq(ite_val->type, RZ_IL_TYPE_PURE_BOOL, "Return a Bool Val");
	mu_assert_eq(ite_val->data.b->b, true, "Return a True");
	rz_il_value_free(ite_val);

	rz_il_op_pure_free(ite_root);
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_let() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	// simple case:
	//   let preanswer = 41 in preanswer + 1
	RzILOpBitVector *op = rz_il_op_new_let("preanswer",
		rz_il_op_new_bitv_from_ut64(16, 41),
		rz_il_op_new_add(rz_il_op_new_var("preanswer", RZ_IL_VAR_KIND_LOCAL_PURE), rz_il_op_new_bitv_from_ut64(16, 1)));
	RzBitVector *r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 16, "eval len");
	mu_assert_eq(rz_bv_to_ut64(r), 42, "eval val");
	rz_bv_free(r);
	RzPVector *vars = rz_il_var_set_get_all(&vm->local_pure_vars);
	mu_assert_notnull(vars, "vars vector");
	mu_assert_eq(rz_pvector_len(vars), 0, "cleanup");
	rz_pvector_free(vars);

	// complex case with shadowing
	// let y = 0x23 in
	//   let x = 0xaaaa in
	//     y + cast 8 (let y = x + 0x2212 in y - x)
	op = rz_il_op_new_let("y", rz_il_op_new_bitv_from_ut64(8, 0x23),
		rz_il_op_new_let("x", rz_il_op_new_bitv_from_ut64(16, 0xaaaa),
			rz_il_op_new_add(
				rz_il_op_new_var("y", RZ_IL_VAR_KIND_LOCAL_PURE),
				rz_il_op_new_cast(8, rz_il_op_new_b0(),
					rz_il_op_new_let("y",
						rz_il_op_new_add(rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL_PURE), rz_il_op_new_bitv_from_ut64(16, 0x2212)),
						rz_il_op_new_sub(rz_il_op_new_var("y", RZ_IL_VAR_KIND_LOCAL_PURE), rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL_PURE)))))));
	r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 8, "eval len");
	mu_assert_eq(rz_bv_to_ut64(r), 0x35, "eval val");
	rz_bv_free(r);
	vars = rz_il_var_set_get_all(&vm->local_pure_vars);
	mu_assert_notnull(vars, "vars vector");
	mu_assert_eq(rz_pvector_len(vars), 0, "cleanup");
	rz_pvector_free(vars);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_cast() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	// 8 -> 8
	RzILOpPure *op = rz_il_op_new_cast(8, rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(8, 0x42));
	RzBitVector *r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 8, "eval length");
	mu_assert_eq(rz_bv_to_ut64(r), 0x42, "eval val");
	rz_bv_free(r);

	// 8 -> 4
	op = rz_il_op_new_cast(4, rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(8, 0x42));
	r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 4, "eval length");
	mu_assert_eq(rz_bv_to_ut64(r), 0x2, "eval val");
	rz_bv_free(r);

	// 8 -> 13 (false)
	op = rz_il_op_new_cast(13, rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(8, 0x42));
	r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 13, "eval length");
	mu_assert_eq(rz_bv_to_ut64(r), 0x42, "eval val");
	rz_bv_free(r);

	// 8 -> 13 (true)
	op = rz_il_op_new_cast(13, rz_il_op_new_b1(), rz_il_op_new_bitv_from_ut64(8, 0x42));
	r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 13, "eval length");
	mu_assert_eq(rz_bv_to_ut64(r), 0x1f42, "eval val");
	rz_bv_free(r);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_unsigned() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	// msb not set, filled with 0
	RzILOpPure *op = rz_il_op_new_unsigned(13, rz_il_op_new_bitv_from_ut64(8, 0x42));
	RzBitVector *r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 13, "eval length");
	mu_assert_eq(rz_bv_to_ut64(r), 0x42, "eval val");
	rz_bv_free(r);

	// msb set, still filled with 0
	op = rz_il_op_new_unsigned(13, rz_il_op_new_bitv_from_ut64(8, 0xf2));
	r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 13, "eval length");
	mu_assert_eq(rz_bv_to_ut64(r), 0xf2, "eval val");
	rz_bv_free(r);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_signed() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	// msb not set, filled with 0
	RzILOpPure *op = rz_il_op_new_signed(13, rz_il_op_new_bitv_from_ut64(8, 0x42));
	RzBitVector *r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 13, "eval length");
	mu_assert_eq(rz_bv_to_ut64(r), 0x42, "eval val");
	rz_bv_free(r);

	// msb set, filled with 1
	op = rz_il_op_new_signed(13, rz_il_op_new_bitv_from_ut64(8, 0xf2));
	r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 13, "eval length");
	mu_assert_eq(rz_bv_to_ut64(r), 0x1ff2, "eval val");
	rz_bv_free(r);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_set() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	RzILVar *var_r1 = rz_il_vm_create_global_var(vm, "r1", rz_il_sort_pure_bv(32));
	rz_il_vm_create_global_var(vm, "r2", rz_il_sort_pure_bv(32));

	// set global
	RzILOpEffect *op = rz_il_op_new_set("r1", false, rz_il_op_new_bitv_from_ut64(32, 42));
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	RzILVal *val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, var_r1->name);
	mu_assert_true(succ, "success");
	mu_assert_notnull(val, "get val");
	mu_assert_eq(val->type, RZ_IL_TYPE_PURE_BITVECTOR, "set bv");
	mu_assert_eq(rz_bv_len(val->data.bv), 32, "set bv len");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 42, "set bv val");
	RzPVector *vars = rz_il_var_set_get_all(&vm->local_vars);
	mu_assert_notnull(vars, "vars vector");
	mu_assert_eq(rz_pvector_len(vars), 0, "cleanup");
	rz_pvector_free(vars);

	// set local temporarily
	op = rz_il_op_new_seq(
		rz_il_op_new_set("r1", true, rz_il_op_new_bitv_from_ut64(32, 2)),
		rz_il_op_new_set("r1", false,
			rz_il_op_new_div(rz_il_op_new_var("r1", RZ_IL_VAR_KIND_GLOBAL), rz_il_op_new_var("r1", RZ_IL_VAR_KIND_LOCAL))));
	succ = rz_il_vm_step(vm, op, 1);
	rz_il_op_effect_free(op);
	val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, var_r1->name);
	mu_assert_true(succ, "success");
	mu_assert_notnull(val, "get val");
	mu_assert_eq(val->type, RZ_IL_TYPE_PURE_BITVECTOR, "set bv");
	mu_assert_eq(rz_bv_len(val->data.bv), 32, "set bv len");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 21, "set bv val");
	vars = rz_il_var_set_get_all(&vm->local_vars);
	mu_assert_notnull(vars, "vars vector");
	mu_assert_eq(rz_pvector_len(vars), 0, "cleanup");
	rz_pvector_free(vars);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_jmp() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	RzILOpEffect *op = rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(8, 0x42));
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	mu_assert_eq(rz_bv_to_ut64(vm->pc), 0x42, "jumped");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_goto_addr() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	RzBitVector *dst = rz_bv_new_from_ut64(8, 0x42);
	rz_il_vm_create_label(vm, "beach", dst);
	rz_bv_free(dst);

	RzILOpEffect *op = rz_il_op_new_goto("beach");
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	mu_assert_eq(rz_bv_to_ut64(vm->pc), 0x42, "wentto");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_blk() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	RzILVar *var = rz_il_vm_create_global_var(vm, "leetbap", rz_il_sort_pure_bv(8));
	rz_il_vm_set_global_var(vm, var->name, rz_il_value_new_bitv(rz_bv_new_from_ut64(8, 0x42)));
	RzILOpEffect *data_eff = rz_il_op_new_set("leetbap", false, rz_il_op_new_bitv_from_ut64(8, 0x13));

	RzBitVector *dst = rz_bv_new_from_ut64(8, 0x07);
	rz_il_vm_create_label(vm, "beach", dst);
	rz_bv_free(dst);
	RzILOpEffect *ctrl_eff = rz_il_op_new_goto("beach");

	RzILOpEffect *op = rz_il_op_new_blk("newblk", data_eff, ctrl_eff);
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);

	mu_assert_true(succ, "op failed");
	RzILVal *val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, var->name);
	mu_assert_notnull(val, "val null");
	mu_assert_eq(val->type, RZ_IL_TYPE_PURE_BITVECTOR, "type not bv");
	mu_assert_eq(rz_bv_len(val->data.bv), 8, "len not correct");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 0x13, "bitv not correct");
	mu_assert_eq(rz_bv_to_ut64(vm->pc), 0x07, "wrong pc");

	rz_il_vm_free(vm);
	mu_end;
}

/**
 * \brief Test a loop
 *
 * Equivalent C code:
 *
 * ```c
 * unsigned short leetbap = 42;
 * unsigned char i = 7;
 * while (i - 1 != 0) {
 *     leetbap = leetbap * 3;
 *     i = i - 1;
 * }
 * ```
 *
 * In the end, leetbap == 30618
 */
static bool test_rzil_vm_op_repeat() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	RzILVar *var = rz_il_vm_create_global_var(vm, "leetbap", rz_il_sort_pure_bv(16));
	rz_il_vm_set_global_var(vm, var->name, rz_il_value_new_bitv(rz_bv_new_from_ut64(16, 42)));
	RzILVar *count = rz_il_vm_create_global_var(vm, "i", rz_il_sort_pure_bv(8));
	rz_il_vm_set_global_var(vm, count->name, rz_il_value_new_bitv(rz_bv_new_from_ut64(8, 7)));

	RzILOpBitVector *sub = rz_il_op_new_sub(rz_il_op_new_var("i", RZ_IL_VAR_KIND_GLOBAL), rz_il_op_new_bitv_from_ut64(8, 1));
	RzILOpBitVector *mul = rz_il_op_new_mul(rz_il_op_new_var("leetbap", RZ_IL_VAR_KIND_GLOBAL), rz_il_op_new_bitv_from_ut64(16, 3));

	RzILOpEffect *mul_eff = rz_il_op_new_set("leetbap", false, mul);
	RzILOpEffect *sub_eff = rz_il_op_new_set("i", false, rz_il_op_pure_dup(sub));
	RzILOpEffect *data_seq = rz_il_op_new_seq(mul_eff, sub_eff);
	RzILOpBool *c = rz_il_op_new_non_zero(sub);

	RzILOpEffect *op = rz_il_op_new_repeat(c, data_seq);
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);

	mu_assert_true(succ, "op failed");
	RzILVal *val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, var->name);
	mu_assert_notnull(val, "leetbap null");
	mu_assert_eq(val->type, RZ_IL_TYPE_PURE_BITVECTOR, "leetbap type not bv");
	mu_assert_eq(rz_bv_len(val->data.bv), 16, "leetbap len not correct");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 30618, "leetbap bitv not correct");
	RzILVal *val2 = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, count->name);
	mu_assert_notnull(val2, "i null");
	mu_assert_eq(val2->type, RZ_IL_TYPE_PURE_BITVECTOR, "i type not bv");
	mu_assert_eq(rz_bv_len(val2->data.bv), 8, "i len not correct");
	mu_assert_eq(rz_bv_to_ut64(val2->data.bv), 1, "i bitv not correct");

	rz_il_vm_free(vm);
	mu_end;
}

static void hook_test(RzILVM *vm, RzILOpEffect *op) {
	rz_il_vm_set_global_var(vm, "myvar", rz_il_value_new_bitv(rz_bv_new_from_ut64(32, 0xc0ffee)));
}

static bool test_rzil_vm_op_goto_hook() {
	RzILVM *vm = rz_il_vm_new(0, 8, false);

	rz_il_vm_create_global_var(vm, "myvar", rz_il_sort_pure_bv(32));

	RzBitVector *dst = rz_bv_new_from_ut64(8, 0x42);
	RzILEffectLabel *label = rz_il_vm_create_label_lazy(vm, "beach");
	label->type = EFFECT_LABEL_HOOK;
	label->hook = hook_test;
	rz_bv_free(dst);

	RzILOpEffect *op = rz_il_op_new_goto("beach");
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");

	// check the effect we implemented in hook_test
	RzILVal *val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, "myvar");
	mu_assert_eq(val->type, RZ_IL_TYPE_PURE_BITVECTOR, "val type");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 0xc0ffee, "val contents");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_load() {
	const ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 8, false);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new(buf, 16));
	rz_buf_free(buf);

	RzILOpPure *op = rz_il_op_new_load(0, rz_il_op_new_bitv_from_ut64(16, 3));
	RzBitVector *res = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(res, "eval res");
	mu_assert_eq(rz_bv_len(res), 8, "res byte size");
	mu_assert_eq(rz_bv_to_ut64(res), 0x42, "res value");
	rz_bv_free(res);

	op = rz_il_op_new_load(0, rz_il_op_new_bitv_from_ut64(16, 100));
	res = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(res, "eval res");
	mu_assert_eq(rz_bv_len(res), 8, "res byte size");
	mu_assert_eq(rz_bv_to_ut64(res), 0xaa, "res value (overflow)");
	rz_bv_free(res);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_store() {
	ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 8, false);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new(buf, 16));
	rz_buf_free(buf);

	RzILOpEffect *op = rz_il_op_new_store(0, rz_il_op_new_bitv_from_ut64(16, 2), rz_il_op_new_bitv_from_ut64(8, 0xab));
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	ut8 expect[] = { 0x0, 0x1, 0xab, 0x42, 0x4, 0x5 };
	mu_assert_memeq(data, expect, sizeof(expect), "stored");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_loadw_le() {
	const ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 8, false);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new(buf, 16));
	rz_buf_free(buf);

	RzILOpPure *op = rz_il_op_new_loadw(0, rz_il_op_new_bitv_from_ut64(16, 3), 16);
	RzBitVector *res = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(res, "eval res");
	mu_assert_eq(rz_bv_len(res), 16, "res byte size");
	mu_assert_eq(rz_bv_to_ut64(res), 0x442, "res value");
	rz_bv_free(res);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_storew_le() {
	ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 8, false);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new(buf, 16));
	rz_buf_free(buf);

	RzILOpEffect *op = rz_il_op_new_storew(0, rz_il_op_new_bitv_from_ut64(16, 2), rz_il_op_new_bitv_from_ut64(16, 0xabcd));
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	ut8 expect[] = { 0x0, 0x1, 0xcd, 0xab, 0x4, 0x5 };
	mu_assert_memeq(data, expect, sizeof(expect), "stored");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_loadw_be() {
	const ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 8, true);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new(buf, 16));
	rz_buf_free(buf);

	RzILOpPure *op = rz_il_op_new_loadw(0, rz_il_op_new_bitv_from_ut64(16, 3), 16);
	RzBitVector *res = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(res, "eval res");
	mu_assert_eq(rz_bv_len(res), 16, "res byte size");
	mu_assert_eq(rz_bv_to_ut64(res), 0x4204, "res value");
	rz_bv_free(res);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_storew_be() {
	ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 8, true);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new(buf, 16));
	rz_buf_free(buf);

	RzILOpEffect *op = rz_il_op_new_storew(0, rz_il_op_new_bitv_from_ut64(16, 2), rz_il_op_new_bitv_from_ut64(16, 0xabcd));
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	ut8 expect[] = { 0x0, 0x1, 0xab, 0xcd, 0x4, 0x5 };
	mu_assert_memeq(data, expect, sizeof(expect), "stored");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_append() {
	RzILVM *vm = rz_il_vm_new(0, 8, true);

	RzILOpPure *op = rz_il_op_new_append(rz_il_op_new_bitv_from_ut64(16, 0xc0ff), rz_il_op_new_bitv_from_ut64(8, 0xee));
	RzBitVector *r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 24, "eval len");
	mu_assert_eq(rz_bv_to_ut64(r), 0xc0ffee, "eval val");
	rz_bv_free(r);

	rz_il_vm_free(vm);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rzil_vm_init);
	mu_run_test(test_rzil_vm_global_vars);
	mu_run_test(test_rzil_vm_labels);
	mu_run_test(test_rzil_vm_root_evaluation);
	mu_run_test(test_rzil_vm_op_let);
	mu_run_test(test_rzil_vm_op_cast);
	mu_run_test(test_rzil_vm_op_unsigned);
	mu_run_test(test_rzil_vm_op_signed);
	mu_run_test(test_rzil_vm_op_set);
	mu_run_test(test_rzil_vm_op_jmp);
	mu_run_test(test_rzil_vm_op_goto_addr);
	mu_run_test(test_rzil_vm_op_goto_hook);
	mu_run_test(test_rzil_vm_op_blk);
	mu_run_test(test_rzil_vm_op_repeat);
	mu_run_test(test_rzil_vm_op_load);
	mu_run_test(test_rzil_vm_op_store);
	mu_run_test(test_rzil_vm_op_loadw_le);
	mu_run_test(test_rzil_vm_op_storew_le);
	mu_run_test(test_rzil_vm_op_loadw_be);
	mu_run_test(test_rzil_vm_op_storew_be);
	mu_run_test(test_rzil_vm_op_append);
	return tests_passed != tests_run;
}

mu_main(all_tests)
