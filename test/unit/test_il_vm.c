// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"
#include "rz_il/rz_il_events.h"
#include "rz_il/rz_il_opcodes.h"

static bool test_rzil_vm_init() {
	RzILVM *vm = rz_il_vm_new(0, 8, true, RZ_IL_EVENT_EXC_NONE);
	mu_assert_eq(vm->addr_size, 8, "VM Init");
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_global_vars() {
	RzILVM *vm = rz_il_vm_new(0, 8, true, RZ_IL_EVENT_EXC_NONE);

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
	mu_assert_ptreq(var_r1, find_var_r1, "Store and find r1");
	mu_assert_ptreq(var_r2, find_var_r2, "Store and find r2");

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
	RzILVM *vm = rz_il_vm_new(0, 8, true, RZ_IL_EVENT_EXC_NONE);
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
	mu_assert_ptreq(blackhole, find_blackhole, "Find Label");

	RzBitVector *find_addr = rz_il_hash_find_addr_by_lblname(vm, "blackhole");
	is_equal_bv = rz_bv_cmp(find_addr, addr) == 0 ? true : false;
	mu_assert("Find address equal", is_equal_bv);

	// create label lazy (without giving an address)
	RzILEffectLabel *lazy = rz_il_vm_create_label_lazy(vm, "lazy");
	RzILEffectLabel *find_lazy = rz_il_vm_find_label_by_name(vm, "lazy");
	mu_assert_ptreq(lazy, find_lazy, "Find lazy label");

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
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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

static bool test_rzil_vm_step() {
	RzILVM *vm = rz_il_vm_new(0, 16, false, RZ_IL_EVENT_EXC_NONE);

	RzILVar *var_r1 = rz_il_vm_create_global_var(vm, "r1", rz_il_sort_pure_bv(32));
	rz_il_vm_create_global_var(vm, "r2", rz_il_sort_pure_bv(32));

	// fallthrough
	RzILOpEffect *op = rz_il_op_new_set("r1", false, rz_il_op_new_bitv_from_ut64(32, 42));
	bool succ = rz_il_vm_step(vm, op, 0x321);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	RzILVal *val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, var_r1->name);
	mu_assert_notnull(val, "get val");
	mu_assert_eq(val->type, RZ_IL_TYPE_PURE_BITVECTOR, "set bv");
	mu_assert_eq(rz_bv_len(val->data.bv), 32, "set bv len");
	mu_assert_eq(rz_bv_to_ut64(val->data.bv), 42, "set bv val");
	RzBitVector *pc = vm->pc;
	mu_assert_notnull(pc, "pc");
	mu_assert_eq(rz_bv_to_ut64(pc), 0x321, "fallthrough pc");

	// jump overriding fallthrough
	op = rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(16, 0x678));
	succ = rz_il_vm_step(vm, op, 0x123);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	pc = vm->pc;
	mu_assert_notnull(pc, "pc");
	mu_assert_eq(rz_bv_to_ut64(pc), 0x678, "jumped pc");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_halt_on_exc() {
	ut64 expected_last_pc = 0x332; // The PC of the halting (div 0) instruction
	RzILEventException halt_for = RZ_IL_EVENT_EXC_DIV_ZERO;
	do {
		RzILVM *vm = rz_il_vm_new(0, 16, false, halt_for);

		RzILVar *var_r1 = rz_il_vm_create_global_var(vm, "r1", rz_il_sort_pure_bv(32));
		RzILVar *var_r2 = rz_il_vm_create_global_var(vm, "r2", rz_il_sort_pure_bv(32));

		RzILOpEffect *op = rz_il_op_new_set("r1", false, rz_il_op_new_bitv_from_ut64(32, 42));
		bool succ = rz_il_vm_step(vm, op, 0x331);
		rz_il_op_effect_free(op);
		mu_assert_true(succ, "success set r1");

		op = rz_il_op_new_set("r2", false, rz_il_op_new_bitv_from_ut64(32, 0));
		succ = rz_il_vm_step(vm, op, 0x332);
		rz_il_op_effect_free(op);
		mu_assert_true(succ, "success set r2");

		RzILOpPure *r1 = rz_il_op_new_var(var_r1->name, RZ_IL_VAR_KIND_GLOBAL);
		mu_assert_notnull(r1, "get val");
		RzILOpPure *r2 = rz_il_op_new_var(var_r2->name, RZ_IL_VAR_KIND_GLOBAL);
		mu_assert_notnull(r2, "get val");

		op = rz_il_op_new_set("r2", false, rz_il_op_new_div(r1, r2));
		succ = rz_il_vm_step(vm, op, 0x333);
		rz_il_op_effect_free(op);

		if (halt_for == RZ_IL_EVENT_EXC_DIV_ZERO) {
			mu_assert_false(succ, "VM did not halt after div0.");
			mu_assert_true(vm->halt, "VM halt flag not set.");
		} else {
			mu_assert_true(succ, "VM did halt after div0, but should not have.");
			mu_assert_false(vm->halt, "VM halt flag is set.");
		}
		RzBitVector *pc = vm->pc;
		mu_assert_notnull(pc, "pc");
		mu_assert_eq(rz_bv_to_ut64(pc), expected_last_pc, "VM pc doesn't match.");

		rz_il_vm_free(vm);

		// Do it again, this time don't halt on div 0
		// Expected PC is now one past div0 instruction (fallthrough address).
		expected_last_pc++;
		halt_for = RZ_IL_EVENT_EXC_NONE;
	} while (expected_last_pc == 0x334);

	mu_end;
}
static bool test_rzil_vm_op_let() {
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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

	// var and set for local pure vars should not emit events because everything is local
	mu_assert_eq(rz_pvector_len(vm->events), 0, "no events");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_cast() {
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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

	mu_assert_eq(rz_pvector_len(vm->events), 0, "no events");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_unsigned() {
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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

	mu_assert_eq(rz_pvector_len(vm->events), 0, "no events");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_signed() {
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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

	mu_assert_eq(rz_pvector_len(vm->events), 0, "no events");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_set() {
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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

	mu_assert_eq(rz_pvector_len(vm->events), 1, "events count");
	RzILEvent *ev = rz_pvector_at(vm->events, 0);
	mu_assert_eq(ev->type, RZ_IL_EVENT_VAR_WRITE, "event type");
	mu_assert_streq(ev->data.var_write.variable, "r1", "event var");
	RzBitVector *ref = rz_bv_new_from_ut64(32, 0);
	mu_assert_eq(ev->data.var_write.old_value->type, RZ_IL_TYPE_PURE_BITVECTOR, "event old value type");
	mu_assert_true(rz_bv_eq(ev->data.var_write.old_value->data.bv, ref), "event value");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(32, 42);
	mu_assert_eq(ev->data.var_write.new_value->type, RZ_IL_TYPE_PURE_BITVECTOR, "event old value type");
	mu_assert_true(rz_bv_eq(ev->data.var_write.new_value->data.bv, ref), "event value");
	rz_bv_free(ref);
	rz_il_vm_clear_events(vm);

	// set local temporarily
	op = rz_il_op_new_seq(
		rz_il_op_new_set("r1", true, rz_il_op_new_bitv_from_ut64(32, 2)),
		rz_il_op_new_set("r1", false,
			rz_il_op_new_div(rz_il_op_new_var("r1", RZ_IL_VAR_KIND_GLOBAL), rz_il_op_new_var("r1", RZ_IL_VAR_KIND_LOCAL))));
	succ = rz_il_vm_step(vm, op, 1); // use step here because it also clears the local vars
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

	mu_assert_eq(rz_pvector_len(vm->events), 3, "events count");

	ev = rz_pvector_at(vm->events, 0);
	mu_assert_eq(ev->type, RZ_IL_EVENT_PC_WRITE, "event type"); // pc write done by the step
	ref = rz_bv_new_from_ut64(8, 0);
	mu_assert_true(rz_bv_eq(ev->data.pc_write.old_pc, ref), "old pc");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(8, 1);
	mu_assert_true(rz_bv_eq(ev->data.pc_write.new_pc, ref), "new pc");
	rz_bv_free(ref);

	ev = rz_pvector_at(vm->events, 1);
	mu_assert_eq(ev->type, RZ_IL_EVENT_VAR_READ, "event type");
	mu_assert_streq(ev->data.var_write.variable, "r1", "event var");
	ref = rz_bv_new_from_ut64(32, 42);
	mu_assert_eq(ev->data.var_read.value->type, RZ_IL_TYPE_PURE_BITVECTOR, "event old value type");
	mu_assert_true(rz_bv_eq(ev->data.var_read.value->data.bv, ref), "event value");
	rz_bv_free(ref);

	ev = rz_pvector_at(vm->events, 2);
	mu_assert_eq(ev->type, RZ_IL_EVENT_VAR_WRITE, "event type");
	mu_assert_streq(ev->data.var_write.variable, "r1", "event var");
	ref = rz_bv_new_from_ut64(32, 42);
	mu_assert_eq(ev->data.var_write.old_value->type, RZ_IL_TYPE_PURE_BITVECTOR, "event old value type");
	mu_assert_true(rz_bv_eq(ev->data.var_write.old_value->data.bv, ref), "event value");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(32, 21);
	mu_assert_eq(ev->data.var_write.old_value->type, RZ_IL_TYPE_PURE_BITVECTOR, "event old value type");
	mu_assert_true(rz_bv_eq(ev->data.var_write.new_value->data.bv, ref), "event value");
	rz_bv_free(ref);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_jmp() {
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

	RzILOpEffect *op = rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(8, 0x42));
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	mu_assert_eq(rz_bv_to_ut64(vm->pc), 0x42, "jumped");

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_goto_addr() {
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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
	RzILVM *vm = rz_il_vm_new(0, 8, false, RZ_IL_EVENT_EXC_NONE);

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
	const ut8 data[] = { 0x10, 0x11, 0x12, 0x42, 0x14, 0x15 };
	RzILVM *vm = rz_il_vm_new(0, 12, false, RZ_IL_EVENT_EXC_NONE);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new_owned(buf, 16));

	RzILOpPure *op = rz_il_op_new_load(0, rz_il_op_new_bitv_from_ut64(16, 3));
	RzBitVector *res = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(res, "eval res");
	mu_assert_eq(rz_bv_len(res), 8, "res byte size");
	mu_assert_eq(rz_bv_to_ut64(res), 0x42, "res value");
	rz_bv_free(res);

	mu_assert_eq(rz_pvector_len(vm->events), 1, "events count");
	RzILEvent *ev = rz_pvector_at(vm->events, 0);
	mu_assert_eq(ev->type, RZ_IL_EVENT_MEM_READ, "event type");
	RzBitVector *ref = rz_bv_new_from_ut64(16, 3);
	mu_assert_true(rz_bv_eq(ev->data.mem_read.address, ref), "event addr");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(8, 0x42);
	mu_assert_true(rz_bv_eq(ev->data.mem_read.value, ref), "event value");
	rz_bv_free(ref);
	rz_il_vm_clear_events(vm);

	op = rz_il_op_new_load(0, rz_il_op_new_bitv_from_ut64(16, 100));
	res = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(res, "eval res");
	mu_assert_eq(rz_bv_len(res), 8, "res byte size");
	mu_assert_eq(rz_bv_to_ut64(res), 0xaa, "res value (overflow)");
	rz_bv_free(res);

	mu_assert_eq(rz_pvector_len(vm->events), 1, "events count");
	ev = rz_pvector_at(vm->events, 0);
	mu_assert_eq(ev->type, RZ_IL_EVENT_MEM_READ, "event type");
	ref = rz_bv_new_from_ut64(16, 100);
	mu_assert_true(rz_bv_eq(ev->data.mem_read.address, ref), "event addr");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(8, 0xaa);
	mu_assert_true(rz_bv_eq(ev->data.mem_read.value, ref), "event value");
	rz_bv_free(ref);
	rz_il_vm_clear_events(vm);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_store() {
	ut8 data[] = { 0x10, 0x11, 0x12, 0x42, 0x14, 0x15 };
	RzILVM *vm = rz_il_vm_new(0, 12, false, RZ_IL_EVENT_EXC_NONE);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new_owned(buf, 16));

	RzILOpEffect *op = rz_il_op_new_store(0, rz_il_op_new_bitv_from_ut64(16, 2), rz_il_op_new_bitv_from_ut64(8, 0xab));
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	ut8 expect[] = { 0x10, 0x11, 0xab, 0x42, 0x14, 0x15 };
	mu_assert_memeq(data, expect, sizeof(expect), "stored");

	mu_assert_eq(rz_pvector_len(vm->events), 1, "events count");
	RzILEvent *ev = rz_pvector_at(vm->events, 0);
	mu_assert_eq(ev->type, RZ_IL_EVENT_MEM_WRITE, "event type");
	RzBitVector *ref = rz_bv_new_from_ut64(16, 2);
	mu_assert_true(rz_bv_eq(ev->data.mem_write.address, ref), "event addr");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(8, 0x12);
	mu_assert_true(rz_bv_eq(ev->data.mem_write.old_value, ref), "event old value");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(8, 0xab);
	mu_assert_true(rz_bv_eq(ev->data.mem_write.new_value, ref), "event new value");
	rz_bv_free(ref);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_loadw_le() {
	const ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 12, false, RZ_IL_EVENT_EXC_NONE);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new_owned(buf, 16));

	RzILOpPure *op = rz_il_op_new_loadw(0, rz_il_op_new_bitv_from_ut64(16, 3), 16);
	RzBitVector *res = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(res, "eval res");
	mu_assert_eq(rz_bv_len(res), 16, "res byte size");
	mu_assert_eq(rz_bv_to_ut64(res), 0x442, "res value");
	rz_bv_free(res);

	mu_assert_eq(rz_pvector_len(vm->events), 1, "events count");
	RzILEvent *ev = rz_pvector_at(vm->events, 0);
	mu_assert_eq(ev->type, RZ_IL_EVENT_MEM_READ, "event type");
	RzBitVector *ref = rz_bv_new_from_ut64(16, 3);
	mu_assert_true(rz_bv_eq(ev->data.mem_read.address, ref), "event addr");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(16, 0x442);
	mu_assert_true(rz_bv_eq(ev->data.mem_read.value, ref), "event value");
	rz_bv_free(ref);
	rz_il_vm_clear_events(vm);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_storew_le() {
	ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 12, false, RZ_IL_EVENT_EXC_NONE);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new_owned(buf, 16));

	RzILOpEffect *op = rz_il_op_new_storew(0, rz_il_op_new_bitv_from_ut64(16, 2), rz_il_op_new_bitv_from_ut64(16, 0xabcd));
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	ut8 expect[] = { 0x0, 0x1, 0xcd, 0xab, 0x4, 0x5 };
	mu_assert_memeq(data, expect, sizeof(expect), "stored");

	mu_assert_eq(rz_pvector_len(vm->events), 1, "events count");
	RzILEvent *ev = rz_pvector_at(vm->events, 0);
	mu_assert_eq(ev->type, RZ_IL_EVENT_MEM_WRITE, "event type");
	RzBitVector *ref = rz_bv_new_from_ut64(16, 2);
	mu_assert_true(rz_bv_eq(ev->data.mem_write.address, ref), "event addr");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(16, 0x4202);
	mu_assert_true(rz_bv_eq(ev->data.mem_write.old_value, ref), "event old value");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(16, 0xabcd);
	mu_assert_true(rz_bv_eq(ev->data.mem_write.new_value, ref), "event new value");
	rz_bv_free(ref);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_loadw_be() {
	const ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 12, true, RZ_IL_EVENT_EXC_NONE);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new_owned(buf, 16));

	RzILOpPure *op = rz_il_op_new_loadw(0, rz_il_op_new_bitv_from_ut64(16, 3), 16);
	RzBitVector *res = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(res, "eval res");
	mu_assert_eq(rz_bv_len(res), 16, "res byte size");
	mu_assert_eq(rz_bv_to_ut64(res), 0x4204, "res value");

	mu_assert_eq(rz_pvector_len(vm->events), 1, "events count");
	RzILEvent *ev = rz_pvector_at(vm->events, 0);
	mu_assert_eq(ev->type, RZ_IL_EVENT_MEM_READ, "event type");
	RzBitVector *ref = rz_bv_new_from_ut64(16, 3);
	mu_assert_true(rz_bv_eq(ev->data.mem_read.address, ref), "event addr");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(16, 0x4204);
	mu_assert_true(rz_bv_eq(ev->data.mem_read.value, ref), "event value");
	rz_bv_free(ref);
	rz_il_vm_clear_events(vm);
	rz_bv_free(res);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_storew_be() {
	ut8 data[] = { 0x0, 0x1, 0x2, 0x42, 0x4, 0x5 };
	RzILVM *vm = rz_il_vm_new(0, 8, true, RZ_IL_EVENT_EXC_NONE);
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_il_vm_add_mem(vm, 0, rz_il_mem_new_owned(buf, 16));

	RzILOpEffect *op = rz_il_op_new_storew(0, rz_il_op_new_bitv_from_ut64(16, 2), rz_il_op_new_bitv_from_ut64(16, 0xabcd));
	bool succ = rz_il_evaluate_effect(vm, op);
	rz_il_op_effect_free(op);
	mu_assert_true(succ, "success");
	ut8 expect[] = { 0x0, 0x1, 0xab, 0xcd, 0x4, 0x5 };
	mu_assert_memeq(data, expect, sizeof(expect), "stored");

	mu_assert_eq(rz_pvector_len(vm->events), 1, "events count");
	RzILEvent *ev = rz_pvector_at(vm->events, 0);
	mu_assert_eq(ev->type, RZ_IL_EVENT_MEM_WRITE, "event type");
	RzBitVector *ref = rz_bv_new_from_ut64(16, 2);
	mu_assert_true(rz_bv_eq(ev->data.mem_write.address, ref), "event addr");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(16, 0x242);
	mu_assert_true(rz_bv_eq(ev->data.mem_write.old_value, ref), "event old value");
	rz_bv_free(ref);
	ref = rz_bv_new_from_ut64(16, 0xabcd);
	mu_assert_true(rz_bv_eq(ev->data.mem_write.new_value, ref), "event new value");
	rz_bv_free(ref);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_append() {
	RzILVM *vm = rz_il_vm_new(0, 8, true, RZ_IL_EVENT_EXC_NONE);

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

static bool test_rzil_vm_op_shiftr() {
	RzILVM *vm = rz_il_vm_new(0, 8, true, RZ_IL_EVENT_EXC_NONE);

	RzILOpPure *op = rz_il_op_new_shiftr(rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(16, 0xc0ff), rz_il_op_new_bitv_from_ut64(4, 3));
	RzBitVector *r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 16, "eval len");
	mu_assert_eq(rz_bv_to_ut64(r), 0xc0ff >> 3, "eval val");
	rz_bv_free(r);

	op = rz_il_op_new_shiftr(rz_il_op_new_b1(),
		rz_il_op_new_bitv_from_ut64(16, 0xc0ff), rz_il_op_new_bitv_from_ut64(4, 3));
	r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 16, "eval len");
	mu_assert_eq(rz_bv_to_ut64(r), (0xc0ff >> 3) | (uint16_t)(0xffff << (16 - 3)), "eval val");
	rz_bv_free(r);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_shiftl() {
	RzILVM *vm = rz_il_vm_new(0, 8, true, RZ_IL_EVENT_EXC_NONE);

	RzILOpPure *op = rz_il_op_new_shiftl(rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(16, 0xc0ff), rz_il_op_new_bitv_from_ut64(4, 3));
	RzBitVector *r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 16, "eval len");
	mu_assert_eq(rz_bv_to_ut64(r), (uint16_t)(0xc0ff << 3), "eval val");
	rz_bv_free(r);

	op = rz_il_op_new_shiftl(rz_il_op_new_b1(),
		rz_il_op_new_bitv_from_ut64(16, 0xc0ff), rz_il_op_new_bitv_from_ut64(4, 3));
	r = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_notnull(r, "eval");
	mu_assert_eq(rz_bv_len(r), 16, "eval len");
	mu_assert_eq(rz_bv_to_ut64(r), (uint16_t)(0xc0ff << 3) | (0xffff >> (16 - 3)), "eval val");
	rz_bv_free(r);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_compare() {
	RzILVM *vm = rz_il_vm_new(0, 8, true, RZ_IL_EVENT_EXC_NONE);
#define TEST_COMPARE(sign, name, lv, rv, expect) \
	do { \
		RzILOpBool *op = rz_il_op_new_##sign##name(rz_il_op_new_bitv_from_##sign##t64(32, lv), rz_il_op_new_bitv_from_##sign##t64(32, rv)); \
		RzILBool *r = rz_il_evaluate_bool(vm, op); \
		rz_il_op_pure_free(op); \
		mu_assert_notnull(r, "eval"); \
		mu_assert_##expect(r->b, "eval val"); \
		rz_il_bool_free(r); \
	} while (0);

	TEST_COMPARE(u, le, 100, 100, true);
	TEST_COMPARE(u, le, 100, 101, true);
	TEST_COMPARE(u, le, 101, 100, false);
	TEST_COMPARE(u, le, -1, 100, false);
	TEST_COMPARE(u, le, -42, -13, true);
	TEST_COMPARE(u, lt, 100, 100, false);
	TEST_COMPARE(u, lt, 100, 101, true);
	TEST_COMPARE(u, lt, 101, 100, false);
	TEST_COMPARE(u, lt, -1, 100, false);
	TEST_COMPARE(u, lt, -42, -13, true);
	TEST_COMPARE(u, ge, 100, 100, true);
	TEST_COMPARE(u, ge, 100, 101, false);
	TEST_COMPARE(u, ge, 101, 100, true);
	TEST_COMPARE(u, ge, -1, 100, true);
	TEST_COMPARE(u, ge, -42, -13, false);
	TEST_COMPARE(u, gt, 100, 100, false);
	TEST_COMPARE(u, gt, 100, 101, false);
	TEST_COMPARE(u, gt, 101, 100, true);
	TEST_COMPARE(u, gt, -1, 100, true);
	TEST_COMPARE(u, gt, -42, -13, false);

	TEST_COMPARE(s, le, 100, 100, true);
	TEST_COMPARE(s, le, 100, 101, true);
	TEST_COMPARE(s, le, 101, 100, false);
	TEST_COMPARE(s, le, -1, 100, true);
	TEST_COMPARE(s, le, -42, -13, true);
	TEST_COMPARE(s, lt, 100, 100, false);
	TEST_COMPARE(s, lt, 100, 101, true);
	TEST_COMPARE(s, lt, 101, 100, false);
	TEST_COMPARE(s, lt, -1, 100, true);
	TEST_COMPARE(s, lt, -42, -13, true);
	TEST_COMPARE(s, ge, 100, 100, true);
	TEST_COMPARE(s, ge, 100, 101, false);
	TEST_COMPARE(s, ge, 101, 100, true);
	TEST_COMPARE(s, ge, -1, 100, false);
	TEST_COMPARE(s, ge, -42, -13, false);
	TEST_COMPARE(s, gt, 100, 100, false);
	TEST_COMPARE(s, gt, 100, 101, false);
	TEST_COMPARE(s, gt, 101, 100, true);
	TEST_COMPARE(s, gt, -1, 100, false);
	TEST_COMPARE(s, gt, -42, -13, false);

#undef TEST_COMPARE
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_float() {
	RzILVM *vm = rz_il_vm_new(0, 64, false, RZ_IL_EVENT_EXC_NONE);

	// let f = 2.14 in
	//   (ite (is_fneg f)
	//	  (neg (fbits f))
	//	  (fbits (fsucc f))
	RzILOpBitVector *op;
	op = rz_il_op_new_let("f",
		rz_il_op_new_float_from_f64(2.14),
		rz_il_op_new_ite(
			rz_il_op_new_is_fneg(rz_il_op_new_var("f", RZ_IL_VAR_KIND_LOCAL_PURE)),
			rz_il_op_new_neg(
				rz_il_op_new_fbits(rz_il_op_new_var("f", RZ_IL_VAR_KIND_LOCAL_PURE))),
			rz_il_op_new_fbits(
				rz_il_op_new_fsucc(rz_il_op_new_var("f", RZ_IL_VAR_KIND_LOCAL_PURE)))));

	RzBitVector *bv = rz_il_evaluate_bitv(vm, op);
	rz_il_op_pure_free(op);
	mu_assert_eq(rz_bv_to_ut64(bv), 0x40011EB851EB8520, "test let float operations");
	rz_bv_free(bv);

	// let x = 11.25 in
	// let y = 15.02 in
	//  (fmul (fabs (x - y)) x)
	RzILOpFloat *fop;
	fop = rz_il_op_new_let("x",
		rz_il_op_new_float(RZ_FLOAT_IEEE754_BIN_64,
			rz_il_op_new_bitv_from_ut64(64, 0x4026800000000000)),
		rz_il_op_new_let("y",
			rz_il_op_new_float(RZ_FLOAT_IEEE754_BIN_64,
				rz_il_op_new_bitv_from_ut64(64, 0x402E0A3D70A3D70A)),
			rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE,
				rz_il_op_new_fabs(
					(rz_il_op_new_fsub(RZ_FLOAT_RMODE_RNE,
						rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL_PURE),
						rz_il_op_new_var("y", RZ_IL_VAR_KIND_LOCAL_PURE)))),
				rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL_PURE))));

	RzFloat *expect_f = rz_float_new_from_f64((15.02 - 11.25) * 11.25);
	RzFloat *act_f = rz_il_evaluate_float(vm, fop);

	rz_il_op_pure_free(fop);
	mu_assert_false(rz_float_cmp(expect_f, act_f), "float calc gets the same result in c");
	rz_float_free(expect_f);
	rz_float_free(act_f);

	// test float -> bool operations
	RzFloat *pinf = rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_64, false);
	RzFloat *nan = rz_float_new_qnan(RZ_FLOAT_IEEE754_BIN_64);
	RzFloat *zero = rz_float_new_zero(RZ_FLOAT_IEEE754_BIN_64, false);

	// bind value to var, ownership transfered
	rz_il_vm_create_global_var(vm, "inf", rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64));
	rz_il_vm_create_global_var(vm, "nan", rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64));
	rz_il_vm_create_global_var(vm, "zero", rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64));
	rz_il_vm_set_global_var(vm, "inf", rz_il_value_new_float(pinf));
	rz_il_vm_set_global_var(vm, "nan", rz_il_value_new_float(nan));
	rz_il_vm_set_global_var(vm, "zero", rz_il_value_new_float(zero));

	// is true (and (and is_inf is_nan) is_zero)
	RzILOpBool *bop = rz_il_op_new_bool_and(
		rz_il_op_new_bool_and(
			rz_il_op_new_is_inf(rz_il_op_new_var("inf", RZ_IL_VAR_KIND_GLOBAL)),
			rz_il_op_new_is_nan(rz_il_op_new_var("nan", RZ_IL_VAR_KIND_GLOBAL))),
		rz_il_op_new_is_fzero(rz_il_op_new_var("zero", RZ_IL_VAR_KIND_GLOBAL)));

	RzILBool *bool_ = rz_il_evaluate_bool(vm, bop);
	rz_il_op_pure_free(bop);
	mu_assert_true(bool_->b, "test fbasic bool operations");
	rz_il_bool_free(bool_);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_fcast() {
	// cast of float
	RzILVM *vm = rz_il_vm_new(0, 64, false, RZ_IL_EVENT_EXC_NONE);
	RzFloat *act_float;
	RzFloat *expect_float;

	// (cast-float 1)
	RzILOpFloat *op1 = rz_il_op_new_fcast_float(
		RZ_FLOAT_IEEE754_BIN_64,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_ut64(64, 1));
	act_float = rz_il_evaluate_float(vm, op1);
	expect_float = rz_float_new_from_f64(1.0);
	rz_il_op_pure_free(op1);
	mu_assert_false(rz_float_cmp(act_float, expect_float), "cast-float 1");
	rz_float_free(act_float);
	rz_float_free(expect_float);

	// (cast-sfloat -1)
	op1 = rz_il_op_new_fcast_sfloat(
		RZ_FLOAT_IEEE754_BIN_64,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_st64(64, -1));
	act_float = rz_il_evaluate_float(vm, op1);
	expect_float = rz_float_new_from_f64(-1.0);
	rz_il_op_pure_free(op1);
	mu_assert_false(rz_float_cmp(act_float, expect_float), "cast-sfloat -1");
	rz_float_free(act_float);
	rz_float_free(expect_float);

	// (cast-float -1)
	op1 = rz_il_op_new_fcast_float(
		RZ_FLOAT_IEEE754_BIN_64,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_ut64(64, -1));
	act_float = rz_il_evaluate_float(vm, op1);
	expect_float = rz_float_new_from_ut64_as_f64(0x43F0000000000000);
	rz_il_op_pure_free(op1);
	mu_assert_false(rz_float_cmp(act_float, expect_float), "cast-float -1");
	rz_float_free(act_float);
	rz_float_free(expect_float);

	// (cast-int (cast-float 1))
	RzILOpBitVector *op2 = rz_il_op_new_fcast_int(
		64,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_fcast_float(
			RZ_FLOAT_IEEE754_BIN_64,
			RZ_FLOAT_RMODE_RNE,
			rz_il_op_new_bitv_from_ut64(64, 1)));
	RzBitVector *bv = rz_il_evaluate_bitv(vm, op2);
	rz_il_op_pure_free(op2);
	mu_assert_eq(rz_bv_to_ut64(bv), 1, "cast-int cast-float 1");
	rz_bv_free(bv);

	// (convert 64 (cast-float 32 1))
	op1 = rz_il_op_new_fconvert(
		RZ_FLOAT_IEEE754_BIN_64,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_fcast_float(
			RZ_FLOAT_IEEE754_BIN_32,
			RZ_FLOAT_RMODE_RNE,
			rz_il_op_new_bitv_from_ut64(32, 1)));
	act_float = rz_il_evaluate_float(vm, op1);
	expect_float = rz_float_new_from_f64(1.0);

	rz_il_op_pure_free(op1);
	mu_assert_false(rz_float_cmp(act_float, expect_float), "fconvert 64-float -> 32 float");
	rz_float_free(expect_float);
	rz_float_free(act_float);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_op_fexcept() {
	/**
	 * test for execute fexcept op in rzil vm
	 * 1. div by zero
	 * 2. overflow
	 * 3. underflow
	 * 4. inexact result
	 */

	RzILVM *vm = rz_il_vm_new(0, 32, false, RZ_IL_EVENT_EXC_NONE);
	RzFloat *result;
	RzILBool *e;
	RzILOpFloat *op;
	RzILOpBool *eop;

	// 1. Test division by zero
	op = rz_il_op_new_fdiv(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(1.0),
		rz_il_op_new_float_from_f64(0.0));
	result = rz_il_evaluate_float(vm, op);

	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_DIV_ZERO, op);
	e = rz_il_evaluate_bool(vm, eop);

	mu_assert_true(rz_float_is_inf(result), "div by zero should result in infinity");
	mu_assert_true(e->b, "div by zero exception should be set");
	rz_float_free(result);
	rz_il_op_pure_free(eop);

	// 2. Test overflow
	op = rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(1e308),
		rz_il_op_new_float_from_f64(1e308));
	result = rz_il_evaluate_float(vm, op);
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_OVERFLOW, op);
	e = rz_il_evaluate_bool(vm, eop);

	mu_assert_true(rz_float_is_inf(result), "overflow should result in infinity");
	mu_assert_true(e->b, "overflow exception should be set");
	rz_float_free(result);
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);

	// 3. Test underflow
	op = rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(1e-308),
		rz_il_op_new_float_from_f64(1e-308));
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_UNDERFLOW, op);
	e = rz_il_evaluate_bool(vm, eop);
	mu_assert_true(e->b, "underflow exception should be set");
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);

	// 4. Test inexact result
	op = rz_il_op_new_fdiv(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(1.0),
		rz_il_op_new_float_from_f64(3.0));
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_INEXACT, op);
	e = rz_il_evaluate_bool(vm, eop);
	mu_assert_true(e->b, "inexact exception should be set");
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);

	rz_il_vm_free(vm);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rzil_vm_init);
	mu_run_test(test_rzil_vm_global_vars);
	mu_run_test(test_rzil_vm_labels);
	mu_run_test(test_rzil_vm_root_evaluation);
	mu_run_test(test_rzil_vm_step);
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
	mu_run_test(test_rzil_vm_op_shiftr);
	mu_run_test(test_rzil_vm_op_shiftl);
	mu_run_test(test_rzil_vm_op_compare);
	mu_run_test(test_rzil_vm_op_float);
	mu_run_test(test_rzil_vm_op_fcast);
	mu_run_test(test_rzil_vm_op_fexcept);
	mu_run_test(test_rzil_vm_halt_on_exc);
	return tests_passed != tests_run;
}

mu_main(all_tests)
