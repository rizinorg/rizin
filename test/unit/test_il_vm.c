// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include <rz_util/rz_graph_drawable.h>
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
	mu_assert_eq(rz_pvector_len(vm->events), 1, "div by zero exception event");
	rz_float_free(result);
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);
	rz_il_vm_clear_events(vm);

	// 2. Test overflow
	op = rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(1e308),
		rz_il_op_new_float_from_f64(1e308));
	result = rz_il_evaluate_float(vm, op);
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_OVERFLOW, op);
	e = rz_il_evaluate_bool(vm, eop);

	mu_assert_true(rz_float_is_inf(result), "overflow should result in infinity");
	mu_assert_true(e->b, "overflow exception should be set");
	mu_assert_eq(rz_pvector_len(vm->events), 1, "overflow exception event");
	rz_float_free(result);
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);
	rz_il_vm_clear_events(vm);

	// 3. Test underflow
	op = rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(1e-308),
		rz_il_op_new_float_from_f64(1e-308));
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_UNDERFLOW, op);
	e = rz_il_evaluate_bool(vm, eop);
	mu_assert_true(e->b, "underflow exception should be set");
	mu_assert_eq(rz_pvector_len(vm->events), 1, "underflow exception event");
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);
	rz_il_vm_clear_events(vm);

	// 4. Test inexact result
	op = rz_il_op_new_fdiv(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(1.0),
		rz_il_op_new_float_from_f64(3.0));
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_INEXACT, op);
	e = rz_il_evaluate_bool(vm, eop);
	mu_assert_true(e->b, "inexact exception should be set");
	mu_assert_eq(rz_pvector_len(vm->events), 1, "inexact exception event");
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);
	rz_il_vm_clear_events(vm);

	// Querying an exception that is not present must not emit an event.
	op = rz_il_op_new_fdiv(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(1.0),
		rz_il_op_new_float_from_f64(1.0));
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_INVALID_OP, op);
	e = rz_il_evaluate_bool(vm, eop);
	mu_assert_false(e->b, "invalid-operation exception should be clear");
	mu_assert_eq(rz_pvector_len(vm->events), 0, "absent float exception emits no event");
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);

	// Float conversions must preserve exceptions from nested operations.
	op = rz_il_op_new_fconvert(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_fconvert(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE,
			rz_il_op_new_float_from_f64(1.0 + 0x1p-30)));
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_INEXACT, op);
	e = rz_il_evaluate_bool(vm, eop);
	mu_assert_true(e->b, "float conversion preserves nested inexact exception");
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);
	rz_il_vm_clear_events(vm);

	// Arithmetic composition must preserve exceptions raised by child operations.
	op = rz_il_op_new_fadd(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f32(0.0f),
		rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE,
			rz_il_op_new_float_from_f32(1e38f),
			rz_il_op_new_float_from_f32(1e38f)));
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_OVERFLOW, op);
	e = rz_il_evaluate_bool(vm, eop);
	mu_assert_true(e->b, "float arithmetic preserves nested overflow exception");
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);
	rz_il_vm_clear_events(vm);

	op = rz_il_op_new_fconvert(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_fsub(RZ_FLOAT_RMODE_RNE,
			rz_il_op_new_float_from_f64(F64_PINF),
			rz_il_op_new_float_from_f64(F64_PINF)));
	eop = rz_il_op_new_fexcept(RZ_FLOAT_E_INVALID_OP, op);
	e = rz_il_evaluate_bool(vm, eop);
	mu_assert_true(e->b, "float conversion preserves nested invalid-operation exception");
	rz_il_op_pure_free(eop);
	rz_il_bool_free(e);

	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_binary80_full_precision() {
	RzILVM *vm = rz_il_vm_new(0, 32, false, RZ_IL_EVENT_EXC_NONE);
	RzFloatRPrecision original_precision = rz_float_ext80_get_rounding_precision();
	mu_assert_true(original_precision != RZ_FLOAT_RPREC_UNK, "initial binary80 precision is valid");

	const struct {
		RzFloatRPrecision ambient_precision;
		long double input;
	} mul_cases[] = {
		{ RZ_FLOAT_RPREC_32, 1.0L + 0x1.8p-23L },
		{ RZ_FLOAT_RPREC_64, 1.0L + 0x1.8p-52L },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(mul_cases); i++) {
		mu_assert_true(rz_float_ext80_set_rounding_precision(mul_cases[i].ambient_precision), "set reduced ambient precision");
		RzILOpFloat *op = rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE,
			rz_il_op_new_float_from_f80(mul_cases[i].input),
			rz_il_op_new_float_from_f80(1.0L));
		RzFloat *actual = rz_il_evaluate_float(vm, op);
		RzFloat *expected = rz_float_new_from_f80(mul_cases[i].input);
		mu_assert_notnull(actual, "binary80 multiply");
		mu_assert_false(rz_float_cmp(actual, expected), "RzIL binary80 multiply uses full precision");
		mu_assert_eq(rz_float_ext80_get_rounding_precision(), mul_cases[i].ambient_precision, "multiply restores ambient precision");
		rz_float_free(actual);
		rz_float_free(expected);
		rz_il_op_pure_free(op);
	}

	mu_assert_true(rz_float_ext80_set_rounding_precision(RZ_FLOAT_RPREC_80), "set full precision for reference sqrt");
	RzFloat *sqrt_input = rz_float_new_from_f80(2.0L);
	RzFloat *expected = rz_float_sqrt(sqrt_input, RZ_FLOAT_RMODE_RNE);
	rz_float_free(sqrt_input);
	mu_assert_notnull(expected, "full-precision sqrt reference");
	mu_assert_true(rz_float_ext80_set_rounding_precision(RZ_FLOAT_RPREC_32), "set reduced precision before RzIL sqrt");
	RzILOpFloat *op = rz_il_op_new_fsqrt(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f80(2.0L));
	RzFloat *actual = rz_il_evaluate_float(vm, op);
	mu_assert_notnull(actual, "binary80 sqrt");
	mu_assert_false(rz_float_cmp(actual, expected), "RzIL binary80 sqrt uses full precision");
	mu_assert_eq(rz_float_ext80_get_rounding_precision(), RZ_FLOAT_RPREC_32, "sqrt restores ambient precision");
	rz_float_free(actual);
	rz_float_free(expected);
	rz_il_op_pure_free(op);

	mu_assert_true(rz_float_ext80_set_rounding_precision(RZ_FLOAT_RPREC_32), "set reduced precision before RzIL FMA");
	op = rz_il_op_new_fmad(RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f80(1.0L),
		rz_il_op_new_float_from_f80(1.0L),
		rz_il_op_new_float_from_f80(0x1p-30L));
	actual = rz_il_evaluate_float(vm, op);
	expected = rz_float_new_from_f80(1.0L + 0x1p-30L);
	mu_assert_notnull(actual, "binary80 fused multiply-add");
	mu_assert_false(rz_float_cmp(actual, expected), "RzIL binary80 FMA uses full precision");
	mu_assert_eq(rz_float_ext80_get_rounding_precision(), RZ_FLOAT_RPREC_32, "FMA restores ambient precision");
	rz_float_free(actual);
	rz_float_free(expected);
	rz_il_op_pure_free(op);

	mu_assert_true(rz_float_ext80_set_rounding_precision(original_precision), "restore initial binary80 precision");
	rz_il_vm_free(vm);
	mu_end;
}

static bool runtime_rmode_result_is(RzILVM *vm, RzILOpFloat *op, const char *expected) {
	if (!op) {
		return false;
	}
	RzFloat *actual = rz_il_evaluate_float(vm, op);
	char *hex = actual ? rz_float_as_hex_string(actual, true) : NULL;
	bool matches = hex && !strcmp(hex, expected);
	free(hex);
	rz_float_free(actual);
	rz_il_op_pure_free(op);
	return matches;
}

static bool test_rzil_vm_float_rmode_arguments() {
	RzILOpFloat *op = rz_il_op_new_fadd(
		RZ_FLOAT_RMODE_RTZ,
		rz_il_op_new_float_from_f32(1.0f),
		rz_il_op_new_float_from_f32(2.0f));
	mu_assert_notnull(op, "static-rmode op");
	mu_assert_eq(op->code, RZ_IL_OP_FADD, "static constructor uses base opcode");
	mu_assert_eq(op->op.fadd.rmode.kind, RZ_IL_OP_ARG_FLOAT_RMODE_STATIC, "static rmode tag");
	mu_assert_eq(op->op.fadd.rmode.value.static_mode, RZ_FLOAT_RMODE_RTZ, "static rmode value");

	RzILOpPure *copy = rz_il_op_pure_dup(op);
	mu_assert_notnull(copy, "static-rmode op copy");
	mu_assert_eq(copy->code, RZ_IL_OP_FADD, "copied static op keeps base opcode");
	mu_assert_eq(copy->op.fadd.rmode.kind, RZ_IL_OP_ARG_FLOAT_RMODE_STATIC, "copied static rmode tag");
	mu_assert_eq(copy->op.fadd.rmode.value.static_mode, RZ_FLOAT_RMODE_RTZ, "copied static rmode value");

	RzStrBuf text;
	rz_strbuf_init(&text);
	rz_il_op_pure_stringify(copy, &text, false);
	mu_assert_strcontains(rz_strbuf_get(&text), "(+. rtz ", "static rmode keeps the canonical compact form");
	rz_strbuf_fini(&text);

	PJ *pj = pj_new();
	rz_il_op_pure_json(copy, pj);
	char *json = pj_drain(pj);
	mu_assert_strcontains(json, "\"opcode\":\"+.\"", "static rmode keeps the canonical JSON opcode");
	mu_assert_strcontains(json, "\"rmode\":\"rtz\"", "static rmode stays a JSON string");
	free(json);
	rz_il_op_pure_free(copy);
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fmod_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE),
		rz_il_op_new_float_from_f32(5.0f),
		rz_il_op_new_float_from_f32(2.0f));
	rz_strbuf_init(&text);
	rz_il_op_pure_stringify(op, &text, false);
	mu_assert_strcontains(rz_strbuf_get(&text), "(%. (bv 32", "dynamic fmod keeps the canonical compact opcode");
	rz_strbuf_fini(&text);
	rz_strbuf_init(&text);
	rz_il_op_pure_stringify(op, &text, true);
	mu_assert_strcontains(rz_strbuf_get(&text), "(%.\n", "dynamic fmod keeps the canonical pretty opcode");
	rz_strbuf_fini(&text);
	rz_il_op_pure_free(op);
	mu_end;
}

static bool test_rzil_vm_all_float_rmode_payloads() {
	RzILValidateGlobalContext *validate_ctx = rz_il_validate_global_context_new_empty(32);
	RzILSortPure sort;

#define CHECK_DYNAMIC_RMODE_OP(op_expr, expected_code, member) \
	do { \
		RzILOpPure *dyn_op = (RzILOpPure *)(op_expr); \
		mu_assert_notnull(dyn_op, "dynamic-rmode constructor"); \
		mu_assert_eq(dyn_op->code, expected_code, "dynamic constructor uses the base opcode"); \
		mu_assert_eq(dyn_op->op.member.rmode.kind, RZ_IL_OP_ARG_FLOAT_RMODE_DYNAMIC, "dynamic rmode tag"); \
		mu_assert_eq(dyn_op->op.member.rmode.value.dynamic_mode->code, RZ_IL_OP_BITV, "dynamic rmode child"); \
		RzILValidateReport report = NULL; \
		mu_assert_true(rz_il_validate_pure(dyn_op, validate_ctx, &sort, &report), "dynamic-rmode payload validates"); \
		mu_assert_null(report, "no dynamic-rmode validation report"); \
		RzILOpPure *dyn_copy = rz_il_op_pure_dup(dyn_op); \
		mu_assert_notnull(dyn_copy, "dynamic-rmode payload copy"); \
		mu_assert_eq(dyn_copy->op.member.rmode.kind, RZ_IL_OP_ARG_FLOAT_RMODE_DYNAMIC, "copied dynamic rmode tag"); \
		mu_assert_ptrneq(dyn_copy->op.member.rmode.value.dynamic_mode, dyn_op->op.member.rmode.value.dynamic_mode, "dynamic rmode child is deep-copied"); \
		RzStrBuf compact; \
		rz_strbuf_init(&compact); \
		rz_il_op_pure_stringify(dyn_op, &compact, false); \
		mu_assert_strcontains(rz_strbuf_get(&compact), "(bv 32", "compact export includes the dynamic rmode child"); \
		rz_strbuf_fini(&compact); \
		PJ *pj = pj_new(); \
		rz_il_op_pure_json(dyn_op, pj); \
		char *json = pj_drain(pj); \
		mu_assert_strcontains(json, "\"rmode\":{\"opcode\":\"bitv\"", "JSON export represents the dynamic rmode as an IL child"); \
		free(json); \
		RzILStringifyCtx stringify_ctx = { .indent = 0, .indent_inc = 2 }; \
		RzStrBuf unicode; \
		rz_strbuf_init(&unicode); \
		mu_assert_true(rz_il_op_pure_stringify_unicode(&stringify_ctx, dyn_op, &unicode), "Unicode dynamic-rmode export"); \
		rz_strbuf_fini(&unicode); \
		RzGraph *graph = rz_il_op_pure_graph(dyn_op, "dynamic-rmode"); \
		mu_assert_notnull(graph, "graph dynamic-rmode export"); \
		rz_graph_free(graph); \
		rz_il_op_pure_free(dyn_copy); \
		rz_il_op_pure_free(dyn_op); \
	} while (0)

	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fcast_int_dyn_rmode(32, rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(1.0f)),
		RZ_IL_OP_FCAST_INT, fcast_int);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fcast_sint_dyn_rmode(32, rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(-1.0f)),
		RZ_IL_OP_FCAST_SINT, fcast_sint);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fcast_float_dyn_rmode(RZ_FLOAT_IEEE754_BIN_32, rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_bitv_from_ut64(32, 1)),
		RZ_IL_OP_FCAST_FLOAT, fcast_float);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fcast_sfloat_dyn_rmode(RZ_FLOAT_IEEE754_BIN_32, rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_bitv_from_st64(32, -1)),
		RZ_IL_OP_FCAST_SFLOAT, fcast_sfloat);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fconvert_dyn_rmode(RZ_FLOAT_IEEE754_BIN_64, rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(1.0f)),
		RZ_IL_OP_FCONVERT, fconvert);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_frsqrt_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(1.0f)),
		RZ_IL_OP_FRSQRT, frsqrt);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fhypot_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(3.0f), rz_il_op_new_float_from_f32(4.0f)),
		RZ_IL_OP_FHYPOT, fhypot);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fpow_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(2.0f), rz_il_op_new_float_from_f32(3.0f)),
		RZ_IL_OP_FPOW, fpow);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fmad_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(1.0f), rz_il_op_new_float_from_f32(2.0f), rz_il_op_new_float_from_f32(3.0f)),
		RZ_IL_OP_FMAD, fmad);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_frootn_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(4.0f), rz_il_op_new_bitv_from_ut64(32, 2)),
		RZ_IL_OP_FROOTN, frootn);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fpown_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(2.0f), rz_il_op_new_bitv_from_ut64(32, 3)),
		RZ_IL_OP_FPOWN, fpown);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fcompound_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f), rz_il_op_new_bitv_from_ut64(32, 2)),
		RZ_IL_OP_FCOMPOUND, fcompound);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fexp_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FEXP, fexp);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fexpm1_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FEXPM1, fexpm1);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fexp2_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FEXP2, fexp2);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fexp2m1_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FEXP2M1, fexp2m1);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fexp10_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FEXP10, fexp10);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fexp10m1_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FEXP10M1, fexp10m1);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_flog_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FLOG, flog);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_flog2_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FLOG2, flog2);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_flog10_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FLOG10, flog10);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_flogp1_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FLOGP1, flogp1);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_flog2p1_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FLOG2P1, flog2p1);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_flog10p1_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FLOG10P1, flog10p1);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fsin_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FSIN, fsin);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fcos_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FCOS, fcos);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_ftan_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FTAN, ftan);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fsinpi_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FSINPI, fsinpi);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fcospi_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FCOSPI, fcospi);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_ftanpi_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FTANPI, ftanpi);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fasin_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FASIN, fasin);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_facos_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FACOS, facos);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fatan_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FATAN, fatan);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fasinpi_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FASINPI, fasinpi);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_facospi_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FACOSPI, facospi);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fatanpi_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FATANPI, fatanpi);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fsinh_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FSINH, fsinh);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fcosh_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FCOSH, fcosh);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_ftanh_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FTANH, ftanh);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fasinh_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FASINH, fasinh);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_facosh_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FACOSH, facosh);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fatanh_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(0.5f)),
		RZ_IL_OP_FATANH, fatanh);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fatan2_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(1.0f), rz_il_op_new_float_from_f32(2.0f)),
		RZ_IL_OP_FATAN2, fatan2);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fatan2pi_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(1.0f), rz_il_op_new_float_from_f32(2.0f)),
		RZ_IL_OP_FATAN2PI, fatan2pi);
	CHECK_DYNAMIC_RMODE_OP(
		rz_il_op_new_fpowr_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE), rz_il_op_new_float_from_f32(1.0f), rz_il_op_new_float_from_f32(2.0f)),
		RZ_IL_OP_FPOWR, fpowr);

#undef CHECK_DYNAMIC_RMODE_OP

	rz_il_validate_global_context_free(validate_ctx);
	mu_end;
}

static bool test_rzil_vm_runtime_rmode_helpers() {
	RzILVM *vm = rz_il_vm_new(0, 32, false, RZ_IL_EVENT_EXC_NONE);
	const struct {
		ut32 mode;
		const char *expected;
	} add_cases[] = {
		{ RZ_FLOAT_RMODE_RNE, "0x3f800000" },
		{ RZ_FLOAT_RMODE_RNA, "0x3f800001" },
		{ RZ_FLOAT_RMODE_RTP, "0x3f800001" },
		{ RZ_FLOAT_RMODE_RTN, "0x3f800000" },
		{ RZ_FLOAT_RMODE_RTZ, "0x3f800000" },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(add_cases); i++) {
		RzILOpFloat *op = rz_il_op_new_fadd_dyn_rmode(
			rz_il_op_new_bitv_from_ut64(32, add_cases[i].mode),
			rz_il_op_new_float_from_f32(1.0f),
			rz_il_op_new_float_from_f32(0x1p-24f));
		mu_assert_true(runtime_rmode_result_is(vm, op, add_cases[i].expected), "runtime fadd rounding-mode selection");
	}

	RzILOpFloat *op = rz_il_op_new_fadd_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_UNK + 1),
		rz_il_op_new_float_from_f32(1.0f),
		rz_il_op_new_float_from_f32(0x1p-24f));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x3f800000"), "invalid runtime rounding mode falls back to RNE");

	op = rz_il_op_new_fadd(
		(RzFloatRMode)(RZ_FLOAT_RMODE_UNK + 1),
		rz_il_op_new_float_from_f32(1.0f),
		rz_il_op_new_float_from_f32(0x1p-24f));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x3f800000"), "invalid static rounding mode falls back to RNE");

	op = rz_il_op_new_fadd_dyn_rmode(
		rz_il_op_new_add(
			rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTP),
			rz_il_op_new_bitv_from_ut64(32, 0)),
		rz_il_op_new_float_from_f32(1.0f),
		rz_il_op_new_float_from_f32(0x1p-24f));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x3f800001"), "runtime rounding-mode expressions are evaluated");

	RzILOpFloat *bad_op = rz_il_op_new_fadd_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(8, RZ_FLOAT_RMODE_RNE),
		rz_il_op_new_float_from_f32(1.0f),
		rz_il_op_new_float_from_f32(0.0f));
	RzFloat *bad_result = rz_il_evaluate_float(vm, bad_op);
	mu_assert_null(bad_result, "non-32-bit runtime rounding mode fails direct evaluation");
	rz_il_op_pure_free(bad_op);

	op = rz_il_op_new_fconvert_dyn_rmode(
		RZ_FLOAT_IEEE754_BIN_32,
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTP),
		rz_il_op_new_float_from_f64(1.0 + 0x1p-24));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x3f800001"), "runtime fconvert rounding mode");

	op = rz_il_op_new_fround_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNA),
		rz_il_op_new_float_from_f64(0.5));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x3ff0000000000000"), "runtime fround rounding mode");

	op = rz_il_op_new_fsqrt_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTZ),
		rz_il_op_new_float_from_f64(4.0));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x4000000000000000"), "runtime fsqrt rounding mode");

	op = rz_il_op_new_fsub_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE),
		rz_il_op_new_float_from_f32(3.0f),
		rz_il_op_new_float_from_f32(2.0f));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x3f800000"), "runtime fsub rounding mode");

	op = rz_il_op_new_fmul_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE),
		rz_il_op_new_float_from_f32(3.0f),
		rz_il_op_new_float_from_f32(2.0f));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x40c00000"), "runtime fmul rounding mode");

	op = rz_il_op_new_fdiv_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE),
		rz_il_op_new_float_from_f32(6.0f),
		rz_il_op_new_float_from_f32(2.0f));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x40400000"), "runtime fdiv rounding mode");

	op = rz_il_op_new_fmod_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE),
		rz_il_op_new_float_from_f32(5.0f),
		rz_il_op_new_float_from_f32(2.0f));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x3f800000"), "runtime fmod rounding mode");

	RzILOpBitVector *cast_int_op = rz_il_op_new_fcast_int_dyn_rmode(
		32,
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTP),
		rz_il_op_new_float_from_f32(1.125f));
	RzBitVector *cast_int = rz_il_evaluate_bitv(vm, cast_int_op);
	mu_assert_notnull(cast_int, "runtime unsigned float-to-integer cast");
	mu_assert_eq(rz_bv_to_ut64(cast_int), 2, "runtime unsigned float-to-integer rounding mode");
	rz_bv_free(cast_int);
	rz_il_op_pure_free(cast_int_op);

	RzILOpBitVector *cast_sint_op = rz_il_op_new_fcast_sint_dyn_rmode(
		32,
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTN),
		rz_il_op_new_float_from_f32(-0.125f));
	RzBitVector *cast_sint = rz_il_evaluate_bitv(vm, cast_sint_op);
	mu_assert_notnull(cast_sint, "runtime signed float-to-integer cast");
	mu_assert_eq(rz_bv_to_ut32(cast_sint), UT32_MAX, "runtime signed float-to-integer rounding mode");
	rz_bv_free(cast_sint);
	rz_il_op_pure_free(cast_sint_op);

	op = rz_il_op_new_fcast_float_dyn_rmode(
		RZ_FLOAT_IEEE754_BIN_32,
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTP),
		rz_il_op_new_bitv_from_ut64(32, 134217730));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x4d000001"), "runtime unsigned integer-to-float rounding mode");

	op = rz_il_op_new_fcast_sfloat_dyn_rmode(
		RZ_FLOAT_IEEE754_BIN_32,
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTP),
		rz_il_op_new_bitv_from_ut64(32, 134217730));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x4d000001"), "runtime signed integer-to-float rounding mode");

	op = rz_il_op_new_fmad_dyn_rmode(
		rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTP),
		rz_il_op_new_float_from_f32(1.0f),
		rz_il_op_new_float_from_f32(1.0f),
		rz_il_op_new_float_from_f32(0x1p-24f));
	mu_assert_true(runtime_rmode_result_is(vm, op, "0x3f800001"), "runtime fused multiply-add rounding mode");

	rz_il_vm_free(vm);
	mu_end;
}

#include <rz_il/rz_il_opbuilder_begin.h>

static bool test_rzil_opbuilder_float_rmode_aliases() {
	RzILOpFloat *op = FMOD(
		RZ_FLOAT_RMODE_RNE,
		F32(5.0f),
		F32(2.0f));
	mu_assert_notnull(op, "static fmod opbuilder alias");
	mu_assert_eq(op->code, RZ_IL_OP_FMOD, "static fmod alias maps to fmod");
	rz_il_op_pure_free(op);

	op = FRSQRT_DYN_RMODE(
		U32(RZ_FLOAT_RMODE_RNE),
		F32(1.0f));
	mu_assert_notnull(op, "dynamic frsqrt opbuilder alias");
	mu_assert_eq(op->code, RZ_IL_OP_FRSQRT, "dynamic frsqrt alias maps to frsqrt");
	rz_il_op_pure_free(op);

	op = FMAD_DYN_RMODE(
		U32(RZ_FLOAT_RMODE_RNE),
		F32(1.0f),
		F32(2.0f),
		F32(3.0f));
	mu_assert_notnull(op, "dynamic fmad opbuilder alias");
	mu_assert_eq(op->code, RZ_IL_OP_FMAD, "dynamic fmad alias maps to fmad");
	rz_il_op_pure_free(op);

	op = FEXP(RZ_FLOAT_RMODE_RNE, F64(1.0));
	mu_assert_notnull(op, "static fexp opbuilder alias");
	mu_assert_eq(op->code, RZ_IL_OP_FEXP, "static fexp alias maps to fexp");
	rz_il_op_pure_free(op);

	op = FLOG2P1_DYN_RMODE(U32(RZ_FLOAT_RMODE_RNE), F32(1.0f));
	mu_assert_notnull(op, "dynamic flog2p1 opbuilder alias");
	mu_assert_eq(op->code, RZ_IL_OP_FLOG2P1, "dynamic flog2p1 alias maps to flog2p1");
	rz_il_op_pure_free(op);

	op = FATANH(RZ_FLOAT_RMODE_RTZ, F32(0.5f));
	mu_assert_notnull(op, "static fatanh opbuilder alias");
	mu_assert_eq(op->code, RZ_IL_OP_FATANH, "static fatanh alias maps to fatanh");
	rz_il_op_pure_free(op);

	op = FATAN2(RZ_FLOAT_RMODE_RNE, F32(1.0f), F32(2.0f));
	mu_assert_notnull(op, "static fatan2 opbuilder alias");
	mu_assert_eq(op->code, RZ_IL_OP_FATAN2, "static fatan2 alias maps to fatan2");
	rz_il_op_pure_free(op);

	op = FATAN2PI_DYN_RMODE(U32(RZ_FLOAT_RMODE_RNE), F32(1.0f), F32(2.0f));
	mu_assert_notnull(op, "dynamic fatan2pi opbuilder alias");
	mu_assert_eq(op->code, RZ_IL_OP_FATAN2PI, "dynamic fatan2pi alias maps to fatan2pi");
	rz_il_op_pure_free(op);

	op = FPOWR_DYN_RMODE(U32(RZ_FLOAT_RMODE_RNE), F32(2.0f), F32(3.0f));
	mu_assert_notnull(op, "dynamic fpowr opbuilder alias");
	mu_assert_eq(op->code, RZ_IL_OP_FPOWR, "dynamic fpowr alias maps to fpowr");
	rz_il_op_pure_free(op);
	mu_end;
}

#include <rz_il/rz_il_opbuilder_end.h>

static bool test_rzil_vm_runtime_rmode_avoids_let_capture() {
	const char *name = "_rz_il_runtime_rmode";
	RzILOpFloat *op = rz_il_op_new_let(
		name,
		rz_il_op_new_bitv_from_ut64(32, 0x3f800000),
		rz_il_op_new_fadd_dyn_rmode(
			rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTZ),
			rz_il_op_new_float(
				RZ_FLOAT_IEEE754_BIN_32,
				rz_il_op_new_var(name, RZ_IL_VAR_KIND_LOCAL_PURE)),
			rz_il_op_new_float_from_f32(0.0f)));

	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(32);
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	mu_assert_true(rz_il_validate_pure(op, ctx, &sort, &report), "same-named outer let validates");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_32)), "captured expression sort");
	mu_assert_null(report, "no validation report");
	rz_il_validate_global_context_free(ctx);

	RzILVM *vm = rz_il_vm_new(0, 32, false, RZ_IL_EVENT_EXC_NONE);
	RzFloat *result = rz_il_evaluate_float(vm, op);
	char *hex = result ? rz_float_as_hex_string(result, true) : NULL;
	mu_assert_streq(hex, "0x3f800000", "runtime rmode does not capture the outer let value");
	free(hex);
	rz_float_free(result);
	rz_il_op_pure_free(op);
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_vm_runtime_rmode_compact_composition() {
	RzILOpFloat *op = rz_il_op_new_float_from_f32(1.0f);
	for (size_t i = 0; i < 8; i++) {
		RzILOpBitVector *rmode = i == 7
			? rz_il_op_new_add(
				  rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE),
				  rz_il_op_new_bitv_from_ut64(32, 0))
			: rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RNE);
		op = rz_il_op_new_fadd_dyn_rmode(
			rmode,
			op,
			rz_il_op_new_float_from_f32(0.0f));
	}
	mu_assert_notnull(op, "nested runtime-rmode expression");
	mu_assert_eq(op->code, RZ_IL_OP_FADD, "runtime-rmode constructor uses base opcode");
	mu_assert_streq(rz_il_op_pure_code_stringify(op->code), "fadd", "runtime-rmode opcode string");
	mu_assert_eq(op->op.fadd.rmode.kind, RZ_IL_OP_ARG_FLOAT_RMODE_DYNAMIC, "dynamic rmode tag");
	mu_assert_eq(op->op.fadd.rmode.value.dynamic_mode->code, RZ_IL_OP_ADD, "dynamic rmode expression");

	RzILOpPure *copy = rz_il_op_pure_dup(op);
	mu_assert_notnull(copy, "runtime-rmode expression copy");
	mu_assert_eq(copy->op.fadd.rmode.kind, RZ_IL_OP_ARG_FLOAT_RMODE_DYNAMIC, "copied dynamic rmode tag");
	mu_assert_ptrneq(copy->op.fadd.rmode.value.dynamic_mode, op->op.fadd.rmode.value.dynamic_mode, "dynamic rmode expression is deep-copied");

	RzStrBuf original;
	RzStrBuf copied;
	rz_strbuf_init(&original);
	rz_strbuf_init(&copied);
	rz_il_op_pure_stringify(op, &original, false);
	rz_il_op_pure_stringify(copy, &copied, false);
	mu_assert("nested runtime-rmode stringify stays below 64 KiB", rz_strbuf_length(&original) < 64 * 1024);
	mu_assert_streq(rz_strbuf_get(&copied), rz_strbuf_get(&original), "copied runtime-rmode expression output");
	mu_assert_strcontains(rz_strbuf_get(&original), "(+. (+ (bv 32", "dynamic rmode uses the canonical compact opcode");
	rz_strbuf_fini(&original);
	rz_strbuf_fini(&copied);

	PJ *pj = pj_new();
	rz_il_op_pure_json(copy, pj);
	char *json = pj_drain(pj);
	mu_assert_strcontains(json, "\"opcode\":\"+.\"", "dynamic rmode uses the canonical JSON opcode");
	mu_assert_strcontains(json, "\"rmode\":{\"opcode\":\"+\"", "dynamic rmode is a JSON child node");
	free(json);

	RzILStringifyCtx stringify_ctx = { .indent = 0, .indent_inc = 2 };
	RzStrBuf unicode;
	rz_strbuf_init(&unicode);
	mu_assert_true(rz_il_op_pure_stringify_unicode(&stringify_ctx, copy, &unicode), "runtime-rmode Unicode export");
	mu_assert("runtime-rmode Unicode output stays compact", rz_strbuf_length(&unicode) < 64 * 1024);
	mu_assert_strcontains(rz_strbuf_get(&unicode), "((0x0", "Unicode export includes the dynamic rmode expression");
	rz_strbuf_fini(&unicode);

	RzGraph *graph = rz_il_op_pure_graph(copy, "runtime-rmode");
	mu_assert_notnull(graph, "runtime-rmode graph export");
	char *dot = rz_graph_drawable_to_dot(graph, NULL, NULL);
	mu_assert_notnull(dot, "runtime-rmode graph rendering");
	mu_assert_strcontains(dot, "label=\"fadd\"", "graph keeps the canonical opcode node");
	mu_assert_strcontains(dot, "label=\"add\"", "graph includes the dynamic rmode expression");
	free(dot);
	rz_graph_free(graph);
	rz_il_op_pure_free(copy);
	rz_il_op_pure_free(op);
	mu_end;
}

static RzFloat *eval_float_op(RzILVM *vm, RzILOpFloat *op) {
	RzFloat *result = op ? rz_il_evaluate_float(vm, op) : NULL;
	rz_il_op_pure_free(op);
	return result;
}

#define CHECK_FLOAT_RESULT(op_expr, expected_hex, expected_exception, message) \
	do { \
		RzFloat *res = eval_float_op(vm, (op_expr)); \
		mu_assert_notnull(res, message); \
		mu_assert_streq_free(rz_float_as_hex_string(res, true), expected_hex, message); \
		mu_assert_eq(res->exception, expected_exception, message); \
		rz_float_free(res); \
	} while (0)

static bool test_rzil_vm_op_exp_log() {
	RzILVM *vm = rz_il_vm_new(0, 32, false, RZ_IL_EVENT_EXC_NONE);

	// exact results carry no exception
	CHECK_FLOAT_RESULT(rz_il_op_new_fexp2(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(3.0)),
		"0x4020000000000000", 0, "fexp2 3.0 = 8.0");
	CHECK_FLOAT_RESULT(rz_il_op_new_flog2(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(8.0)),
		"0x4008000000000000", 0, "flog2 8.0 = 3.0");
	CHECK_FLOAT_RESULT(rz_il_op_new_fexp10(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f32(2.0f)),
		"0x42c80000", 0, "fexp10 2.0f = 100.0f");
	CHECK_FLOAT_RESULT(rz_il_op_new_flog10(RZ_FLOAT_RMODE_RTZ, rz_il_op_new_float_from_f32(1000.0f)),
		"0x40400000", 0, "flog10 1000.0f = 3.0f");
	CHECK_FLOAT_RESULT(rz_il_op_new_flog(RZ_FLOAT_RMODE_RTN, rz_il_op_new_float_from_f64(1.0)),
		"0x0000000000000000", 0, "flog 1.0 = +0 even when rounding down");
	CHECK_FLOAT_RESULT(rz_il_op_new_fexpm1(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(-0.0)),
		"0x8000000000000000", 0, "fexpm1 -0 = -0");
	CHECK_FLOAT_RESULT(rz_il_op_new_flog2p1(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(1.0)),
		"0x3ff0000000000000", 0, "flog2p1 1.0 = 1.0");

	// e is irrational: e^1 is inexact and lies between ...769 and ...76a
	CHECK_FLOAT_RESULT(rz_il_op_new_fexp(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(1.0)),
		"0x4005bf0a8b145769", RZ_FLOAT_E_INEXACT, "fexp 1.0 rne");
	CHECK_FLOAT_RESULT(rz_il_op_new_fexp(RZ_FLOAT_RMODE_RTZ, rz_il_op_new_float_from_f64(1.0)),
		"0x4005bf0a8b145769", RZ_FLOAT_E_INEXACT, "fexp 1.0 rtz");
	CHECK_FLOAT_RESULT(rz_il_op_new_fexp_dyn_rmode(rz_il_op_new_bitv_from_ut64(32, RZ_FLOAT_RMODE_RTP), rz_il_op_new_float_from_f64(1.0)),
		"0x4005bf0a8b14576a", RZ_FLOAT_E_INEXACT, "fexp 1.0 with a run-time rtp");

	// special operands
	CHECK_FLOAT_RESULT(rz_il_op_new_flog(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(0.0)),
		"0xfff0000000000000", RZ_FLOAT_E_DIV_ZERO, "flog +0 = -inf with divide by zero");
	CHECK_FLOAT_RESULT(rz_il_op_new_fexp(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(F64_NINF)),
		"0x0000000000000000", 0, "fexp -inf = +0");
	RzFloat *res = eval_float_op(vm, rz_il_op_new_flog(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(-1.0)));
	mu_assert_notnull(res, "flog -1.0");
	mu_assert_true(rz_float_is_nan(res), "flog -1.0 is NaN");
	mu_assert_eq(res->exception, RZ_FLOAT_E_INVALID_OP, "flog -1.0 is invalid");
	rz_float_free(res);

	// the result keeps the format of the operand
	CHECK_FLOAT_RESULT(rz_il_op_new_fexp2(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f80(3.0L)),
		"0x40028000000000000000", 0, "binary80 fexp2 3.0 = 8.0");

	// exceptions raised while computing the operand are kept
	CHECK_FLOAT_RESULT(rz_il_op_new_fexp2(RZ_FLOAT_RMODE_RNE,
				   rz_il_op_new_fconvert(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE,
					   rz_il_op_new_float_from_f64(3.0 + 0x1p-40))),
		"0x41000000", RZ_FLOAT_E_INEXACT, "fexp2 keeps the inexact operand exception");

	RzILOpBool *eop = rz_il_op_new_fexcept(RZ_FLOAT_E_INEXACT,
		rz_il_op_new_fexp(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(1.0)));
	RzILBool *e = rz_il_evaluate_bool(vm, eop);
	mu_assert_notnull(e, "fexcept of fexp");
	mu_assert_true(e->b, "fexp 1.0 raises inexact");
	mu_assert_eq(rz_pvector_len(vm->events), 1, "inexact exception event");
	rz_il_bool_free(e);
	rz_il_op_pure_free(eop);
	rz_il_vm_clear_events(vm);

	rz_il_vm_free(vm);
	mu_end;
}

#undef CHECK_FLOAT_RESULT

static bool float_results_agree(RzFloat *a, RzFloat *b) {
	if (!a || !b) {
		return !a && !b;
	}
	return a->r == b->r && rz_bv_eq(a->s, b->s) && a->exception == b->exception;
}

/* Every handler must call its own rz_float_* function with the operands in
 * order and the rounding mode of the op: compare it with a direct call. */
static bool test_rzil_vm_float_math_dispatch() {
	const struct {
		RzILOpPureCode code;
		RzILOpFloat *(*ctor)(RzFloatRMode, RzILOpFloat *);
		RzFloat *(*fn)(RzFloat *, RzFloatRMode);
	} unops[] = {
		{ RZ_IL_OP_FRSQRT, rz_il_op_new_frsqrt, rz_float_rsqrt },
		{ RZ_IL_OP_FEXP, rz_il_op_new_fexp, rz_float_exp },
		{ RZ_IL_OP_FEXPM1, rz_il_op_new_fexpm1, rz_float_expm1 },
		{ RZ_IL_OP_FEXP2, rz_il_op_new_fexp2, rz_float_exp2 },
		{ RZ_IL_OP_FEXP2M1, rz_il_op_new_fexp2m1, rz_float_exp2m1 },
		{ RZ_IL_OP_FEXP10, rz_il_op_new_fexp10, rz_float_exp10 },
		{ RZ_IL_OP_FEXP10M1, rz_il_op_new_fexp10m1, rz_float_exp10m1 },
		{ RZ_IL_OP_FLOG, rz_il_op_new_flog, rz_float_log },
		{ RZ_IL_OP_FLOG2, rz_il_op_new_flog2, rz_float_log2 },
		{ RZ_IL_OP_FLOG10, rz_il_op_new_flog10, rz_float_log10 },
		{ RZ_IL_OP_FLOGP1, rz_il_op_new_flogp1, rz_float_logp1 },
		{ RZ_IL_OP_FLOG2P1, rz_il_op_new_flog2p1, rz_float_log2p1 },
		{ RZ_IL_OP_FLOG10P1, rz_il_op_new_flog10p1, rz_float_log10p1 },
		{ RZ_IL_OP_FSIN, rz_il_op_new_fsin, rz_float_sin },
		{ RZ_IL_OP_FCOS, rz_il_op_new_fcos, rz_float_cos },
		{ RZ_IL_OP_FTAN, rz_il_op_new_ftan, rz_float_tan },
		{ RZ_IL_OP_FSINPI, rz_il_op_new_fsinpi, rz_float_sinpi },
		{ RZ_IL_OP_FCOSPI, rz_il_op_new_fcospi, rz_float_cospi },
		{ RZ_IL_OP_FTANPI, rz_il_op_new_ftanpi, rz_float_tanpi },
		{ RZ_IL_OP_FASIN, rz_il_op_new_fasin, rz_float_asin },
		{ RZ_IL_OP_FACOS, rz_il_op_new_facos, rz_float_acos },
		{ RZ_IL_OP_FATAN, rz_il_op_new_fatan, rz_float_atan },
		{ RZ_IL_OP_FASINPI, rz_il_op_new_fasinpi, rz_float_asinpi },
		{ RZ_IL_OP_FACOSPI, rz_il_op_new_facospi, rz_float_acospi },
		{ RZ_IL_OP_FATANPI, rz_il_op_new_fatanpi, rz_float_atanpi },
		{ RZ_IL_OP_FSINH, rz_il_op_new_fsinh, rz_float_sinh },
		{ RZ_IL_OP_FCOSH, rz_il_op_new_fcosh, rz_float_cosh },
		{ RZ_IL_OP_FTANH, rz_il_op_new_ftanh, rz_float_tanh },
		{ RZ_IL_OP_FASINH, rz_il_op_new_fasinh, rz_float_asinh },
		{ RZ_IL_OP_FACOSH, rz_il_op_new_facosh, rz_float_acosh },
		{ RZ_IL_OP_FATANH, rz_il_op_new_fatanh, rz_float_atanh },
	};
	const struct {
		RzILOpPureCode code;
		RzILOpFloat *(*ctor)(RzFloatRMode, RzILOpFloat *, RzILOpFloat *);
		RzFloat *(*fn)(RzFloat *, RzFloat *, RzFloatRMode);
	} binops[] = {
		{ RZ_IL_OP_FHYPOT, rz_il_op_new_fhypot, rz_float_hypot },
		{ RZ_IL_OP_FPOW, rz_il_op_new_fpow, rz_float_pow },
		{ RZ_IL_OP_FATAN2, rz_il_op_new_fatan2, rz_float_atan2 },
		{ RZ_IL_OP_FATAN2PI, rz_il_op_new_fatan2pi, rz_float_atan2pi },
		{ RZ_IL_OP_FPOWR, rz_il_op_new_fpowr, rz_float_powr },
	};
	const struct {
		RzILOpPureCode code;
		RzILOpFloat *(*ctor)(RzFloatRMode, RzILOpFloat *, RzILOpBitVector *);
		RzFloat *(*fn)(RzFloat *, RzBitVector *, RzFloatRMode);
	} hybrids[] = {
		{ RZ_IL_OP_FROOTN, rz_il_op_new_frootn, rz_float_rootn },
		{ RZ_IL_OP_FPOWN, rz_il_op_new_fpown, rz_float_pown },
		{ RZ_IL_OP_FCOMPOUND, rz_il_op_new_fcompound, rz_float_compound },
	};
	// asymmetric operands, so that swapped operands give a different result
	const double xs[] = { 0.375, 2.5, -0.75 };
	const double ys[] = { 2.5, -0.5, 3.0 };
	const st64 ns[] = { 3, -2, 0 };
	const RzFloatRMode mode = RZ_FLOAT_RMODE_RTP;

	RzILVM *vm = rz_il_vm_new(0, 32, false, RZ_IL_EVENT_EXC_NONE);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(unops); i++) {
		const char *name = rz_il_op_pure_code_stringify(unops[i].code);
		for (size_t j = 0; j < RZ_ARRAY_SIZE(xs); j++) {
			RzILOpFloat *op = unops[i].ctor(mode, rz_il_op_new_float_from_f64(xs[j]));
			mu_assert_eq(op->code, unops[i].code, name);
			RzFloat *actual = eval_float_op(vm, op);
			RzFloat *x = rz_float_new_from_f64(xs[j]);
			RzFloat *expected = unops[i].fn(x, mode);
			mu_assert_true(float_results_agree(actual, expected), name);
			rz_float_free(x);
			rz_float_free(expected);
			rz_float_free(actual);
		}
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(binops); i++) {
		const char *name = rz_il_op_pure_code_stringify(binops[i].code);
		for (size_t j = 0; j < RZ_ARRAY_SIZE(xs); j++) {
			RzILOpFloat *op = binops[i].ctor(mode, rz_il_op_new_float_from_f64(xs[j]), rz_il_op_new_float_from_f64(ys[j]));
			mu_assert_eq(op->code, binops[i].code, name);
			RzFloat *actual = eval_float_op(vm, op);
			RzFloat *x = rz_float_new_from_f64(xs[j]);
			RzFloat *y = rz_float_new_from_f64(ys[j]);
			RzFloat *expected = binops[i].fn(x, y, mode);
			mu_assert_true(float_results_agree(actual, expected), name);
			rz_float_free(x);
			rz_float_free(y);
			rz_float_free(expected);
			rz_float_free(actual);
		}
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(hybrids); i++) {
		const char *name = rz_il_op_pure_code_stringify(hybrids[i].code);
		for (size_t j = 0; j < RZ_ARRAY_SIZE(xs); j++) {
			RzILOpFloat *op = hybrids[i].ctor(mode, rz_il_op_new_float_from_f64(xs[j]), rz_il_op_new_bitv_from_st64(32, ns[j]));
			mu_assert_eq(op->code, hybrids[i].code, name);
			RzFloat *actual = eval_float_op(vm, op);
			RzFloat *x = rz_float_new_from_f64(xs[j]);
			RzBitVector *n = rz_bv_new_from_st64(32, ns[j]);
			RzFloat *expected = hybrids[i].fn(x, n, mode);
			mu_assert_true(float_results_agree(actual, expected), name);
			rz_float_free(x);
			rz_bv_free(n);
			rz_float_free(expected);
			rz_float_free(actual);
		}
	}
	rz_il_vm_free(vm);
	mu_end;
}

static bool test_rzil_float_math_export() {
	RzILOpFloat *op = rz_il_op_new_fexp(RZ_FLOAT_RMODE_RNE, rz_il_op_new_float_from_f64(1.0));
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_il_op_pure_stringify(op, &sb, false);
	mu_assert_streq(rz_strbuf_get(&sb), "(fexp rne (float 1 (bv 64 0x3ff0000000000000) ))", "fexp string export");
	rz_strbuf_fini(&sb);
	PJ *pj = pj_new();
	rz_il_op_pure_json(op, pj);
	mu_assert_streq_free(pj_drain(pj),
		"{\"opcode\":\"fexp\",\"rmode\":\"rne\",\"f\":{\"opcode\":\"float\",\"format\":1,\"bv\":{\"opcode\":\"bitv\",\"bits\":\"0x3ff0000000000000\",\"len\":64}}}",
		"fexp JSON export");
	RzGraph *graph = rz_il_op_pure_graph(op, "fexp");
	mu_assert_notnull(graph, "fexp graph export");
	char *dot = rz_graph_drawable_to_dot(graph, NULL, NULL);
	mu_assert_strcontains(dot, "label=\"fexp\"", "graph names the fexp node");
	free(dot);
	rz_graph_free(graph);
	rz_il_op_pure_free(op);

	// atan2 takes the ordinate first
	op = rz_il_op_new_fatan2(RZ_FLOAT_RMODE_RTZ,
		rz_il_op_new_var("y", RZ_IL_VAR_KIND_GLOBAL),
		rz_il_op_new_var("x", RZ_IL_VAR_KIND_GLOBAL));
	mu_assert_eq(op->op.fatan2.y->code, RZ_IL_OP_VAR, "first atan2 operand");
	mu_assert_streq(op->op.fatan2.y->op.var.v, "y", "the first atan2 operand is the ordinate");
	mu_assert_streq(op->op.fatan2.x->op.var.v, "x", "the second atan2 operand is the abscissa");
	mu_assert_ptreq(op->op.binop_float_alg.x, op->op.fatan2.y, "positional access sees the ordinate first");
	rz_strbuf_init(&sb);
	rz_il_op_pure_stringify(op, &sb, false);
	mu_assert_streq(rz_strbuf_get(&sb), "(fatan2 rtz (var y) (var x))", "fatan2 string export");
	rz_strbuf_fini(&sb);
	pj = pj_new();
	rz_il_op_pure_json(op, pj);
	mu_assert_streq_free(pj_drain(pj),
		"{\"opcode\":\"fatan2\",\"rmode\":\"rtz\",\"y\":{\"opcode\":\"var\",\"value\":\"y\"},\"x\":{\"opcode\":\"var\",\"value\":\"x\"}}",
		"fatan2 JSON export keys the operands y and x");
	RzILStringifyCtx stringify_ctx = { .indent = 0, .indent_inc = 2 };
	rz_strbuf_init(&sb);
	mu_assert_true(rz_il_op_pure_stringify_unicode(&stringify_ctx, op, &sb), "fatan2 Unicode export");
	mu_assert_streq(rz_strbuf_get(&sb), "(rtz y ∡ x)", "fatan2 Unicode export");
	rz_strbuf_fini(&sb);
	rz_il_op_pure_free(op);

	op = rz_il_op_new_flog2p1_dyn_rmode(rz_il_op_new_var("m", RZ_IL_VAR_KIND_GLOBAL), rz_il_op_new_var("f", RZ_IL_VAR_KIND_GLOBAL));
	rz_strbuf_init(&sb);
	rz_il_op_pure_stringify(op, &sb, false);
	mu_assert_streq(rz_strbuf_get(&sb), "(flog2p1 (var m) (var f))", "dynamic flog2p1 string export");
	rz_strbuf_fini(&sb);
	rz_strbuf_init(&sb);
	mu_assert_true(rz_il_op_pure_stringify_unicode(&stringify_ctx, op, &sb), "flog2p1 Unicode export");
	mu_assert_streq(rz_strbuf_get(&sb), "(m log₂1+ f)", "flog2p1 Unicode export");
	rz_strbuf_fini(&sb);
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fpowr(RZ_FLOAT_RMODE_RNA, rz_il_op_new_var("x", RZ_IL_VAR_KIND_GLOBAL), rz_il_op_new_var("y", RZ_IL_VAR_KIND_GLOBAL));
	rz_strbuf_init(&sb);
	mu_assert_true(rz_il_op_pure_stringify_unicode(&stringify_ctx, op, &sb), "fpowr Unicode export");
	mu_assert_streq(rz_strbuf_get(&sb), "(rna x ˰ʳ y)", "fpowr Unicode export");
	rz_strbuf_fini(&sb);
	rz_il_op_pure_free(op);

	const RzILOpPureCode codes[] = {
		RZ_IL_OP_FEXP, RZ_IL_OP_FEXPM1, RZ_IL_OP_FEXP2, RZ_IL_OP_FEXP2M1, RZ_IL_OP_FEXP10, RZ_IL_OP_FEXP10M1,
		RZ_IL_OP_FLOG, RZ_IL_OP_FLOG2, RZ_IL_OP_FLOG10, RZ_IL_OP_FLOGP1, RZ_IL_OP_FLOG2P1, RZ_IL_OP_FLOG10P1,
		RZ_IL_OP_FSIN, RZ_IL_OP_FCOS, RZ_IL_OP_FTAN, RZ_IL_OP_FSINPI, RZ_IL_OP_FCOSPI, RZ_IL_OP_FTANPI,
		RZ_IL_OP_FASIN, RZ_IL_OP_FACOS, RZ_IL_OP_FATAN, RZ_IL_OP_FASINPI, RZ_IL_OP_FACOSPI, RZ_IL_OP_FATANPI,
		RZ_IL_OP_FSINH, RZ_IL_OP_FCOSH, RZ_IL_OP_FTANH, RZ_IL_OP_FASINH, RZ_IL_OP_FACOSH, RZ_IL_OP_FATANH,
		RZ_IL_OP_FATAN2, RZ_IL_OP_FATAN2PI, RZ_IL_OP_FPOWR
	};
	const char *names[] = {
		"fexp", "fexpm1", "fexp2", "fexp2m1", "fexp10", "fexp10m1",
		"flog", "flog2", "flog10", "flogp1", "flog2p1", "flog10p1",
		"fsin", "fcos", "ftan", "fsinpi", "fcospi", "ftanpi",
		"fasin", "facos", "fatan", "fasinpi", "facospi", "fatanpi",
		"fsinh", "fcosh", "ftanh", "fasinh", "facosh", "fatanh",
		"fatan2", "fatan2pi", "fpowr"
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(codes); i++) {
		mu_assert_streq(rz_il_op_pure_code_stringify(codes[i]), names[i], "opcode name");
	}
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
	mu_run_test(test_rzil_vm_binary80_full_precision);
	mu_run_test(test_rzil_vm_float_rmode_arguments);
	mu_run_test(test_rzil_vm_all_float_rmode_payloads);
	mu_run_test(test_rzil_vm_runtime_rmode_helpers);
	mu_run_test(test_rzil_opbuilder_float_rmode_aliases);
	mu_run_test(test_rzil_vm_runtime_rmode_avoids_let_capture);
	mu_run_test(test_rzil_vm_runtime_rmode_compact_composition);
	mu_run_test(test_rzil_vm_op_exp_log);
	mu_run_test(test_rzil_vm_float_math_dispatch);
	mu_run_test(test_rzil_float_math_export);
	mu_run_test(test_rzil_vm_halt_on_exc);
	return tests_passed != tests_run;
}

mu_main(all_tests)
