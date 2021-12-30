// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opcodes.h>
#include <rz_il/rz_il_vm.h>

static RzILEvent *il_event_new_write_from_var(RzILVM *vm, RzILVar *var, RzILVal *new_val) {
	rz_return_val_if_fail(vm && var && new_val, NULL);
	RzILVal *old_val = NULL;
	RzILEvent *evt = NULL;
	RzBitVector *oldnum = NULL;
	RzBitVector *newnum = NULL;

	if (new_val->type == RZIL_VAR_TYPE_BOOL) {
		newnum = rz_bv_new_from_ut64(1, new_val->data.b->b);
	} else {
		newnum = new_val->data.bv;
	}

	old_val = rz_il_hash_find_val_by_var(vm, var);
	if (old_val) {
		if (old_val->type == RZIL_VAR_TYPE_BOOL) {
			oldnum = rz_bv_new_from_ut64(1, old_val->data.b->b);
		} else {
			oldnum = old_val->data.bv;
		}
	}

	evt = rz_il_event_var_write_new(var->var_name, oldnum, newnum);
	if (old_val && old_val->type == RZIL_VAR_TYPE_BOOL) {
		rz_bv_free(oldnum);
	}
	if (new_val->type == RZIL_VAR_TYPE_BOOL) {
		rz_bv_free(newnum);
	}
	return evt;
}

static void rz_il_set(RzILVM *vm, const char *var_name, bool is_local, bool is_mutable, RZ_OWN RzILVal *val) {
	RzILVar *var = NULL;
	RzILEvent *evt = NULL;
	if (is_local) {
		var = rz_il_find_local_var_by_name(vm, var_name);
	} else {
		var = rz_il_find_var_by_name(vm, var_name);
	}
	if (!var && !is_local) {
		// it's a set to a global variable which has not been defined.
		char *message = rz_str_newf("unknown global variable '%s'.", var_name);
		evt = rz_il_event_exception_new(message);
		free(message);
		rz_il_value_free(val);
		rz_il_vm_event_add(vm, evt);
		return;
	} else if (var && !var->is_mutable) {
		// forbid changing an immutable type
		char *message = rz_str_newf("cannot change %s variable '%s' because is not mutable.", is_local ? "local" : "global", var_name);
		evt = rz_il_event_exception_new(message);
		free(message);
		rz_il_value_free(val);
		rz_il_vm_event_add(vm, evt);
		return;
	}

	// enforce var type to val except if var is unk, because unk type can be set to any type.
	if (var && var->type == RZIL_VAR_TYPE_BV && val->type == RZIL_VAR_TYPE_BOOL) {
		RzBitVector *bv = rz_bv_new_from_ut64(1, val->data.b->b);
		RzILVal *cast = rz_il_value_new_bitv(bv);
		rz_il_value_free(val);
		val = cast;
	} else if (var && var->type == RZIL_VAR_TYPE_BOOL && val->type == RZIL_VAR_TYPE_BV) {
		RzILBool *b = rz_il_bool_new(!rz_bv_is_zero_vector(val->data.bv));
		RzILVal *cast = rz_il_value_new_bool(b);
		rz_il_value_free(val);
		val = cast;
	}

	if (is_local) {
		// add/update local variable
		if (var) {
			// update mutable local variable
			rz_il_hash_cancel_local_binding(vm, var);
		} else {
			// first set of an mutable/immutable local variable
			var = rz_il_vm_create_local_variable(vm, var_name, val->type, is_mutable);
		}
		rz_il_hash_local_bind(vm, var, val);
	} else {
		// update global variable
		evt = il_event_new_write_from_var(vm, var, val);
		rz_il_hash_cancel_binding(vm, var);
		rz_il_hash_bind(vm, var, val);

		rz_il_vm_fortify_val(vm, val);
		rz_il_vm_event_add(vm, evt);
	}
}

bool rz_il_handler_nop(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);
	return true;
}

bool rz_il_handler_set(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);
	RzILOpArgsSet *set_op = &op->op.set;
	RzILVal *val = rz_il_evaluate_val(vm, set_op->x);
	if (!val) {
		return false;
	}
	rz_il_set(vm, set_op->v, false, true, val);
	return true;
}

bool rz_il_handler_let(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);
	RzILOpArgsLet *let_op = &op->op.let;
	RzILVal *val = rz_il_evaluate_val(vm, let_op->x);
	if (!val) {
		return false;
	}
	rz_il_set(vm, let_op->v, true, let_op->mut, val);
	return false;
}

static void perform_jump(RzILVM *vm, RZ_OWN RzBitVector *dst) {
	rz_il_vm_event_add(vm, rz_il_event_pc_write_new(vm->pc, dst));
	rz_bv_free(vm->pc);
	vm->pc = dst;
}

bool rz_il_handler_jmp(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);
	RzBitVector *dst = rz_il_evaluate_bitv(vm, op->op.jmp.dst);
	if (!dst) {
		return false;
	}
	perform_jump(vm, dst);
	return true;
}

bool rz_il_handler_goto(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);
	RzILOpArgsGoto *op_goto = &op->op.goto_;
	const char *lname = op_goto->lbl;
	RzILEffectLabel *label = rz_il_vm_find_label_by_name(vm, lname);
	if (!label) {
		return false;
	}
	if (label->type == EFFECT_LABEL_SYSCALL || label->type == EFFECT_LABEL_HOOK) {
		RzILVmHook internal_hook = (RzILVmHook)label->hook;
		internal_hook(vm, op);
	} else {
		perform_jump(vm, rz_bv_dup(label->addr));
	}
	return true;
}

bool rz_il_handler_seq(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);
	RzILOpArgsSeq *op_seq = &op->op.seq;
	return rz_il_evaluate_effect(vm, op_seq->x) && rz_il_evaluate_effect(vm, op_seq->y);
}

bool rz_il_handler_branch(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);

	RzILOpArgsBranch *op_branch = &op->op.branch;

	RzILBool *condition = rz_il_evaluate_bool(vm, op_branch->condition);
	if (!condition) {
		return false;
	}
	bool ret;
	if (condition->b) {
		ret = rz_il_evaluate_effect(vm, op_branch->true_eff);
	} else {
		ret = rz_il_evaluate_effect(vm, op_branch->false_eff);
	}
	rz_il_bool_free(condition);

	return ret;
}
