// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opcodes.h>
#include <rz_il/rz_il_vm.h>

static RzILEvent *il_event_new_write_from_var(RzILVM *vm, RzILVar *var, RzILVal *new_val) {
	rz_return_val_if_fail(vm && var && new_val, NULL);
	RzILVal *old_val = rz_il_vm_get_var_value(vm, RZ_IL_VAR_KIND_GLOBAL, var->name);
	if (!old_val) {
		return NULL;
	}
	return rz_il_event_var_write_new(var->name, old_val, new_val);
}

static void rz_il_set(RzILVM *vm, const char *var_name, bool is_local, RZ_OWN RzILVal *val) {
	if (is_local) {
		rz_il_vm_set_local_var(vm, var_name, val);
	} else {
		RzILVar *var = rz_il_vm_get_var(vm, RZ_IL_VAR_KIND_GLOBAL, var_name);
		RzILEvent *evt = il_event_new_write_from_var(vm, var, val);
		rz_il_vm_event_add(vm, evt);
		rz_il_vm_set_global_var(vm, var_name, val);
	}
}

bool rz_il_handler_empty(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);
	char *pc = rz_bv_as_hex_string(vm->pc, true);
	RZ_LOG_INFO("Encountered an empty instruction at %s\n", pc);
	free(pc);
	return true;
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
	rz_il_set(vm, set_op->v, set_op->is_local, val);
	return true;
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

bool rz_il_handler_blk(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);

	RzILOpArgsBlk *op_blk = &op->op.blk;
	if (op_blk->label) {
		rz_il_vm_create_label(vm, op_blk->label, vm->pc); // create the label if `blk` is labelled
	}

	return rz_il_evaluate_effect(vm, op_blk->data_eff) && rz_il_evaluate_effect(vm, op_blk->ctrl_eff);
}

bool rz_il_handler_repeat(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);

	RzILOpArgsRepeat *op_repeat = &op->op.repeat;
	bool res = true;
	RzILBool *condition;
	while ((condition = rz_il_evaluate_bool(vm, op_repeat->condition))) {
		if (!condition->b) {
			break;
		}
		if (!rz_il_evaluate_effect(vm, op_repeat->data_eff)) {
			res = false;
			break;
		}
		rz_il_bool_free(condition);
	}
	rz_il_bool_free(condition);

	return res;
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
