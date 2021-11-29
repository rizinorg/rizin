// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>
#include <rz_il/vm_layer.h>
#include <rz_il/rzil_vm.h>

static RzILEvent *il_event_new_write_from_var(RzILVM *vm, RzILVar *var, RzILVal *new_val) {
	rz_return_val_if_fail(vm && var && new_val, NULL);
	RzILVal *old_val = NULL;
	RzILEvent *evt = NULL;
	RzBitVector *oldnum = NULL;
	RzBitVector *newnum = NULL;

	if (new_val->type == RZIL_VAR_TYPE_BOOL) {
		newnum = rz_bitvector_new_from_ut64(1, new_val->data.b->b);
	} else {
		newnum = new_val->data.bv;
	}

	old_val = rz_il_hash_find_val_by_var(vm, var);
	if (old_val) {
		if (old_val->type == RZIL_VAR_TYPE_BOOL) {
			oldnum = rz_bitvector_new_from_ut64(1, old_val->data.b->b);
		} else {
			oldnum = old_val->data.bv;
		}
	}

	evt = rz_il_event_var_write_new(var->var_name, oldnum, newnum);
	if (old_val->type == RZIL_VAR_TYPE_BOOL) {
		rz_bitvector_free(oldnum);
	}
	if (new_val->type == RZIL_VAR_TYPE_BOOL) {
		rz_bitvector_free(newnum);
	}
	return evt;
}

static void rz_il_perform_data(RzILVM *vm, RzILEffect *eff) {
	RzILVar *var = NULL;
	RzILVal *val = NULL;
	RzILEvent *evt = NULL;

	val = eff->data_eff->val;
	eff->data_eff->val = NULL;
	var = rz_il_find_var_by_name(vm, eff->data_eff->var_name);
	evt = il_event_new_write_from_var(vm, var, val);

	rz_il_hash_cancel_binding(vm, var);
	rz_il_hash_bind(vm, var, val);

	rz_il_vm_fortify_val(vm, val);
	rz_il_vm_event_add(vm, evt);
}

static void rz_il_perform_ctrl(RzILVM *vm, RzILEffect *eff) {
	if (eff->notation & (EFFECT_NOTATION_GOTO_HOOK | EFFECT_NOTATION_GOTO_SYS)) {
		RzILOp *goto_op = (RzILOp *)eff->ctrl_eff;
		eff->ctrl_eff = NULL;

		RzILEffectLabel *label = rz_il_vm_find_label_by_name(vm, goto_op->op.goto_->lbl);
		RzILVmHook internal_hook = (RzILVmHook)label->hook;

		internal_hook(vm, goto_op);
		return;
	}

	// Normal
	RzBitVector *new_addr = rz_bitvector_dup(eff->ctrl_eff->pc);
	rz_il_vm_event_add(vm, rz_il_event_pc_write_new(vm->pc, new_addr));
	rz_bitvector_free(vm->pc);
	vm->pc = new_addr;
}

void *rz_il_handler_perform(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpPerform *perform_op = op->op.perform;

	RzILEffect *eff = rz_il_evaluate_effect(vm, perform_op->eff, type);
	do {
		if (eff->effect_type == EFFECT_TYPE_DATA) {
			rz_il_perform_data(vm, eff);
		} else if (eff->effect_type == EFFECT_TYPE_CTRL) {
			rz_il_perform_ctrl(vm, eff);
		}
		RzILEffect *tmp = eff->next_eff;
		rz_il_effect_free(eff);
		eff = tmp;
	} while (eff != NULL);

	return NULL;
}

void *rz_il_handler_set(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpSet *set_op = op->op.set;

	RzILEffect *eff = rz_il_effect_new(EFFECT_TYPE_DATA);
	eff->data_eff->var_name = set_op->v;
	eff->data_eff->val = rz_il_evaluate_val(vm, set_op->x, type);

	// store effect in the temporay list
	*type = RZIL_OP_ARG_EFF;
	return eff;
}

void *rz_il_handler_jmp(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpJmp *op_jmp = op->op.jmp;
	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_jmp->dst, type);
	RzILEffect *eff = rz_il_effect_new(EFFECT_TYPE_CTRL);

	eff->ctrl_eff->pc = addr;

	*type = RZIL_OP_ARG_EFF;
	return eff;
}

void *rz_il_handler_goto(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpGoto *op_goto = op->op.goto_;
	const char *lname = op_goto->lbl;
	RzILEffect *eff = rz_il_effect_new(EFFECT_TYPE_CTRL);

	RzILEffectLabel *label = rz_il_vm_find_label_by_name(vm, lname);
	if (label->type == EFFECT_LABEL_SYSCALL) {
		rz_il_effect_ctrl_free(eff->ctrl_eff);
		eff->notation = EFFECT_NOTATION_GOTO_SYS;
		// WARN : HACK to call hook
		eff->ctrl_eff = (void *)op;
	} else if (label->type == EFFECT_LABEL_HOOK) {
		rz_il_effect_ctrl_free(eff->ctrl_eff);
		eff->notation = EFFECT_NOTATION_GOTO_HOOK;
		// WARN : HACK to call
		eff->ctrl_eff = (void *)op;
	} else {
		// Normal
		eff->ctrl_eff->pc = rz_il_hash_find_addr_by_lblname(vm, lname);
	}

	*type = RZIL_OP_ARG_EFF;
	return eff;
}

void *rz_il_handler_seq(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpSeq *op_seq = op->op.seq;

	RzILEffect *eff_x = rz_il_evaluate_effect(vm, op_seq->x, type);
	RzILEffect *eff_y = rz_il_evaluate_effect(vm, op_seq->y, type);

	// add eff_y to the next eff of eff_x
	RzILEffect *eff_uni = eff_x;
	eff_uni->next_eff = eff_y;

	return eff_uni;
}

void *rz_il_handler_branch(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpBranch *op_branch = op->op.branch;

	RzILBool *condition = rz_il_evaluate_bool(vm, op_branch->condition, type);
	RzILEffect *ret;
	if (condition->b) {
		// true branch
		ret = (op_branch->true_eff == NULL) ? rz_il_effect_new(EFFECT_TYPE_NON) : rz_il_evaluate_effect(vm, op_branch->true_eff, type);
	} else {
		// false branch
		ret = (op_branch->false_eff == NULL) ? rz_il_effect_new(EFFECT_TYPE_NON) : rz_il_evaluate_effect(vm, op_branch->false_eff, type);
	}
	rz_il_bool_free(condition);

	if (ret) {
		*type = RZIL_OP_ARG_EFF;
	}
	return ret;
}
