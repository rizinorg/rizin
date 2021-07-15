#include "core_theory_opcodes.h"
#include "core_theory_vm.h"
#include "definitions/effect.h"

void rz_il_perform_data(RzILVM vm, Effect eff) {
	RzILVar var;
	RzILVal val;

	val = rz_il_get_val_temp(vm, eff->data_eff->val_index);
	var = rz_il_find_var_by_name(vm, eff->data_eff->var_name);
	rz_il_hash_cancel_binding(vm, var);
	rz_il_hash_bind(vm, var, val);
	rz_il_vm_fortify_val(vm, eff->data_eff->val_index);
}

void rz_il_perform_ctrl(RzILVM vm, Effect eff) {
	if (eff->notation & (EFFECT_NOTATION_GOTO_HOOK | EFFECT_NOTATION_GOTO_SYS)) {
		RzILOp goto_op = (RzILOp)eff->ctrl_eff;
		eff->ctrl_eff = NULL;

		EffectLabel label = rz_il_vm_find_label_by_name(vm, goto_op->op.goto_->lbl);
		RzILVmHook internal_hook = (RzILVmHook)label->addr;

		internal_hook(vm, goto_op);
		return;
	}

	// Normal
	BitVector new_addr = bv_dump(eff->ctrl_eff->pc);
	bv_free(vm->pc);
	vm->pc = new_addr;
}

// TODO : Clean temp val after binding
void rz_il_handler_perform(RzILVM vm, RzILOp op) {
	// printf("[Perform effect]\n");
	RzILOpPerform perform_op = op->op.perform;

	Effect eff = rz_il_get_temp(vm, perform_op->eff);

	do {
		if (eff->effect_type == EFFECT_TYPE_DATA) {
			rz_il_perform_data(vm, eff);
		}

		if (eff->effect_type == EFFECT_TYPE_CTRL) {
			rz_il_perform_ctrl(vm, eff);
		}

		eff = eff->next_eff;
	} while (eff != NULL);
}

void rz_il_handler_set(RzILVM vm, RzILOp op) {
	RzILOpSet set_op = op->op.set;

	Effect eff = effect_new(EFFECT_TYPE_DATA);
	eff->data_eff->var_name = set_op->v;
	eff->data_eff->val_index = set_op->x;

	// store effect in the temporay list
	rz_il_make_eff_temp(vm, set_op->ret, eff);
}

void rz_il_handler_jmp(RzILVM vm, RzILOp op) {
	RzILOpJmp op_jmp = op->op.jmp;
	BitVector addr = rz_il_get_bv_temp(vm, op_jmp->dst);
	// TODO set ctrl effect here
}

void rz_il_handler_goto(RzILVM vm, RzILOp op) {
	RzILOpGoto op_goto = op->op.goto_;
	string lname = op_goto->lbl;
	Effect eff = effect_new(EFFECT_TYPE_CTRL);

	EffectLabel label = rz_il_vm_find_label_by_name(vm, lname);
	if (label->type == EFFECT_LABEL_SYSCALL) {
		effect_free_ctrl(eff->ctrl_eff);
		eff->notation = EFFECT_NOTATION_GOTO_SYS;
		// WARN : HACK to call hook
		eff->ctrl_eff = (void *)op;
	} else if (label->type == EFFECT_LABEL_HOOK) {
		effect_free_ctrl(eff->ctrl_eff);
		eff->notation = EFFECT_NOTATION_GOTO_HOOK;
		// WARN : HACK to call
		eff->ctrl_eff = (void *)op;
	} else {
		// Normal
		eff->ctrl_eff->pc = rz_il_hash_find_addr_by_lblname(vm, lname);
	}

	rz_il_make_eff_temp(vm, op_goto->ret_ctrl_eff, eff);
}

void rz_il_handler_seq(RzILVM vm, RzILOp op) {
	RzILOpSeq op_seq = op->op.seq;

	Effect eff_x = rz_il_get_temp(vm, op_seq->x);
	Effect eff_y = rz_il_get_temp(vm, op_seq->y);

	Effect eff_uni = eff_x;
	eff_uni->next_eff = eff_y;
	rz_il_make_eff_temp(vm, op_seq->ret, eff_uni);

	// clean to prevent free before use
	// TODO : if an effect should be used in different places
	//        it would be better to dump effect
	//        rather than modify the origin effect
	rz_il_empty_temp(vm, op_seq->x);
	rz_il_empty_temp(vm, op_seq->y);
}

void rz_il_handler_blk(RzILVM vm, RzILOp op) {
	// TODO : a named label ?
}

void rz_il_handler_repeat(RzILVM vm, RzILOp op) {
	RzILOpRepeat op_repeat = op->op.repeat;

	Bool condition = rz_il_get_bool_temp(vm, op_repeat->condition);
	Effect eff = rz_il_get_temp(vm, op_repeat->data_eff);
	DataEffect d_eff = eff->data_eff;
	// TODO : find a proper to handle repeat
}

void rz_il_handler_branch(RzILVM vm, RzILOp op) {
	RzILOpBranch op_branch = op->op.branch;

	Bool condition = rz_il_get_bool_temp(vm, op_branch->condition);
	Effect true_branch, false_branch;

	if (condition->b) {
		true_branch = (op_branch->true_eff == -1) ? effect_new(EFFECT_TYPE_NON) : rz_il_get_temp(vm, op_branch->true_eff);
		rz_il_make_eff_temp(vm, op_branch->ret, true_branch);
		rz_il_empty_temp(vm, op_branch->true_eff);
	} else {
		false_branch = (op_branch->false_eff == -1) ? effect_new(EFFECT_TYPE_NON) : rz_il_get_temp(vm, op_branch->false_eff);
		rz_il_make_eff_temp(vm, op_branch->ret, false_branch);
		rz_il_empty_temp(vm, op_branch->false_eff);
	}
}
