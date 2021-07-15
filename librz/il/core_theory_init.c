#include "core_theory_opcodes.h"
#include "core_theory_vm.h"

void rz_il_handler_ite(RzILVM vm, RzILOp op) {
	RzILOpIte op_ite = op->op.ite;

	Bool condition = rz_il_get_bool_temp(vm, op_ite->condition);
	RzILVal true_branch = rz_il_get_val_temp(vm, op_ite->x);
	RzILVal false_branch = rz_il_get_val_temp(vm, op_ite->y);

	if (condition->b) {
		rz_il_make_val_temp(vm, op_ite->ret, true_branch);
		rz_il_empty_temp(vm, op_ite->x); // the true branch has moved to `ret`, set [x] to NULL
	} else {
		rz_il_make_val_temp(vm, op_ite->ret, false_branch);
		rz_il_empty_temp(vm, op_ite->y);
	}
}

void rz_il_handler_var(RzILVM vm, RzILOp op) {
	RzILOpVar var_op = op->op.var;
	RzILVal val = rz_il_hash_find_val_by_name(vm, var_op->v);
	val = rz_il_dump_value(val);
	rz_il_make_val_temp(vm, var_op->ret, val);
}

void rz_il_handler_unk(RzILVM vm, RzILOp op) {
	RzILOpUnk op_unk = op->op.unk;
	RzILVal val = rz_il_new_value(); // has UNK

	rz_il_make_val_temp(vm, op_unk->ret, val);
}
