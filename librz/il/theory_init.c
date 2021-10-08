// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>
#include <rz_il/rzil_vm.h>

void *rz_il_handler_ite(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpIte *op_ite = op->op.ite;

	RzILBool *condition = rz_il_evaluate_bool(vm, op_ite->condition, type);
	RzILVal *ret;

	*type = RZIL_OP_ARG_VAL;
	if (condition->b) {
		ret = rz_il_evaluate_val(vm, op_ite->x, type); // true branch
	} else {
		ret = rz_il_evaluate_val(vm, op_ite->y, type); // false branch
	}

	return ret;
}

void *rz_il_handler_var(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpVar *var_op = op->op.var;
	RzILVal *val = rz_il_hash_find_val_by_name(vm, var_op->v);
	val = rz_il_dup_value(val);

	*type = RZIL_OP_ARG_VAL;
	return val;
}

void *rz_il_handler_unk(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILVal *val = rz_il_new_value(); // has UNK
	*type = RZIL_OP_ARG_VAL;
	return val;
}
