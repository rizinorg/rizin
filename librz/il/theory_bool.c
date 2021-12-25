// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>
#include <rz_il/rzil_vm.h>

/**
 * \brief also known as b0
 */
void *rz_il_handler_bool_false(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILBool *ret = rz_il_bool_new(false);
	*type = RZIL_OP_ARG_BOOL;
	return ret;
}

/**
 * \brief also known as b1
 */
void *rz_il_handler_bool_true(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILBool *ret = rz_il_bool_new(true);
	*type = RZIL_OP_ARG_BOOL;
	return ret;
}

void *rz_il_handler_bool_and(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsBoolAnd *op_and = op->op.booland;
	RzILBool *x = rz_il_evaluate_bool(vm, op_and->x, type);
	RzILBool *y = rz_il_evaluate_bool(vm, op_and->y, type);

	RzILBool *result = rz_il_bool_and(x, y);
	rz_il_bool_free(x);
	rz_il_bool_free(y);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_bool_or(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsBoolOr *op_or = op->op.boolor;
	RzILBool *x = rz_il_evaluate_bool(vm, op_or->x, type);
	RzILBool *y = rz_il_evaluate_bool(vm, op_or->y, type);

	RzILBool *result = rz_il_bool_or(x, y);
	rz_il_bool_free(x);
	rz_il_bool_free(y);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_bool_xor(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsBoolXor *op_xor = op->op.boolxor;
	RzILBool *x = rz_il_evaluate_bool(vm, op_xor->x, type);
	RzILBool *y = rz_il_evaluate_bool(vm, op_xor->y, type);

	RzILBool *result = rz_il_bool_xor(x, y);
	rz_il_bool_free(x);
	rz_il_bool_free(y);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

/**
 * \brief also known as boolean not
 */
void *rz_il_handler_bool_inv(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsBoolInv *op_inv = op->op.boolinv;
	RzILBool *x = rz_il_evaluate_bool(vm, op_inv->x, type);
	RzILBool *result = rz_il_bool_not(x);
	rz_il_bool_free(x);

	return result;
}
