// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opcodes.h>
#include <rz_il/rz_il_vm.h>

/**
 * \brief also known as b0
 */
void *rz_il_handler_bool_false(RzILVM *vm, RzILOpBool *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILBool *ret = rz_il_bool_new(false);
	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

/**
 * \brief also known as b1
 */
void *rz_il_handler_bool_true(RzILVM *vm, RzILOpBool *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILBool *ret = rz_il_bool_new(true);
	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

void *rz_il_handler_bool_and(RzILVM *vm, RzILOpBool *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsBoolAnd *op_and = &op->op.booland;
	RzILBool *x = rz_il_evaluate_bool(vm, op_and->x);
	RzILBool *y = rz_il_evaluate_bool(vm, op_and->y);

	RzILBool *result = x && y ? rz_il_bool_and(x, y) : NULL;
	rz_il_bool_free(x);
	rz_il_bool_free(y);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}

void *rz_il_handler_bool_or(RzILVM *vm, RzILOpBool *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsBoolOr *op_or = &op->op.boolor;
	RzILBool *x = rz_il_evaluate_bool(vm, op_or->x);
	RzILBool *y = rz_il_evaluate_bool(vm, op_or->y);

	RzILBool *result = x && y ? rz_il_bool_or(x, y) : NULL;
	rz_il_bool_free(x);
	rz_il_bool_free(y);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}

void *rz_il_handler_bool_xor(RzILVM *vm, RzILOpBool *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsBoolXor *op_xor = &op->op.boolxor;
	RzILBool *x = rz_il_evaluate_bool(vm, op_xor->x);
	RzILBool *y = rz_il_evaluate_bool(vm, op_xor->y);

	RzILBool *result = x && y ? rz_il_bool_xor(x, y) : NULL;
	rz_il_bool_free(x);
	rz_il_bool_free(y);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}

/**
 * \brief also known as boolean not
 */
void *rz_il_handler_bool_inv(RzILVM *vm, RzILOpBool *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsBoolInv *op_inv = &op->op.boolinv;
	RzILBool *x = rz_il_evaluate_bool(vm, op_inv->x);
	RzILBool *result = x ? rz_il_bool_not(x) : NULL;
	rz_il_bool_free(x);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}
