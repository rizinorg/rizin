// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>
#include <rz_il/rzil_vm.h>

void rz_il_handler_b0(RzILVM *vm, RzILOp *op) {
	RzILOpB0 *op_b0 = op->op.b0;
	rz_il_make_bool_temp(vm, op_b0->ret, rz_il_new_bool(false));
}

void rz_il_handler_b1(RzILVM *vm, RzILOp *op) {
	RzILOpB1 *op_b1 = op->op.b1;
	rz_il_make_bool_temp(vm, op_b1->ret, rz_il_new_bool(true));
}

void rz_il_handler_and_(RzILVM *vm, RzILOp *op) {
	RzILOpAnd_ *op_and_ = op->op.and_;
	RzILBool *x = rz_il_get_bool_temp(vm, op_and_->x);
	RzILBool *y = rz_il_get_bool_temp(vm, op_and_->y);

	RzILBool *result = rz_il_bool_and(x, y);
	rz_il_make_bool_temp(vm, op_and_->ret, result);
}

void rz_il_handler_or_(RzILVM *vm, RzILOp *op) {
	RzILOpOr_ *op_or_ = op->op.or_;
	RzILBool *x = rz_il_get_bool_temp(vm, op_or_->x);
	RzILBool *y = rz_il_get_bool_temp(vm, op_or_->y);

	RzILBool *result = rz_il_bool_or(x, y);
	rz_il_make_bool_temp(vm, op_or_->ret, result);
}

void rz_il_handler_inv(RzILVM *vm, RzILOp *op) {
	RzILOpInv *op_inv = op->op.inv;
	RzILBool *x = rz_il_get_bool_temp(vm, op_inv->x);
	RzILBool *result = rz_il_bool_not(x);
	rz_il_make_bool_temp(vm, op_inv->ret, result);
}
