#include "core_theory_opcodes.h"
#include "core_theory_vm.h"

void rz_il_handler_b0(RzILVM vm, RzILOp op) {
	RzILOpB0 op_b0 = op->op.b0;
	rz_il_make_bool_temp(vm, op_b0->ret, rz_il_new_bool(false));
}

void rz_il_handler_b1(RzILVM vm, RzILOp op) {
	RzILOpB1 op_b1 = op->op.b1;
	rz_il_make_bool_temp(vm, op_b1->ret, rz_il_new_bool(true));
}

void rz_il_handler_and_(RzILVM vm, RzILOp op) {
	RzILOpAnd_ op_and_ = op->op.and_;
	Bool x = rz_il_get_bool_temp(vm, op_and_->x);
	Bool y = rz_il_get_bool_temp(vm, op_and_->y);

	Bool result = rz_il_bool_and_(x, y);
	rz_il_make_bool_temp(vm, op_and_->ret, result);
}

void rz_il_handler_or_(RzILVM vm, RzILOp op) {
	RzILOpOr_ op_or_ = op->op.or_;
	Bool x = rz_il_get_bool_temp(vm, op_or_->x);
	Bool y = rz_il_get_bool_temp(vm, op_or_->y);

	Bool result = rz_il_bool_or_(x, y);
	rz_il_make_bool_temp(vm, op_or_->ret, result);
}

void rz_il_handler_inv(RzILVM vm, RzILOp op) {
	RzILOpInv op_inv = op->op.inv;
	Bool x = rz_il_get_bool_temp(vm, op_inv->x);
	Bool result = rz_il_bool_not_(x);
	rz_il_make_bool_temp(vm, op_inv->ret, result);
}
