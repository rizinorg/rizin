// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>
#include <rz_il/rzil_vm.h>

void *rz_il_handler_msb(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpMsb *op_msb = op->op.msb;
	RzILBitVector *bv = rz_il_evaluate_bitv(vm, op_msb->bv, type);
	RzILBool *result = rz_il_bool_new(rz_il_bv_msb(bv));
	rz_il_bv_free(bv);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_lsb(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpLsb *op_lsb = op->op.lsb;
	RzILBitVector *bv = rz_il_evaluate_bitv(vm, op_lsb->bv, type);
	RzILBool *result = rz_il_bool_new(rz_il_bv_lsb(bv));
	rz_il_bv_free(bv);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_neg(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpNeg *neg = op->op.neg;

	RzILBitVector *bv_arg = rz_il_evaluate_bitv(vm, neg->bv, type);
	RzILBitVector *bv_result = rz_il_bv_neg(bv_arg);
	rz_il_bv_free(bv_arg);

	*type = RZIL_OP_ARG_BITV;
	return bv_result;
}

void *rz_il_handler_not(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpNot *op_not = op->op.not_;

	RzILBitVector *bv = rz_il_evaluate_bitv(vm, op_not->bv, type);
	RzILBitVector *result = rz_il_bv_not(bv);
	rz_il_bv_free(bv);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_sle(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpSle *op_sle = op->op.sle;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_sle->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_sle->y, type);
	RzILBool *result = rz_il_bool_new(rz_il_bv_sle(x, y));

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_ule(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpUle *op_ule = op->op.ule;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_ule->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_ule->y, type);
	RzILBool *result = rz_il_bool_new(rz_il_bv_ule(x, y));

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_add(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpAdd *op_add = op->op.add;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_add->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_add->y, type);
	RzILBitVector *result = rz_il_bv_add(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_logical_and(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpAdd *op_add = op->op.add;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_add->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_add->y, type);
	RzILBitVector *result = rz_il_bv_and(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_logical_or(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpAdd *op_add = op->op.add;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_add->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_add->y, type);
	RzILBitVector *result = rz_il_bv_or(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_logical_xor(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpAdd *op_add = op->op.add;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_add->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_add->y, type);
	RzILBitVector *result = rz_il_bv_xor(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_sub(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpSub *op_sub = op->op.sub;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_sub->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_sub->y, type);
	RzILBitVector *result = rz_il_bv_sub(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_mul(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpMul *op_mul = op->op.mul;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_mul->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_mul->y, type);
	RzILBitVector *result = rz_il_bv_mul(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_div(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpDiv *op_div = op->op.div;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_div->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_div->y, type);
	RzILBitVector *result = rz_il_bv_div(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_sdiv(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpSdiv *op_sdiv = op->op.sdiv;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_sdiv->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_sdiv->y, type);
	RzILBitVector *result = rz_il_bv_sdiv(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_mod(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpMod *op_mod = op->op.mod;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_mod->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_mod->y, type);
	RzILBitVector *result = rz_il_bv_mod(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_smod(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpSmod *op_smod = op->op.smod;

	RzILBitVector *x = rz_il_evaluate_bitv(vm, op_smod->x, type);
	RzILBitVector *y = rz_il_evaluate_bitv(vm, op_smod->y, type);
	RzILBitVector *result = rz_il_bv_smod(x, y);

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_shiftl(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpShiftl *op_shiftl = op->op.shiftl;

	RzILBitVector *bv = rz_il_evaluate_bitv(vm, op_shiftl->x, type);
	RzILBitVector *shift = rz_il_evaluate_bitv(vm, op_shiftl->y, type);
	ut32 shift_size = rz_il_bv_to_ut32(shift);
	RzILBool *fill_bit = rz_il_evaluate_bool(vm, op_shiftl->fill_bit, type);

	RzILBitVector *result = rz_il_bv_dup(bv);
	rz_il_bv_lshift_fill(result, shift_size, fill_bit);

	rz_il_bv_free(shift);
	rz_il_bv_free(bv);
	rz_il_bool_free(fill_bit);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_shiftr(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpShiftr *op_shr = op->op.shiftr;

	RzILBitVector *bv = rz_il_evaluate_bitv(vm, op_shr->x, type);
	RzILBitVector *shift = rz_il_evaluate_bitv(vm, op_shr->y, type);
	ut32 shift_size = rz_il_bv_to_ut32(shift);
	RzILBool *fill_bit = rz_il_evaluate_bool(vm, op_shr->fill_bit, type);

	RzILBitVector *result = rz_il_bv_dup(bv);
	rz_il_bv_rshift_fill(result, shift_size, fill_bit);

	rz_il_bv_free(shift);
	rz_il_bv_free(bv);
	rz_il_bool_free(fill_bit);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_int(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	RzILOpInt *op_int = op->op.int_;

	ut32 length = op_int->length;
	int value = op_int->value;
	RzILBitVector *bv = rz_il_bv_new_from_ut32(length, value);

	*type = RZIL_OP_ARG_BITV;
	return bv;
}
