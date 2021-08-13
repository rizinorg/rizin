// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>
#include <rz_il/rzil_vm.h>

void rz_il_handler_msb(RzILVM vm, RzILOp op) {
	RzILOpMsb op_msb = op->op.msb;
	RzILBitVector bv = rz_il_get_bv_temp(vm, op_msb->bv);
	RzILBool result = rz_il_new_bool(rz_il_bv_msb(bv));
	rz_il_make_bool_temp(vm, op_msb->ret, result);
}

void rz_il_handler_lsb(RzILVM vm, RzILOp op) {
	RzILOpLsb op_lsb = op->op.lsb;
	RzILBitVector bv = rz_il_get_bv_temp(vm, op_lsb->bv);
	RzILBool result = rz_il_new_bool(rz_il_bv_lsb(bv));
	rz_il_make_bool_temp(vm, op_lsb->ret, result);
}

void rz_il_handler_neg(RzILVM vm, RzILOp op) {
	RzILOpNeg neg = op->op.neg;

	RzILBitVector bv_arg = rz_il_get_bv_temp(vm, neg->bv);
	RzILBitVector bv_result = rz_il_bv_neg(bv_arg);

	rz_il_make_bv_temp(vm, neg->ret, bv_result);
}

void rz_il_handler_not(RzILVM vm, RzILOp op) {
	RzILOpNot op_not = op->op.not ;

	RzILBitVector bv = rz_il_get_bv_temp(vm, op_not->bv);
	RzILBitVector result = rz_il_bv_not(bv);

	rz_il_make_bv_temp(vm, op_not->ret, result);
}

void rz_il_handler_sle(RzILVM vm, RzILOp op) {
	RzILOpSle op_sle = op->op.sle;

	RzILBitVector x = rz_il_get_bv_temp(vm, op_sle->x);
	RzILBitVector y = rz_il_get_bv_temp(vm, op_sle->y);
	RzILBool result = rz_il_new_bool(rz_il_bv_sle(x, y));

	rz_il_make_bool_temp(vm, op_sle->ret, result);
}

void rz_il_handler_ule(RzILVM vm, RzILOp op) {
	RzILOpUle op_ule = op->op.ule;

	RzILBitVector x = rz_il_get_bv_temp(vm, op_ule->x);
	RzILBitVector y = rz_il_get_bv_temp(vm, op_ule->y);
	RzILBool result = rz_il_new_bool(rz_il_bv_ule(x, y));

	rz_il_make_bool_temp(vm, op_ule->ret, result);
}

void rz_il_handler_add(RzILVM vm, RzILOp op) {
	RzILOpAdd op_add = op->op.add;

	RzILBitVector x = rz_il_get_bv_temp(vm, op_add->x);
	RzILBitVector y = rz_il_get_bv_temp(vm, op_add->y);
	RzILBitVector result = rz_il_bv_add(x, y);

	rz_il_make_bv_temp(vm, op_add->ret, result);
}

void rz_il_handler_sub(RzILVM vm, RzILOp op) {
	RzILOpSub op_sub = op->op.sub;

	RzILBitVector x = rz_il_get_bv_temp(vm, op_sub->x);
	RzILBitVector y = rz_il_get_bv_temp(vm, op_sub->y);
	RzILBitVector result = rz_il_bv_sub(x, y);

	rz_il_make_bv_temp(vm, op_sub->ret, result);
}

void rz_il_handler_mul(RzILVM vm, RzILOp op) {
	RzILOpMul op_mul = op->op.mul;

	RzILBitVector x = rz_il_get_bv_temp(vm, op_mul->x);
	RzILBitVector y = rz_il_get_bv_temp(vm, op_mul->y);
	RzILBitVector result = rz_il_bv_mul(x, y);

	rz_il_make_bv_temp(vm, op_mul->ret, result);
}

void rz_il_handler_div(RzILVM vm, RzILOp op) {
	RzILOpDiv op_div = op->op.div;

	RzILBitVector x = rz_il_get_bv_temp(vm, op_div->x);
	RzILBitVector y = rz_il_get_bv_temp(vm, op_div->y);
	RzILBitVector result = rz_il_bv_div(x, y);

	rz_il_make_bv_temp(vm, op_div->ret, result);
}

void rz_il_handler_sdiv(RzILVM vm, RzILOp op) {
	RzILOpSdiv op_sdiv = op->op.sdiv;

	RzILBitVector x = rz_il_get_bv_temp(vm, op_sdiv->x);
	RzILBitVector y = rz_il_get_bv_temp(vm, op_sdiv->y);
	RzILBitVector result = rz_il_bv_sdiv(x, y);

	rz_il_make_bv_temp(vm, op_sdiv->ret, result);
}

void rz_il_handler_mod(RzILVM vm, RzILOp op) {
	RzILOpMod op_mod = op->op.mod;

	RzILBitVector x = rz_il_get_bv_temp(vm, op_mod->x);
	RzILBitVector y = rz_il_get_bv_temp(vm, op_mod->y);
	RzILBitVector result = rz_il_bv_mod(x, y);

	rz_il_make_bv_temp(vm, op_mod->ret, result);
}

void rz_il_handler_smod(RzILVM vm, RzILOp op) {
	RzILOpSmod op_smod = op->op.smod;

	RzILBitVector x = rz_il_get_bv_temp(vm, op_smod->x);
	RzILBitVector y = rz_il_get_bv_temp(vm, op_smod->y);
	RzILBitVector result = rz_il_bv_smod(x, y);

	rz_il_make_bv_temp(vm, op_smod->ret, result);
}

void rz_il_handler_shiftl(RzILVM vm, RzILOp op) {
	RzILOpShiftl op_shiftl = op->op.shiftl;

	RzILBitVector bv = rz_il_get_bv_temp(vm, op_shiftl->x);
	RzILBitVector shift = rz_il_get_bv_temp(vm, op_shiftl->y);
	ut32 shift_size = rz_il_bv_to_ut32(shift);
	RzILBool fill_bit = rz_il_get_bool_temp(vm, op_shiftl->fill_bit);

	RzILBitVector result = rz_il_bv_dup(bv);
	rz_il_bv_lshift_fill(result, shift_size, fill_bit);

	rz_il_make_bv_temp(vm, op_shiftl->ret, result);
}

void rz_il_handler_shiftr(RzILVM vm, RzILOp op) {
	RzILOpShiftr op_shr = op->op.shiftr;

	RzILBitVector bv = rz_il_get_bv_temp(vm, op_shr->x);
	ut32 shift_size = rz_il_bv_to_ut32(rz_il_get_bv_temp(vm, op_shr->y));
	RzILBool fill_bit = rz_il_get_bool_temp(vm, op_shr->fill_bit);

	RzILBitVector result = rz_il_bv_dup(bv);
	rz_il_bv_rshift_fill(result, shift_size, fill_bit);

	rz_il_make_bv_temp(vm, op_shr->ret, result);
}

void rz_il_handler_int(RzILVM vm, RzILOp op) {
	RzILOpInt op_int = op->op.int_;

	ut32 length = op_int->length;
	int value = op_int->value;
	RzILBitVector bv = rz_il_bv_new_from_ut32(length, value);

	rz_il_make_bv_temp(vm, op_int->ret, bv);
}
