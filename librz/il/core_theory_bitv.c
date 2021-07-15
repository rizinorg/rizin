#include "definitions/bitvector.h"
#include "core_theory_opcodes.h"
#include "core_theory_vm.h"

void rz_il_handler_msb(RzILVM vm, RzILOp op) {
	RzILOpMsb op_msb = op->op.msb;
	BitVector bv = rz_il_get_bv_temp(vm, op_msb->bv);
	Bool result = rz_il_new_bool(bv_msb(bv));
	rz_il_make_bool_temp(vm, op_msb->ret, result);
}

void rz_il_handler_lsb(RzILVM vm, RzILOp op) {
	RzILOpLsb op_lsb = op->op.lsb;
	BitVector bv = rz_il_get_bv_temp(vm, op_lsb->bv);
	Bool result = rz_il_new_bool(bv_lsb(bv));
	rz_il_make_bool_temp(vm, op_lsb->ret, result);
}

void rz_il_handler_neg(RzILVM vm, RzILOp op) {
	RzILOpNeg neg = op->op.neg;

	BitVector bv_arg = rz_il_get_bv_temp(vm, neg->bv);
	BitVector bv_result = bv_neg(bv_arg);

	rz_il_make_bv_temp(vm, neg->ret, bv_result);
}

void rz_il_handler_not(RzILVM vm, RzILOp op) {
	RzILOpNot op_not = op->op.not ;

	BitVector bv = rz_il_get_bv_temp(vm, op_not->bv);
	BitVector result = bv_not(bv);

	rz_il_make_bv_temp(vm, op_not->ret, result);
}

void rz_il_handler_sle(RzILVM vm, RzILOp op) {
	RzILOpSle op_sle = op->op.sle;

	BitVector x = rz_il_get_bv_temp(vm, op_sle->x);
	BitVector y = rz_il_get_bv_temp(vm, op_sle->y);
	Bool result = rz_il_new_bool(bv_sle(x, y));

	rz_il_make_bool_temp(vm, op_sle->ret, result);
}

void rz_il_handler_ule(RzILVM vm, RzILOp op) {
	RzILOpUle op_ule = op->op.ule;

	BitVector x = rz_il_get_bv_temp(vm, op_ule->x);
	BitVector y = rz_il_get_bv_temp(vm, op_ule->y);
	Bool result = rz_il_new_bool(bv_ule(x, y));

	rz_il_make_bool_temp(vm, op_ule->ret, result);
}

void rz_il_handler_add(RzILVM vm, RzILOp op) {
	RzILOpAdd op_add = op->op.add;

	BitVector x = rz_il_get_bv_temp(vm, op_add->x);
	BitVector y = rz_il_get_bv_temp(vm, op_add->y);
	BitVector result = bv_add(x, y);

	rz_il_make_bv_temp(vm, op_add->ret, result);
}

void rz_il_handler_sub(RzILVM vm, RzILOp op) {
	RzILOpSub op_sub = op->op.sub;

	BitVector x = rz_il_get_bv_temp(vm, op_sub->x);
	BitVector y = rz_il_get_bv_temp(vm, op_sub->y);
	BitVector result = bv_sub(x, y);

	rz_il_make_bv_temp(vm, op_sub->ret, result);
}

void rz_il_handler_mul(RzILVM vm, RzILOp op) {
	RzILOpMul op_mul = op->op.mul;

	BitVector x = rz_il_get_bv_temp(vm, op_mul->x);
	BitVector y = rz_il_get_bv_temp(vm, op_mul->y);
	BitVector result = bv_mul(x, y);

	rz_il_make_bv_temp(vm, op_mul->ret, result);
}

void rz_il_handler_div(RzILVM vm, RzILOp op) {
	RzILOpDiv op_div = op->op.div;

	BitVector x = rz_il_get_bv_temp(vm, op_div->x);
	BitVector y = rz_il_get_bv_temp(vm, op_div->y);
	BitVector result = bv_div(x, y);

	rz_il_make_bv_temp(vm, op_div->ret, result);
}

void rz_il_handler_sdiv(RzILVM vm, RzILOp op) {
	RzILOpSdiv op_sdiv = op->op.sdiv;

	BitVector x = rz_il_get_bv_temp(vm, op_sdiv->x);
	BitVector y = rz_il_get_bv_temp(vm, op_sdiv->y);
	BitVector result = bv_sdiv(x, y);

	rz_il_make_bv_temp(vm, op_sdiv->ret, result);
}

void rz_il_handler_mod(RzILVM vm, RzILOp op) {
	RzILOpMod op_mod = op->op.mod;

	BitVector x = rz_il_get_bv_temp(vm, op_mod->x);
	BitVector y = rz_il_get_bv_temp(vm, op_mod->y);
	BitVector result = bv_mod(x, y);

	rz_il_make_bv_temp(vm, op_mod->ret, result);
}

void rz_il_handler_smod(RzILVM vm, RzILOp op) {
	RzILOpSmod op_smod = op->op.smod;

	BitVector x = rz_il_get_bv_temp(vm, op_smod->x);
	BitVector y = rz_il_get_bv_temp(vm, op_smod->y);
	BitVector result = bv_smod(x, y);

	rz_il_make_bv_temp(vm, op_smod->ret, result);
}

void rz_il_handler_shiftl(RzILVM vm, RzILOp op) {
	RzILOpShiftl op_shiftl = op->op.shiftl;

	BitVector bv = rz_il_get_bv_temp(vm, op_shiftl->x);
	BitVector shift = rz_il_get_bv_temp(vm, op_shiftl->y);
	int shift_size = bv_to_ut32(shift);
	Bool fill_bit = rz_il_get_bool_temp(vm, op_shiftl->fill_bit);

	BitVector result = bv_dump(bv);
	bv_lshift_fill(result, shift_size, fill_bit);

	rz_il_make_bv_temp(vm, op_shiftl->ret, result);
}

void rz_il_handler_shiftr(RzILVM vm, RzILOp op) {
	RzILOpShiftr op_shr = op->op.shiftr;

	BitVector bv = rz_il_get_bv_temp(vm, op_shr->x);
	int shift_size = bv_to_ut32(rz_il_get_bv_temp(vm, op_shr->y));
	Bool fill_bit = rz_il_get_bool_temp(vm, op_shr->fill_bit);

	BitVector result = bv_dump(bv);
	bv_rshift_fill(result, shift_size, fill_bit);

	rz_il_make_bv_temp(vm, op_shr->ret, result);
}

void rz_il_handler_int(RzILVM vm, RzILOp op) {
	RzILOpInt op_int = op->op.int_;

	int length = op_int->length;
	int value = op_int->value;
	BitVector bv = bv_new_from_ut32(length, value);

	rz_il_make_bv_temp(vm, op_int->ret, bv);
}
