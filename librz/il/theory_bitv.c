// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>
#include <rz_il/vm_layer.h>
#include <rz_il/rzil_vm.h>

void *rz_il_handler_msb(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpMsb *op_msb = op->op.msb;
	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_msb->bv, type);
	RzILBool *result = rz_il_bool_new(rz_bv_msb(bv));
	rz_bv_free(bv);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_lsb(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpLsb *op_lsb = op->op.lsb;
	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_lsb->bv, type);
	RzILBool *result = rz_il_bool_new(rz_bv_lsb(bv));
	rz_bv_free(bv);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_neg(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpNeg *neg = op->op.neg;

	RzBitVector *bv_arg = rz_il_evaluate_bitv(vm, neg->bv, type);
	RzBitVector *bv_result = rz_bv_neg(bv_arg);
	rz_bv_free(bv_arg);

	*type = RZIL_OP_ARG_BITV;
	return bv_result;
}

void *rz_il_handler_logical_not(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpLogNot *op_not = op->op.lognot;

	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_not->bv, type);
	RzBitVector *result = rz_bv_not(bv);
	rz_bv_free(bv);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_sle(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpSle *op_sle = op->op.sle;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_sle->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_sle->y, type);
	RzILBool *result = rz_il_bool_new(rz_bv_sle(x, y));

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_ule(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpUle *op_ule = op->op.ule;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_ule->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_ule->y, type);
	RzILBool *result = rz_il_bool_new(rz_bv_ule(x, y));

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_add(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpAdd *op_add = op->op.add;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_add->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_add->y, type);
	RzBitVector *result = rz_bv_add(x, y, NULL);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_append(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpAppend *op_append = op->op.append;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_append->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_append->y, type);
	RzBitVector *result = rz_bv_append(x, y);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_logical_and(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpAdd *op_add = op->op.add;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_add->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_add->y, type);
	RzBitVector *result = rz_bv_and(x, y);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_logical_or(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpAdd *op_add = op->op.add;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_add->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_add->y, type);
	RzBitVector *result = rz_bv_or(x, y);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_logical_xor(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpAdd *op_add = op->op.add;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_add->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_add->y, type);
	RzBitVector *result = rz_bv_xor(x, y);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_sub(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpSub *op_sub = op->op.sub;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_sub->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_sub->y, type);
	RzBitVector *result = rz_bv_sub(x, y, NULL);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_mul(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpMul *op_mul = op->op.mul;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_mul->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_mul->y, type);
	RzBitVector *result = rz_bv_mul(x, y);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_div(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpDiv *op_div = op->op.div;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_div->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_div->y, type);
	RzBitVector *result = NULL;
	if (rz_bv_is_zero_vector(y)) {
		result = rz_bv_new(y->len);
		rz_bv_set_all(result, true);
		rz_il_vm_event_add(vm, rz_il_event_exception_new("division by zero"));
	} else {
		result = rz_bv_div(x, y);
	}

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_sdiv(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpSdiv *op_sdiv = op->op.sdiv;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_sdiv->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_sdiv->y, type);
	RzBitVector *result = rz_bv_sdiv(x, y);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_mod(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpMod *op_mod = op->op.mod;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_mod->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_mod->y, type);
	RzBitVector *result = rz_bv_mod(x, y);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_smod(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpSmod *op_smod = op->op.smod;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_smod->x, type);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_smod->y, type);
	RzBitVector *result = rz_bv_smod(x, y);

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_shiftl(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpShiftLeft *op_shiftl = op->op.shiftl;

	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_shiftl->x, type);
	RzBitVector *shift = rz_il_evaluate_bitv(vm, op_shiftl->y, type);
	ut32 shift_size = rz_bv_to_ut32(shift);
	RzILBool *fill_bit = rz_il_evaluate_bool(vm, op_shiftl->fill_bit, type);

	RzBitVector *result = rz_bv_dup(bv);
	rz_bv_lshift_fill(result, shift_size, fill_bit);

	rz_bv_free(shift);
	rz_bv_free(bv);
	rz_il_bool_free(fill_bit);

	*type = RZIL_OP_ARG_BOOL;
	return result;
}

void *rz_il_handler_shiftr(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpShiftRight *op_shr = op->op.shiftr;

	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_shr->x, type);
	RzBitVector *shift = rz_il_evaluate_bitv(vm, op_shr->y, type);
	ut32 shift_size = rz_bv_to_ut32(shift);
	RzILBool *fill_bit = rz_il_evaluate_bool(vm, op_shr->fill_bit, type);

	RzBitVector *result = rz_bv_dup(bv);
	rz_bv_rshift_fill(result, shift_size, fill_bit);

	rz_bv_free(shift);
	rz_bv_free(bv);
	rz_il_bool_free(fill_bit);

	*type = RZIL_OP_ARG_BITV;
	return result;
}

void *rz_il_handler_bitv(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpBv *op_bitv = op->op.bitv;

	RzBitVector *bv = rz_bv_dup(op_bitv->value);

	*type = RZIL_OP_ARG_BITV;
	return bv;
}

void *rz_il_handler_cast(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpCast *op_cast = op->op.cast;
	int shift = op_cast->shift;

	RzBitVector *ret = rz_bv_new(op_cast->length);
	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_cast->val, type);

	if (shift == 0) {
		rz_bv_copy_nbits(bv, 0, ret, 0, RZ_MIN(bv->len, ret->len));
	} else if (shift > 0) {
		// left shift <<
		rz_bv_copy_nbits(bv, 0, ret, shift, RZ_MIN(bv->len, ret->len));
	} else {
		// right shift >>
		rz_bv_copy_nbits(bv, -shift, ret, 0, RZ_MIN(bv->len, ret->len));
	}
	rz_bv_free(bv);

	*type = RZIL_OP_ARG_BITV;
	return ret;
}
