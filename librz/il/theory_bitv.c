// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opcodes.h>
#include <rz_il/rz_il_vm.h>

void *rz_il_handler_msb(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsMsb *op_msb = &op->op.msb;
	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_msb->bv);
	RzILBool *result = bv ? rz_il_bool_new(rz_bv_msb(bv)) : NULL;
	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}

void *rz_il_handler_lsb(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsLsb *op_lsb = &op->op.lsb;
	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_lsb->bv);
	RzILBool *result = bv ? rz_il_bool_new(rz_bv_lsb(bv)) : NULL;
	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}

void *rz_il_handler_is_zero(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsLsb *op_lsb = &op->op.lsb;
	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_lsb->bv);
	RzILBool *result = bv ? rz_il_bool_new(rz_bv_is_zero_vector(bv)) : NULL;
	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}

void *rz_il_handler_neg(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsNeg *neg = &op->op.neg;

	RzBitVector *bv_arg = rz_il_evaluate_bitv(vm, neg->bv);
	RzBitVector *bv_result = bv_arg ? rz_bv_neg(bv_arg) : NULL;
	rz_bv_free(bv_arg);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return bv_result;
}

void *rz_il_handler_logical_not(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsLogNot *op_not = &op->op.lognot;

	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_not->bv);
	RzBitVector *result = bv ? rz_bv_not(bv) : NULL;
	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_eq(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsSle *op_sle = &op->op.sle;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_sle->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_sle->y);
	RzILBool *result = x && y ? rz_il_bool_new(rz_bv_eq(x, y)) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}

void *rz_il_handler_sle(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsSle *op_sle = &op->op.sle;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_sle->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_sle->y);
	RzILBool *result = x && y ? rz_il_bool_new(rz_bv_sle(x, y)) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}

void *rz_il_handler_ule(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsUle *op_ule = &op->op.ule;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_ule->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_ule->y);
	RzILBool *result = x && y ? rz_il_bool_new(rz_bv_ule(x, y)) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return result;
}

void *rz_il_handler_add(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsAdd *op_add = &op->op.add;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_add->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_add->y);
	RzBitVector *result = x && y ? rz_bv_add(x, y, NULL) : NULL;

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_append(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsAppend *op_append = &op->op.append;

	RzBitVector *high = rz_il_evaluate_bitv(vm, op_append->high);
	RzBitVector *low = rz_il_evaluate_bitv(vm, op_append->low);
	RzBitVector *result = high && low ? rz_bv_append(high, low) : NULL;
	rz_bv_free(low);
	rz_bv_free(high);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_logical_and(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsAdd *op_add = &op->op.add;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_add->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_add->y);
	RzBitVector *result = x && y ? rz_bv_and(x, y) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_logical_or(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsAdd *op_add = &op->op.add;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_add->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_add->y);
	RzBitVector *result = x && y ? rz_bv_or(x, y) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_logical_xor(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsAdd *op_add = &op->op.add;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_add->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_add->y);
	RzBitVector *result = x && y ? rz_bv_xor(x, y) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_sub(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsSub *op_sub = &op->op.sub;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_sub->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_sub->y);
	RzBitVector *result = x && y ? rz_bv_sub(x, y, NULL) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_mul(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsMul *op_mul = &op->op.mul;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_mul->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_mul->y);
	RzBitVector *result = x && y ? rz_bv_mul(x, y) : NULL;

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_div(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsDiv *op_div = &op->op.div;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_div->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_div->y);
	RzBitVector *result = NULL;
	if (x && y) {
		if (rz_bv_is_zero_vector(y)) {
			result = rz_bv_new(y->len);
			rz_bv_set_all(result, true);
			rz_il_vm_event_add(vm, rz_il_event_exception_new(RZ_IL_EVENT_EXC_DIV_ZERO));
		} else {
			result = rz_bv_div(x, y);
		}
	}

	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_sdiv(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsSdiv *op_sdiv = &op->op.sdiv;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_sdiv->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_sdiv->y);
	RzBitVector *result = x && y ? rz_bv_sdiv(x, y) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_mod(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsMod *op_mod = &op->op.mod;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_mod->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_mod->y);
	RzBitVector *result = x && y ? rz_bv_mod(x, y) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_smod(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsSmod *op_smod = &op->op.smod;

	RzBitVector *x = rz_il_evaluate_bitv(vm, op_smod->x);
	RzBitVector *y = rz_il_evaluate_bitv(vm, op_smod->y);
	RzBitVector *result = x && y ? rz_bv_smod(x, y) : NULL;
	rz_bv_free(x);
	rz_bv_free(y);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_shiftl(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsShiftLeft *op_shiftl = &op->op.shiftl;

	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_shiftl->x);
	RzBitVector *shift = rz_il_evaluate_bitv(vm, op_shiftl->y);
	RzILBool *fill_bit = rz_il_evaluate_bool(vm, op_shiftl->fill_bit);

	RzBitVector *result = NULL;
	if (bv && shift && fill_bit) {
		result = rz_bv_dup(bv);
		rz_bv_lshift_fill(result, rz_bv_to_ut32(shift), fill_bit->b);
	}
	rz_bv_free(shift);
	rz_bv_free(bv);
	rz_il_bool_free(fill_bit);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_shiftr(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsShiftRight *op_shr = &op->op.shiftr;

	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_shr->x);
	RzBitVector *shift = rz_il_evaluate_bitv(vm, op_shr->y);
	RzILBool *fill_bit = rz_il_evaluate_bool(vm, op_shr->fill_bit);

	RzBitVector *result = NULL;
	if (bv && shift && fill_bit) {
		result = rz_bv_dup(bv);
		rz_bv_rshift_fill(result, rz_bv_to_ut32(shift), fill_bit->b);
	}

	rz_bv_free(shift);
	rz_bv_free(bv);
	rz_il_bool_free(fill_bit);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return result;
}

void *rz_il_handler_bitv(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsBv *op_bitv = &op->op.bitv;

	RzBitVector *bv = rz_bv_dup(op_bitv->value);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return bv;
}

void *rz_il_handler_cast(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsCast *op_cast = &op->op.cast;
	RzILBool *fill = rz_il_evaluate_bool(vm, op_cast->fill);
	if (!fill) {
		return NULL;
	}
	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_cast->val);
	if (!bv) {
		return NULL;
	}

	RzBitVector *ret = rz_bv_new(op_cast->length);
	rz_bv_set_all(ret, fill->b);
	rz_bv_copy_nbits(ret, 0, bv, 0, RZ_MIN(bv->len, ret->len));

	rz_il_bool_free(fill);
	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return ret;
}
