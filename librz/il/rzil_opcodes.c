// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>

#define rz_il_op_new_0(id) \
	do { \
		ret = RZ_NEW0(RzILOp); \
		if (!ret) { \
			return NULL; \
		} \
		ret->code = id; \
	} while (0)

#define rz_il_op_new_1(id, t, s, v0) \
	do { \
		ret = RZ_NEW0(RzILOp); \
		if (!ret) { \
			return NULL; \
		} \
		ret->op.s = RZ_NEW0(t); \
		if (!ret->op.s) { \
			free(ret); \
			return NULL; \
		} \
		ret->code = id; \
		ret->op.s->v0 = v0; \
	} while (0)

#define rz_il_op_new_2(id, t, s, v0, v1) \
	do { \
		ret = RZ_NEW0(RzILOp); \
		if (!ret) { \
			return NULL; \
		} \
		ret->op.s = RZ_NEW0(t); \
		if (!ret->op.s) { \
			free(ret); \
			return NULL; \
		} \
		ret->code = id; \
		ret->op.s->v0 = v0; \
		ret->op.s->v1 = v1; \
	} while (0)

#define rz_il_op_new_3(id, t, s, v0, v1, v2) \
	do { \
		ret = RZ_NEW0(RzILOp); \
		if (!ret) { \
			return NULL; \
		} \
		ret->op.s = RZ_NEW0(t); \
		if (!ret->op.s) { \
			free(ret); \
			return NULL; \
		} \
		ret->code = id; \
		ret->op.s->v0 = v0; \
		ret->op.s->v1 = v1; \
		ret->op.s->v2 = v2; \
	} while (0)

/**
 *  \brief op structure for `ite` (bool -> 'a pure -> 'a pure -> 'a pure)
 *
 *  ite condition x y is x if condition evaluates to b1 else y.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_ite(RZ_NONNULL RzILOp *condition, RZ_NULLABLE RzILOp *x, RZ_NULLABLE RzILOp *y) {
	rz_return_val_if_fail(condition && (x || y), NULL);
	RzILOp *ret;
	rz_il_op_new_3(RZIL_OP_ITE, RzILOpIte, ite, condition, x, y);
	return ret;
}

/**
 * \brief op structure for unknown
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_unk() {
	RzILOp *ret;
	rz_il_op_new_0(RZIL_OP_UNK);
	return ret;
}

/**
 *  \brief op structure for `var` ('a var -> 'a pure)
 *
 *  var v is the value of the variable v.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_var(RZ_NONNULL const char *v) {
	rz_return_val_if_fail(v, NULL);
	RzILOp *ret;
	rz_il_op_new_1(RZIL_OP_VAR, RzILOpVar, var, v);
	return ret;
}

/**
 * \brief op structure for bool false
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_b0() {
	RzILOp *ret;
	rz_il_op_new_0(RZIL_OP_B0);
	return ret;
}

/**
 * \brief op structure for bool true
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_b1() {
	RzILOp *ret;
	rz_il_op_new_0(RZIL_OP_B1);
	return ret;
}

/**
 *  \brief op structure for `and` (bool -> bool -> bool)
 *
 *  BAP equivalent:
 *    val and_ : bool -> bool -> bool
 *  and(x, y) is a conjunction of x and y.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_bool_and(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_AND, RzILOpBoolAnd, booland, x, y);
	return ret;
}

/**
 *  \brief op structure for `or` (bool -> bool -> bool)
 *
 *  BAP equivalent:
 *    val or_ : bool -> bool -> bool
 *  or(x, y)  is a conjunction of x or y.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_bool_or(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_OR, RzILOpBoolOr, boolor, x, y);
	return ret;
}

/**
 *  \brief op structure for `xor` (bool -> bool -> bool)
 *
 *  BAP equivalent:
 *    val xor_ : bool -> bool -> bool
 *  xor(x, y) is a conjunction of x xor y.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_bool_xor(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_XOR, RzILOpBoolXor, boolxor, x, y);
	return ret;
}

/**
 *  \brief op structure for `inv` (!bool -> bool)
 *
 *	BAP equivalent:
 *	  val inv : bool -> bool
 *  inv(x) inverts x (also known as not operation).
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_bool_inv(RZ_NONNULL RzILOp *x) {
	rz_return_val_if_fail(x, NULL);
	RzILOp *ret;
	rz_il_op_new_1(RZIL_OP_INV, RzILOpBoolInv, boolinv, x);
	return ret;
}

/**
 *  \brief op structure for bitvector
 *
 *  value is a bitvector constant.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_bitv(RZ_NONNULL RzBitVector *value) {
	rz_return_val_if_fail(value, NULL);
	RzILOp *ret;
	rz_il_op_new_1(RZIL_OP_BITV, RzILOpBv, bitv, value);
	return ret;
}

/**
 *  \brief op structure for bitvector converted from ut64
 *
 *  value is a bitvector constant.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_bitv_from_ut64(ut32 length, ut64 number) {
	RzBitVector *value = rz_bv_new_from_ut64(length, number);
	if (!value) {
		return NULL;
	}
	RzILOp *ret = RZ_NEW0(RzILOp);
	if (!ret) {
		rz_bv_free(value);
		return NULL;
	}
	ret->op.bitv = RZ_NEW0(RzILOpBv);
	if (!ret->op.bitv) {
		rz_bv_free(value);
		free(ret);
		return NULL;
	}
	ret->code = RZIL_OP_BITV;
	ret->op.bitv->value = value;
	return ret;
}

/**
 *  \brief op structure for bitvector converted from st64
 *
 *  value is a bitvector constant.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_bitv_from_st64(ut32 length, st64 number) {
	RzBitVector *value = rz_bv_new_from_st64(length, number);
	if (!value) {
		return NULL;
	}
	RzILOp *ret = RZ_NEW0(RzILOp);
	if (!ret) {
		rz_bv_free(value);
		return NULL;
	}
	ret->op.bitv = RZ_NEW0(RzILOpBv);
	if (!ret->op.bitv) {
		rz_bv_free(value);
		free(ret);
		return NULL;
	}
	ret->code = RZIL_OP_BITV;
	ret->op.bitv->value = value;
	return ret;
}

/**
 *  \brief op structure for `msb` ('s bitv -> bool)
 *  [MSB] msb x is the most significant bit of x.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_msb(RZ_NONNULL RzILOp *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILOp *ret;
	rz_il_op_new_1(RZIL_OP_MSB, RzILOpLsb, lsb, bv);
	return ret;
}

/**
 *  \brief op structure for `lsb` ('s bitv -> bool)
 *  [LSB] lsb x is the least significant bit of x.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_lsb(RZ_NONNULL RzILOp *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILOp *ret;
	rz_il_op_new_1(RZIL_OP_LSB, RzILOpMsb, lsb, bv);
	return ret;
}

/**
 *  \brief op structure for sle/ule ('a bitv -> 'a bitv -> bool)
 *
 *  [ULE] ule x y binary predicate for unsigned less than or equal
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_ule(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_ULE, RzILOpUle, ule, x, y);
	return ret;
}

/**
 *  \brief op structure for sle/ule ('a bitv -> 'a bitv -> bool)
 *
 *  [SLE] sle x y binary predicate for singed less than or equal
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_sle(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_SLE, RzILOpSle, sle, x, y);
	return ret;
}

/**
 *  \brief op structure for casting bitv
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_cast(ut32 length, int shift, RZ_NONNULL RzILOp *val) {
	rz_return_val_if_fail(length > 0 && val, NULL);
	RzILOp *ret;
	rz_il_op_new_3(RZIL_OP_CAST, RzILOpCast, cast, length, shift, val);
	return ret;
}

/**
 *  \brief op structure for `neg` ('s bitv -> 's bitv)
 *
 *  neg x is two-complement unary minus
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_neg(RZ_NONNULL RzILOp *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILOp *ret;
	rz_il_op_new_1(RZIL_OP_NEG, RzILOpNeg, neg, bv);
	return ret;
}

/**
 *  \brief op structure for `not` ('s bitv -> 's bitv)
 *
 *  neg x is one-complement unary minus
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_log_not(RZ_NONNULL RzILOp *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILOp *ret;
	rz_il_op_new_1(RZIL_OP_LOGNOT, RzILOpLogNot, lognot, bv);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [ADD] add x y addition modulo 2^'s
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_add(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_ADD, RzILOpAdd, add, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [SUB] sub x y subtraction modulo 2^'s
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_sub(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_SUB, RzILOpSub, sub, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [MUL] mul x y multiplication modulo 2^'s
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_mul(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_MUL, RzILOpMul, mul, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [DIV] div x y unsigned division modulo 2^'s truncating towards 0. The division by zero is defined to be a vector of all ones of size 's.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_div(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_DIV, RzILOpDiv, div, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [SDIV] sdiv x y is signed division of x by y modulo 2^'s.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_sdiv(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_SDIV, RzILOpSdiv, sdiv, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [SMOD] smodulo x y is the signed remainder of div x y modulo 2^'s.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_smod(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_MOD, RzILOpSmod, smod, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [MOD] modulo x y is the remainder of div x y modulo 2^'s.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_mod(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_SMOD, RzILOpMod, mod, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [LOGAND] logand x y is a bitwise logical and of x and y.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_log_and(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_LOGAND, RzILOpLogand, logand, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [LOGOR] logor x y is a bitwise logical or of x and y.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_log_or(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_LOGOR, RzILOpLogor, logor, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [LOGXOR] logxor x y is a bitwise logical xor of x and y.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_log_xor(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_LOGXOR, RzILOpLogxor, logxor, x, y);
	return ret;
}

/**
 *  \brief op structure for left shift (bool -> 's bitv -> 'b bitv -> 's bitv)
 *
 *  [LSHIFT] shiftl s x m shifts x left by m bits filling with s.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_shiftl(RZ_NONNULL RzILOp *fill_bit, RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(fill_bit && x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_3(RZIL_OP_SHIFTL, RzILOpShiftLeft, shiftl, fill_bit, x, y);
	return ret;
}

/**
 *  \brief op structure for right shift (bool -> 's bitv -> 'b bitv -> 's bitv)
 *
 *  [RSHIFT] shiftr s x m shifts x right by m bits filling with s.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_shiftr(RZ_NONNULL RzILOp *fill_bit, RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(fill_bit && x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_3(RZIL_OP_SHIFTR, RzILOpShiftRight, shiftr, fill_bit, x, y);
	return ret;
}

/**
 *  \brief op structure for appending 2 bitv: MSB:LSB y:x
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_append(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_APPEND, RzILOpAppend, append, x, y);
	return ret;
}

RZ_API RZ_OWN RzILOp *rz_il_op_new_nop(RZ_NONNULL RzILOp *eff) {
	rz_return_val_if_fail(eff, NULL);
	RzILOp *ret;
	rz_il_op_new_0(RZIL_OP_NOP);
	return ret;
}

/**
 *  \brief op structure for `set` ('a var -> 'a pure -> data eff)
 *
 *  set v x changes the value stored in v to the value of x.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_set(RZ_NONNULL const char *v, RZ_NONNULL RzILOp *x) {
	rz_return_val_if_fail(v && x, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_SET, RzILOpSet, set, v, x);
	return ret;
}

/**
 *  \brief op structure for `let` ('a var -> 'a pure -> 'b pure -> 'b pure -> data eff)
 *
 *  let v exp body bind the value of exp to v body.
 *  essentially allows you to create a local variable
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_let(RZ_NONNULL const char *v, RZ_NONNULL RzILOp *x, bool mut) {
	rz_return_val_if_fail(v && x, NULL);
	RzILOp *ret;
	rz_il_op_new_3(RZIL_OP_LET, RzILOpLet, let, v, x, mut);
	return ret;
}

/**
 *  \brief op structure for `jmp` (_ bitv -> ctrl eff)
 *
 *  jmp dst passes the control to a program located at dst.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_jmp(RZ_NONNULL RzILOp *dst) {
	rz_return_val_if_fail(dst, NULL);
	RzILOp *ret;
	rz_il_op_new_1(RZIL_OP_JMP, RzILOpJmp, jmp, dst);
	return ret;
}

/**
 *  \brief op structure for `goto` (label -> ctrl eff)
 *
 *  goto label passes the control to a program labeled with lbl.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_goto(RZ_NONNULL const char *lbl) {
	rz_return_val_if_fail(lbl, NULL);
	RzILOp *ret;
	rz_il_op_new_1(RZIL_OP_GOTO, RzILOpGoto, goto_, lbl);
	return ret;
}

/**
 *  \brief op structure for `Seq` ('a eff -> 'a eff -> 'a eff)
 *
 *  seq x y performs effect x, after that perform effect y. Pack two effects into one.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_seq(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_SEQ, RzILOpSeq, seq, x, y);
	return ret;
}

/**
 *  \brief op structure for `blk` (label -> data eff -> ctrl eff -> unit eff)
 *
 *  blk lbl data ctrl a labeled sequence of effects.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_blk(RZ_NONNULL RzILOp *data_eff, RZ_NONNULL RzILOp *ctrl_eff) {
	rz_return_val_if_fail(data_eff && ctrl_eff, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_BLK, RzILOpBlk, blk, data_eff, ctrl_eff);
	return ret;
}

/**
 *  \brief op structure for `repeat` (bool -> data eff -> data eff)
 *
 *  repeat c data repeats data effects until the condition c holds.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_repeat(RZ_NONNULL RzILOp *condition, RZ_NONNULL RzILOp *data_eff) {
	rz_return_val_if_fail(condition && data_eff, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_REPEAT, RzILOpRepeat, repeat, condition, data_eff);
	return ret;
}

/**
 *  \brief op structure for `branch` (bool -> 'a eff -> 'a eff -> 'a eff)
 *
 *  branch c lhs rhs if c holds then performs lhs else rhs.
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_branch(RZ_NONNULL RzILOp *condition, RZ_NULLABLE RzILOp *true_eff, RZ_NULLABLE RzILOp *false_eff) {
	rz_return_val_if_fail(condition && (true_eff || false_eff), NULL);
	RzILOp *ret;
	rz_il_op_new_3(RZIL_OP_BRANCH, RzILOpBranch, branch, condition, true_eff, false_eff);
	return ret;
}

/**
 * \brief op structure for bitvector
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_load(RzILMemIndex mem, RZ_NONNULL RzILOp *key) {
	rz_return_val_if_fail(key, NULL);
	RzILOp *ret;
	rz_il_op_new_2(RZIL_OP_LOAD, RzILOpLoad, load, mem, key);
	return ret;
}

/**
 * \brief op structure for bitvector
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_store(RzILMemIndex mem, RZ_NONNULL RzILOp *key, RZ_NONNULL RzILOp *value) {
	rz_return_val_if_fail(key && value, NULL);
	RzILOp *ret;
	rz_il_op_new_3(RZIL_OP_STORE, RzILOpStore, store, mem, key, value);
	return ret;
}

/**
 * \brief op structure for illegal/invalid
 */
RZ_API RZ_OWN RzILOp *rz_il_op_new_invalid() {
	RzILOp *ret;
	rz_il_op_new_0(RZIL_OP_INVALID);
	return ret;
}
#undef rz_il_op_new_0
#undef rz_il_op_new_1
#undef rz_il_op_new_2
#undef rz_il_op_new_3

#define rz_il_op_free_0(s) free(op->op.s)

#define rz_il_op_free_1(s, v0) \
	rz_il_op_free(op->op.s->v0); \
	free(op->op.s)

#define rz_il_op_free_2(s, v0, v1) \
	rz_il_op_free(op->op.s->v0); \
	rz_il_op_free(op->op.s->v1); \
	free(op->op.s)

#define rz_il_op_free_3(s, v0, v1, v2) \
	rz_il_op_free(op->op.s->v0); \
	rz_il_op_free(op->op.s->v1); \
	rz_il_op_free(op->op.s->v2); \
	free(op->op.s)

/**
 * Free core theory opcode instance
 * \param op RzILOp, pointer to opcode instance
 */
RZ_API void rz_il_op_free(RZ_NULLABLE RzILOp *op) {
	if (!op) {
		return;
	}
	switch (op->code) {
	case RZIL_OP_VAR:
		rz_il_op_free_0(var);
		break;
	case RZIL_OP_UNK:
		// nothing to free
		break;
	case RZIL_OP_ITE:
		rz_il_op_free_3(ite, condition, x, y);
		break;
	case RZIL_OP_B0:
	case RZIL_OP_B1:
		// nothing to free
		break;
	case RZIL_OP_INV:
		rz_il_op_free_1(boolinv, x);
		break;
	case RZIL_OP_AND:
	case RZIL_OP_OR:
	case RZIL_OP_XOR:
		// BoolXor, BoolOr and BoolAnd shares the same struct
		rz_il_op_free_2(boolxor, x, y);
		break;
	case RZIL_OP_BITV:
		rz_bv_free(op->op.bitv->value);
		rz_il_op_free_0(bitv);
		break;
	case RZIL_OP_MSB:
		rz_il_op_free_1(msb, bv);
		break;
	case RZIL_OP_LSB:
		rz_il_op_free_1(lsb, bv);
		break;
	case RZIL_OP_NEG:
		rz_il_op_free_1(neg, bv);
		break;
	case RZIL_OP_LOGNOT:
		rz_il_op_free_1(lognot, bv);
		break;
	case RZIL_OP_ADD:
		rz_il_op_free_2(add, x, y);
		break;
	case RZIL_OP_SUB:
		rz_il_op_free_2(sub, x, y);
		break;
	case RZIL_OP_MUL:
		rz_il_op_free_2(mul, x, y);
		break;
	case RZIL_OP_DIV:
		rz_il_op_free_2(div, x, y);
		break;
	case RZIL_OP_SDIV:
		rz_il_op_free_2(sdiv, x, y);
		break;
	case RZIL_OP_MOD:
		rz_il_op_free_2(mod, x, y);
		break;
	case RZIL_OP_SMOD:
		rz_il_op_free_2(smod, x, y);
		break;
	case RZIL_OP_LOGAND:
		rz_il_op_free_2(logand, x, y);
		break;
	case RZIL_OP_LOGOR:
		rz_il_op_free_2(logor, x, y);
		break;
	case RZIL_OP_LOGXOR:
		rz_il_op_free_2(logxor, x, y);
		break;
	case RZIL_OP_SHIFTR:
		rz_il_op_free_3(shiftr, fill_bit, x, y);
		break;
	case RZIL_OP_SHIFTL:
		rz_il_op_free_3(shiftl, fill_bit, x, y);
		break;
	case RZIL_OP_SLE:
		rz_il_op_free_2(sle, x, y);
		break;
	case RZIL_OP_ULE:
		rz_il_op_free_2(ule, x, y);
		break;
	case RZIL_OP_CAST:
		rz_il_op_free_1(cast, val);
		break;
	case RZIL_OP_CONCAT:
		rz_warn_if_reached();
		break;
	case RZIL_OP_APPEND:
		rz_il_op_free_2(append, x, y);
		break;
	case RZIL_OP_LOAD:
		rz_il_op_free_1(load, key);
		break;
	case RZIL_OP_STORE:
		rz_il_op_free_2(store, key, value);
		break;
	case RZIL_OP_NOP:
		// nothing to free
		break;
	case RZIL_OP_SET:
		rz_il_op_free_1(set, x);
		break;
	case RZIL_OP_LET:
		rz_il_op_free_1(let, x);
		break;
	case RZIL_OP_JMP:
		rz_il_op_free_1(jmp, dst);
		break;
	case RZIL_OP_GOTO:
		rz_il_op_free_0(goto_);
		break;
	case RZIL_OP_SEQ:
		rz_il_op_free_2(seq, x, y);
		break;
	case RZIL_OP_BLK:
		rz_il_op_free_2(blk, data_eff, ctrl_eff);
		break;
	case RZIL_OP_REPEAT:
		rz_il_op_free_2(repeat, condition, data_eff);
		break;
	case RZIL_OP_BRANCH:
		rz_il_op_free_3(branch, condition, true_eff, false_eff);
		break;
	case RZIL_OP_INVALID:
		break;
	default:
		rz_warn_if_reached();
		RZ_LOG_ERROR("RzIl: unknown opcode %u\n", op->code);
		break;
	}
	free(op);
}
#undef rz_il_op_free_0
#undef rz_il_op_free_1
#undef rz_il_op_free_2
#undef rz_il_op_free_3
