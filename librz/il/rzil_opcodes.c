// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>

#define rz_il_op_new_0(sort, id) \
	do { \
		ret = RZ_NEW0(RzILOp##sort); \
		if (!ret) { \
			return NULL; \
		} \
		ret->code = id; \
	} while (0)

#define rz_il_op_new_1(sort, id, t, s, v0) \
	do { \
		ret = RZ_NEW0(RzILOp##sort); \
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

#define rz_il_op_new_2(sort, id, t, s, v0, v1) \
	do { \
		ret = RZ_NEW0(RzILOp##sort); \
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

#define rz_il_op_new_3(sort, id, t, s, v0, v1, v2) \
	do { \
		ret = RZ_NEW0(RzILOp##sort); \
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
RZ_API RZ_OWN RzILOpPure *rz_il_op_new_ite(RZ_NONNULL RzILOpPure *condition, RZ_NULLABLE RzILOpPure *x, RZ_NULLABLE RzILOpPure *y) {
	rz_return_val_if_fail(condition && (x || y), NULL);
	RzILOpPure *ret;
	rz_il_op_new_3(Pure, RZIL_OP_ITE, RzILOpArgsIte, ite, condition, x, y);
	return ret;
}

/**
 * \brief op structure for unknown
 */
RZ_API RZ_OWN RzILOpPure *rz_il_op_new_unk() {
	RzILOpPure *ret;
	rz_il_op_new_0(Pure, RZIL_OP_UNK);
	return ret;
}

/**
 *  \brief op structure for `var` ('a var -> 'a pure)
 *
 *  var v is the value of the variable v.
 */
RZ_API RZ_OWN RzILOpPure *rz_il_op_new_var(RZ_NONNULL const char *v) {
	rz_return_val_if_fail(v, NULL);
	RzILOpPure *ret;
	rz_il_op_new_1(Pure, RZIL_OP_VAR, RzILOpArgsVar, var, v);
	return ret;
}

/**
 * \brief op structure for bool false
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_b0() {
	RzILOpPure *ret;
	rz_il_op_new_0(Pure, RZIL_OP_B0);
	return ret;
}

/**
 * \brief op structure for bool true
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_b1() {
	RzILOpPure *ret;
	rz_il_op_new_0(Pure, RZIL_OP_B1);
	return ret;
}

/**
 *  \brief op structure for `and` (bool -> bool -> bool)
 *
 *  BAP equivalent:
 *    val and_ : bool -> bool -> bool
 *  and(x, y) is a conjunction of x and y.
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bool_and(RZ_NONNULL RzILOpBool *x, RZ_NONNULL RzILOpBool *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *ret;
	rz_il_op_new_2(Bool, RZIL_OP_AND, RzILOpArgsBoolAnd, booland, x, y);
	return ret;
}

/**
 *  \brief op structure for `or` (bool -> bool -> bool)
 *
 *  BAP equivalent:
 *    val or_ : bool -> bool -> bool
 *  or(x, y)  is a conjunction of x or y.
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bool_or(RZ_NONNULL RzILOpBool *x, RZ_NONNULL RzILOpBool *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *ret;
	rz_il_op_new_2(Bool, RZIL_OP_OR, RzILOpArgsBoolOr, boolor, x, y);
	return ret;
}

/**
 *  \brief op structure for `xor` (bool -> bool -> bool)
 *
 *  BAP equivalent:
 *    val xor_ : bool -> bool -> bool
 *  xor(x, y) is a conjunction of x xor y.
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bool_xor(RZ_NONNULL RzILOpBool *x, RZ_NONNULL RzILOpBool *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *ret;
	rz_il_op_new_2(Bool, RZIL_OP_XOR, RzILOpArgsBoolXor, boolxor, x, y);
	return ret;
}

/**
 *  \brief op structure for `inv` (!bool -> bool)
 *
 *	BAP equivalent:
 *	  val inv : bool -> bool
 *  inv(x) inverts x (also known as not operation).
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bool_inv(RZ_NONNULL RzILOpBool *x) {
	rz_return_val_if_fail(x, NULL);
	RzILOpBool *ret;
	rz_il_op_new_1(Bool, RZIL_OP_INV, RzILOpArgsBoolInv, boolinv, x);
	return ret;
}

/**
 *  \brief op structure for bitvector
 *
 *  value is a bitvector constant.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_bitv(RZ_NONNULL RzBitVector *value) {
	rz_return_val_if_fail(value, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_1(BitVector, RZIL_OP_BITV, RzILOpArgsBv, bitv, value);
	return ret;
}

/**
 *  \brief op structure for bitvector converted from ut64
 *
 *  value is a bitvector constant.
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bitv_from_ut64(ut32 length, ut64 number) {
	RzBitVector *value = rz_bv_new_from_ut64(length, number);
	if (!value) {
		return NULL;
	}
	RzILOpBool *ret = RZ_NEW0(RzILOpBool);
	if (!ret) {
		rz_bv_free(value);
		return NULL;
	}
	ret->op.bitv = RZ_NEW0(RzILOpArgsBv);
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
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bitv_from_st64(ut32 length, st64 number) {
	RzBitVector *value = rz_bv_new_from_st64(length, number);
	if (!value) {
		return NULL;
	}
	RzILOpBool *ret = RZ_NEW0(RzILOpBool);
	if (!ret) {
		rz_bv_free(value);
		return NULL;
	}
	ret->op.bitv = RZ_NEW0(RzILOpArgsBv);
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
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_msb(RZ_NONNULL RzILOpBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILOpBool *ret;
	rz_il_op_new_1(Bool, RZIL_OP_MSB, RzILOpArgsLsb, lsb, bv);
	return ret;
}

/**
 *  \brief op structure for `lsb` ('s bitv -> bool)
 *  [LSB] lsb x is the least significant bit of x.
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_lsb(RZ_NONNULL RzILOpBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILOpBool *ret;
	rz_il_op_new_1(Bool, RZIL_OP_LSB, RzILOpArgsMsb, lsb, bv);
	return ret;
}

/**
 *  [EQ] eq x y binary predicate for bitwise equality
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_eq(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *ret;
	rz_il_op_new_2(Bool, RZIL_OP_EQ, RzILOpArgsEq, eq, x, y);
	return ret;
}

/**
 *  \brief op structure for sle/ule ('a bitv -> 'a bitv -> bool)
 *
 *  [ULE] ule x y binary predicate for unsigned less than or equal
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_ule(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *ret;
	rz_il_op_new_2(Bool, RZIL_OP_ULE, RzILOpArgsUle, ule, x, y);
	return ret;
}

/**
 *  \brief op structure for sle/ule ('a bitv -> 'a bitv -> bool)
 *
 *  [SLE] sle x y binary predicate for singed less than or equal
 */
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_sle(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBool *ret;
	rz_il_op_new_2(Bool, RZIL_OP_SLE, RzILOpArgsSle, sle, x, y);
	return ret;
}

/**
 *  \brief op structure for casting bitv
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_cast(ut32 length, int shift, RZ_NONNULL RzILOpBitVector *val) {
	rz_return_val_if_fail(length > 0 && val, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_3(BitVector, RZIL_OP_CAST, RzILOpArgsCast, cast, length, shift, val);
	return ret;
}

/**
 *  \brief op structure for `neg` ('s bitv -> 's bitv)
 *
 *  neg x is two-complement unary minus
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_neg(RZ_NONNULL RzILOpBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_1(BitVector, RZIL_OP_NEG, RzILOpArgsNeg, neg, bv);
	return ret;
}

/**
 *  \brief op structure for `not` ('s bitv -> 's bitv)
 *
 *  neg x is one-complement unary minus
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_log_not(RZ_NONNULL RzILOpBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_1(BitVector, RZIL_OP_LOGNOT, RzILOpArgsLogNot, lognot, bv);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [ADD] add x y addition modulo 2^'s
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_add(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_ADD, RzILOpArgsAdd, add, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [SUB] sub x y subtraction modulo 2^'s
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_sub(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_SUB, RzILOpArgsSub, sub, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [MUL] mul x y multiplication modulo 2^'s
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_mul(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_MUL, RzILOpArgsMul, mul, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [DIV] div x y unsigned division modulo 2^'s truncating towards 0. The division by zero is defined to be a vector of all ones of size 's.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_div(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_DIV, RzILOpArgsDiv, div, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [SDIV] sdiv x y is signed division of x by y modulo 2^'s.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_sdiv(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_SDIV, RzILOpArgsSdiv, sdiv, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [SMOD] smodulo x y is the signed remainder of div x y modulo 2^'s.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_smod(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_MOD, RzILOpArgsSmod, smod, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [MOD] modulo x y is the remainder of div x y modulo 2^'s.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_mod(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_SMOD, RzILOpArgsMod, mod, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [LOGAND] logand x y is a bitwise logical and of x and y.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_log_and(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_LOGAND, RzILOpArgsLogand, logand, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [LOGOR] logor x y is a bitwise logical or of x and y.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_log_or(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_LOGOR, RzILOpArgsLogor, logor, x, y);
	return ret;
}

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [LOGXOR] logxor x y is a bitwise logical xor of x and y.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_log_xor(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_LOGXOR, RzILOpArgsLogxor, logxor, x, y);
	return ret;
}

/**
 *  \brief op structure for left shift (bool -> 's bitv -> 'b bitv -> 's bitv)
 *
 *  [LSHIFT] shiftl s x m shifts x left by m bits filling with s.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_shiftl(RZ_NONNULL RzILOpBitVector *fill_bit, RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(fill_bit && x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_3(BitVector, RZIL_OP_SHIFTL, RzILOpArgsShiftLeft, shiftl, fill_bit, x, y);
	return ret;
}

/**
 *  \brief op structure for right shift (bool -> 's bitv -> 'b bitv -> 's bitv)
 *
 *  [RSHIFT] shiftr s x m shifts x right by m bits filling with s.
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_shiftr(RZ_NONNULL RzILOpBitVector *fill_bit, RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(fill_bit && x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_3(BitVector, RZIL_OP_SHIFTR, RzILOpArgsShiftRight, shiftr, fill_bit, x, y);
	return ret;
}

/**
 *  \brief op structure for appending 2 bitv: MSB:LSB y:x
 */
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_append(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpBitVector *ret;
	rz_il_op_new_2(BitVector, RZIL_OP_APPEND, RzILOpArgsAppend, append, x, y);
	return ret;
}

RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_nop() {
	RzILOpEffect *ret;
	rz_il_op_new_0(Effect, RZIL_OP_NOP);
	return ret;
}

/**
 *  \brief op structure for `set` ('a var -> 'a pure -> data eff)
 *
 *  set v x changes the value stored in v to the value of x.
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_set(RZ_NONNULL const char *v, RZ_NONNULL RzILOpPure *x) {
	rz_return_val_if_fail(v && x, NULL);
	RzILOpEffect *ret;
	rz_il_op_new_2(Effect, RZIL_OP_SET, RzILOpArgsSet, set, v, x);
	return ret;
}

/**
 *  \brief op structure for `let` ('a var -> 'a pure -> 'b pure -> 'b pure -> data eff)
 *
 *  let v exp body bind the value of exp to v body.
 *  essentially allows you to create a local variable
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_let(RZ_NONNULL const char *v, RZ_NONNULL RzILOpPure *x, bool mut) {
	rz_return_val_if_fail(v && x, NULL);
	RzILOpEffect *ret;
	rz_il_op_new_3(Effect, RZIL_OP_LET, RzILOpArgsLet, let, v, x, mut);
	return ret;
}

/**
 *  \brief op structure for `jmp` (_ bitv -> ctrl eff)
 *
 *  jmp dst passes the control to a program located at dst.
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_jmp(RZ_NONNULL RzILOpBitVector *dst) {
	rz_return_val_if_fail(dst, NULL);
	RzILOpEffect *ret;
	rz_il_op_new_1(Effect, RZIL_OP_JMP, RzILOpArgsJmp, jmp, dst);
	return ret;
}

/**
 *  \brief op structure for `goto` (label -> ctrl eff)
 *
 *  goto label passes the control to a program labeled with lbl.
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_goto(RZ_NONNULL const char *lbl) {
	rz_return_val_if_fail(lbl, NULL);
	RzILOpEffect *ret;
	rz_il_op_new_1(Effect, RZIL_OP_GOTO, RzILOpArgsGoto, goto_, lbl);
	return ret;
}

/**
 *  \brief op structure for `Seq` ('a eff -> 'a eff -> 'a eff)
 *
 *  seq x y performs effect x, after that perform effect y. Pack two effects into one.
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_seq(RZ_NONNULL RzILOpEffect *x, RZ_NONNULL RzILOpEffect *y) {
	rz_return_val_if_fail(x && y, NULL);
	RzILOpEffect *ret;
	rz_il_op_new_2(Effect, RZIL_OP_SEQ, RzILOpArgsSeq, seq, x, y);
	return ret;
}

/**
 *  \brief op structure for `blk` (label -> data eff -> ctrl eff -> unit eff)
 *
 *  blk lbl data ctrl a labeled sequence of effects.
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_blk(RZ_NONNULL RzILOpEffect *data_eff, RZ_NONNULL RzILOpEffect *ctrl_eff) {
	rz_return_val_if_fail(data_eff && ctrl_eff, NULL);
	RzILOpEffect *ret;
	rz_il_op_new_2(Effect, RZIL_OP_BLK, RzILOpArgsBlk, blk, data_eff, ctrl_eff);
	return ret;
}

/**
 *  \brief op structure for `repeat` (bool -> data eff -> data eff)
 *
 *  repeat c data repeats data effects until the condition c holds.
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_repeat(RZ_NONNULL RzILOpBool *condition, RZ_NONNULL RzILOpEffect *data_eff) {
	rz_return_val_if_fail(condition && data_eff, NULL);
	RzILOpEffect *ret;
	rz_il_op_new_2(Effect, RZIL_OP_REPEAT, RzILOpArgsRepeat, repeat, condition, data_eff);
	return ret;
}

/**
 *  \brief op structure for `branch` (bool -> 'a eff -> 'a eff -> 'a eff)
 *
 *  branch c lhs rhs if c holds then performs lhs else rhs.
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_branch(RZ_NONNULL RzILOpBool *condition, RZ_NULLABLE RzILOpEffect *true_eff, RZ_NULLABLE RzILOpEffect *false_eff) {
	rz_return_val_if_fail(condition && (true_eff || false_eff), NULL);
	RzILOpEffect *ret;
	rz_il_op_new_3(Effect, RZIL_OP_BRANCH, RzILOpArgsBranch, branch, condition, true_eff, false_eff);
	return ret;
}

/**
 * \brief Helper to create RzILOpArgsLoad
 */
RZ_API RZ_OWN RzILOpPure *rz_il_op_new_load(RzILMemIndex mem, RZ_NONNULL RzILOpPure *key) {
	rz_return_val_if_fail(key, NULL);
	RzILOpPure *ret;
	rz_il_op_new_2(Pure, RZIL_OP_LOAD, RzILOpArgsLoad, load, mem, key);
	return ret;
}

/**
 * \brief Helper to create RzILOpArgsStoreW
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_store(RzILMemIndex mem, RZ_NONNULL RzILOpBitVector *key, RZ_NONNULL RzILOpBitVector *value) {
	rz_return_val_if_fail(key && value, NULL);
	RzILOpEffect *ret;
	rz_il_op_new_3(Effect, RZIL_OP_STORE, RzILOpArgsStore, store, mem, key, value);
	return ret;
}

/**
 * \brief Helper to create RzILOpArgsLoadW
 */
RZ_API RZ_OWN RzILOpPure *rz_il_op_new_loadw(RzILMemIndex mem, RZ_NONNULL RzILOpBitVector *key, ut32 n_bits) {
	rz_return_val_if_fail(key && n_bits, NULL);
	RzILOpPure *ret;
	rz_il_op_new_3(Pure, RZIL_OP_LOADW, RzILOpArgsLoadW, loadw, mem, key, n_bits);
	return ret;
}

/**
 * \brief Helper to create RzILOpArgsStoreW
 */
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_storew(RzILMemIndex mem, RZ_NONNULL RzILOpBitVector *key, RZ_NONNULL RzILOpBitVector *value) {
	rz_return_val_if_fail(key && value, NULL);
	RzILOpEffect *ret;
	rz_il_op_new_3(Effect, RZIL_OP_STOREW, RzILOpArgsStoreW, storew, mem, key, value);
	return ret;
}

#undef rz_il_op_new_0
#undef rz_il_op_new_1
#undef rz_il_op_new_2
#undef rz_il_op_new_3

#define rz_il_op_free_0(s) free(op->op.s)

#define rz_il_op_free_1(sort, s, v0) \
	rz_il_op_##sort##_free(op->op.s->v0); \
	free(op->op.s)

#define rz_il_op_free_2(sort, s, v0, v1) \
	rz_il_op_##sort##_free(op->op.s->v0); \
	rz_il_op_##sort##_free(op->op.s->v1); \
	free(op->op.s)

#define rz_il_op_free_3(sort, s, v0, v1, v2) \
	rz_il_op_##sort##_free(op->op.s->v0); \
	rz_il_op_##sort##_free(op->op.s->v1); \
	rz_il_op_##sort##_free(op->op.s->v2); \
	free(op->op.s)

RZ_API void rz_il_op_pure_free(RZ_NULLABLE RzILOpPure *op) {
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
		rz_il_op_free_3(pure, ite, condition, x, y);
		break;
	case RZIL_OP_B0:
	case RZIL_OP_B1:
		// nothing to free
		break;
	case RZIL_OP_INV:
		rz_il_op_free_1(pure, boolinv, x);
		break;
	case RZIL_OP_AND:
	case RZIL_OP_OR:
	case RZIL_OP_XOR:
		// BoolXor, BoolOr and BoolAnd shares the same struct
		rz_il_op_free_2(pure, boolxor, x, y);
		break;
	case RZIL_OP_BITV:
		rz_bv_free(op->op.bitv->value);
		rz_il_op_free_0(bitv);
		break;
	case RZIL_OP_MSB:
		rz_il_op_free_1(pure, msb, bv);
		break;
	case RZIL_OP_LSB:
		rz_il_op_free_1(pure, lsb, bv);
		break;
	case RZIL_OP_NEG:
		rz_il_op_free_1(pure, neg, bv);
		break;
	case RZIL_OP_LOGNOT:
		rz_il_op_free_1(pure, lognot, bv);
		break;
	case RZIL_OP_ADD:
		rz_il_op_free_2(pure, add, x, y);
		break;
	case RZIL_OP_SUB:
		rz_il_op_free_2(pure, sub, x, y);
		break;
	case RZIL_OP_MUL:
		rz_il_op_free_2(pure, mul, x, y);
		break;
	case RZIL_OP_DIV:
		rz_il_op_free_2(pure, div, x, y);
		break;
	case RZIL_OP_SDIV:
		rz_il_op_free_2(pure, sdiv, x, y);
		break;
	case RZIL_OP_MOD:
		rz_il_op_free_2(pure, mod, x, y);
		break;
	case RZIL_OP_SMOD:
		rz_il_op_free_2(pure, smod, x, y);
		break;
	case RZIL_OP_LOGAND:
		rz_il_op_free_2(pure, logand, x, y);
		break;
	case RZIL_OP_LOGOR:
		rz_il_op_free_2(pure, logor, x, y);
		break;
	case RZIL_OP_LOGXOR:
		rz_il_op_free_2(pure, logxor, x, y);
		break;
	case RZIL_OP_SHIFTR:
		rz_il_op_free_3(pure, shiftr, fill_bit, x, y);
		break;
	case RZIL_OP_SHIFTL:
		rz_il_op_free_3(pure, shiftl, fill_bit, x, y);
		break;
	case RZIL_OP_EQ:
		rz_il_op_free_2(pure, eq, x, y);
		break;
	case RZIL_OP_SLE:
		rz_il_op_free_2(pure, sle, x, y);
		break;
	case RZIL_OP_ULE:
		rz_il_op_free_2(pure, ule, x, y);
		break;
	case RZIL_OP_CAST:
		rz_il_op_free_1(pure, cast, val);
		break;
	case RZIL_OP_CONCAT:
		rz_warn_if_reached();
		break;
	case RZIL_OP_APPEND:
		rz_il_op_free_2(pure, append, x, y);
		break;
	case RZIL_OP_LOAD:
		rz_il_op_free_1(pure, load, key);
		break;
	case RZIL_OP_LOADW:
		rz_il_op_free_1(pure, loadw, key);
		break;
	default:
		rz_warn_if_reached();
		RZ_LOG_ERROR("RzIl: unknown opcode %u\n", op->code);
		break;
	}
	free(op);
}

RZ_API void rz_il_op_effect_free(RZ_NULLABLE RzILOpEffect *op) {
	if (!op) {
		return;
	}
	switch (op->code) {
	case RZIL_OP_STORE:
		rz_il_op_free_2(pure, store, key, value);
		break;
	case RZIL_OP_STOREW:
		rz_il_op_free_2(pure, storew, key, value);
		break;
	case RZIL_OP_NOP:
		// nothing to free
		break;
	case RZIL_OP_SET:
		rz_il_op_free_1(pure, set, x);
		break;
	case RZIL_OP_LET:
		rz_il_op_free_1(pure, let, x);
		break;
	case RZIL_OP_JMP:
		rz_il_op_free_1(pure, jmp, dst);
		break;
	case RZIL_OP_GOTO:
		rz_il_op_free_0(goto_);
		break;
	case RZIL_OP_SEQ:
		rz_il_op_free_2(effect, seq, x, y);
		break;
	case RZIL_OP_BLK:
		rz_il_op_free_2(effect, blk, data_eff, ctrl_eff);
		break;
	case RZIL_OP_REPEAT:
		rz_il_op_pure_free(op->op.repeat->condition);
		rz_il_op_free_1(effect, repeat, data_eff);
		break;
	case RZIL_OP_BRANCH:
		rz_il_op_pure_free(op->op.repeat->condition);
		rz_il_op_free_2(effect, branch, true_eff, false_eff);
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
