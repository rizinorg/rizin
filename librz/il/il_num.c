// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Lift an RzNum expression to a typed RzILOpPure.
 *
 * The tree-sitter parse and the grounding of non-structural constructs
 * live in librz_util (rz_num_expression_parse), which hands back a
 * tree-sitter-free RzNumExpression. This file is the second half: it
 * walks that abstraction and builds the corresponding RzILOpPure, so the
 * caller gets a real op tree (which it can evaluate, transform, or
 * stringify) instead of pre-rendered text. The layering keeps tree-sitter
 * out of librz_il entirely.
 */

#include <string.h>

#include <rz_il/rz_il_opcodes.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_bitvector.h>
#include <rz_util/rz_float.h>

static RzILOpPure *expr_to_pure(const RzNumExpression *e);

// A float leaf: take the double's IEEE-754 bit pattern as a 64-bit
// bit-vector and wrap it as a binary64 float constant - the form RzNum's
// FLOAT kind carries. A future widening to f32/f128 changes only this.
static RzILOpPure *float_leaf(double d) {
	ut64 bits;
	memcpy(&bits, &d, sizeof(bits));
	RzBitVector *bv = rz_bv_new_from_ut64(64, bits);
	if (!bv) {
		return NULL;
	}
	RzILOpBitVector *bvop = rz_il_op_new_bitv(bv);
	if (!bvop) {
		rz_bv_free(bv);
		return NULL;
	}
	return rz_il_op_new_float(RZ_FLOAT_IEEE754_BIN_64, bvop);
}

static RzILOpPure *binop_to_pure(const RzNumExpression *e) {
	RzILOpPure *x = expr_to_pure(e->operands[0]);
	RzILOpPure *y = expr_to_pure(e->operands[1]);
	if (!x || !y) {
		rz_il_op_pure_free(x);
		rz_il_op_pure_free(y);
		return NULL;
	}
	switch (e->op) {
	case RZ_NUM_EXPRESSION_OP_ADD: return rz_il_op_new_add(x, y);
	case RZ_NUM_EXPRESSION_OP_SUB: return rz_il_op_new_sub(x, y);
	case RZ_NUM_EXPRESSION_OP_MUL: return rz_il_op_new_mul(x, y);
	case RZ_NUM_EXPRESSION_OP_DIV: return rz_il_op_new_div(x, y);
	case RZ_NUM_EXPRESSION_OP_SDIV: return rz_il_op_new_sdiv(x, y);
	case RZ_NUM_EXPRESSION_OP_MOD: return rz_il_op_new_mod(x, y);
	case RZ_NUM_EXPRESSION_OP_SMOD: return rz_il_op_new_smod(x, y);
	case RZ_NUM_EXPRESSION_OP_LOGAND: return rz_il_op_new_log_and(x, y);
	case RZ_NUM_EXPRESSION_OP_LOGOR: return rz_il_op_new_log_or(x, y);
	case RZ_NUM_EXPRESSION_OP_LOGXOR: return rz_il_op_new_log_xor(x, y);
	case RZ_NUM_EXPRESSION_OP_SHL: return rz_il_op_new_shiftl(rz_il_op_new_b0(), x, y);
	case RZ_NUM_EXPRESSION_OP_SHR: return rz_il_op_new_shiftr(rz_il_op_new_b0(), x, y);
	// Arithmetic shift right fills vacated bits with the sign bit of x;
	// x is duplicated so it serves both as the value and the fill source.
	case RZ_NUM_EXPRESSION_OP_SAR: return rz_il_op_new_shiftr(rz_il_op_new_msb(rz_il_op_pure_dup(x)), x, y);
	case RZ_NUM_EXPRESSION_OP_EQ: return rz_il_op_new_eq(x, y);
	case RZ_NUM_EXPRESSION_OP_ULE: return rz_il_op_new_ule(x, y);
	case RZ_NUM_EXPRESSION_OP_FADD: return rz_il_op_new_fadd(RZ_FLOAT_RMODE_RNE, x, y);
	case RZ_NUM_EXPRESSION_OP_FSUB: return rz_il_op_new_fsub(RZ_FLOAT_RMODE_RNE, x, y);
	case RZ_NUM_EXPRESSION_OP_FMUL: return rz_il_op_new_fmul(RZ_FLOAT_RMODE_RNE, x, y);
	case RZ_NUM_EXPRESSION_OP_FDIV: return rz_il_op_new_fdiv(RZ_FLOAT_RMODE_RNE, x, y);
	default:
		rz_il_op_pure_free(x);
		rz_il_op_pure_free(y);
		return NULL;
	}
}

static RzILOpPure *unop_to_pure(const RzNumExpression *e) {
	RzILOpPure *x = expr_to_pure(e->operands[0]);
	if (!x) {
		return NULL;
	}
	switch (e->op) {
	case RZ_NUM_EXPRESSION_OP_NEG: return rz_il_op_new_neg(x);
	case RZ_NUM_EXPRESSION_OP_LOGNOT: return rz_il_op_new_log_not(x);
	case RZ_NUM_EXPRESSION_OP_IS_FZERO: return rz_il_op_new_is_fzero(x);
	default:
		rz_il_op_pure_free(x);
		return NULL;
	}
}

static RzILOpPure *expr_to_pure(const RzNumExpression *e) {
	if (!e) {
		return NULL;
	}
	switch (e->kind) {
	case RZ_NUM_EXPRESSION_KIND_BV: {
		RzBitVector *bv = e->bv ? rz_bv_dup(e->bv) : NULL;
		if (!bv) {
			return NULL;
		}
		RzILOpPure *op = rz_il_op_new_bitv(bv);
		if (!op) {
			rz_bv_free(bv);
		}
		return op;
	}
	case RZ_NUM_EXPRESSION_KIND_FLOAT:
		return float_leaf(e->f);
	case RZ_NUM_EXPRESSION_KIND_BINOP:
		return binop_to_pure(e);
	case RZ_NUM_EXPRESSION_KIND_UNOP:
		return unop_to_pure(e);
	case RZ_NUM_EXPRESSION_KIND_ITE: {
		RzILOpPure *cond = expr_to_pure(e->operands[0]);
		RzILOpPure *t = expr_to_pure(e->operands[1]);
		RzILOpPure *f = expr_to_pure(e->operands[2]);
		if (!cond || !t || !f) {
			rz_il_op_pure_free(cond);
			rz_il_op_pure_free(t);
			rz_il_op_pure_free(f);
			return NULL;
		}
		return rz_il_op_new_ite(cond, t, f);
	}
	}
	return NULL;
}

/**
 * \brief Build an RzILOpPure from a grounded RzNumExpression.
 *
 * \param expr The expression tree produced by rz_num_expression_parse().
 * \return A newly-owned RzILOpPure, or NULL on allocation failure.
 */
RZ_API RZ_OWN RzILOpPure *rz_il_op_pure_from_num_expression(RZ_NONNULL const RzNumExpression *expr) {
	rz_return_val_if_fail(expr, NULL);
	return expr_to_pure(expr);
}

/**
 * \brief Parse and lift an RzNum expression directly to an RzILOpPure.
 *
 * Convenience over rz_num_expression_parse() + the converter: the
 * intermediate RzNumExpression is built and freed internally.
 *
 * \param num       Optional RzNum for resolving identifiers when a
 *                  sub-expression must be grounded. May be NULL.
 * \param expr      The expression to lift. Must be non-NULL.
 * \param opts      Optional evaluation options used when grounding. May
 *                  be NULL.
 * \param error_msg Optional out-pointer for a caller-owned diagnostic on
 *                  failure. May be NULL.
 * \return A newly-owned RzILOpPure, or NULL on a parse or lift error.
 */
RZ_API RZ_OWN RzILOpPure *rz_il_lift_num(RZ_NULLABLE RzNum *num,
	RZ_NONNULL const char *expr, RZ_NULLABLE const RzNumMathOptions *opts,
	RZ_NULLABLE char **error_msg) {
	rz_return_val_if_fail(expr, NULL);
	RzNumExpression *e = rz_num_expression_parse(num, expr, opts, error_msg);
	if (!e) {
		return NULL;
	}
	RzILOpPure *op = expr_to_pure(e);
	rz_num_expression_free(e);
	if (!op && error_msg && !*error_msg) {
		*error_msg = rz_str_dup("out of memory");
	}
	return op;
}
