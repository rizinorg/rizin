// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Self-contained arithmetic expression tree: the parser/RzIL boundary.
 *
 * librz_util builds an RzNumExpression from a textual expression
 * (rz_num_expression_parse) and librz_il lifts it to an RzILOpPure
 * without ever seeing tree-sitter. It lives in its own header rather
 * than the rz_num.h umbrella so ordinary numeric-parsing consumers of
 * rz_num.h do not pull in the IL-bridge types.
 */

#ifndef RZ_NUM_EXPRESSION_H
#define RZ_NUM_EXPRESSION_H

#include <rz_util/rz_num.h>
#include <rz_util/rz_bitvector.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Kind of an RzNumExpression node.
 */
typedef enum {
	RZ_NUM_EXPRESSION_KIND_BV, ///< grounded bit-vector constant (\p bv)
	RZ_NUM_EXPRESSION_KIND_FLOAT, ///< IEEE-754 double constant (\p f)
	RZ_NUM_EXPRESSION_KIND_BINOP, ///< binary op \p op over operands[0], operands[1]
	RZ_NUM_EXPRESSION_KIND_UNOP, ///< unary op \p op over operands[0]
	RZ_NUM_EXPRESSION_KIND_ITE, ///< operands[0] ? operands[1] : operands[2]
} RzNumExpressionKind;

/**
 * \brief Operator of an RzNumExpression BINOP / UNOP node.
 *
 * The float operators (FADD..FDIV, IS_FZERO) appear only over float
 * sub-expressions; the rest are bit-vector operators. The names mirror
 * the RzIL pure ops they lift to, but the enum is deliberately
 * independent of librz_il so the type can live in librz_util.
 */
typedef enum {
	RZ_NUM_EXPRESSION_OP_ADD,
	RZ_NUM_EXPRESSION_OP_SUB,
	RZ_NUM_EXPRESSION_OP_MUL,
	RZ_NUM_EXPRESSION_OP_DIV, ///< unsigned division
	RZ_NUM_EXPRESSION_OP_SDIV, ///< signed division
	RZ_NUM_EXPRESSION_OP_MOD, ///< unsigned remainder
	RZ_NUM_EXPRESSION_OP_SMOD, ///< signed remainder
	RZ_NUM_EXPRESSION_OP_LOGAND,
	RZ_NUM_EXPRESSION_OP_LOGOR,
	RZ_NUM_EXPRESSION_OP_LOGXOR,
	RZ_NUM_EXPRESSION_OP_SHL, ///< logical shift left
	RZ_NUM_EXPRESSION_OP_SHR, ///< logical shift right
	RZ_NUM_EXPRESSION_OP_SAR, ///< arithmetic (sign-extending) shift right
	RZ_NUM_EXPRESSION_OP_EQ,
	RZ_NUM_EXPRESSION_OP_ULE, ///< unsigned less-or-equal
	RZ_NUM_EXPRESSION_OP_FADD,
	RZ_NUM_EXPRESSION_OP_FSUB,
	RZ_NUM_EXPRESSION_OP_FMUL,
	RZ_NUM_EXPRESSION_OP_FDIV,
	RZ_NUM_EXPRESSION_OP_NEG, ///< two's-complement negation
	RZ_NUM_EXPRESSION_OP_LOGNOT, ///< bitwise not
	RZ_NUM_EXPRESSION_OP_IS_FZERO, ///< float "is zero" predicate
} RzNumExpressionOp;

/**
 * \brief A self-contained arithmetic expression tree.
 *
 * Built by rz_num_expression_parse() from a textual expression, it holds no
 * reference to the tree-sitter parse it was built from, so a higher layer
 * (librz_il) can walk it to build a typed RzILOpPure without depending on the
 * parser. Anything with no node kind of its own - function calls,
 * typed-address reads, host variables, exponent / logarithm, ';' sequences -
 * is evaluated to a concrete value while building and stored as a constant
 * leaf.
 */
typedef struct rz_num_expression_t RzNumExpression;

/**
 * \brief Fields of an RzNumExpression; which are valid depends on \ref RzNumExpressionKind.
 */
struct rz_num_expression_t {
	RzNumExpressionKind kind;
	RzNumExpressionOp op; ///< valid for BINOP / UNOP
	RzBitVector *bv; ///< valid for BV
	double f; ///< valid for FLOAT
	RZ_OWN RzNumExpression *operands[3]; ///< children; layout per \ref RzNumExpressionKind
};

RZ_API RZ_OWN RzNumExpression *rz_num_expression_parse(RZ_NULLABLE RzNum *num,
	RZ_NONNULL const char *expr, RZ_NULLABLE const RzNumMathOptions *opts,
	RZ_NULLABLE char **error_msg);

RZ_API void rz_num_expression_free(RZ_NULLABLE RzNumExpression *e);

#ifdef __cplusplus
}
#endif

#endif // RZ_NUM_EXPRESSION_H
