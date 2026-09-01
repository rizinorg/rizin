// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Build an RzNumExpression tree from an RzNum expression string.
 *
 * Walks the tree-sitter parse tree and renders it as a self-contained
 * RzNumExpression - one that keeps no tree-sitter references - which
 * librz_il converts into an RzILOpPure. The structural shape mirrors what
 * the RzIL pure form expects: binary and unary operators become typed
 * BINOP / UNOP nodes, ternaries become ITE nodes, numeric literals become
 * bit-vector (or float) constants.
 *
 * Constructs that have no structural RzIL counterpart - function calls,
 * the typed-address dereference, host variables, exponent / logarithm,
 * and ';'-separated sequences - are evaluated to a concrete value first
 * (through \p num and \p opts) and embedded as a constant leaf, so the
 * resulting tree is fully grounded and carries no tree-sitter state.
 *
 * Keeping this in librz_util means the tree-sitter dependency stays here;
 * the librz_il converter only ever sees RzNumExpression.
 */

#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <rz_types.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_num_expression.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_bitvector.h>
#include <tree_sitter/api.h>

#include "parser.h"

// Default bit-vector width for a plain numeric literal that carries no
// explicit width suffix. RzNum's ut64 domain is 64-bit.
#define EXPR_DEFAULT_WIDTH 64

typedef struct {
	RzNum *num;
	const char *src;
	const RzNumMathOptions *opts;
	char *err; // first error encountered
} BuildCtx;

#define EXPR_FIELD(node, name) \
	ts_node_child_by_field_name((node), (name), (uint32_t)(sizeof(name) - 1))

static RzNumExpression *build_node(BuildCtx *c, TSNode n);

/**
 * \brief Recursively free an RzNumExpression and all of its children.
 * \param e Expression tree to free; NULL is ignored.
 */
RZ_API void rz_num_expression_free(RZ_NULLABLE RzNumExpression *e) {
	if (!e) {
		return;
	}
	rz_bv_free(e->bv);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(e->operands); i++) {
		rz_num_expression_free(e->operands[i]);
	}
	free(e);
}

static void build_set_err(BuildCtx *c, const char *fmt, ...) {
	if (c->err) {
		return; // keep the first error
	}
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	va_list ap;
	va_start(ap, fmt);
	rz_strbuf_vappendf(&sb, fmt, ap);
	va_end(ap);
	c->err = rz_strbuf_drain_nofree(&sb);
}

// --- node constructors ---

static RzNumExpression *expr_bv(RZ_OWN RzBitVector *bv) {
	if (!bv) {
		return NULL;
	}
	RzNumExpression *e = RZ_NEW0(RzNumExpression);
	if (!e) {
		rz_bv_free(bv);
		return NULL;
	}
	e->kind = RZ_NUM_EXPRESSION_KIND_BV;
	e->bv = bv;
	return e;
}

static RzNumExpression *expr_float(double d) {
	RzNumExpression *e = RZ_NEW0(RzNumExpression);
	if (e) {
		e->kind = RZ_NUM_EXPRESSION_KIND_FLOAT;
		e->f = d;
	}
	return e;
}

static RzNumExpression *expr_binop(RzNumExpressionOp op, RZ_OWN RzNumExpression *l, RZ_OWN RzNumExpression *r) {
	if (!l || !r) {
		rz_num_expression_free(l);
		rz_num_expression_free(r);
		return NULL;
	}
	RzNumExpression *e = RZ_NEW0(RzNumExpression);
	if (!e) {
		rz_num_expression_free(l);
		rz_num_expression_free(r);
		return NULL;
	}
	e->kind = RZ_NUM_EXPRESSION_KIND_BINOP;
	e->op = op;
	e->operands[0] = l;
	e->operands[1] = r;
	return e;
}

static RzNumExpression *expr_unop(RzNumExpressionOp op, RZ_OWN RzNumExpression *x) {
	if (!x) {
		return NULL;
	}
	RzNumExpression *e = RZ_NEW0(RzNumExpression);
	if (!e) {
		rz_num_expression_free(x);
		return NULL;
	}
	e->kind = RZ_NUM_EXPRESSION_KIND_UNOP;
	e->op = op;
	e->operands[0] = x;
	return e;
}

static RzNumExpression *expr_ite(RZ_OWN RzNumExpression *cond, RZ_OWN RzNumExpression *t, RZ_OWN RzNumExpression *f) {
	if (!cond || !t || !f) {
		rz_num_expression_free(cond);
		rz_num_expression_free(t);
		rz_num_expression_free(f);
		return NULL;
	}
	RzNumExpression *e = RZ_NEW0(RzNumExpression);
	if (!e) {
		rz_num_expression_free(cond);
		rz_num_expression_free(t);
		rz_num_expression_free(f);
		return NULL;
	}
	e->kind = RZ_NUM_EXPRESSION_KIND_ITE;
	e->operands[0] = cond;
	e->operands[1] = t;
	e->operands[2] = f;
	return e;
}

// --- float detection (mirrors the kind-promotion the evaluator does) ---

static char *node_text(TSNode n, const char *src) {
	ut32 a = ts_node_start_byte(n);
	ut32 b = ts_node_end_byte(n);
	if (b < a) {
		return NULL;
	}
	ut32 len = b - a;
	char *s = malloc(len + 1);
	if (!s) {
		return NULL;
	}
	memcpy(s, src + a, len);
	s[len] = '\0';
	return s;
}

// True if a numeric literal node's text is a float (a '.' or a non-hex
// 'e'/'E' exponent). A hex literal like "0xea" contains 'e' but is not.
static bool number_node_is_float(const char *src, TSNode n) {
	TSNode v = n;
	if (ts_node_symbol(n) == rz_num_parse_syms()->sym_number) {
		v = ts_node_named_child(n, 0);
		if (ts_node_is_null(v)) {
			return false;
		}
	}
	ut32 start = ts_node_start_byte(v), end = ts_node_end_byte(v);
	for (ut32 i = start; i < end; i++) {
		char ch = src[i];
		if (ch == '.' || ch == 'e' || ch == 'E') {
			if (ch == 'e' || ch == 'E') {
				if (end - start >= 2 && src[start] == '0' &&
					(src[start + 1] == 'x' || src[start + 1] == 'X')) {
					continue;
				}
			}
			return true;
		}
	}
	return false;
}

// Conservative over-approximation of "this sub-expression is a float".
static bool is_float_subexpr(const char *src, TSNode n) {
	const RzNumSymCache *s = rz_num_parse_syms();
	TSSymbol sym = ts_node_symbol(n);
	if (sym == s->sym_number) {
		return number_node_is_float(src, n);
	}
	// Typed reads are float only with a wired IO callback, which we
	// cannot know statically; classify as non-float so a typed read
	// mixed with a float literal is grounded rather than mis-lifted.
	if (sym == s->sym_address_typed) {
		return false;
	}
	if (sym == s->sym_expression || sym == s->sym_source_file ||
		sym == s->sym_parenthesized_expression || sym == s->sym_argument) {
		TSNode child = ts_node_named_child(n, 0);
		return !ts_node_is_null(child) && is_float_subexpr(src, child);
	}
	if (sym == s->sym_unary_minus || sym == s->sym_unary_plus) {
		TSNode operand = EXPR_FIELD(n, "right");
		return !ts_node_is_null(operand) && is_float_subexpr(src, operand);
	}
	if (sym == s->sym_sum || sym == s->sym_subtraction ||
		sym == s->sym_product || sym == s->sym_division ||
		sym == s->sym_modulo) {
		TSNode l = EXPR_FIELD(n, "left");
		TSNode r = EXPR_FIELD(n, "right");
		return (!ts_node_is_null(l) && is_float_subexpr(src, l)) ||
			(!ts_node_is_null(r) && is_float_subexpr(src, r));
	}
	if (sym == s->sym_conditional) {
		TSNode then_n = EXPR_FIELD(n, "consequence");
		TSNode else_n = EXPR_FIELD(n, "alternative");
		return !ts_node_is_null(then_n) && !ts_node_is_null(else_n) &&
			is_float_subexpr(src, then_n) && is_float_subexpr(src, else_n);
	}
	return false;
}

// --- operator maps (node type -> RzNumExpressionOp) ---

static bool binop_of(TSSymbol sym, RzNumExpressionOp *out) {
	const RzNumSymCache *s = rz_num_parse_syms();
	RzNumExpressionOp op;
	if (sym == s->sym_sum) {
		op = RZ_NUM_EXPRESSION_OP_ADD;
	} else if (sym == s->sym_subtraction) {
		op = RZ_NUM_EXPRESSION_OP_SUB;
	} else if (sym == s->sym_product) {
		op = RZ_NUM_EXPRESSION_OP_MUL;
	} else if (sym == s->sym_division) {
		op = RZ_NUM_EXPRESSION_OP_DIV;
	} else if (sym == s->sym_signed_division) {
		op = RZ_NUM_EXPRESSION_OP_SDIV;
	} else if (sym == s->sym_modulo) {
		op = RZ_NUM_EXPRESSION_OP_MOD;
	} else if (sym == s->sym_signed_modulo) {
		op = RZ_NUM_EXPRESSION_OP_SMOD;
	} else if (sym == s->sym_logical_and) {
		op = RZ_NUM_EXPRESSION_OP_LOGAND;
	} else if (sym == s->sym_logical_or) {
		op = RZ_NUM_EXPRESSION_OP_LOGOR;
	} else if (sym == s->sym_logical_xor) {
		op = RZ_NUM_EXPRESSION_OP_LOGXOR;
	} else if (sym == s->sym_logical_shl) {
		op = RZ_NUM_EXPRESSION_OP_SHL;
	} else if (sym == s->sym_logical_shr) {
		op = RZ_NUM_EXPRESSION_OP_SHR;
	} else if (sym == s->sym_arith_shr) {
		op = RZ_NUM_EXPRESSION_OP_SAR;
	} else if (sym == s->sym_equal) {
		op = RZ_NUM_EXPRESSION_OP_EQ;
	} else if (sym == s->sym_less_equal) {
		op = RZ_NUM_EXPRESSION_OP_ULE;
	} else {
		return false;
	}
	*out = op;
	return true;
}

// Float arithmetic has a direct RzIL equivalent only for + - * / .
static bool float_binop_of(TSSymbol sym, RzNumExpressionOp *out) {
	const RzNumSymCache *s = rz_num_parse_syms();
	if (sym == s->sym_sum) {
		*out = RZ_NUM_EXPRESSION_OP_FADD;
	} else if (sym == s->sym_subtraction) {
		*out = RZ_NUM_EXPRESSION_OP_FSUB;
	} else if (sym == s->sym_product) {
		*out = RZ_NUM_EXPRESSION_OP_FMUL;
	} else if (sym == s->sym_division) {
		*out = RZ_NUM_EXPRESSION_OP_FDIV;
	} else {
		return false;
	}
	return true;
}

// Evaluate the sub-expression a node spans to a concrete value and emit
// it as a constant leaf (used for constructs with no structural form).
static RzNumExpression *build_ground(BuildCtx *c, TSNode n) {
	char *text = node_text(n, c->src);
	if (!text) {
		build_set_err(c, "out of memory");
		return NULL;
	}
	RzNumValue v;
	rz_num_value_init(&v);
	char *everr = NULL;
	bool ok = rz_num_math_value_ex(c->num, text, c->opts, &v, &everr);
	free(text);
	if (!ok) {
		build_set_err(c, "cannot ground sub-expression: %s",
			everr ? everr : "evaluation failed");
		free(everr);
		rz_num_value_fini(&v);
		return NULL;
	}
	free(everr);
	// Width follows the grounded value's kind: a bit-vector keeps its
	// width, everything else projects to the default 64-bit domain.
	ut32 width = EXPR_DEFAULT_WIDTH;
	if (v.kind == RZ_NUM_KIND_BITVECTOR && v.val.bv) {
		width = rz_bv_len(v.val.bv);
	}
	ut64 value = rz_num_value_to_ut64(&v);
	rz_num_value_fini(&v);
	return expr_bv(rz_bv_new_from_ut64(width ? width : EXPR_DEFAULT_WIDTH, value));
}

// Numeric literal -> float constant (for a '.'/'e' literal) or a grounded
// bit-vector constant (which uniformly handles width and base suffixes).
static RzNumExpression *build_number(BuildCtx *c, TSNode n) {
	if (number_node_is_float(c->src, n)) {
		char *text = node_text(n, c->src);
		if (!text) {
			build_set_err(c, "out of memory");
			return NULL;
		}
		double d = strtod(text, NULL);
		free(text);
		return expr_float(d);
	}
	return build_ground(c, n);
}

static RzNumExpression *build_node(BuildCtx *c, TSNode n) {
	if (c->err) {
		return NULL;
	}
	const RzNumSymCache *s = rz_num_parse_syms();
	TSSymbol sym = ts_node_symbol(n);

	// A ';'-separated sequence is grounded as a whole: the evaluator
	// computes the final value honouring earlier bindings; lifting only
	// the last statement would lose variables bound before it.
	if ((sym == s->sym_source_file || sym == s->sym_expression) &&
		ts_node_named_child_count(n) > 1) {
		return build_ground(c, n);
	}

	// Wrappers: descend into the single meaningful child.
	if (sym == s->sym_source_file || sym == s->sym_expression ||
		sym == s->sym_parenthesized_expression || sym == s->sym_argument) {
		TSNode child = ts_node_named_child(n, 0);
		if (ts_node_is_null(child)) {
			build_set_err(c, "empty expression");
			return NULL;
		}
		return build_node(c, child);
	}

	if (sym == s->sym_number) {
		return build_number(c, n);
	}

	// Ternary -> ITE. A float condition uses RzNum's "non-zero float is
	// true" semantic, which RzIL's ite (Bool condition) does not share;
	// the faithful form is is_fzero(cond) ? else : then (branches swapped
	// because is_fzero is true exactly when the original condition was
	// false).
	if (sym == s->sym_conditional) {
		TSNode cond = EXPR_FIELD(n, "condition");
		TSNode then_n = EXPR_FIELD(n, "consequence");
		TSNode else_n = EXPR_FIELD(n, "alternative");
		if (ts_node_is_null(cond) || ts_node_is_null(then_n) || ts_node_is_null(else_n)) {
			return build_ground(c, n);
		}
		bool cond_is_float = is_float_subexpr(c->src, cond);
		RzNumExpression *ce = build_node(c, cond);
		RzNumExpression *te = build_node(c, then_n);
		RzNumExpression *ee = build_node(c, else_n);
		if (cond_is_float) {
			return expr_ite(expr_unop(RZ_NUM_EXPRESSION_OP_IS_FZERO, ce), ee, te);
		}
		return expr_ite(ce, te, ee);
	}

	// Float-pure arithmetic (+ - * / with two float operands) -> float
	// binop; mixed float/bit-vector arithmetic is grounded rather than
	// fabricating a cast the user did not write.
	{
		RzNumExpressionOp fop;
		if (float_binop_of(sym, &fop)) {
			TSNode l = EXPR_FIELD(n, "left");
			TSNode r = EXPR_FIELD(n, "right");
			if (!ts_node_is_null(l) && !ts_node_is_null(r)) {
				bool lf = is_float_subexpr(c->src, l);
				bool rf = is_float_subexpr(c->src, r);
				if (lf && rf) {
					return expr_binop(fop, build_node(c, l), build_node(c, r));
				}
				if (lf != rf) {
					return build_ground(c, n);
				}
			}
		}
	}

	// Bit-vector binary operators.
	{
		RzNumExpressionOp iop;
		if (binop_of(sym, &iop)) {
			TSNode l = EXPR_FIELD(n, "left");
			TSNode r = EXPR_FIELD(n, "right");
			if (ts_node_is_null(l) || ts_node_is_null(r)) {
				// e.g. exponent uses base/exponent fields and has no
				// bit-vector op: ground the whole node.
				return build_ground(c, n);
			}
			return expr_binop(iop, build_node(c, l), build_node(c, r));
		}
	}

	// Unary minus / bitwise not: operand is in the "right" field.
	if (sym == s->sym_unary_minus || sym == s->sym_logical_negation) {
		TSNode operand = EXPR_FIELD(n, "right");
		if (!ts_node_is_null(operand)) {
			RzNumExpressionOp uop = (sym == s->sym_logical_negation)
				? RZ_NUM_EXPRESSION_OP_LOGNOT
				: RZ_NUM_EXPRESSION_OP_NEG;
			return expr_unop(uop, build_node(c, operand));
		}
	}
	// unary_plus is a no-op on the value.
	if (sym == s->sym_unary_plus) {
		TSNode operand = EXPR_FIELD(n, "right");
		if (!ts_node_is_null(operand)) {
			return build_node(c, operand);
		}
	}

	// Everything else (function calls, typed reads, host variables,
	// exponent / logarithm, string-bytes) has no structural form.
	return build_ground(c, n);
}

/**
 * \brief Parse \p expr into a self-contained RzNumExpression (no tree-sitter references).
 * \param num Evaluation context used to fold non-structural sub-expressions to constants.
 * \param expr Expression source string.
 * \param opts Evaluation options forwarded to the evaluator.
 * \param error_msg Set to an error string on failure when non-NULL.
 * \return Expression tree, or NULL on a parse or grounding error.
 *
 * Sub-expressions with no structural lift (function calls, typed reads,
 * host variables, exponent / logarithm, ';' sequences) are evaluated
 * through \p num / \p opts and embedded as constant leaves, so the
 * returned tree carries no tree-sitter state.
 */
RZ_API RZ_OWN RzNumExpression *rz_num_expression_parse(RZ_NULLABLE RzNum *num,
	RZ_NONNULL const char *expr, RZ_NULLABLE const RzNumMathOptions *opts,
	RZ_NULLABLE char **error_msg) {
	rz_return_val_if_fail(expr, NULL);
	RzNumParseResult *pr = rz_num_parse(expr);
	if (!pr) {
		if (error_msg) {
			*error_msg = rz_str_dup("out of memory");
		}
		return NULL;
	}
	if (pr->has_error) {
		if (error_msg) {
			*error_msg = rz_str_dup(pr->error_msg ? pr->error_msg : "parse error");
		}
		rz_num_parse_result_free(pr);
		return NULL;
	}

	BuildCtx c = {
		.num = num,
		.src = rz_num_parse_source(pr),
		.opts = opts,
		.err = NULL
	};
	RzNumExpression *e = build_node(&c, rz_num_parse_root(pr));
	rz_num_parse_result_free(pr);

	if (!e || c.err) {
		if (error_msg) {
			*error_msg = c.err ? c.err : rz_str_dup("lift failed");
		} else {
			free(c.err);
		}
		rz_num_expression_free(e);
		return NULL;
	}
	return e;
}
