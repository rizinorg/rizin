// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file float_trans_hyp.c
 * Hyperbolic functions and their inverses of the IEEE 754-2019 9.2
 * recommended operations, correctly rounded. See float_trans.h.
 *
 * For a nonzero rational x (every finite operand is rational) e^x is
 * transcendental (Lindemann-Weierstrass). sinh, cosh and tanh of x are then
 * transcendental too, since a rational value of any of them would make e^x
 * a root of a rational quadratic. asinh, acosh and atanh map a rational
 * x != 0 (x != 1 for acosh) to an irrational value, as sinh, cosh and tanh
 * would map that value back to the rational x. So the only exact results
 * are at 0 and acosh(1), and the evaluations below only need proxies where
 * the result lies very close to a representable value: f(x) ~ x and
 * cosh(x) ~ 1 for a tiny x, tanh(x) ~ 1 for a large x and the overflow of
 * sinh and cosh.
 */

#include "float_trans.h"
#include <rz_util/rz_assert.h>
#include <math.h>

/**
 * \name Evaluations
 * \{
 */

/* Working precision: counting each core result as 2 ulps, the evaluations
 * below stay within a relative error of 16 2^-wp = 2^-(w + 12), plus the
 * final rounding to the w + 8 bits of r, well inside the 2^-(w + 1) that
 * Ziv's loop needs. */
static ut32 hyp_prec(ut32 w) {
	return RZ_MIN(w + 16, MP_MAX_PREC - 32);
}

/* r = |x| exactly, at precision prec or more */
static void hyp_abs(MpFloat *r, const MpFloat *x, ut32 prec) {
	rz_mp_init(r, RZ_MAX(prec, x->prec));
	rz_mp_set(r, x, RZ_FLOAT_RMODE_RNE);
	rz_mp_abs(r);
}

/* x^2 < 2^-(p + 5): the series give |f(x)/x - 1| < x^2/2 for sinh, tanh,
 * asinh and atanh and 0 < cosh(x) - 1 < x^2 for cosh, all below 2^-(p + 5)
 * and far inside the half ulp a proxy may move (relative 2^-(p + 1) for
 * the ulp below a power of two) */
static bool hyp_tiny(const TransCtx *ctx) {
	return 2 * ctx->x.exp < -(st64)ctx->p - 4;
}

/* sinh and cosh overflow above this integer bound: for |x| > hi,
 * cosh(x) >= sinh(|x|) > (e^|x| - 1)/2 > e 2^(emax + 1) - 1/2 */
static st64 hyp_overflow_bound(const TransCtx *ctx) {
	return (st64)ceil((double)(ctx->emax + 2) * M_LN2) + 1;
}

/* f(x) proxy for a tiny x: x moved by a fraction of its ulp, away from 0
 * when \p above else towards 0 */
static void hyp_tiny_proxy(MpFloat *r, TransCtx *ctx, bool above) {
	MpFloat a;
	hyp_abs(&a, &ctx->x, ctx->p + 8);
	rz_float_trans_proxy_nudge(r, ctx, &a, above);
	if (ctx->x.sign) {
		rz_mp_neg(r);
	}
}

/* 1 moved by a fraction of its ulp, up or down */
static void hyp_one_proxy(MpFloat *r, TransCtx *ctx, bool up) {
	MpFloat one;
	rz_mp_init(&one, 8);
	rz_mp_set_si(&one, 1, RZ_FLOAT_RMODE_RNE);
	rz_float_trans_proxy_nudge(r, ctx, &one, up);
}

/* sinh(x) - x = x^3/6 + ... has the sign of x */
static void eval_sinh(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	if (hyp_tiny(ctx)) {
		hyp_tiny_proxy(r, ctx, true);
		*exact = true;
		return;
	}
	MpFloat a;
	hyp_abs(&a, &ctx->x, TRANS_OPERAND_PREC);
	if (rz_mp_cmp_si(&a, hyp_overflow_bound(ctx)) > 0) {
		rz_float_trans_proxy_overflow(r, ctx, ctx->x.sign);
		*exact = true;
		return;
	}
	/* sinh|x| = E (E + 2) / (2 (E + 1)) with E = expm1|x| > 0: no
	 * cancellation, the relative error stays below 8 2^-wp */
	ut32 wp = hyp_prec(w);
	MpFloat e, n, d;
	rz_mp_init(&e, wp);
	rz_mp_init(&n, wp);
	rz_mp_init(&d, wp);
	rz_float_trans_expm1(&e, &a, wp);
	rz_mp_add_si(&n, &e, 2, RZ_FLOAT_RMODE_RNE);
	rz_mp_add_si(&d, &e, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul(&n, &e, &n, RZ_FLOAT_RMODE_RNE);
	rz_mp_div(r, &n, &d, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(r, -1);
	if (ctx->x.sign) {
		rz_mp_neg(r);
	}
}

/* cosh(x) - 1 = x^2/2 + ... is positive */
static void eval_cosh(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	if (hyp_tiny(ctx)) {
		hyp_one_proxy(r, ctx, true);
		*exact = true;
		return;
	}
	MpFloat a;
	hyp_abs(&a, &ctx->x, TRANS_OPERAND_PREC);
	if (rz_mp_cmp_si(&a, hyp_overflow_bound(ctx)) > 0) {
		rz_float_trans_proxy_overflow(r, ctx, false);
		*exact = true;
		return;
	}
	/* cosh|x| = (e^|x| + e^-|x|) / 2, a sum of positive terms */
	ut32 wp = hyp_prec(w);
	MpFloat e, inv;
	rz_mp_init(&e, wp);
	rz_mp_init(&inv, wp);
	rz_float_trans_exp(&e, &a, wp);
	rz_mp_set_si(&inv, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_div(&inv, &inv, &e, RZ_FLOAT_RMODE_RNE);
	rz_mp_add(r, &e, &inv, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(r, -1);
}

/* tanh(x) - x = -x^3/3 + ... has the sign of -x */
static void eval_tanh(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	if (hyp_tiny(ctx)) {
		hyp_tiny_proxy(r, ctx, false);
		*exact = true;
		return;
	}
	MpFloat a;
	hyp_abs(&a, &ctx->x, TRANS_OPERAND_PREC);
	/* 1 - tanh|x| = 2 / (e^2|x| + 1) < 2 e^-2|x| < 2^-(p + 5) above
	 * (p + 6) ln(2) / 2: within a quarter of an ulp below 1 */
	st64 sat = (st64)ceil((double)(ctx->p + 6) * M_LN2 / 2) + 1;
	if (rz_mp_cmp_si(&a, sat) > 0) {
		hyp_one_proxy(r, ctx, false);
		if (ctx->x.sign) {
			rz_mp_neg(r);
		}
		*exact = true;
		return;
	}
	/* tanh|x| = E / (E + 2) with E = expm1(2|x|) > 0 */
	ut32 wp = hyp_prec(w);
	MpFloat e, d;
	rz_mp_init(&e, wp);
	rz_mp_init(&d, wp);
	rz_mp_mul_2si(&a, 1);
	rz_float_trans_expm1(&e, &a, wp);
	rz_mp_add_si(&d, &e, 2, RZ_FLOAT_RMODE_RNE);
	rz_mp_div(r, &e, &d, RZ_FLOAT_RMODE_RNE);
	if (ctx->x.sign) {
		rz_mp_neg(r);
	}
}

/* asinh(x) - x = -x^3/6 + ... has the sign of -x */
static void eval_asinh(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	if (hyp_tiny(ctx)) {
		hyp_tiny_proxy(r, ctx, false);
		*exact = true;
		return;
	}
	/* asinh|x| = log1p(|x| + x^2 / (1 + sqrt(1 + x^2))): the argument
	 * is a sum of positive terms and log1p has a relative condition
	 * number below 1 for a positive argument. The exponent of x^2 stays
	 * far inside the MpFloat range. */
	ut32 wp = hyp_prec(w);
	MpFloat a, x2, t, u;
	hyp_abs(&a, &ctx->x, wp);
	rz_mp_init(&x2, wp);
	rz_mp_init(&t, wp);
	rz_mp_init(&u, wp);
	rz_mp_mul(&x2, &a, &a, RZ_FLOAT_RMODE_RNE);
	rz_mp_add_si(&t, &x2, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_sqrt(&t, &t, RZ_FLOAT_RMODE_RNE);
	rz_mp_add_si(&t, &t, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_div(&t, &x2, &t, RZ_FLOAT_RMODE_RNE);
	rz_mp_add(&u, &a, &t, RZ_FLOAT_RMODE_RNE);
	rz_float_trans_log1p(r, &u, wp);
	if (ctx->x.sign) {
		rz_mp_neg(r);
	}
}

/* x > 1: acosh(x) >= acosh(1 + 2^(1 - p)) ~ 2^(1 - p/2) is not tiny, and
 * acosh(1 + d) = sqrt(2d) (1 - d/12 + ...) stays a relative distance of
 * about d/12 >= 2^-(p + 3) away from sqrt(2d), which may be representable:
 * Ziv's loop resolves that at its first precision */
static void eval_acosh(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	/* acosh(x) = log1p((x - 1) + sqrt((x - 1)(x + 1))), all terms
	 * positive; x - 1 is exact unless x is huge */
	ut32 wp = hyp_prec(w);
	MpFloat dm, dp, u;
	rz_mp_init(&dm, wp);
	rz_mp_init(&dp, wp);
	rz_mp_init(&u, wp);
	rz_mp_add_si(&dm, &ctx->x, -1, RZ_FLOAT_RMODE_RNE);
	rz_mp_add_si(&dp, &ctx->x, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul(&dp, &dm, &dp, RZ_FLOAT_RMODE_RNE);
	rz_mp_sqrt(&dp, &dp, RZ_FLOAT_RMODE_RNE);
	rz_mp_add(&u, &dm, &dp, RZ_FLOAT_RMODE_RNE);
	rz_float_trans_log1p(r, &u, wp);
}

/* 0 < |x| < 1; atanh(x) - x = x^3/3 + ... has the sign of x */
static void eval_atanh(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	if (hyp_tiny(ctx)) {
		hyp_tiny_proxy(r, ctx, true);
		*exact = true;
		return;
	}
	/* atanh|x| = log1p(2|x| / (1 - |x|)) / 2 with a positive argument;
	 * 1 - |x| is exact for |x| >= 1/2 and well conditioned below */
	ut32 wp = hyp_prec(w);
	MpFloat a, d, u;
	hyp_abs(&a, &ctx->x, wp);
	rz_mp_init(&d, wp);
	rz_mp_init(&u, wp);
	rz_mp_set_si(&d, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_sub(&d, &d, &a, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&a, 1);
	rz_mp_div(&u, &a, &d, RZ_FLOAT_RMODE_RNE);
	rz_float_trans_log1p(r, &u, wp);
	rz_mp_mul_2si(r, -1);
	if (ctx->x.sign) {
		rz_mp_neg(r);
	}
}

/** \} */

/**
 * \name Public operations
 * \{
 */

static bool float_sign(const RzFloat *f) {
	return rz_float_is_negative((RzFloat *)f);
}

/**
 * \brief sinh(x) correctly rounded (IEEE 754-2019 9.2 sinh).
 * \param x operand
 * \param mode rounding mode
 * \return the result in the format of \p x with its exception flags
 */
RZ_API RZ_OWN RzFloat *rz_float_sinh(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	bool neg = float_sign(x);
	if (rz_float_trans_is_inf(x)) {
		return rz_float_trans_inf(x->r, neg);
	}
	if (rz_float_trans_is_zero(x)) {
		return rz_float_trans_zero(x->r, neg);
	}
	return rz_float_trans_unary(x, mode, eval_sinh);
}

/** \brief cosh(x) correctly rounded (IEEE 754-2019 9.2 cosh). */
RZ_API RZ_OWN RzFloat *rz_float_cosh(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	if (rz_float_trans_is_inf(x)) {
		return rz_float_trans_inf(x->r, false);
	}
	if (rz_float_trans_is_zero(x)) {
		return rz_float_trans_si(x->r, 1);
	}
	return rz_float_trans_unary(x, mode, eval_cosh);
}

/** \brief tanh(x) correctly rounded (IEEE 754-2019 9.2 tanh). */
RZ_API RZ_OWN RzFloat *rz_float_tanh(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	bool neg = float_sign(x);
	if (rz_float_trans_is_inf(x)) {
		return rz_float_trans_si(x->r, neg ? -1 : 1);
	}
	if (rz_float_trans_is_zero(x)) {
		return rz_float_trans_zero(x->r, neg);
	}
	return rz_float_trans_unary(x, mode, eval_tanh);
}

/** \brief asinh(x) correctly rounded (IEEE 754-2019 9.2 asinh). */
RZ_API RZ_OWN RzFloat *rz_float_asinh(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	bool neg = float_sign(x);
	if (rz_float_trans_is_inf(x)) {
		return rz_float_trans_inf(x->r, neg);
	}
	if (rz_float_trans_is_zero(x)) {
		return rz_float_trans_zero(x->r, neg);
	}
	return rz_float_trans_unary(x, mode, eval_asinh);
}

/**
 * \brief acosh(x) correctly rounded (IEEE 754-2019 9.2 acosh).
 * acosh(1) = +0, x < 1 (including -inf and +-0) is invalid.
 */
RZ_API RZ_OWN RzFloat *rz_float_acosh(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	if (rz_float_trans_is_inf(x)) {
		return float_sign(x) ? rz_float_trans_invalid(x->r) : rz_float_trans_inf(x->r, false);
	}
	TransCtx ctx;
	rz_float_trans_ctx_init(&ctx, x->r);
	if (!rz_mp_set_float(&ctx.x, x)) {
		return NULL;
	}
	int c = rz_mp_cmp_si(&ctx.x, 1);
	if (c < 0) {
		return rz_float_trans_invalid(x->r);
	}
	if (!c) {
		return rz_float_trans_zero(x->r, false);
	}
	return rz_float_trans_round(&ctx, eval_acosh, mode);
}

/**
 * \brief atanh(x) correctly rounded (IEEE 754-2019 9.2 atanh).
 * atanh(+-1) = +-inf with divide by zero, |x| > 1 is invalid.
 */
RZ_API RZ_OWN RzFloat *rz_float_atanh(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	bool neg = float_sign(x);
	if (rz_float_trans_is_inf(x)) {
		return rz_float_trans_invalid(x->r);
	}
	if (rz_float_trans_is_zero(x)) {
		return rz_float_trans_zero(x->r, neg);
	}
	TransCtx ctx;
	rz_float_trans_ctx_init(&ctx, x->r);
	if (!rz_mp_set_float(&ctx.x, x)) {
		return NULL;
	}
	MpFloat one;
	rz_mp_init(&one, 8);
	rz_mp_set_si(&one, 1, RZ_FLOAT_RMODE_RNE);
	int c = rz_mp_cmp_abs(&ctx.x, &one);
	if (c > 0) {
		return rz_float_trans_invalid(x->r);
	}
	if (!c) {
		return rz_float_trans_div_zero(x->r, neg);
	}
	return rz_float_trans_round(&ctx, eval_atanh, mode);
}

/** \} */
