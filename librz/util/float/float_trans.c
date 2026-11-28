// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file float_trans.c
 * Correctly rounded driver, special values and the exponential and
 * logarithmic families of the IEEE 754-2019 9.2 recommended operations.
 * See float_trans.h.
 */

#include "float_trans.h"
#include <rz_util/rz_assert.h>
#include <math.h>

/**
 * \name Special values
 * \{
 */

static ut32 float_total_len(RzFloatFormat format) {
	return rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
}

static ut32 float_man_len(RzFloatFormat format) {
	return rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
}

static ut32 float_exp_len(RzFloatFormat format) {
	return rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
}

/* Bit of the significand that marks a quiet NaN. */
static ut32 float_quiet_bit(RzFloatFormat format) {
	ut32 man = float_man_len(format);
	return format == RZ_FLOAT_IEEE754_BIN_80 ? man - 2 : man - 1;
}

/* binary80 fields: biased exponent and the 63 fraction bits below the
 * explicit integer bit. Specials are classified from the fraction alone, so
 * pseudo-infinities are infinities and pseudo-NaNs are NaNs, and a
 * pseudo-zero (nonzero exponent, zero significand) is a zero, as in the
 * SoftFloat operations behind the other RzFloat functions. */
static ut32 f80_exp(const RzFloat *f) {
	ut32 e = 0;
	for (ut32 i = 0; i < 15; i++) {
		e |= (ut32)rz_bv_get(f->s, 64 + i) << i;
	}
	return e;
}

static bool f80_fraction_zero(const RzFloat *f) {
	for (ut32 i = 0; i < 63; i++) {
		if (rz_bv_get(f->s, i)) {
			return false;
		}
	}
	return true;
}

RZ_IPI bool rz_float_trans_is_nan(const RzFloat *f) {
	if (f->r != RZ_FLOAT_IEEE754_BIN_80) {
		return rz_float_is_nan((RzFloat *)f);
	}
	return f80_exp(f) == 0x7fff && !f80_fraction_zero(f);
}

RZ_IPI bool rz_float_trans_is_inf(const RzFloat *f) {
	if (f->r != RZ_FLOAT_IEEE754_BIN_80) {
		return rz_float_is_inf((RzFloat *)f);
	}
	return f80_exp(f) == 0x7fff && f80_fraction_zero(f);
}

RZ_IPI bool rz_float_trans_is_zero(const RzFloat *f) {
	if (f->r != RZ_FLOAT_IEEE754_BIN_80) {
		return rz_float_is_zero((RzFloat *)f);
	}
	if (f80_exp(f) == 0x7fff || !f80_fraction_zero(f)) {
		return false;
	}
	/* an all-zero significand is zero whatever the exponent */
	return !rz_bv_get(f->s, 63);
}

RZ_IPI bool rz_float_trans_is_snan(const RzFloat *f) {
	return rz_float_trans_is_nan(f) && !rz_bv_get(f->s, float_quiet_bit(f->r));
}

static RzFloat *float_with_exp_all_ones(RzFloatFormat format, bool sign) {
	RzFloat *ret = rz_float_new(format);
	if (!ret) {
		return NULL;
	}
	ut32 man = float_man_len(format);
	ut32 exp = float_exp_len(format);
	rz_bv_set_range(ret->s, man, man + exp - 1, true);
	if (format == RZ_FLOAT_IEEE754_BIN_80) {
		rz_bv_set(ret->s, man - 1, true);
	}
	rz_bv_set(ret->s, float_total_len(format) - 1, sign);
	return ret;
}

RZ_IPI RZ_OWN RzFloat *rz_float_trans_inf(RzFloatFormat format, bool sign) {
	return float_with_exp_all_ones(format, sign);
}

RZ_IPI RZ_OWN RzFloat *rz_float_trans_zero(RzFloatFormat format, bool sign) {
	RzFloat *ret = rz_float_new(format);
	if (ret) {
		rz_bv_set(ret->s, float_total_len(format) - 1, sign);
	}
	return ret;
}

/** Exact small integer v in \p format. */
RZ_IPI RZ_OWN RzFloat *rz_float_trans_si(RzFloatFormat format, st64 v) {
	MpFloat t;
	rz_mp_init(&t, 64);
	rz_mp_set_si(&t, v, RZ_FLOAT_RMODE_RNE);
	return rz_mp_get_float(&t, format, RZ_FLOAT_RMODE_RNE);
}

/**
 * The default NaN of an invalid operation, matching the SoftFloat
 * specialization used by the other RzFloat operations (sign set, quiet).
 */
RZ_IPI RZ_OWN RzFloat *rz_float_trans_invalid(RzFloatFormat format) {
	RzFloat *ret = float_with_exp_all_ones(format, true);
	if (ret) {
		rz_bv_set(ret->s, float_quiet_bit(format), true);
		ret->exception = RZ_FLOAT_E_INVALID_OP;
	}
	return ret;
}

RZ_IPI RZ_OWN RzFloat *rz_float_trans_div_zero(RzFloatFormat format, bool sign) {
	RzFloat *ret = rz_float_trans_inf(format, sign);
	if (ret) {
		ret->exception = RZ_FLOAT_E_DIV_ZERO;
	}
	return ret;
}

/**
 * NaN result for NaN operands: the first NaN operand, quieted. A signaling
 * NaN operand raises invalid. \p b may be NULL.
 */
RZ_IPI RZ_OWN RzFloat *rz_float_trans_nan(const RzFloat *a, const RzFloat *b) {
	const RzFloat *src = rz_float_trans_is_nan(a) ? a : b;
	RzFloat *ret = rz_float_dup((RzFloat *)src);
	if (!ret) {
		return NULL;
	}
	ret->exception = 0;
	if (rz_float_trans_is_snan(a) || (b && rz_float_trans_is_snan(b))) {
		ret->exception = RZ_FLOAT_E_INVALID_OP;
	}
	rz_bv_set(ret->s, float_quiet_bit(ret->r), true);
	if (ret->r == RZ_FLOAT_IEEE754_BIN_80) {
		/* canonical: set the explicit integer bit of a pseudo-NaN */
		rz_bv_set(ret->s, 63, true);
	}
	return ret;
}

/** \} */

/**
 * \name Correct rounding
 * \{
 */

RZ_IPI void rz_float_trans_ctx_init(TransCtx *ctx, RzFloatFormat format) {
	memset(ctx, 0, sizeof(*ctx));
	ctx->format = format;
	ctx->p = rz_mp_format_prec(format);
	st64 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	ctx->emin = 1 - bias;
	ctx->emax = bias;
	rz_mp_init(&ctx->x, TRANS_OPERAND_PREC);
	rz_mp_init(&ctx->y, TRANS_OPERAND_PREC);
}

RZ_IPI RZ_OWN RzFloat *rz_float_trans_from_mp(TransCtx *ctx, const MpFloat *v, RzFloatRMode mode) {
	return rz_mp_get_float(v, ctx->format, mode);
}

static bool float_same(const RzFloat *a, const RzFloat *b) {
	return a->exception == b->exception && rz_bv_eq(a->s, b->s);
}

/**
 * Ziv's strategy: evaluate with increasing precision until the error
 * interval of the approximation rounds to a single value with the same
 * exception flags in the requested mode.
 */
RZ_IPI RZ_OWN RzFloat *rz_float_trans_round(TransCtx *ctx, TransEval eval, RzFloatRMode mode) {
	ut32 w = ctx->p + 32;
	while (true) {
		MpFloat r;
		bool exact = false;
		rz_mp_init(&r, w + 8);
		eval(&r, ctx, w, &exact);
		if (exact || r.zero) {
			return rz_mp_get_float(&r, ctx->format, mode);
		}
		MpFloat delta, lo, hi;
		rz_mp_init(&delta, 2);
		rz_mp_init(&lo, w + 24);
		rz_mp_init(&hi, w + 24);
		rz_mp_set_2exp(&delta, 1, r.exp - (st64)w, RZ_FLOAT_RMODE_RNE);
		rz_mp_sub(&lo, &r, &delta, RZ_FLOAT_RMODE_RTN);
		rz_mp_add(&hi, &r, &delta, RZ_FLOAT_RMODE_RTP);
		RzFloat *a = rz_mp_get_float(&lo, ctx->format, mode);
		RzFloat *b = rz_mp_get_float(&hi, ctx->format, mode);
		if (!a || !b) {
			rz_float_free(a);
			rz_float_free(b);
			return NULL;
		}
		if (float_same(a, b)) {
			rz_float_free(b);
			return a;
		}
		rz_float_free(a);
		rz_float_free(b);
		if (w >= MP_MAX_PREC - 64) {
			/* Not decided at the precision limit: the result is the
			 * rounding of the best approximation. */
			RzFloat *ret = rz_mp_get_float(&r, ctx->format, mode);
			if (ret) {
				ret->exception |= RZ_FLOAT_E_INEXACT;
			}
			return ret;
		}
		w = RZ_MIN(2 * w, MP_MAX_PREC - 64);
	}
}

/**
 * Proxies: values that round like the exact result in every mode. The
 * caller must know that the exact result lies strictly inside the same
 * rounding cell, on the same side of its midpoint.
 */

/* |result| >= 2^(emax + 1): overflows in every mode */
RZ_IPI void rz_float_trans_proxy_overflow(MpFloat *r, TransCtx *ctx, bool sign) {
	rz_mp_set_2exp(r, sign ? -1 : 1, ctx->emax + 2, RZ_FLOAT_RMODE_RNE);
}

/* 0 < |result| < 2^(emin - p): below half of the smallest subnormal */
RZ_IPI void rz_float_trans_proxy_underflow(MpFloat *r, TransCtx *ctx, bool sign) {
	rz_mp_set_2exp(r, sign ? -1 : 1, ctx->emin - (st64)ctx->p - 2, RZ_FLOAT_RMODE_RNE);
}

/* result = v + tiny with v representable and |tiny| < ulp(v) / 8: v moved
 * towards +inf (up) or -inf by |v| 2^-(p + 3). Also valid for |result| close
 * to 1 from either side (v = +-1). */
RZ_IPI void rz_float_trans_proxy_nudge(MpFloat *r, TransCtx *ctx, const MpFloat *v, bool up) {
	MpFloat d;
	rz_mp_init(&d, ctx->p + 8);
	rz_mp_init(r, ctx->p + 8);
	rz_mp_set(&d, v, RZ_FLOAT_RMODE_RNE);
	rz_mp_abs(&d);
	rz_mp_mul_2si(&d, -(st64)ctx->p - 3);
	if (!up) {
		rz_mp_neg(&d);
	}
	rz_mp_add(r, v, &d, RZ_FLOAT_RMODE_RNE);
}

/** \} */

/**
 * \name Cores
 * \{
 */

static ut32 isqrt32(ut32 v) {
	ut32 r = 0;
	while ((r + 1) * (r + 1) <= v) {
		r++;
	}
	return r;
}

/** r = expm1(t) for |t| < 1, relative error below 2^-w. */
RZ_IPI void rz_float_trans_expm1_small(MpFloat *r, const MpFloat *t, ut32 w) {
	if (t->zero) {
		rz_mp_set_zero(r, t->sign);
		return;
	}
	st64 target = -(st64)(isqrt32(w) / 2 + 1);
	ut32 s = t->exp > target ? (ut32)(t->exp - target) : 0;
	ut32 wp = RZ_MIN(w + s + 24, MP_MAX_PREC);
	MpFloat u, sum, term, tmp;
	rz_mp_init(&u, wp);
	rz_mp_init(&sum, wp);
	rz_mp_init(&term, wp);
	rz_mp_init(&tmp, wp);
	rz_mp_set(&u, t, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&u, -(st64)s);
	rz_mp_set(&sum, &u, RZ_FLOAT_RMODE_RNE);
	rz_mp_set(&term, &u, RZ_FLOAT_RMODE_RNE);
	for (st64 n = 2; n < 100000; n++) {
		rz_mp_mul(&term, &term, &u, RZ_FLOAT_RMODE_RNE);
		rz_mp_div_si(&term, &term, n, RZ_FLOAT_RMODE_RNE);
		if (term.zero || term.exp < sum.exp - (st64)wp - 2) {
			break;
		}
		rz_mp_add(&sum, &sum, &term, RZ_FLOAT_RMODE_RNE);
	}
	/* expm1(2a) = expm1(a) * (expm1(a) + 2) */
	for (ut32 i = 0; i < s; i++) {
		rz_mp_add_si(&tmp, &sum, 2, RZ_FLOAT_RMODE_RNE);
		rz_mp_mul(&sum, &sum, &tmp, RZ_FLOAT_RMODE_RNE);
	}
	rz_mp_set(r, &sum, RZ_FLOAT_RMODE_RNE);
}

/** k = round(x / ln 2) for |x| below 2^40. */
static st64 exp_quotient(const MpFloat *x) {
	MpFloat ln2, q, k;
	rz_mp_init(&ln2, 96);
	rz_mp_init(&q, 96);
	rz_mp_init(&k, 96);
	rz_mp_const_ln2(&ln2);
	rz_mp_div(&q, x, &ln2, RZ_FLOAT_RMODE_RNE);
	rz_mp_round_int(&k, &q, RZ_FLOAT_RMODE_RNE);
	return rz_mp_get_si(&k);
}

/** r = e^x with relative error below 2^-w; |x| < 2^20. */
RZ_IPI void rz_float_trans_exp(MpFloat *r, const MpFloat *x, ut32 w) {
	ut32 wp = RZ_MIN(w + 24, MP_MAX_PREC - 64);
	st64 k = exp_quotient(x);
	MpFloat ln2, t, em1;
	rz_mp_init(&ln2, wp + 64);
	rz_mp_init(&t, wp + 64);
	rz_mp_init(&em1, wp);
	rz_mp_const_ln2(&ln2);
	rz_mp_mul_si(&t, &ln2, k, RZ_FLOAT_RMODE_RNE);
	rz_mp_sub(&t, x, &t, RZ_FLOAT_RMODE_RNE);
	rz_float_trans_expm1_small(&em1, &t, wp);
	rz_mp_add_si(r, &em1, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(r, k);
}

/** r = e^x - 1 with relative error below 2^-w; |x| < 2^20. */
RZ_IPI void rz_float_trans_expm1(MpFloat *r, const MpFloat *x, ut32 w) {
	if (x->exp <= -1) {
		/* |x| < 1/2 */
		rz_float_trans_expm1_small(r, x, w);
		return;
	}
	MpFloat e;
	rz_mp_init(&e, RZ_MIN(w + 8, MP_MAX_PREC));
	rz_float_trans_exp(&e, x, w + 8);
	rz_mp_add_si(r, &e, -1, RZ_FLOAT_RMODE_RNE);
}

/* 2 atanh(u) = 2 (u + u^3/3 + u^5/5 + ...) for |u| <= 1/5, relative 2^-wp. */
static void atanh2_series(MpFloat *r, const MpFloat *u, ut32 wp) {
	MpFloat u2, p, sum, term;
	rz_mp_init(&u2, wp);
	rz_mp_init(&p, wp);
	rz_mp_init(&sum, wp);
	rz_mp_init(&term, wp);
	rz_mp_mul(&u2, u, u, RZ_FLOAT_RMODE_RNE);
	rz_mp_set(&p, u, RZ_FLOAT_RMODE_RNE);
	rz_mp_set(&sum, u, RZ_FLOAT_RMODE_RNE);
	for (st64 n = 3; n < 1000000; n += 2) {
		rz_mp_mul(&p, &p, &u2, RZ_FLOAT_RMODE_RNE);
		rz_mp_div_si(&term, &p, n, RZ_FLOAT_RMODE_RNE);
		if (term.zero || term.exp < sum.exp - (st64)wp - 2) {
			break;
		}
		rz_mp_add(&sum, &sum, &term, RZ_FLOAT_RMODE_RNE);
	}
	rz_mp_set(r, &sum, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(r, 1);
}

/** r = ln(1 + x) for |x| <= 1/4 with relative error below 2^-w (x - 1 exact). */
static void log1p_small(MpFloat *r, const MpFloat *x, ut32 w) {
	ut32 wp = RZ_MIN(w + 24, MP_MAX_PREC);
	MpFloat d, u;
	rz_mp_init(&d, wp);
	rz_mp_init(&u, wp);
	/* u = x / (2 + x) */
	rz_mp_add_si(&d, x, 2, RZ_FLOAT_RMODE_RNE);
	rz_mp_div(&u, x, &d, RZ_FLOAT_RMODE_RNE);
	atanh2_series(r, &u, wp);
}

/** r = ln(x) for x > 0 with relative error below 2^-w. */
RZ_IPI void rz_float_trans_log(MpFloat *r, const MpFloat *x, ut32 w) {
	ut32 wp = RZ_MIN(w + 24, MP_MAX_PREC - 64);
	MpFloat m, sqrt_half, lnm, ln2, t;
	/* x = 2^e m, m in [sqrt(1/2), sqrt(2)) */
	st64 e = x->exp;
	rz_mp_init(&m, RZ_MAX(x->prec, TRANS_OPERAND_PREC));
	rz_mp_set(&m, x, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&m, -e);
	rz_mp_init(&sqrt_half, 64);
	rz_mp_set_si(&sqrt_half, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&sqrt_half, -1);
	rz_mp_sqrt(&sqrt_half, &sqrt_half, RZ_FLOAT_RMODE_RNE);
	if (rz_mp_cmp(&m, &sqrt_half) < 0) {
		rz_mp_mul_2si(&m, 1);
		e--;
	}
	/* ln m = log1p(m - 1), m - 1 is exact */
	/* |m - 1| < m and m - 1 is a multiple of m's last bit: exact at m.prec */
	MpFloat d;
	rz_mp_init(&d, m.prec);
	rz_mp_add_si(&d, &m, -1, RZ_FLOAT_RMODE_RNE);
	rz_mp_init(&lnm, wp);
	if (d.zero) {
		rz_mp_set_zero(&lnm, false);
	} else {
		log1p_small(&lnm, &d, wp);
	}
	if (!e) {
		rz_mp_set(r, &lnm, RZ_FLOAT_RMODE_RNE);
		return;
	}
	rz_mp_init(&ln2, wp + 64);
	rz_mp_init(&t, wp + 64);
	rz_mp_const_ln2(&ln2);
	rz_mp_mul_si(&t, &ln2, e, RZ_FLOAT_RMODE_RNE);
	rz_mp_add(r, &t, &lnm, RZ_FLOAT_RMODE_RNE);
}

/** r = ln(1 + x) for x > -1 with relative error below 2^-w. */
RZ_IPI void rz_float_trans_log1p(MpFloat *r, const MpFloat *x, ut32 w) {
	if (x->exp <= -2) {
		/* |x| < 1/4 */
		log1p_small(r, x, w);
		return;
	}
	/* |ln(1 + x)| >= ln(4/3) / 2: a relative error in 1 + x stays relative */
	MpFloat s;
	rz_mp_init(&s, RZ_MIN(w + 32, MP_MAX_PREC));
	rz_mp_add_si(&s, x, 1, RZ_FLOAT_RMODE_RNE);
	rz_float_trans_log(r, &s, w + 8);
}

/** \} */

/**
 * \name Operand helpers
 * \{
 */

static bool float_sign(const RzFloat *f) {
	return rz_float_is_negative((RzFloat *)f);
}

/* Integer bounds for overflow and underflow of base^x: x > hi overflows,
 * x < lo underflows below half of the smallest subnormal. */
static void exp_bounds(TransCtx *ctx, double ln_base, st64 *lo, st64 *hi) {
	*hi = (st64)ceil((double)(ctx->emax + 1) * M_LN2 / ln_base) + 1;
	*lo = (st64)floor((double)(ctx->emin - (st64)ctx->p) * M_LN2 / ln_base) - 1;
}

static bool mp_x_above(const MpFloat *x, st64 bound) {
	return rz_mp_cmp_si(x, bound) > 0;
}

static bool mp_x_below(const MpFloat *x, st64 bound) {
	return rz_mp_cmp_si(x, bound) < 0;
}

/* exact copy of the operand at a working precision */
static void mp_copy(MpFloat *r, const MpFloat *x, ut32 prec) {
	rz_mp_init(r, RZ_MAX(prec, x->prec));
	rz_mp_set(r, x, RZ_FLOAT_RMODE_RNE);
}

/** \} */

/**
 * \name Exponential functions
 * \{
 */

typedef enum {
	EXP_BASE_E,
	EXP_BASE_2,
	EXP_BASE_10,
} ExpBase;

static double exp_base_ln(ExpBase base) {
	switch (base) {
	case EXP_BASE_2:
		return M_LN2;
	case EXP_BASE_10:
		return M_LN10;
	default:
		return 1.0;
	}
}

/* r = x * ln(base) with relative error below 2^-wp (exact for base e) */
static void exp_scale_arg(MpFloat *r, const MpFloat *x, ExpBase base, ut32 wp) {
	MpFloat c;
	rz_mp_init(&c, wp + 8);
	switch (base) {
	case EXP_BASE_2:
		rz_mp_const_ln2(&c);
		break;
	case EXP_BASE_10:
		rz_mp_const_ln10(&c);
		break;
	default:
		mp_copy(r, x, wp);
		return;
	}
	rz_mp_mul(r, x, &c, RZ_FLOAT_RMODE_RNE);
}

/* 5^n exactly into r (precision large enough), n >= 0 */
static bool mp_pow5(MpFloat *r, st64 n) {
	MpFloat b;
	ut64 bits = (ut64)(n * 2.33) + 8;
	if (bits > MP_MAX_PREC) {
		return false;
	}
	rz_mp_init(&b, MP_MAX_PREC);
	rz_mp_init(r, MP_MAX_PREC);
	rz_mp_set_si(r, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_set_si(&b, 5, RZ_FLOAT_RMODE_RNE);
	for (st64 e = n; e; e >>= 1) {
		if (e & 1) {
			rz_mp_mul(r, r, &b, RZ_FLOAT_RMODE_RNE);
		}
		if (e > 1) {
			rz_mp_mul(&b, &b, &b, RZ_FLOAT_RMODE_RNE);
		}
	}
	return true;
}

/**
 * base^x (- 1 when \p minus_one). Exact results: base 2 at an integer x,
 * base 10 at a nonnegative integer x. Close to 0 (and close to 1 for
 * base^x) a proxy fixes the rounding direction.
 */
static void eval_exp_any(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact, ExpBase base, bool minus_one) {
	const MpFloat *x = &ctx->x;
	st64 lo, hi;
	exp_bounds(ctx, exp_base_ln(base), &lo, &hi);
	if (mp_x_above(x, hi)) {
		rz_float_trans_proxy_overflow(r, ctx, false);
		*exact = true;
		return;
	}
	/* base^x < 2^-(p + 4): base^x - 1 is -1 + tiny */
	st64 m1_bound = (st64)floor(-(double)(ctx->p + 4) * M_LN2 / exp_base_ln(base)) - 1;
	if (minus_one && mp_x_below(x, m1_bound)) {
		MpFloat m1;
		rz_mp_init(&m1, 8);
		rz_mp_set_si(&m1, -1, RZ_FLOAT_RMODE_RNE);
		rz_float_trans_proxy_nudge(r, ctx, &m1, true);
		*exact = true;
		return;
	}
	if (mp_x_below(x, lo)) {
		rz_float_trans_proxy_underflow(r, ctx, false);
		*exact = true;
		return;
	}
	/* |x| (and |x ln(base)|) below 2^-(p + 4) */
	if (x->exp < -(st64)ctx->p - 6) {
		if (!minus_one) {
			/* base^x = 1 + x ln(base) + ... */
			MpFloat one;
			rz_mp_init(&one, 8);
			rz_mp_set_si(&one, 1, RZ_FLOAT_RMODE_RNE);
			rz_float_trans_proxy_nudge(r, ctx, &one, !x->sign);
			*exact = true;
			return;
		}
		if (base == EXP_BASE_E) {
			/* e^x - 1 = x + x^2/2 + ... is above x */
			rz_float_trans_proxy_nudge(r, ctx, x, true);
			*exact = true;
			return;
		}
		/* x ln(base) is not near a representable value: approximate */
	}
	if (rz_mp_is_integer(x) && base != EXP_BASE_E) {
		st64 n = rz_mp_get_si(x);
		MpFloat v;
		bool have = false;
		if (base == EXP_BASE_2) {
			rz_mp_init(&v, 8);
			rz_mp_set_2exp(&v, 1, n, RZ_FLOAT_RMODE_RNE);
			have = true;
		} else if (n >= 0 && mp_pow5(&v, n)) {
			rz_mp_mul_2si(&v, n);
			have = true;
		}
		if (have && !minus_one) {
			rz_mp_init(r, RZ_MAX(v.prec, r->prec));
			rz_mp_set(r, &v, RZ_FLOAT_RMODE_RNE);
			*exact = true;
			return;
		}
		if (have && v.exp <= MP_MAX_PREC - 8 && v.exp >= -(st64)MP_MAX_PREC + 8) {
			/* base^n - 1 exactly */
			rz_mp_init(r, MP_MAX_PREC);
			rz_mp_add_si(r, &v, -1, RZ_FLOAT_RMODE_RNE);
			*exact = true;
			return;
		}
		if (have && base == EXP_BASE_2 && n > 0) {
			/* 2^n - 1 with 1 far below ulp(2^n) / 8 */
			rz_float_trans_proxy_nudge(r, ctx, &v, false);
			*exact = true;
			return;
		}
		/* 10^n - 1 for a large n rounds like 10^n, which is not on a
		 * rounding boundary: approximate */
	}
	ut32 wp = RZ_MIN(w + 16, MP_MAX_PREC - 128);
	MpFloat t;
	rz_mp_init(&t, wp + 64);
	if (minus_one) {
		/* For |x ln(base)| < 1/2 stay relative to the small result. */
		exp_scale_arg(&t, x, base, wp + 64);
		if (t.exp <= -1) {
			rz_float_trans_expm1_small(r, &t, wp);
			return;
		}
	}
	/* base^x = 2^k e^t with t = x ln(base) - k ln 2 */
	MpFloat full, ln2, kl;
	rz_mp_init(&full, wp + 80);
	exp_scale_arg(&full, x, base, wp + 80);
	st64 k = exp_quotient(&full);
	rz_mp_init(&ln2, wp + 80);
	rz_mp_init(&kl, wp + 80);
	rz_mp_const_ln2(&ln2);
	rz_mp_mul_si(&kl, &ln2, k, RZ_FLOAT_RMODE_RNE);
	rz_mp_sub(&t, &full, &kl, RZ_FLOAT_RMODE_RNE);
	MpFloat em1, e;
	rz_mp_init(&em1, wp);
	rz_mp_init(&e, wp + 8);
	rz_float_trans_expm1_small(&em1, &t, wp);
	rz_mp_add_si(&e, &em1, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&e, k);
	if (minus_one) {
		rz_mp_add_si(r, &e, -1, RZ_FLOAT_RMODE_RNE);
	} else {
		rz_mp_set(r, &e, RZ_FLOAT_RMODE_RNE);
	}
}

static void eval_exp(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_exp_any(r, ctx, w, exact, EXP_BASE_E, false);
}

static void eval_expm1(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_exp_any(r, ctx, w, exact, EXP_BASE_E, true);
}

static void eval_exp2(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_exp_any(r, ctx, w, exact, EXP_BASE_2, false);
}

static void eval_exp2m1(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_exp_any(r, ctx, w, exact, EXP_BASE_2, true);
}

static void eval_exp10(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_exp_any(r, ctx, w, exact, EXP_BASE_10, false);
}

static void eval_exp10m1(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_exp_any(r, ctx, w, exact, EXP_BASE_10, true);
}

/** \} */

/**
 * \name Logarithms
 * \{
 */

/* Is |v| = 10^k for an integer k >= 1? Sets k. */
static bool mp_is_pow10(const MpFloat *v, st64 *k) {
	if (!rz_mp_is_integer(v) || v->zero) {
		return false;
	}
	/* v = 2^a * b, b odd: need b = 5^a */
	ut64 total = (ut64)mp_nlimbs(v->prec) * MP_LIMB_BITS;
	st64 a = v->exp - (st64)total + (st64)rz_mp_trailing_zeros(v);
	if (a < 1 || a > 1000) {
		return false;
	}
	MpFloat p;
	if (!mp_pow5(&p, a)) {
		return false;
	}
	rz_mp_mul_2si(&p, a);
	if (rz_mp_cmp_abs(&p, v)) {
		return false;
	}
	*k = a;
	return true;
}

typedef enum {
	LOG_BASE_E,
	LOG_BASE_2,
	LOG_BASE_10,
} LogBase;

/* r = ln(v) / ln(base) with relative error below 2^-w, v > 0 */
static void log_any(MpFloat *r, const MpFloat *v, LogBase base, bool plus_one, ut32 w) {
	ut32 wp = RZ_MIN(w + 16, MP_MAX_PREC - 64);
	MpFloat l, c;
	rz_mp_init(&l, wp);
	if (plus_one) {
		rz_float_trans_log1p(&l, v, wp);
	} else {
		rz_float_trans_log(&l, v, wp);
	}
	if (base == LOG_BASE_E) {
		rz_mp_set(r, &l, RZ_FLOAT_RMODE_RNE);
		return;
	}
	rz_mp_init(&c, wp + 8);
	if (base == LOG_BASE_2) {
		rz_mp_const_ln2(&c);
	} else {
		rz_mp_const_ln10(&c);
	}
	rz_mp_div(r, &l, &c, RZ_FLOAT_RMODE_RNE);
}

/**
 * log_base(x) (of 1 + x when \p plus_one) for x in the domain, not 0 and
 * not 1. Exact results: integer powers of the base (of 1 + x).
 */
static void eval_log_any(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact, LogBase base, bool plus_one) {
	const MpFloat *x = &ctx->x;
	if (plus_one && x->exp < -(st64)ctx->p - 6) {
		/* ln(1 + x) = x - x^2/2 + ... is below x */
		if (base == LOG_BASE_E) {
			rz_float_trans_proxy_nudge(r, ctx, x, false);
			*exact = true;
			return;
		}
		/* x / ln(base) is not close to a representable value */
		rz_mp_init(r, w + 8);
		log_any(r, x, base, true, w);
		return;
	}
	if (plus_one && base == LOG_BASE_2 && !x->sign && x->exp - 1 > (st64)ctx->p + 8 &&
		rz_mp_trailing_zeros(x) + 1 == (ut64)mp_nlimbs(x->prec) * MP_LIMB_BITS) {
		/* x = 2^k: log2(1 + 2^k) = k + log2(1 + 2^-k) lies just above the
		 * integer k, closer than ulp(k) / 8 */
		MpFloat k;
		rz_mp_init(&k, 64);
		rz_mp_set_si(&k, x->exp - 1, RZ_FLOAT_RMODE_RNE);
		rz_float_trans_proxy_nudge(r, ctx, &k, true);
		*exact = true;
		return;
	}
	if (base != LOG_BASE_E) {
		MpFloat s;
		rz_mp_init(&s, 2 * TRANS_OPERAND_PREC + 64);
		if (plus_one) {
			/* 1 + x exactly; x far above 2^(2 * prec) cannot be a power
			 * of the base minus one */
			if (x->exp >= TRANS_OPERAND_PREC || rz_mp_add_si(&s, x, 1, RZ_FLOAT_RMODE_RNE)) {
				rz_mp_set_zero(&s, false);
			}
		} else {
			rz_mp_set(&s, x, RZ_FLOAT_RMODE_RNE);
		}
		if (!s.zero) {
			st64 k;
			bool pow2 = rz_mp_trailing_zeros(&s) + 1 == (ut64)mp_nlimbs(s.prec) * MP_LIMB_BITS;
			if (base == LOG_BASE_2 && pow2) {
				rz_mp_set_si(r, s.exp - 1, RZ_FLOAT_RMODE_RNE);
				*exact = true;
				return;
			}
			if (base == LOG_BASE_10 && mp_is_pow10(&s, &k)) {
				rz_mp_set_si(r, k, RZ_FLOAT_RMODE_RNE);
				*exact = true;
				return;
			}
		}
	}
	log_any(r, x, base, plus_one, w);
}

static void eval_log(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_log_any(r, ctx, w, exact, LOG_BASE_E, false);
}

static void eval_log2(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_log_any(r, ctx, w, exact, LOG_BASE_2, false);
}

static void eval_log10(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_log_any(r, ctx, w, exact, LOG_BASE_10, false);
}

static void eval_logp1(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_log_any(r, ctx, w, exact, LOG_BASE_E, true);
}

static void eval_log2p1(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_log_any(r, ctx, w, exact, LOG_BASE_2, true);
}

static void eval_log10p1(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_log_any(r, ctx, w, exact, LOG_BASE_10, true);
}

/** \} */

/**
 * \name Public operations
 * \{
 */

RZ_IPI RZ_OWN RzFloat *rz_float_trans_unary(RzFloat *x, RzFloatRMode mode, TransEval eval) {
	TransCtx ctx;
	rz_float_trans_ctx_init(&ctx, x->r);
	if (!rz_mp_set_float(&ctx.x, x)) {
		return NULL;
	}
	return rz_float_trans_round(&ctx, eval, mode);
}

/* exp family: f(+-0) = 1 (or +-0 for the minus-one variants),
 * f(+inf) = +inf, f(-inf) = +0 (or -1) */
static RzFloat *exp_family(RzFloat *x, RzFloatRMode mode, TransEval eval, bool minus_one) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	bool neg = float_sign(x);
	if (rz_float_trans_is_inf(x)) {
		if (!neg) {
			return rz_float_trans_inf(x->r, false);
		}
		return minus_one ? rz_float_trans_si(x->r, -1) : rz_float_trans_zero(x->r, false);
	}
	if (rz_float_trans_is_zero(x)) {
		return minus_one ? rz_float_trans_zero(x->r, neg) : rz_float_trans_si(x->r, 1);
	}
	return rz_float_trans_unary(x, mode, eval);
}

/**
 * \brief e^x correctly rounded (IEEE 754-2019 9.2 exp).
 * \param x operand
 * \param mode rounding mode
 * \return the result in the format of \p x with its exception flags
 */
RZ_API RZ_OWN RzFloat *rz_float_exp(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return exp_family(x, mode, eval_exp, false);
}

/** \brief e^x - 1 correctly rounded (IEEE 754-2019 9.2 expm1). */
RZ_API RZ_OWN RzFloat *rz_float_expm1(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return exp_family(x, mode, eval_expm1, true);
}

/** \brief 2^x correctly rounded (IEEE 754-2019 9.2 exp2). */
RZ_API RZ_OWN RzFloat *rz_float_exp2(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return exp_family(x, mode, eval_exp2, false);
}

/** \brief 2^x - 1 correctly rounded (IEEE 754-2019 9.2 exp2m1). */
RZ_API RZ_OWN RzFloat *rz_float_exp2m1(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return exp_family(x, mode, eval_exp2m1, true);
}

/** \brief 10^x correctly rounded (IEEE 754-2019 9.2 exp10). */
RZ_API RZ_OWN RzFloat *rz_float_exp10(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return exp_family(x, mode, eval_exp10, false);
}

/** \brief 10^x - 1 correctly rounded (IEEE 754-2019 9.2 exp10m1). */
RZ_API RZ_OWN RzFloat *rz_float_exp10m1(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return exp_family(x, mode, eval_exp10m1, true);
}

/* log family: log(+-0) = -inf (divide by zero), log(1) = +0, log(x < 0) is
 * invalid, log(+inf) = +inf. The p1 variants shift the domain by one and
 * return +-0 for +-0. */
static RzFloat *log_family(RzFloat *x, RzFloatRMode mode, TransEval eval, bool plus_one) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	bool neg = float_sign(x);
	if (rz_float_trans_is_inf(x)) {
		return neg ? rz_float_trans_invalid(x->r) : rz_float_trans_inf(x->r, false);
	}
	if (rz_float_trans_is_zero(x)) {
		return plus_one ? rz_float_trans_zero(x->r, neg) : rz_float_trans_div_zero(x->r, true);
	}
	TransCtx ctx;
	rz_float_trans_ctx_init(&ctx, x->r);
	rz_mp_set_float(&ctx.x, x);
	if (plus_one) {
		int c = rz_mp_cmp_si(&ctx.x, -1);
		if (!c) {
			return rz_float_trans_div_zero(x->r, true);
		}
		if (c < 0) {
			return rz_float_trans_invalid(x->r);
		}
	} else {
		if (neg) {
			return rz_float_trans_invalid(x->r);
		}
		if (!rz_mp_cmp_si(&ctx.x, 1)) {
			return rz_float_trans_zero(x->r, false);
		}
	}
	return rz_float_trans_round(&ctx, eval, mode);
}

/** \brief ln(x) correctly rounded (IEEE 754-2019 9.2 log). */
RZ_API RZ_OWN RzFloat *rz_float_log(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return log_family(x, mode, eval_log, false);
}

/** \brief log2(x) correctly rounded (IEEE 754-2019 9.2 log2). */
RZ_API RZ_OWN RzFloat *rz_float_log2(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return log_family(x, mode, eval_log2, false);
}

/** \brief log10(x) correctly rounded (IEEE 754-2019 9.2 log10). */
RZ_API RZ_OWN RzFloat *rz_float_log10(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return log_family(x, mode, eval_log10, false);
}

/** \brief ln(1 + x) correctly rounded (IEEE 754-2019 9.2 logp1). */
RZ_API RZ_OWN RzFloat *rz_float_logp1(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return log_family(x, mode, eval_logp1, true);
}

/** \brief log2(1 + x) correctly rounded (IEEE 754-2019 9.2 log2p1). */
RZ_API RZ_OWN RzFloat *rz_float_log2p1(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return log_family(x, mode, eval_log2p1, true);
}

/** \brief log10(1 + x) correctly rounded (IEEE 754-2019 9.2 log10p1). */
RZ_API RZ_OWN RzFloat *rz_float_log10p1(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return log_family(x, mode, eval_log10p1, true);
}

/** \} */
