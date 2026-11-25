// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file float_trans_trig.c
 * Trigonometric functions of the IEEE 754-2019 9.2 recommended operations:
 * sin, cos, tan, sinPi, cosPi, tanPi, asin, acos, atan, asinPi, acosPi,
 * atanPi, atan2 and atan2Pi. See float_trans.h.
 *
 * Exact results are recognized before Ziv's loop:
 * - By the Lindemann-Weierstrass theorem sin, cos and tan of a nonzero
 *   rational number, asin, acos and atan of a rational number other than 0
 *   (1 for acos) and nonzero rational multiples of pi are transcendental:
 *   never representable and never a midpoint. So are pi/2 -+ atan(q) and
 *   pi - atan(q) in atan2 (a rational value would make cot or tan of a
 *   nonzero rational algebraic).
 * - By Niven's theorem sin(pi x) and cos(pi x) of a rational x are rational
 *   only when they are 0, +-1/2 or +-1, and tan(pi x) only when it is 0 or
 *   +-1. Values +-1/2 need a non-dyadic x (1/6, 1/3, ...), so for a binary
 *   float x sinPi and cosPi are exact iff 2x is an integer, tanPi iff 4x is.
 *   For the same reason asinPi, acosPi, atanPi and atan2Pi are dyadic only
 *   at those values; asinPi(1/2) = 1/6 and the like are not dyadic and
 *   thus not on a rounding boundary.
 */

#include "float_trans.h"
#include <rz_util/rz_assert.h>

typedef enum {
	TRIG_SIN,
	TRIG_COS,
	TRIG_TAN,
} TrigFn;

/**
 * \name Helpers
 * \{
 */

/* Working precision: the guard bits absorb the few hundred roundings of the
 * reductions and series below (each analysed to stay below 2^(10 - wp)). */
static ut32 trig_wp(ut32 w) {
	return RZ_MIN(w + 40, MP_MAX_PREC - 16);
}

static bool float_sign(const RzFloat *f) {
	return rz_float_is_negative((RzFloat *)f);
}

/* exact copy of x at precision >= prec */
static void mp_copy(MpFloat *r, const MpFloat *x, ut32 prec) {
	rz_mp_init(r, RZ_MAX(prec, x->prec));
	rz_mp_set(r, x, RZ_FLOAT_RMODE_RNE);
}

/* |v| < 2^e implies v^2 < 2^-(p + 6) */
static bool tiny_square(st64 e, ut32 p) {
	return 2 * e + (st64)p + 6 <= 0;
}

/* the exact value num * 2^e in the format, without exception */
static RzFloat *float_exact(RzFloatFormat format, st64 num, st64 e) {
	MpFloat t;
	rz_mp_init(&t, 64);
	rz_mp_set_2exp(&t, num, e, RZ_FLOAT_RMODE_RNE);
	return rz_mp_get_float(&t, format, RZ_FLOAT_RMODE_RNE);
}

/* r = num * 2^e exactly, a small precision suffices */
static void mp_small(MpFloat *r, st64 num, st64 e) {
	rz_mp_init(r, 64);
	rz_mp_set_2exp(r, num, e, RZ_FLOAT_RMODE_RNE);
}

/* r = pi with relative error below 2^-prec */
static void mp_pi(MpFloat *r, ut32 prec) {
	rz_mp_init(r, RZ_MIN(prec, MP_MAX_PREC));
	rz_mp_const_pi(r);
}

/* r = a / pi with relative error below 2^(1 - wp) beyond that of a */
static void mp_div_pi(MpFloat *r, const MpFloat *a, ut32 wp) {
	MpFloat pi;
	mp_pi(&pi, wp + 8);
	rz_mp_div(r, a, &pi, RZ_FLOAT_RMODE_RNE);
}

static void nudge_si(MpFloat *r, TransCtx *ctx, st64 num, st64 e, bool up) {
	MpFloat v;
	mp_small(&v, num, e);
	rz_float_trans_proxy_nudge(r, ctx, &v, up);
}

/* k pi / 4 for the nonzero integer k = ctx->n */
static void eval_pi_quarter(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	MpFloat pi;
	mp_pi(&pi, trig_wp(w));
	rz_mp_mul_si(r, &pi, ctx->n, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(r, -2);
}

/* k pi / 4 correctly rounded (inexact), or k / 4 exactly in units of pi */
static RzFloat *float_quarter(RzFloatFormat format, st64 k, bool pi_units, RzFloatRMode mode) {
	if (pi_units) {
		return float_exact(format, k, -2);
	}
	TransCtx ctx;
	rz_float_trans_ctx_init(&ctx, format);
	ctx.n = k;
	return rz_float_trans_round(&ctx, eval_pi_quarter, mode);
}

/** \} */

/**
 * \name Cores
 * \{
 */

/**
 * r = sin(v) or cos(v) for |v| <= 1 with relative error below 2^(9 - wp):
 * at most 170 terms with 2 roundings each, partial sums within a factor 2
 * of the result (sin(v) / v >= sin 1, cos v >= cos 1).
 */
static void sincos_series(MpFloat *r, const MpFloat *v, bool cosine, ut32 wp) {
	MpFloat u, term, sum;
	rz_mp_init(&u, wp);
	rz_mp_init(&term, wp);
	rz_mp_init(&sum, wp);
	rz_mp_mul(&u, v, v, RZ_FLOAT_RMODE_RNE);
	if (cosine) {
		rz_mp_set_si(&term, 1, RZ_FLOAT_RMODE_RNE);
	} else {
		rz_mp_set(&term, v, RZ_FLOAT_RMODE_RNE);
	}
	rz_mp_set(&sum, &term, RZ_FLOAT_RMODE_RNE);
	/* alternating with decreasing terms: the tail is below the first
	 * omitted term */
	for (st64 n = cosine ? 1 : 2; n < 100000; n += 2) {
		rz_mp_mul(&term, &term, &u, RZ_FLOAT_RMODE_RNE);
		rz_mp_div_si(&term, &term, -n * (n + 1), RZ_FLOAT_RMODE_RNE);
		if (term.zero || term.exp < sum.exp - (st64)wp - 2) {
			break;
		}
		rz_mp_add(&sum, &sum, &term, RZ_FLOAT_RMODE_RNE);
	}
	rz_mp_set(r, &sum, RZ_FLOAT_RMODE_RNE);
}

static ut32 isqrt32(ut32 v) {
	ut32 r = 0;
	while ((r + 1) * (r + 1) <= v) {
		r++;
	}
	return r;
}

/**
 * r = atan(a) for 0 < a <= 1 with relative error below 2^(10 - wp).
 * Each halving step atan(a) = 2 atan(a / (1 + sqrt(1 + a^2))) costs 4
 * roundings (relative condition of the step <= 1), then the alternating
 * series a - a^3/3 + ... runs with |a| < 2^(2 - sqrt(wp)/2).
 */
static void atan_unit(MpFloat *r, const MpFloat *x, ut32 wp) {
	st64 target = -(st64)(isqrt32(wp) / 2 + 2);
	MpFloat a, t, a2, pw, sum;
	rz_mp_init(&a, wp);
	rz_mp_init(&t, wp);
	rz_mp_set(&a, x, RZ_FLOAT_RMODE_RNE);
	st64 s = 0;
	while (a.exp > target) {
		rz_mp_mul(&t, &a, &a, RZ_FLOAT_RMODE_RNE);
		rz_mp_add_si(&t, &t, 1, RZ_FLOAT_RMODE_RNE);
		rz_mp_sqrt(&t, &t, RZ_FLOAT_RMODE_RNE);
		rz_mp_add_si(&t, &t, 1, RZ_FLOAT_RMODE_RNE);
		rz_mp_div(&a, &a, &t, RZ_FLOAT_RMODE_RNE);
		s++;
	}
	rz_mp_init(&a2, wp);
	rz_mp_init(&pw, wp);
	rz_mp_init(&sum, wp);
	rz_mp_mul(&a2, &a, &a, RZ_FLOAT_RMODE_RNE);
	rz_mp_set(&pw, &a, RZ_FLOAT_RMODE_RNE);
	rz_mp_set(&sum, &a, RZ_FLOAT_RMODE_RNE);
	for (st64 n = 3; n < 1000000; n += 2) {
		rz_mp_mul(&pw, &pw, &a2, RZ_FLOAT_RMODE_RNE);
		rz_mp_div_si(&t, &pw, n, RZ_FLOAT_RMODE_RNE);
		if (t.zero || t.exp < sum.exp - (st64)wp - 2) {
			break;
		}
		if ((n / 2) & 1) {
			rz_mp_sub(&sum, &sum, &t, RZ_FLOAT_RMODE_RNE);
		} else {
			rz_mp_add(&sum, &sum, &t, RZ_FLOAT_RMODE_RNE);
		}
	}
	rz_mp_set(r, &sum, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(r, s);
}

/**
 * r = atan(x) for any finite x with relative error below 2^-w (w at most
 * MP_MAX_PREC - 24), plus the rounding to the precision of r. The relative
 * condition number of atan is at most 1, so a relative error of x adds to
 * that of the result.
 */
RZ_IPI void rz_float_trans_atan(MpFloat *r, const MpFloat *x, ut32 w) {
	if (x->zero) {
		rz_mp_set_zero(r, x->sign);
		return;
	}
	ut32 wp = RZ_MIN(w + 16, MP_MAX_PREC - 8);
	MpFloat a, t, c;
	rz_mp_init(&a, wp);
	rz_mp_init(&t, wp);
	rz_mp_set(&a, x, RZ_FLOAT_RMODE_RNE);
	rz_mp_abs(&a);
	int cmp = rz_mp_cmp_si(&a, 1);
	if (cmp > 0) {
		/* atan(a) = pi/2 - atan(1/a) >= pi/4 with atan(1/a) < pi/4 */
		rz_mp_init(&c, wp);
		rz_mp_set_si(&c, 1, RZ_FLOAT_RMODE_RNE);
		rz_mp_div(&a, &c, &a, RZ_FLOAT_RMODE_RNE);
		atan_unit(&t, &a, wp);
		mp_pi(&c, wp + 8);
		rz_mp_mul_2si(&c, -1);
		rz_mp_sub(r, &c, &t, RZ_FLOAT_RMODE_RNE);
	} else if (cmp == 0) {
		mp_pi(&c, wp + 8);
		rz_mp_set(r, &c, RZ_FLOAT_RMODE_RNE);
		rz_mp_mul_2si(r, -2);
	} else {
		atan_unit(&t, &a, wp);
		rz_mp_set(r, &t, RZ_FLOAT_RMODE_RNE);
	}
	if (x->sign) {
		rz_mp_neg(r);
	}
}

/** \} */

/**
 * \name Argument reduction
 * \{
 */

/* enough for wp + 128 + the worst cancellation + retry margins */
#define TRIG_MAX_LIMBS 128
/* clears the two quadrant bits at the top of a limb */
#define TRIG_FRAC_MASK (((MpLimb)1 << (MP_LIMB_BITS - 2)) - 1)

/* r = (a * b) mod 2^(32 n), a of an limbs and b of n limbs */
static void limbs_mul_low(MpLimb *r, const MpLimb *a, ut32 an, const MpLimb *b, ut32 n) {
	memset(r, 0, n * sizeof(MpLimb));
	for (ut32 i = 0; i < an && i < n; i++) {
		ut64 carry = 0;
		for (ut32 j = 0; i + j < n; j++) {
			carry += (ut64)a[i] * b[j] + r[i + j];
			r[i + j] = (MpLimb)carry;
			carry >>= MP_LIMB_BITS;
		}
	}
}

static st64 limbs_bitlen(const MpLimb *a, ut32 n) {
	for (ut32 i = n; i-- > 0;) {
		if (a[i]) {
			ut32 b = MP_LIMB_BITS;
			while (!((a[i] >> (b - 1)) & 1)) {
				b--;
			}
			return (st64)i * MP_LIMB_BITS + b;
		}
	}
	return 0;
}

/* the 32 bits of a (n limbs) from bit pos up, bits outside a are zero */
static MpLimb limbs_get32(const MpLimb *a, ut32 n, st64 pos) {
	MpLimb v = 0;
	for (ut32 i = 0; i < MP_LIMB_BITS; i++) {
		st64 b = pos + i;
		if (b >= 0 && b < (st64)n * MP_LIMB_BITS && ((a[b / MP_LIMB_BITS] >> (b % MP_LIMB_BITS)) & 1)) {
			v |= (MpLimb)1 << i;
		}
	}
	return v;
}

/**
 * Payne-Hanek reduction of x > 0: x * 2/pi = 4k + q + f with |f| <= 1/2.
 * Sets r = f pi / 2 (precision of r at least wp) with relative error below
 * 2^(2 - wp) and returns q.
 *
 * With x = M 2^e (M < 2^m, m = 32 limbs of x), the bits of 2/pi of weight
 * 2^-(e - 2) and more contribute multiples of 4 and are skipped. An N-bit window
 * leaves a tail below M 2^(2 - N), i.e. 2^m units of the last fraction bit,
 * so the fraction is accurate once it has m + wp + 3 significant bits; the
 * window grows until it does. The cancellation is bounded: the minimum of
 * |f| over all floats (from the best approximations of 2^e 2/pi for every
 * exponent e) is about 2^-16.7, 2^-29.9, 2^-61.5, 2^-76.2 and 2^-123.9 for
 * binary16, 32, 64, 80 and 128, so even at MP_MAX_PREC the window ends
 * before bit 18600 of the 18816-bit table.
 */
static int trig_reduce(MpFloat *r, const MpFloat *x, ut32 wp) {
	ut32 xn = mp_nlimbs(x->prec);
	st64 m = (st64)xn * MP_LIMB_BITS;
	st64 first = x->exp - m - 2;
	st64 need = m + (st64)wp + 64;
	MpLimb win[TRIG_MAX_LIMBS], prod[TRIG_MAX_LIMBS];
	ut32 n;
	int q;
	bool neg;
	st64 g;
	while (true) {
		n = (ut32)RZ_MIN((need + MP_LIMB_BITS - 1) / MP_LIMB_BITS, (st64)TRIG_MAX_LIMBS);
		bool last = n == TRIG_MAX_LIMBS;
		if (!rz_mp_two_over_pi_window(win, n, first)) {
			last = true;
		}
		if (last) {
			/* unreachable by the bound above: use the widest window */
			rz_warn_if_reached();
			while (n > 1 && !rz_mp_two_over_pi_window(win, n, first)) {
				n--;
			}
		}
		limbs_mul_low(prod, x->d, xn, win, n);
		/* the top two bits are q, then the fraction f in [0, 1) */
		q = (int)(prod[n - 1] >> (MP_LIMB_BITS - 2));
		prod[n - 1] &= TRIG_FRAC_MASK;
		neg = (prod[n - 1] >> (MP_LIMB_BITS - 3)) & 1;
		if (neg) {
			/* f - 1 in [-1/2, 0): negate modulo 2^(32 n - 2) */
			ut64 carry = 1;
			for (ut32 i = 0; i < n; i++) {
				carry += (MpLimb)~prod[i];
				prod[i] = (MpLimb)carry;
				carry >>= MP_LIMB_BITS;
			}
			prod[n - 1] &= TRIG_FRAC_MASK;
			q = (q + 1) & 3;
		}
		g = limbs_bitlen(prod, n);
		if (g >= m + (st64)wp + 3 || last) {
			break;
		}
		need += m + (st64)wp + 3 - g + MP_LIMB_BITS;
	}
	if (!g) {
		rz_mp_set_zero(r, false);
		return q;
	}
	/* f = prod / 2^(32 n - 2), truncated to its top 32 L bits */
	ut32 limbs = RZ_MIN((wp + 34 + MP_LIMB_BITS - 1) / MP_LIMB_BITS, MP_MAX_LIMBS);
	MpFloat f, pi;
	rz_mp_init(&f, limbs * MP_LIMB_BITS);
	for (ut32 k = 0; k < limbs; k++) {
		f.d[k] = limbs_get32(prod, n, g - (st64)(limbs - k) * MP_LIMB_BITS);
	}
	f.zero = false;
	f.sign = neg;
	f.exp = g - ((st64)n * MP_LIMB_BITS - 2);
	mp_pi(&pi, wp + 8);
	rz_mp_mul(r, &f, &pi, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(r, -1);
	return q;
}

/**
 * Exact binary reduction for the pi functions: x = 2k + j/2 + u with an
 * integer k, j in -2 .. 2 and |u| <= 1/4. Sets u and returns j mod 4.
 * Every float with |x| >= 2^p is an even integer.
 */
static int pi_reduce(MpFloat *u, const MpFloat *x, ut32 p) {
	if (x->exp > (st64)p) {
		rz_mp_set_zero(u, x->sign);
		return 0;
	}
	/* the operations are exact: x has at most p significant bits and
	 * |x| < 2^p, so t and u live on the grid of x within [-1, 1] */
	MpFloat h, k, t;
	rz_mp_init(&h, 2 * TRANS_OPERAND_PREC);
	rz_mp_init(&k, 2 * TRANS_OPERAND_PREC);
	rz_mp_init(&t, 2 * TRANS_OPERAND_PREC);
	rz_mp_set(&h, x, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&h, -1);
	rz_mp_round_int(&k, &h, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&k, 1);
	rz_mp_sub(&t, x, &k, RZ_FLOAT_RMODE_RNE);
	rz_mp_set(&h, &t, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&h, 1);
	rz_mp_round_int(&k, &h, RZ_FLOAT_RMODE_RNE);
	st64 j = rz_mp_get_si(&k);
	rz_mp_mul_2si(&k, -1);
	rz_mp_sub(u, &t, &k, RZ_FLOAT_RMODE_RNE);
	return (int)(j & 3);
}

/** \} */

/**
 * \name Sine, cosine and tangent
 * \{
 */

/**
 * f(q pi/2 + v) for f = sin, cos, tan (negated when \p neg), from sin(v)
 * and cos(v) with |v| <= 1 known with relative error below 2^(2 - wp) and
 * |v| < 2^ve. The relative condition numbers of sin, cos, tan and cot at
 * |v| <= 1 are below 3. A result +-cos(v) with a tiny v is +-1 moved
 * towards zero by at most v^2/2 < 2^-(p + 7), which a proxy rounds.
 */
static void trig_quadrant(MpFloat *r, TransCtx *ctx, TrigFn fn, int q, const MpFloat *v, st64 ve, bool neg, ut32 wp, bool *exact) {
	bool odd = q & 1;
	if (fn == TRIG_TAN) {
		MpFloat s, c;
		rz_mp_init(&s, wp);
		rz_mp_init(&c, wp);
		sincos_series(&s, v, false, wp);
		sincos_series(&c, v, true, wp);
		/* tan(v), or -cot(v) in the odd quadrants */
		if (odd) {
			rz_mp_div(r, &c, &s, RZ_FLOAT_RMODE_RNE);
			neg = !neg;
		} else {
			rz_mp_div(r, &s, &c, RZ_FLOAT_RMODE_RNE);
		}
		if (neg) {
			rz_mp_neg(r);
		}
		return;
	}
	bool cosine = (fn == TRIG_COS) != odd;
	bool negate = neg != (fn == TRIG_SIN ? q >= 2 : (q == 1 || q == 2));
	if (cosine && tiny_square(ve, ctx->p)) {
		nudge_si(r, ctx, negate ? -1 : 1, 0, negate);
		*exact = true;
		return;
	}
	sincos_series(r, v, cosine, wp);
	if (negate) {
		rz_mp_neg(r);
	}
}

static void eval_trig(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact, TrigFn fn) {
	const MpFloat *x = &ctx->x;
	if (fn != TRIG_COS && tiny_square(x->exp, ctx->p)) {
		/* sin(x) = x (1 - x^2/6 + ...) is below |x|, tan(x) =
		 * x (1 + x^2/3 + ...) above, both within |x| 2^-(p + 6) */
		rz_float_trans_proxy_nudge(r, ctx, x, (fn == TRIG_TAN) != x->sign);
		*exact = true;
		return;
	}
	ut32 wp = trig_wp(w);
	MpFloat v, ax;
	rz_mp_init(&v, wp);
	int q = 0;
	st64 ve;
	if (x->exp <= 0) {
		/* |x| < 1 needs no reduction, v = |x| exactly */
		rz_mp_set(&v, x, RZ_FLOAT_RMODE_RNE);
		rz_mp_abs(&v);
		ve = x->exp;
	} else {
		mp_copy(&ax, x, TRANS_OPERAND_PREC);
		rz_mp_abs(&ax);
		q = trig_reduce(&v, &ax, wp);
		ve = v.exp + 1;
	}
	/* sin and tan are odd, cos is even */
	trig_quadrant(r, ctx, fn, q, &v, ve, x->sign && fn != TRIG_COS, wp, exact);
}

static void eval_sin(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_trig(r, ctx, w, exact, TRIG_SIN);
}

static void eval_cos(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_trig(r, ctx, w, exact, TRIG_COS);
}

static void eval_tan(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_trig(r, ctx, w, exact, TRIG_TAN);
}

/* f(pi x) with x = 2k + j/2 + u, u = ctx->y and j = ctx->n from pi_reduce */
static void eval_trig_pi(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact, TrigFn fn) {
	ut32 wp = trig_wp(w);
	MpFloat pi, v;
	mp_pi(&pi, wp + 8);
	rz_mp_init(&v, wp);
	rz_mp_mul(&v, &ctx->y, &pi, RZ_FLOAT_RMODE_RNE);
	/* |pi u| < 2^(u.exp + 2) */
	trig_quadrant(r, ctx, fn, (int)ctx->n, &v, ctx->y.exp + 2, false, wp, exact);
}

static void eval_sinpi(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_trig_pi(r, ctx, w, exact, TRIG_SIN);
}

static void eval_cospi(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_trig_pi(r, ctx, w, exact, TRIG_COS);
}

static void eval_tanpi(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_trig_pi(r, ctx, w, exact, TRIG_TAN);
}

/** \} */

/**
 * \name Inverse functions
 * \{
 */

/**
 * asin, acos, atan of x (finite, nonzero, |x| < 1 for asin and acos), divided
 * by pi when \p pi_units. Near-representable results take proxies.
 */
static void eval_arc(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact, TrigFn fn, bool pi_units) {
	const MpFloat *x = &ctx->x;
	ut32 p = ctx->p;
	if (!pi_units && fn != TRIG_COS && tiny_square(x->exp, p)) {
		/* asin(x) = x (1 + x^2/6 + ...) is above |x|, atan(x) =
		 * x (1 - x^2/3 + ...) below, both within |x| 2^-(p + 6) */
		rz_float_trans_proxy_nudge(r, ctx, x, (fn == TRIG_SIN) != x->sign);
		*exact = true;
		return;
	}
	if (pi_units && fn == TRIG_COS && x->exp + (st64)p + 5 <= 0) {
		/* acosPi(x) = 1/2 - asin(x)/pi with |asin(x)/pi| < |x|/2 below
		 * 2^-(p + 6) */
		nudge_si(r, ctx, 1, -1, x->sign);
		*exact = true;
		return;
	}
	if (pi_units && fn == TRIG_TAN && x->exp >= (st64)p + 6) {
		/* atanPi(x) = +-(1/2 - atan(1/|x|)/pi) with atan(1/|x|)/pi below
		 * 1/|x| <= 2^-(p + 5) */
		nudge_si(r, ctx, x->sign ? -1 : 1, -1, x->sign);
		*exact = true;
		return;
	}
	ut32 wp = trig_wp(w);
	MpFloat a, d, s, t;
	rz_mp_init(&a, wp);
	rz_mp_init(&d, wp);
	rz_mp_init(&s, wp);
	rz_mp_init(&t, wp);
	rz_mp_set(&a, x, RZ_FLOAT_RMODE_RNE);
	switch (fn) {
	case TRIG_SIN:
		/* asin(|x|) = atan(|x| / sqrt((1 - |x|)(1 + |x|))), 1 - |x| is
		 * exact where it is small (Sterbenz) */
		rz_mp_abs(&a);
		rz_mp_set_si(&d, 1, RZ_FLOAT_RMODE_RNE);
		rz_mp_sub(&d, &d, &a, RZ_FLOAT_RMODE_RNE);
		rz_mp_add_si(&s, &a, 1, RZ_FLOAT_RMODE_RNE);
		rz_mp_mul(&d, &d, &s, RZ_FLOAT_RMODE_RNE);
		rz_mp_sqrt(&d, &d, RZ_FLOAT_RMODE_RNE);
		rz_mp_div(&t, &a, &d, RZ_FLOAT_RMODE_RNE);
		rz_float_trans_atan(&s, &t, wp);
		if (x->sign) {
			rz_mp_neg(&s);
		}
		break;
	case TRIG_COS:
		/* acos(x) = 2 atan(sqrt((1 - x) / (1 + x))), 1 -+ x are exact
		 * where they are small (Sterbenz) */
		rz_mp_set_si(&d, 1, RZ_FLOAT_RMODE_RNE);
		rz_mp_sub(&d, &d, &a, RZ_FLOAT_RMODE_RNE);
		rz_mp_add_si(&s, &a, 1, RZ_FLOAT_RMODE_RNE);
		rz_mp_div(&d, &d, &s, RZ_FLOAT_RMODE_RNE);
		rz_mp_sqrt(&t, &d, RZ_FLOAT_RMODE_RNE);
		rz_float_trans_atan(&s, &t, wp);
		rz_mp_mul_2si(&s, 1);
		break;
	default:
		rz_float_trans_atan(&s, &a, wp);
		break;
	}
	if (pi_units) {
		mp_div_pi(r, &s, wp);
	} else {
		rz_mp_set(r, &s, RZ_FLOAT_RMODE_RNE);
	}
}

static void eval_asin(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_arc(r, ctx, w, exact, TRIG_SIN, false);
}

static void eval_acos(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_arc(r, ctx, w, exact, TRIG_COS, false);
}

static void eval_atan(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_arc(r, ctx, w, exact, TRIG_TAN, false);
}

static void eval_asinpi(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_arc(r, ctx, w, exact, TRIG_SIN, true);
}

static void eval_acospi(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_arc(r, ctx, w, exact, TRIG_COS, true);
}

static void eval_atanpi(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_arc(r, ctx, w, exact, TRIG_TAN, true);
}

/**
 * atan2(y, x) (divided by pi when \p pi_units) for finite nonzero y = ctx->y
 * and x = ctx->x, |y| != |x| in units of pi.
 */
static void eval_atan2_any(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact, bool pi_units) {
	const MpFloat *y = &ctx->y;
	const MpFloat *x = &ctx->x;
	st64 p = ctx->p;
	bool neg = y->sign;
	bool left = x->sign;
	/* 2^(e - 1) < |y / x| < 2^(e + 1) */
	st64 e = y->exp - x->exp;
	if (!pi_units && !left && e + p + 6 <= 0) {
		/* atan(q) = q (1 - d) with 0 < d < q^2/3 < 2^-(2p + 10) for
		 * q = y / x. As q = Y / X 2^k with p-bit integers Y, X, q is a
		 * rounding boundary or at least |q| 2^-(2p + 1) away from one, so
		 * q moved towards zero by |q| 2^-(2p + 6) (computed within
		 * 2^-(2p + 15)) rounds like atan(q). */
		ut32 qp = 2 * (ut32)p + 16;
		MpFloat q, d;
		rz_mp_init(&q, qp);
		rz_mp_init(&d, qp);
		rz_mp_div(&q, y, x, RZ_FLOAT_RMODE_RNE);
		rz_mp_set(&d, &q, RZ_FLOAT_RMODE_RNE);
		rz_mp_mul_2si(&d, -(2 * p + 6));
		rz_mp_init(r, qp + 8);
		rz_mp_sub(r, &q, &d, RZ_FLOAT_RMODE_RNE);
		*exact = true;
		return;
	}
	if (pi_units && left && e + p + 5 <= 0) {
		/* +-(1 - atan(|q|)/pi) with atan(|q|)/pi < |q|/3 < 2^-(p + 5) */
		nudge_si(r, ctx, neg ? -1 : 1, 0, neg);
		*exact = true;
		return;
	}
	if (pi_units && e >= p + 6) {
		/* +-(1/2 -+ atan(1/|q|)/pi) with atan(1/|q|)/pi < 2^-(p + 6) */
		nudge_si(r, ctx, neg ? -1 : 1, -1, neg != left);
		*exact = true;
		return;
	}
	ut32 wp = trig_wp(w);
	MpFloat a, b, q, t, c;
	mp_copy(&a, y, TRANS_OPERAND_PREC);
	mp_copy(&b, x, TRANS_OPERAND_PREC);
	rz_mp_abs(&a);
	rz_mp_abs(&b);
	bool steep = rz_mp_cmp_abs(&a, &b) > 0;
	rz_mp_init(&q, wp);
	rz_mp_init(&t, wp);
	if (steep) {
		rz_mp_div(&q, &b, &a, RZ_FLOAT_RMODE_RNE);
	} else {
		rz_mp_div(&q, &a, &b, RZ_FLOAT_RMODE_RNE);
	}
	rz_float_trans_atan(&t, &q, wp);
	/* atan(a/b) = pi/2 - atan(b/a), the left half-plane reflects to
	 * pi - atan(a/b): no cancellation, the results are >= pi/4 */
	if (steep || left) {
		mp_pi(&c, wp + 8);
		if (steep) {
			rz_mp_mul_2si(&c, -1);
		}
		if (steep && left) {
			rz_mp_add(&t, &c, &t, RZ_FLOAT_RMODE_RNE);
		} else {
			rz_mp_sub(&t, &c, &t, RZ_FLOAT_RMODE_RNE);
		}
	}
	if (pi_units) {
		mp_div_pi(r, &t, wp);
	} else {
		rz_mp_set(r, &t, RZ_FLOAT_RMODE_RNE);
	}
	if (neg) {
		rz_mp_neg(r);
	}
}

static void eval_atan2(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_atan2_any(r, ctx, w, exact, false);
}

static void eval_atan2pi(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	eval_atan2_any(r, ctx, w, exact, true);
}

/** \} */

/**
 * \name Public operations
 * \{
 */

/* sin(+-0) = +-0, cos(+-0) = 1, tan(+-0) = +-0, infinities are invalid */
static RzFloat *trig_family(RzFloat *x, RzFloatRMode mode, TrigFn fn, TransEval eval) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	if (rz_float_trans_is_inf(x)) {
		return rz_float_trans_invalid(x->r);
	}
	if (rz_float_trans_is_zero(x)) {
		return fn == TRIG_COS ? rz_float_trans_si(x->r, 1) : rz_float_trans_zero(x->r, float_sign(x));
	}
	return rz_float_trans_unary(x, mode, eval);
}

/**
 * \brief sin(x) correctly rounded (IEEE 754-2019 9.2 sin).
 * \param x operand
 * \param mode rounding mode
 * \return the result in the format of \p x with its exception flags
 */
RZ_API RZ_OWN RzFloat *rz_float_sin(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return trig_family(x, mode, TRIG_SIN, eval_sin);
}

/** \brief cos(x) correctly rounded (IEEE 754-2019 9.2 cos). */
RZ_API RZ_OWN RzFloat *rz_float_cos(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return trig_family(x, mode, TRIG_COS, eval_cos);
}

/** \brief tan(x) correctly rounded (IEEE 754-2019 9.2 tan). */
RZ_API RZ_OWN RzFloat *rz_float_tan(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return trig_family(x, mode, TRIG_TAN, eval_tan);
}

/* Exact cases of the pi functions (2x, 4x integers) with the signs of
 * ISO C F.10.1.12 - 14, the rest through Ziv's loop. */
static RzFloat *trig_pi_family(RzFloat *x, RzFloatRMode mode, TrigFn fn, TransEval eval) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	if (rz_float_trans_is_inf(x)) {
		return rz_float_trans_invalid(x->r);
	}
	RzFloatFormat format = x->r;
	bool neg = float_sign(x);
	if (rz_float_trans_is_zero(x)) {
		return fn == TRIG_COS ? rz_float_trans_si(format, 1) : rz_float_trans_zero(format, neg);
	}
	TransCtx ctx;
	rz_float_trans_ctx_init(&ctx, format);
	if (!rz_mp_set_float(&ctx.x, x)) {
		return NULL;
	}
	int j = pi_reduce(&ctx.y, &ctx.x, ctx.p);
	bool odd = j & 1;
	ctx.n = j;
	if (ctx.y.zero) {
		switch (fn) {
		case TRIG_SIN:
			/* sinPi(+-n) = +-0, sinPi(n + 1/2) = +-1 */
			return odd ? rz_float_trans_si(format, j == 1 ? 1 : -1) : rz_float_trans_zero(format, neg);
		case TRIG_COS:
			/* cosPi(n + 1/2) = +0, cosPi(n) = +-1 */
			return odd ? rz_float_trans_zero(format, false) : rz_float_trans_si(format, j ? -1 : 1);
		default:
			/* tanPi(n + 1/2) is +inf for even n, -inf for odd n;
			 * tanPi(n) is +0 for positive even and negative odd n */
			if (odd) {
				return rz_float_trans_div_zero(format, j == 3);
			}
			return rz_float_trans_zero(format, neg != (j == 2));
		}
	}
	MpFloat quarter;
	mp_small(&quarter, 1, -2);
	if (fn == TRIG_TAN && !rz_mp_cmp_abs(&ctx.y, &quarter)) {
		/* tan(pi u) = +-1 at u = +-1/4, -cot(pi u) in odd quadrants */
		return rz_float_trans_si(format, ctx.y.sign != odd ? -1 : 1);
	}
	return rz_float_trans_round(&ctx, eval, mode);
}

/** \brief sin(pi x) correctly rounded (IEEE 754-2019 9.2 sinPi). */
RZ_API RZ_OWN RzFloat *rz_float_sinpi(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return trig_pi_family(x, mode, TRIG_SIN, eval_sinpi);
}

/** \brief cos(pi x) correctly rounded (IEEE 754-2019 9.2 cosPi). */
RZ_API RZ_OWN RzFloat *rz_float_cospi(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return trig_pi_family(x, mode, TRIG_COS, eval_cospi);
}

/** \brief tan(pi x) correctly rounded (IEEE 754-2019 9.2 tanPi). */
RZ_API RZ_OWN RzFloat *rz_float_tanpi(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return trig_pi_family(x, mode, TRIG_TAN, eval_tanpi);
}

/**
 * Special values of the inverse functions (ISO C F.10.1.1 - 3, 8 - 10):
 * asin(+-1) = +-pi/2, acos(1) = +0, acos(-1) = pi, acos(+-0) = pi/2,
 * atan(+-inf) = +-pi/2, atanPi(+-1) = +-1/4; |x| > 1 is invalid for asin
 * and acos. The pi variants of these values are exact.
 */
static RzFloat *arc_family(RzFloat *x, RzFloatRMode mode, TrigFn fn, bool pi_units, TransEval eval) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	RzFloatFormat format = x->r;
	bool neg = float_sign(x);
	if (rz_float_trans_is_inf(x)) {
		if (fn != TRIG_TAN) {
			return rz_float_trans_invalid(format);
		}
		return float_quarter(format, neg ? -2 : 2, pi_units, mode);
	}
	if (rz_float_trans_is_zero(x)) {
		if (fn == TRIG_COS) {
			return float_quarter(format, 2, pi_units, mode);
		}
		return rz_float_trans_zero(format, neg);
	}
	TransCtx ctx;
	rz_float_trans_ctx_init(&ctx, format);
	if (!rz_mp_set_float(&ctx.x, x)) {
		return NULL;
	}
	MpFloat ax;
	mp_copy(&ax, &ctx.x, TRANS_OPERAND_PREC);
	rz_mp_abs(&ax);
	int c = rz_mp_cmp_si(&ax, 1);
	if (fn != TRIG_TAN) {
		if (c > 0) {
			return rz_float_trans_invalid(format);
		}
		if (!c && fn == TRIG_SIN) {
			return float_quarter(format, neg ? -2 : 2, pi_units, mode);
		}
		if (!c) {
			return neg ? float_quarter(format, 4, pi_units, mode) : rz_float_trans_zero(format, false);
		}
	} else if (!c && pi_units) {
		return float_exact(format, neg ? -1 : 1, -2);
	}
	return rz_float_trans_round(&ctx, eval, mode);
}

/** \brief asin(x) correctly rounded (IEEE 754-2019 9.2 asin). */
RZ_API RZ_OWN RzFloat *rz_float_asin(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return arc_family(x, mode, TRIG_SIN, false, eval_asin);
}

/** \brief acos(x) correctly rounded (IEEE 754-2019 9.2 acos). */
RZ_API RZ_OWN RzFloat *rz_float_acos(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return arc_family(x, mode, TRIG_COS, false, eval_acos);
}

/** \brief atan(x) correctly rounded (IEEE 754-2019 9.2 atan). */
RZ_API RZ_OWN RzFloat *rz_float_atan(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return arc_family(x, mode, TRIG_TAN, false, eval_atan);
}

/** \brief asin(x) / pi correctly rounded (IEEE 754-2019 9.2 asinPi). */
RZ_API RZ_OWN RzFloat *rz_float_asinpi(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return arc_family(x, mode, TRIG_SIN, true, eval_asinpi);
}

/** \brief acos(x) / pi correctly rounded (IEEE 754-2019 9.2 acosPi). */
RZ_API RZ_OWN RzFloat *rz_float_acospi(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return arc_family(x, mode, TRIG_COS, true, eval_acospi);
}

/** \brief atan(x) / pi correctly rounded (IEEE 754-2019 9.2 atanPi). */
RZ_API RZ_OWN RzFloat *rz_float_atanpi(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return arc_family(x, mode, TRIG_TAN, true, eval_atanpi);
}

/* Special values of ISO C F.10.1.4 and F.10.1.11: zeros and infinities give
 * multiples of pi/4 (exact multiples of 1/4 in units of pi) or signed
 * zeros, atan2(+-0, -0) = +-pi and atan2(y, +-0) = +-pi/2 raise nothing. */
static RzFloat *atan2_family(RzFloat *y, RzFloat *x, RzFloatRMode mode, bool pi_units, TransEval eval) {
	rz_return_val_if_fail(y && x && y->r == x->r, NULL);
	if (rz_float_trans_is_nan(y) || rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(y, x);
	}
	RzFloatFormat format = y->r;
	bool neg = float_sign(y);
	bool left = float_sign(x);
	st64 k;
	if (rz_float_trans_is_inf(y)) {
		k = rz_float_trans_is_inf(x) ? (left ? 3 : 1) : 2;
		return float_quarter(format, neg ? -k : k, pi_units, mode);
	}
	if (rz_float_trans_is_inf(x) || rz_float_trans_is_zero(y)) {
		if (!left) {
			return rz_float_trans_zero(format, neg);
		}
		return float_quarter(format, neg ? -4 : 4, pi_units, mode);
	}
	if (rz_float_trans_is_zero(x)) {
		return float_quarter(format, neg ? -2 : 2, pi_units, mode);
	}
	TransCtx ctx;
	rz_float_trans_ctx_init(&ctx, format);
	if (!rz_mp_set_float(&ctx.x, x) || !rz_mp_set_float(&ctx.y, y)) {
		return NULL;
	}
	if (pi_units && !rz_mp_cmp_abs(&ctx.x, &ctx.y)) {
		k = left ? 3 : 1;
		return float_exact(format, neg ? -k : k, -2);
	}
	return rz_float_trans_round(&ctx, eval, mode);
}

/** \brief atan2(y, x) correctly rounded (IEEE 754-2019 9.2 atan2). */
RZ_API RZ_OWN RzFloat *rz_float_atan2(RZ_NONNULL RzFloat *y, RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return atan2_family(y, x, mode, false, eval_atan2);
}

/** \brief atan2(y, x) / pi correctly rounded (IEEE 754-2019 9.2 atan2Pi). */
RZ_API RZ_OWN RzFloat *rz_float_atan2pi(RZ_NONNULL RzFloat *y, RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	return atan2_family(y, x, mode, true, eval_atan2pi);
}

/** \} */
