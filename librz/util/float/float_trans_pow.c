// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file float_trans_pow.c
 * Power functions of the IEEE 754-2019 9.2 recommended operations: rsqrt,
 * hypot, pow, powr, pown, rootn and compound. See float_trans.h.
 *
 * pow, powr, pown, rootn and compound evaluate b^y = e^t with t = y ln(b)
 * (ln(b) / y for rootn, y ln(1 + x) for compound). An estimate of t selects
 * the overflow, underflow and close to one proxies, results that are dyadic
 * rationals (the only ones that can be representable or midpoints) are
 * computed exactly, and everything else is approximated in Ziv's loop.
 */

#include "float_trans.h"
#include <rz_util/rz_assert.h>

/**
 * \name Helpers
 * \{
 */

static bool float_sign(const RzFloat *f) {
	return rz_float_is_negative((RzFloat *)f);
}

/* |f| or f itself as an exact result (no exception flags), re-encoded so
 * that a non-canonical binary80 operand comes out canonical */
static RzFloat *float_exact_copy(const RzFloat *f, bool abs) {
	MpFloat t;
	rz_mp_init(&t, TRANS_OPERAND_PREC);
	if (!rz_mp_set_float(&t, f)) {
		return NULL;
	}
	if (abs) {
		rz_mp_abs(&t);
	}
	return rz_mp_get_float(&t, f->r, RZ_FLOAT_RMODE_RNE);
}

/* Weight 2^k of the lowest set bit of a nonzero a, so a = m 2^k with m odd. */
static st64 mp_low_exp(const MpFloat *a) {
	ut64 total = (ut64)mp_nlimbs(a->prec) * MP_LIMB_BITS;
	return a->exp - (st64)total + (st64)rz_mp_trailing_zeros(a);
}

/* Bit length of the odd part m of a nonzero a = m 2^k. */
static st64 mp_odd_bits(const MpFloat *a) {
	return a->exp - mp_low_exp(a);
}

static bool mp_is_odd_integer(const MpFloat *a) {
	return !a->zero && mp_low_exp(a) == 0;
}

static bool mp_is_one_abs(const MpFloat *a) {
	return !a->zero && a->exp == 1 && mp_odd_bits(a) == 1;
}

/**
 * Integer operand n as a signed two's complement integer of the bitvector
 * width, exact when |n| has at most MP_MAX_PREC significant bits. Wider
 * magnitudes are rounded to MP_MAX_PREC bits (relative error below 2^-2047),
 * keeping the sign; the callers take the parity from the bitvector. Such an
 * |n| >= 2^2048 fixes pown and rootn by its sign and parity alone (overflow,
 * underflow or 1 + tiny), and compound too unless |x| < 2^-2000, where only
 * a result within a relative 2^-2030 of a rounding boundary could differ.
 */
static bool mp_set_bv(MpFloat *r, RzBitVector *bv) {
	ut32 len = rz_bv_len(bv);
	bool neg = rz_bv_msb(bv);
	RzBitVector *mag = neg ? rz_bv_complement_2(bv) : rz_bv_dup(bv);
	if (!mag) {
		return false;
	}
	MpFloat chunk;
	rz_mp_init(r, RZ_MAX(64, RZ_MIN(len, MP_MAX_PREC)));
	rz_mp_init(&chunk, 64);
	/* the magnitude, 32 bits at a time from the most significant end */
	for (ut32 hi = len; hi > 0;) {
		ut32 lo = hi > MP_LIMB_BITS ? hi - MP_LIMB_BITS : 0;
		ut64 v = 0;
		for (ut32 i = hi; i-- > lo;) {
			v = (v << 1) | (rz_bv_get(mag, i) ? 1 : 0);
		}
		rz_mp_mul_2si(r, hi - lo);
		rz_mp_set_ui(&chunk, v, RZ_FLOAT_RMODE_RNE);
		rz_mp_add(r, r, &chunk, RZ_FLOAT_RMODE_RNE);
		hi = lo;
	}
	rz_bv_free(mag);
	if (neg) {
		rz_mp_neg(r);
	}
	return true;
}

/* r = c^j exactly for j >= 1 when every power fits in MP_MAX_PREC bits. */
static bool mp_pow_exact(MpFloat *r, const MpFloat *c, ut64 j) {
	MpFloat b, acc;
	rz_mp_init(&b, MP_MAX_PREC);
	rz_mp_init(&acc, MP_MAX_PREC);
	rz_mp_set(&b, c, RZ_FLOAT_RMODE_RNE);
	rz_mp_set_si(&acc, 1, RZ_FLOAT_RMODE_RNE);
	for (; j; j >>= 1) {
		if ((j & 1) && rz_mp_mul(&acc, &acc, &b, RZ_FLOAT_RMODE_RNE)) {
			return false;
		}
		if (j > 1 && rz_mp_mul(&b, &b, &b, RZ_FLOAT_RMODE_RNE)) {
			return false;
		}
	}
	*r = acc;
	return true;
}

/** \} */

/**
 * \name Powers
 * \{
 */

typedef enum {
	POW_POW, ///< b^y
	POW_ROOT, ///< b^(1/y)
	POW_COMPOUND, ///< (1 + x)^y
} PowKind;

/* Context of the power evaluations. TransCtx must stay the first member. */
typedef struct {
	TransCtx t; ///< t.x: the base b = |x|, or x for compound; t.y: the exact exponent y or n
	PowKind kind;
	bool neg; ///< the result is -|b^y|
} PowCtx;

/* t = ln|b^y| with relative error below 2^-prec, prec <= MP_MAX_PREC - 64
 * (the log cores need room for their own guard bits) */
static void pow_log_arg(MpFloat *t, const PowCtx *ctx, ut32 prec) {
	MpFloat l;
	rz_mp_init(&l, prec + 8);
	if (ctx->kind == POW_COMPOUND) {
		rz_float_trans_log1p(&l, &ctx->t.x, prec + 2);
	} else {
		rz_float_trans_log(&l, &ctx->t.x, prec + 2);
	}
	rz_mp_init(t, prec + 8);
	if (ctx->kind == POW_ROOT) {
		rz_mp_div(t, &l, &ctx->t.y, RZ_FLOAT_RMODE_RNE);
	} else {
		rz_mp_mul(t, &l, &ctx->t.y, RZ_FLOAT_RMODE_RNE);
	}
}

/**
 * Proxies from E = log2|b^y| estimated with relative error below 2^-60:
 * E > emax + 2 means the true E is above emax + 1 (overflow), E below
 * emin - p - 3 means |b^y| < 2^(emin - p - 2) (underflow below half of the
 * smallest subnormal), and |E| < 2^-(p + 7) means |t| < 2^-(p + 7), so
 * b^y = e^t = 1 + d with 0 < |d| < 2^-(p + 6) of the sign of t.
 * Otherwise |t| < 2^14. b != 1 and y != 0, so t != 0.
 */
static bool pow_bounds(MpFloat *r, const PowCtx *ctx) {
	const TransCtx *tc = &ctx->t;
	MpFloat t, ln2, e;
	pow_log_arg(&t, ctx, 64);
	rz_mp_init(&ln2, 80);
	rz_mp_const_ln2(&ln2);
	rz_mp_init(&e, 72);
	rz_mp_div(&e, &t, &ln2, RZ_FLOAT_RMODE_RNE);
	if (rz_mp_cmp_si(&e, tc->emax + 2) > 0) {
		rz_float_trans_proxy_overflow(r, (TransCtx *)tc, false);
		return true;
	}
	if (rz_mp_cmp_si(&e, tc->emin - (st64)tc->p - 3) < 0) {
		rz_float_trans_proxy_underflow(r, (TransCtx *)tc, false);
		return true;
	}
	if (e.exp <= -(st64)tc->p - 7) {
		MpFloat one;
		rz_mp_init(&one, 8);
		rz_mp_set_si(&one, 1, RZ_FLOAT_RMODE_RNE);
		rz_float_trans_proxy_nudge(r, (TransCtx *)tc, &one, !e.sign);
		return true;
	}
	return false;
}

/**
 * b^y exactly when it is a dyadic rational of at most MP_MAX_PREC bits, for
 * b > 0, b != 1, y != 0 and |y log2(b)| < 2^15. Otherwise b^y is irrational,
 * a non-dyadic rational or a dyadic of more than MP_MAX_PREC > p + 1
 * significant bits: never representable nor a midpoint.
 */
static bool pow_exact(MpFloat *r, const MpFloat *b, const MpFloat *y) {
	st64 lb = mp_low_exp(b);
	st64 ly = mp_low_exp(y);
	st64 bits = mp_odd_bits(b);
	if (bits == 1) {
		/* b = 2^lb: 2^(lb y) is irrational unless lb y is an integer
		 * (2^q = u / v for a rational q = s / k gives 2^s = (u / v)^k,
		 * forcing u / v to be a power of two and k | s) */
		MpFloat e;
		rz_mp_init(&e, 256);
		if (y->exp > 32 || rz_mp_mul_si(&e, y, lb, RZ_FLOAT_RMODE_RNE) || !rz_mp_is_integer(&e)) {
			return false;
		}
		rz_mp_init(r, 8);
		rz_mp_set_2exp(r, 1, rz_mp_get_si(&e), RZ_FLOAT_RMODE_RNE);
		return true;
	}
	MpFloat c, j;
	ut64 k = ly < 0 ? (ut64)-ly : 0;
	/* b and its exact square roots fit in bits + 1 bits */
	rz_mp_init(&c, RZ_MIN(RZ_MAX(bits + 1, 64), MP_MAX_PREC));
	rz_mp_set(&c, b, RZ_FLOAT_RMODE_RNE);
	if (k) {
		/* y = j / 2^k with odd j: b^y rational makes b^(1/2^k) rational
		 * (Bezout on j and 2^k), so b = c^(2^k) for a dyadic c and the
		 * odd part of b, at least 3^(2^k), has more than 2^k bits */
		if (k >= 32 || (1ull << k) >= (ut64)bits) {
			return false;
		}
		for (ut64 i = 0; i < k; i++) {
			if (rz_mp_sqrt(&c, &c, RZ_FLOAT_RMODE_RNE)) {
				return false;
			}
		}
	}
	/* b^y = c^j: 1 / c^j is not dyadic as the odd part of c is >= 3, and
	 * j >= 2^12 or j (bits(c) - 1) > MP_MAX_PREC makes c^j too long */
	if (y->sign || y->exp + (st64)k > 12) {
		return false;
	}
	rz_mp_init(&j, RZ_MAX(y->prec, 64));
	rz_mp_set(&j, y, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&j, (st64)k);
	st64 jj = rz_mp_get_si(&j);
	if (jj * (mp_odd_bits(&c) - 1) > MP_MAX_PREC) {
		return false;
	}
	return mp_pow_exact(r, &c, jj);
}

/**
 * b^(1/n) exactly when it is dyadic, for b > 0, b != 1 and an integer n != 0.
 * With b = m 2^e (m odd) a rational b^(1/n) must be c 2^(e/n) with c^n = m
 * (an integer n-th root of an integer is an integer or irrational) and n | e
 * (2^(e/n) is irrational otherwise); for n < 0, 1 / c is dyadic only for
 * c = 1.
 */
static bool root_exact(MpFloat *r, const MpFloat *b, const MpFloat *n) {
	st64 e = mp_low_exp(b);
	st64 bits = mp_odd_bits(b);
	/* |n| >= 2^20 > |e| needs e = 0 and then m = c^n >= 3^|n| */
	if (n->exp > 20) {
		return false;
	}
	st64 k = rz_mp_get_si(n);
	if (e % k) {
		return false;
	}
	if (bits == 1) {
		rz_mp_init(r, 8);
		rz_mp_set_2exp(r, 1, e / k, RZ_FLOAT_RMODE_RNE);
		return true;
	}
	/* m = c^k >= 3^k */
	if (k < 0 || k >= bits) {
		return false;
	}
	/* the candidate c = round(m^(1/k)) < 2^57, from a 128-bit approximation */
	MpFloat m, l, a, c, ck;
	rz_mp_init(&m, b->prec);
	rz_mp_set(&m, b, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(&m, -e);
	rz_mp_init(&l, 136);
	rz_float_trans_log(&l, &m, 128);
	rz_mp_div_si(&l, &l, k, RZ_FLOAT_RMODE_RNE);
	rz_mp_init(&a, 136);
	rz_float_trans_exp(&a, &l, 128);
	rz_mp_init(&c, 136);
	rz_mp_round_int(&c, &a, RZ_FLOAT_RMODE_RNE);
	if (!mp_pow_exact(&ck, &c, k) || rz_mp_cmp(&ck, &m)) {
		return false;
	}
	rz_mp_init(r, 136);
	rz_mp_set(r, &c, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul_2si(r, e / k);
	return true;
}

/**
 * (1 + x)^n exactly, or a proxy, when it is dyadic. For a large x the
 * result is X (1 + d) with X = x^n and 0 < |d| <= 1.01 |n| / x, d of the
 * sign of n. If X is dyadic with B significant bits and |d| < 2^-max(B, p + 4),
 * the result rounds like X nudged towards it: a rounding boundary (a dyadic
 * of at most p + 1 bits) other than X is at a relative distance above
 * 2^-(p + 2) from X when B <= p + 1, and above 2^-B from a non-boundary X.
 * Otherwise 1 + x is computed exactly and raised to n; if it needs more than
 * 1984 bits, |x| < 2^-1800 (the odd part of 1 + x is too long for a
 * representable power) or x >= 2^1984 with n < 0 and X not dyadic.
 */
static bool compound_exact(MpFloat *r, const PowCtx *ctx) {
	const TransCtx *tc = &ctx->t;
	const MpFloat *x = &tc->x;
	const MpFloat *n = &tc->y;
	MpFloat v, b;
	if (!x->sign && x->exp >= (st64)tc->p + 6 && pow_exact(&v, x, n)) {
		st64 bits = mp_odd_bits(&v);
		if (x->exp >= RZ_MAX(bits, (st64)tc->p + 4) + n->exp + 2) {
			if (bits <= (st64)tc->p + 1) {
				rz_float_trans_proxy_nudge(r, (TransCtx *)tc, &v, !n->sign);
			} else {
				*r = v;
			}
			return true;
		}
	}
	rz_mp_init(&b, MP_MAX_PREC - 64);
	if (rz_mp_add_si(&b, x, 1, RZ_FLOAT_RMODE_RNE)) {
		return false;
	}
	return pow_exact(r, &b, n);
}

static void eval_pow(MpFloat *r, TransCtx *tc, ut32 w, bool *exact) {
	PowCtx *ctx = (PowCtx *)tc;
	ut32 prec = r->prec;
	bool done = pow_bounds(r, ctx);
	if (!done) {
		switch (ctx->kind) {
		case POW_ROOT:
			done = root_exact(r, &tc->x, &tc->y);
			break;
		case POW_COMPOUND:
			done = compound_exact(r, ctx);
			break;
		default:
			done = pow_exact(r, &tc->x, &tc->y);
			break;
		}
	}
	if (done) {
		*exact = true;
	} else {
		/* |t| < 2^14 with relative error below 2^-(w + 40) adds a
		 * relative error below 2^-(w + 25) to e^t, the exp core and the
		 * rounding to w + 8 bits stay below 2^-(w + 4) */
		MpFloat t;
		pow_log_arg(&t, ctx, RZ_MIN(w + 40, MP_MAX_PREC - 64));
		rz_mp_init(r, prec);
		rz_float_trans_exp(r, &t, w + 4);
	}
	if (ctx->neg) {
		rz_mp_neg(r);
	}
}

/* base |x| (x itself for compound) and an empty exponent */
static void pow_ctx_init(PowCtx *ctx, RzFloat *x, PowKind kind, bool neg) {
	rz_float_trans_ctx_init(&ctx->t, x->r);
	rz_mp_set_float(&ctx->t.x, x);
	if (kind != POW_COMPOUND) {
		rz_mp_abs(&ctx->t.x);
	}
	ctx->kind = kind;
	ctx->neg = neg;
}

/* exponent from the integer operand; t.n is a saturated copy (+-2^62) */
static bool pow_ctx_set_n(PowCtx *ctx, RzBitVector *n) {
	if (!mp_set_bv(&ctx->t.y, n)) {
		return false;
	}
	ctx->t.n = rz_mp_get_si(&ctx->t.y);
	return true;
}

static RzFloat *pow_round(PowCtx *ctx, RzFloatRMode mode) {
	if (mp_is_one_abs(&ctx->t.x) && ctx->kind != POW_COMPOUND) {
		/* 1^y = 1 */
		return rz_float_trans_si(ctx->t.format, ctx->neg ? -1 : 1);
	}
	return rz_float_trans_round(&ctx->t, eval_pow, mode);
}

/* -1 if |x| < 1, 0 if |x| = 1, 1 if |x| > 1 (x not a NaN) */
static int float_cmp_abs_one(RzFloat *x) {
	if (rz_float_trans_is_inf(x)) {
		return 1;
	}
	if (rz_float_trans_is_zero(x)) {
		return -1;
	}
	MpFloat v, one;
	rz_mp_init(&v, TRANS_OPERAND_PREC);
	rz_mp_init(&one, 8);
	rz_mp_set_float(&v, x);
	rz_mp_set_si(&one, 1, RZ_FLOAT_RMODE_RNE);
	return rz_mp_cmp_abs(&v, &one);
}

/**
 * \brief x^y correctly rounded (IEEE 754-2019 9.2 pow).
 *
 * Special cases follow IEEE 754-2019 9.2.1 (ISO C F.10.4.5): pow(x, +-0) and
 * pow(+1, y) are 1 even for a quiet NaN, a negative finite x with a finite
 * non-integer y is invalid, and integer y give x^y the sign of x for odd y.
 * \param x base
 * \param y exponent, in the format of \p x
 * \param mode rounding mode
 * \return the result in the format of \p x with its exception flags
 */
RZ_API RZ_OWN RzFloat *rz_float_pow(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y, RzFloatRMode mode) {
	rz_return_val_if_fail(x && y && x->r == y->r, NULL);
	RzFloatFormat format = x->r;
	bool snan = rz_float_trans_is_snan(x) || rz_float_trans_is_snan(y);
	if (!snan && (rz_float_trans_is_zero(y) || (!rz_float_trans_is_nan(x) && !float_sign(x) && !float_cmp_abs_one(x)))) {
		return rz_float_trans_si(format, 1);
	}
	if (rz_float_trans_is_nan(x) || rz_float_trans_is_nan(y)) {
		return rz_float_trans_nan(x, y);
	}
	bool xneg = float_sign(x);
	bool yneg = float_sign(y);
	if (rz_float_trans_is_inf(y)) {
		int c = float_cmp_abs_one(x);
		if (!c) {
			/* x = -1 */
			return rz_float_trans_si(format, 1);
		}
		return (c < 0) == yneg ? rz_float_trans_inf(format, false) : rz_float_trans_zero(format, false);
	}
	PowCtx ctx;
	pow_ctx_init(&ctx, x, POW_POW, false);
	rz_mp_set_float(&ctx.t.y, y);
	bool yint = rz_mp_is_integer(&ctx.t.y);
	bool odd = mp_is_odd_integer(&ctx.t.y);
	bool sign = xneg && odd;
	if (rz_float_trans_is_zero(x)) {
		return yneg ? rz_float_trans_div_zero(format, sign) : rz_float_trans_zero(format, sign);
	}
	if (rz_float_trans_is_inf(x)) {
		return yneg ? rz_float_trans_zero(format, sign) : rz_float_trans_inf(format, sign);
	}
	if (xneg && !yint) {
		return rz_float_trans_invalid(format);
	}
	ctx.neg = sign;
	return pow_round(&ctx, mode);
}

/**
 * \brief x^y = e^(y ln x) correctly rounded (IEEE 754-2019 9.2 powr).
 *
 * Special cases follow IEEE 754-2019 9.2.1 (ISO C F.10.4.7): x < 0,
 * powr(+-0, +-0), powr(+inf, +-0) and powr(1, +-inf) are invalid.
 */
RZ_API RZ_OWN RzFloat *rz_float_powr(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y, RzFloatRMode mode) {
	rz_return_val_if_fail(x && y && x->r == y->r, NULL);
	RzFloatFormat format = x->r;
	/* NaNs propagate except for x < 0, which is invalid for every y:
	 * 9.2.1 lists powr(x, qNaN) = qNaN only for x >= 0 */
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, y);
	}
	if (float_sign(x) && !rz_float_trans_is_zero(x)) {
		return rz_float_trans_invalid(format);
	}
	if (rz_float_trans_is_nan(y)) {
		return rz_float_trans_nan(x, y);
	}
	bool yneg = float_sign(y);
	if (rz_float_trans_is_zero(x)) {
		if (rz_float_trans_is_zero(y)) {
			return rz_float_trans_invalid(format);
		}
		if (yneg) {
			return rz_float_trans_is_inf(y) ? rz_float_trans_inf(format, false) : rz_float_trans_div_zero(format, false);
		}
		return rz_float_trans_zero(format, false);
	}
	if (rz_float_trans_is_inf(x)) {
		if (rz_float_trans_is_zero(y)) {
			return rz_float_trans_invalid(format);
		}
		return yneg ? rz_float_trans_zero(format, false) : rz_float_trans_inf(format, false);
	}
	if (rz_float_trans_is_zero(y)) {
		return rz_float_trans_si(format, 1);
	}
	int c = float_cmp_abs_one(x);
	if (!c) {
		return rz_float_trans_is_inf(y) ? rz_float_trans_invalid(format) : rz_float_trans_si(format, 1);
	}
	if (rz_float_trans_is_inf(y)) {
		return (c < 0) == yneg ? rz_float_trans_inf(format, false) : rz_float_trans_zero(format, false);
	}
	PowCtx ctx;
	pow_ctx_init(&ctx, x, POW_POW, false);
	rz_mp_set_float(&ctx.t.y, y);
	return pow_round(&ctx, mode);
}

/**
 * \brief x^n for an integer n correctly rounded (IEEE 754-2019 9.2 pown).
 *
 * Special cases follow IEEE 754-2019 9.2.1 (ISO C F.10.4.6): pown(x, 0) is 1
 * for every x but a signaling NaN.
 * \param x base
 * \param n exponent, a signed two's complement integer of any width (see
 *        mp_set_bv for widths above 2048 bits)
 * \param mode rounding mode
 */
RZ_API RZ_OWN RzFloat *rz_float_pown(RZ_NONNULL RzFloat *x, RZ_NONNULL RzBitVector *n, RzFloatRMode mode) {
	rz_return_val_if_fail(x && n, NULL);
	RzFloatFormat format = x->r;
	bool nneg = rz_bv_msb(n);
	if (rz_bv_is_zero_vector(n) && !rz_float_trans_is_snan(x)) {
		return rz_float_trans_si(format, 1);
	}
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	bool sign = float_sign(x) && rz_bv_lsb(n);
	if (rz_float_trans_is_zero(x)) {
		return nneg ? rz_float_trans_div_zero(format, sign) : rz_float_trans_zero(format, sign);
	}
	if (rz_float_trans_is_inf(x)) {
		return nneg ? rz_float_trans_zero(format, sign) : rz_float_trans_inf(format, sign);
	}
	PowCtx ctx;
	pow_ctx_init(&ctx, x, POW_POW, sign);
	if (!pow_ctx_set_n(&ctx, n)) {
		return NULL;
	}
	return pow_round(&ctx, mode);
}

/**
 * \brief x^(1/n) for an integer n correctly rounded (IEEE 754-2019 9.2 rootn).
 *
 * Special cases follow IEEE 754-2019 9.2.1 (ISO C F.10.4.8): rootn(x, 0) is
 * invalid for every x, a negative x with an even n is invalid.
 */
RZ_API RZ_OWN RzFloat *rz_float_rootn(RZ_NONNULL RzFloat *x, RZ_NONNULL RzBitVector *n, RzFloatRMode mode) {
	rz_return_val_if_fail(x && n, NULL);
	RzFloatFormat format = x->r;
	if (rz_bv_is_zero_vector(n)) {
		return rz_float_trans_invalid(format);
	}
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	bool nneg = rz_bv_msb(n);
	bool odd = rz_bv_lsb(n);
	bool xneg = float_sign(x);
	if (rz_float_trans_is_zero(x)) {
		return nneg ? rz_float_trans_div_zero(format, xneg && odd) : rz_float_trans_zero(format, xneg && odd);
	}
	if (xneg && !odd) {
		return rz_float_trans_invalid(format);
	}
	if (rz_float_trans_is_inf(x)) {
		return nneg ? rz_float_trans_zero(format, xneg) : rz_float_trans_inf(format, xneg);
	}
	PowCtx ctx;
	pow_ctx_init(&ctx, x, POW_ROOT, xneg);
	if (!pow_ctx_set_n(&ctx, n)) {
		return NULL;
	}
	if (!rz_mp_cmp_si(&ctx.t.y, 1)) {
		return float_exact_copy(x, false);
	}
	return pow_round(&ctx, mode);
}

/**
 * \brief (1 + x)^n for an integer n correctly rounded (IEEE 754-2019 9.2
 * compound).
 *
 * Special cases follow IEEE 754-2019 9.2.1 (ISO C F.10.4.2): compound(x, 0)
 * is 1 for x >= -1 and quiet NaNs, x < -1 is invalid, compound(-1, n) is +inf
 * (divide by zero) for n < 0 and +0 for n > 0.
 */
RZ_API RZ_OWN RzFloat *rz_float_compound(RZ_NONNULL RzFloat *x, RZ_NONNULL RzBitVector *n, RzFloatRMode mode) {
	rz_return_val_if_fail(x && n, NULL);
	RzFloatFormat format = x->r;
	bool nzero = rz_bv_is_zero_vector(n);
	bool nneg = rz_bv_msb(n);
	if (rz_float_trans_is_nan(x)) {
		return nzero && !rz_float_trans_is_snan(x) ? rz_float_trans_si(format, 1) : rz_float_trans_nan(x, NULL);
	}
	int c = float_cmp_abs_one(x);
	if (float_sign(x) && c > 0) {
		return rz_float_trans_invalid(format);
	}
	if (nzero || rz_float_trans_is_zero(x)) {
		return rz_float_trans_si(format, 1);
	}
	if (float_sign(x) && !c) {
		return nneg ? rz_float_trans_div_zero(format, false) : rz_float_trans_zero(format, false);
	}
	if (rz_float_trans_is_inf(x)) {
		return nneg ? rz_float_trans_zero(format, false) : rz_float_trans_inf(format, false);
	}
	PowCtx ctx;
	pow_ctx_init(&ctx, x, POW_COMPOUND, false);
	if (!pow_ctx_set_n(&ctx, n)) {
		return NULL;
	}
	return pow_round(&ctx, mode);
}

/** \} */

/**
 * \name Square roots
 * \{
 */

/* 1/sqrt(x) for x > 0 is dyadic only for x = 4^k: a rational sqrt(x) is a
 * dyadic c 2^f, whose reciprocal is dyadic only for c = 1. */
static void eval_rsqrt(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	const MpFloat *x = &ctx->x;
	st64 e = mp_low_exp(x);
	if (mp_odd_bits(x) == 1 && !(e & 1)) {
		rz_mp_set_2exp(r, 1, -e / 2, RZ_FLOAT_RMODE_RNE);
		*exact = true;
		return;
	}
	MpFloat s, one;
	rz_mp_init(&s, w + 16);
	rz_mp_init(&one, 8);
	rz_mp_sqrt(&s, x, RZ_FLOAT_RMODE_RNE);
	rz_mp_set_si(&one, 1, RZ_FLOAT_RMODE_RNE);
	rz_mp_div(r, &one, &s, RZ_FLOAT_RMODE_RNE);
}

/**
 * \brief 1/sqrt(x) correctly rounded (IEEE 754-2019 9.2 rSqrt).
 *
 * rsqrt(+-0) is +-inf (divide by zero), x < 0 is invalid, rsqrt(+inf) = +0.
 */
RZ_API RZ_OWN RzFloat *rz_float_rsqrt(RZ_NONNULL RzFloat *x, RzFloatRMode mode) {
	rz_return_val_if_fail(x, NULL);
	if (rz_float_trans_is_nan(x)) {
		return rz_float_trans_nan(x, NULL);
	}
	bool neg = float_sign(x);
	if (rz_float_trans_is_zero(x)) {
		return rz_float_trans_div_zero(x->r, neg);
	}
	if (neg) {
		return rz_float_trans_invalid(x->r);
	}
	if (rz_float_trans_is_inf(x)) {
		return rz_float_trans_zero(x->r, false);
	}
	return rz_float_trans_unary(x, mode, eval_rsqrt);
}

/**
 * sqrt(a^2 + b^2) for a >= b > 0 (ctx x and y). If b is below a 2^-(p/2 + 2)
 * the result is a + d with 0 < d <= a (b/a)^2 / 2 < a 2^-(p + 3). Otherwise
 * s = a^2 + b^2 spans less than 3p + 8 bits and is exact: sqrt(s) is either
 * a dyadic, computed exactly when it has at most p + 2 bits, or irrational
 * or too long to be representable or a midpoint, and then correctly rounded
 * to the working precision.
 */
static void eval_hypot(MpFloat *r, TransCtx *ctx, ut32 w, bool *exact) {
	const MpFloat *a = &ctx->x;
	const MpFloat *b = &ctx->y;
	if (b->exp <= a->exp - (st64)(ctx->p / 2 + 3)) {
		rz_float_trans_proxy_nudge(r, ctx, a, true);
		*exact = true;
		return;
	}
	MpFloat s, t, q;
	rz_mp_init(&s, 512);
	rz_mp_init(&t, 512);
	rz_mp_mul(&s, a, a, RZ_FLOAT_RMODE_RNE);
	rz_mp_mul(&t, b, b, RZ_FLOAT_RMODE_RNE);
	rz_mp_add(&s, &s, &t, RZ_FLOAT_RMODE_RNE);
	rz_mp_init(&q, ctx->p + 2);
	if (!rz_mp_sqrt(&q, &s, RZ_FLOAT_RMODE_RNE)) {
		*r = q;
		*exact = true;
		return;
	}
	rz_mp_sqrt(r, &s, RZ_FLOAT_RMODE_RNE);
}

/**
 * \brief sqrt(x^2 + y^2) correctly rounded (IEEE 754-2019 9.2 hypot).
 *
 * hypot(+-inf, y) is +inf even for a quiet NaN y, hypot(x, +-0) = |x|.
 */
RZ_API RZ_OWN RzFloat *rz_float_hypot(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y, RzFloatRMode mode) {
	rz_return_val_if_fail(x && y && x->r == y->r, NULL);
	if ((rz_float_trans_is_inf(x) && !rz_float_trans_is_snan(y)) || (rz_float_trans_is_inf(y) && !rz_float_trans_is_snan(x))) {
		return rz_float_trans_inf(x->r, false);
	}
	if (rz_float_trans_is_nan(x) || rz_float_trans_is_nan(y)) {
		return rz_float_trans_nan(x, y);
	}
	if (rz_float_trans_is_zero(y)) {
		return float_exact_copy(x, true);
	}
	if (rz_float_trans_is_zero(x)) {
		return float_exact_copy(y, true);
	}
	TransCtx ctx;
	rz_float_trans_ctx_init(&ctx, x->r);
	rz_mp_set_float(&ctx.x, x);
	rz_mp_set_float(&ctx.y, y);
	rz_mp_abs(&ctx.x);
	rz_mp_abs(&ctx.y);
	if (rz_mp_cmp(&ctx.x, &ctx.y) < 0) {
		MpFloat t = ctx.x;
		ctx.x = ctx.y;
		ctx.y = t;
	}
	return rz_float_trans_round(&ctx, eval_hypot, mode);
}

/** \} */
