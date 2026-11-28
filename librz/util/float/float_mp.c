// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file float_mp.c
 * Multiple-precision binary floating-point arithmetic, see float_mp.h.
 * Every operation computes its exact result (or the exact result truncated
 * with a sticky bit) and rounds it once to the destination precision.
 */

#include "float_mp.h"
#include <rz_util/rz_assert.h>
#include <softfloat.h>

#include "float_mp_tables.inc"

/* Scratch buffers hold up to three operand widths plus guard limbs. */
#define MP_BUF_LIMBS (3 * MP_MAX_LIMBS + 8)

/**
 * \name Natural number primitives on little-endian limb arrays
 * \{
 */

static void mpn_zero(MpLimb *d, ut32 n) {
	memset(d, 0, n * sizeof(MpLimb));
}

static bool mpn_is_zero(const MpLimb *d, ut32 n) {
	for (ut32 i = 0; i < n; i++) {
		if (d[i]) {
			return false;
		}
	}
	return true;
}

static int mpn_cmp(const MpLimb *a, const MpLimb *b, ut32 n) {
	for (ut32 i = n; i-- > 0;) {
		if (a[i] != b[i]) {
			return a[i] < b[i] ? -1 : 1;
		}
	}
	return 0;
}

static MpLimb mpn_add_n(MpLimb *r, const MpLimb *a, const MpLimb *b, ut32 n) {
	ut64 carry = 0;
	for (ut32 i = 0; i < n; i++) {
		carry += (ut64)a[i] + b[i];
		r[i] = (MpLimb)carry;
		carry >>= MP_LIMB_BITS;
	}
	return (MpLimb)carry;
}

static MpLimb mpn_sub_n(MpLimb *r, const MpLimb *a, const MpLimb *b, ut32 n) {
	ut64 borrow = 0;
	for (ut32 i = 0; i < n; i++) {
		ut64 t = (ut64)a[i] - b[i] - borrow;
		r[i] = (MpLimb)t;
		borrow = (t >> MP_LIMB_BITS) & 1;
	}
	return (MpLimb)borrow;
}

static MpLimb mpn_add_1(MpLimb *r, ut32 n, MpLimb v) {
	ut64 carry = v;
	for (ut32 i = 0; i < n && carry; i++) {
		carry += r[i];
		r[i] = (MpLimb)carry;
		carry >>= MP_LIMB_BITS;
	}
	return (MpLimb)carry;
}

static MpLimb mpn_sub_1(MpLimb *r, ut32 n, MpLimb v) {
	ut64 borrow = v;
	for (ut32 i = 0; i < n && borrow; i++) {
		ut64 t = (ut64)r[i] - borrow;
		r[i] = (MpLimb)t;
		borrow = (t >> MP_LIMB_BITS) & 1;
	}
	return (MpLimb)borrow;
}

static ut32 limb_clz(MpLimb v) {
	ut32 n = 0;
	if (!v) {
		return MP_LIMB_BITS;
	}
	while (!(v & 0x80000000u)) {
		v <<= 1;
		n++;
	}
	return n;
}

static ut32 limb_ctz(MpLimb v) {
	ut32 n = 0;
	if (!v) {
		return MP_LIMB_BITS;
	}
	while (!(v & 1)) {
		v >>= 1;
		n++;
	}
	return n;
}

/* r = a << bits, both n limbs (bits shifted out of the top are lost). */
static void mpn_lshift_bits(MpLimb *r, const MpLimb *a, ut32 n, ut64 bits) {
	ut64 limbs = bits / MP_LIMB_BITS;
	ut32 sh = bits % MP_LIMB_BITS;
	for (ut32 i = n; i-- > 0;) {
		MpLimb v = 0;
		if (i >= limbs) {
			ut64 src = i - limbs;
			v = a[src] << sh;
			if (sh && src > 0) {
				v |= a[src - 1] >> (MP_LIMB_BITS - sh);
			}
		}
		r[i] = v;
	}
}

/* r = a >> bits, both n limbs. Returns true if a nonzero bit was shifted out. */
static bool mpn_rshift_bits(MpLimb *r, const MpLimb *a, ut32 n, ut64 bits) {
	ut64 limbs = bits / MP_LIMB_BITS;
	ut32 sh = bits % MP_LIMB_BITS;
	bool lost = false;
	for (ut32 i = 0; i < n && i < limbs; i++) {
		lost |= a[i] != 0;
	}
	if (limbs < n && sh) {
		lost |= (a[limbs] & ((1u << sh) - 1)) != 0;
	}
	for (ut32 i = 0; i < n; i++) {
		MpLimb v = 0;
		ut64 src = i + limbs;
		if (src < n) {
			v = a[src] >> sh;
			if (sh && src + 1 < n) {
				v |= a[src + 1] << (MP_LIMB_BITS - sh);
			}
		}
		r[i] = v;
	}
	return lost;
}

/* r[0 .. an + bn) = a * b. r must not alias a or b. */
static void mpn_mul(MpLimb *r, const MpLimb *a, ut32 an, const MpLimb *b, ut32 bn) {
	mpn_zero(r, an + bn);
	for (ut32 i = 0; i < an; i++) {
		ut64 carry = 0;
		if (!a[i]) {
			continue;
		}
		for (ut32 j = 0; j < bn; j++) {
			carry += (ut64)a[i] * b[j] + r[i + j];
			r[i + j] = (MpLimb)carry;
			carry >>= MP_LIMB_BITS;
		}
		r[i + bn] = (MpLimb)carry;
	}
}

/* q = a / d for a single limb divisor; returns the remainder. */
static MpLimb mpn_divmod_1(MpLimb *q, const MpLimb *a, ut32 n, MpLimb d) {
	ut64 rem = 0;
	for (ut32 i = n; i-- > 0;) {
		ut64 cur = (rem << MP_LIMB_BITS) | a[i];
		q[i] = (MpLimb)(cur / d);
		rem = cur % d;
	}
	return (MpLimb)rem;
}

/**
 * Knuth's algorithm D: q[0 .. nn - dn] = floor(num / den). Returns true when
 * the remainder is nonzero. den[dn - 1] must be nonzero and nn >= dn.
 */
static bool mpn_divrem(MpLimb *q, const MpLimb *num, ut32 nn, const MpLimb *den, ut32 dn) {
	if (dn == 1) {
		return mpn_divmod_1(q, num, nn, den[0]) != 0;
	}
	MpLimb u[MP_BUF_LIMBS + 1];
	MpLimb v[MP_BUF_LIMBS];
	ut32 s = limb_clz(den[dn - 1]);
	mpn_lshift_bits(v, den, dn, s);
	u[nn] = s ? num[nn - 1] >> (MP_LIMB_BITS - s) : 0;
	mpn_lshift_bits(u, num, nn, s);
	for (ut32 j = nn - dn + 1; j-- > 0;) {
		ut64 top = ((ut64)u[j + dn] << MP_LIMB_BITS) | u[j + dn - 1];
		ut64 qhat = top / v[dn - 1];
		ut64 rhat = top % v[dn - 1];
		while (qhat > 0xffffffffull || qhat * v[dn - 2] > ((rhat << MP_LIMB_BITS) | u[j + dn - 2])) {
			qhat--;
			rhat += v[dn - 1];
			if (rhat > 0xffffffffull) {
				break;
			}
		}
		/* u[j .. j + dn] -= qhat * v */
		st64 borrow = 0;
		ut64 carry = 0;
		for (ut32 i = 0; i < dn; i++) {
			ut64 p = qhat * v[i] + carry;
			carry = p >> MP_LIMB_BITS;
			st64 t = (st64)u[i + j] - borrow - (st64)(p & 0xffffffffull);
			u[i + j] = (MpLimb)t;
			borrow = t < 0 ? 1 : 0;
		}
		st64 t = (st64)u[j + dn] - borrow - (st64)carry;
		u[j + dn] = (MpLimb)t;
		if (t < 0) {
			/* qhat was one too large: add v back */
			qhat--;
			ut64 c = 0;
			for (ut32 i = 0; i < dn; i++) {
				c += (ut64)u[i + j] + v[i];
				u[i + j] = (MpLimb)c;
				c >>= MP_LIMB_BITS;
			}
			u[j + dn] += (MpLimb)c;
		}
		q[j] = (MpLimb)qhat;
	}
	return !mpn_is_zero(u, dn);
}

/* s = floor(sqrt(a)) with a of n limbs (n even); returns true if inexact. */
static bool mpn_sqrtrem(MpLimb *s, const MpLimb *a, ut32 n) {
	MpLimb rem[MP_BUF_LIMBS];
	MpLimb t[MP_BUF_LIMBS];
	ut32 rn = n / 2 + 2;
	ut32 sn = n / 2;
	mpn_zero(rem, rn);
	mpn_zero(s, sn);
	for (ut32 pair = n * (MP_LIMB_BITS / 2); pair-- > 0;) {
		ut32 bit = pair * 2;
		MpLimb two = (a[bit / MP_LIMB_BITS] >> (bit % MP_LIMB_BITS)) & 3;
		/* rem = rem * 4 + two */
		mpn_lshift_bits(rem, rem, rn, 2);
		rem[0] |= two;
		/* t = s * 4 + 1 */
		mpn_zero(t, rn);
		memcpy(t, s, sn * sizeof(MpLimb));
		mpn_lshift_bits(t, t, rn, 2);
		t[0] |= 1;
		mpn_lshift_bits(s, s, sn, 1);
		if (mpn_cmp(rem, t, rn) >= 0) {
			mpn_sub_n(rem, rem, t, rn);
			s[0] |= 1;
		}
	}
	return !mpn_is_zero(rem, rn);
}

/** \} */

/**
 * Round (-1)^sign * 0.buf * 2^exp, plus a positive amount below the last
 * limb when \p sticky is set, to the precision of \p r.
 * \p buf is modified. Returns the ternary value.
 */
static int mp_round_buf(MpFloat *r, bool sign, st64 exp, MpLimb *buf, ut32 n, bool sticky, RzFloatRMode rnd) {
	ut32 top = n;
	while (top > 0 && !buf[top - 1]) {
		top--;
	}
	if (!top) {
		rz_warn_if_fail(!sticky);
		rz_mp_set_zero(r, sign);
		return 0;
	}
	/* drop zero limbs at the top, then normalize the leading bit */
	exp -= (st64)(n - top) * MP_LIMB_BITS;
	n = top;
	ut32 lz = limb_clz(buf[n - 1]);
	if (lz) {
		mpn_lshift_bits(buf, buf, n, lz);
		exp -= lz;
	}
	ut32 p = r->prec;
	ut32 m = mp_nlimbs(p);
	ut32 unused = m * MP_LIMB_BITS - p;
	mpn_zero(r->d, m);
	bool round = false;
	if (n >= m) {
		memcpy(r->d, buf + (n - m), m * sizeof(MpLimb));
		if (n > m) {
			round = false;
			if (unused) {
				round = (r->d[0] >> (unused - 1)) & 1;
				sticky |= (r->d[0] & ((1u << (unused - 1)) - 1)) != 0;
				sticky |= !mpn_is_zero(buf, n - m);
			} else {
				round = (buf[n - m - 1] >> (MP_LIMB_BITS - 1)) & 1;
				sticky |= (buf[n - m - 1] & 0x7fffffffu) != 0;
				sticky |= !mpn_is_zero(buf, n - m - 1);
			}
		} else if (unused) {
			round = (r->d[0] >> (unused - 1)) & 1;
			sticky |= (r->d[0] & ((1u << (unused - 1)) - 1)) != 0;
		}
	} else {
		memcpy(r->d + (m - n), buf, n * sizeof(MpLimb));
		if (unused) {
			round = (r->d[0] >> (unused - 1)) & 1;
			sticky |= (r->d[0] & ((1u << (unused - 1)) - 1)) != 0;
		}
	}
	if (unused) {
		r->d[0] &= ~((1u << unused) - 1);
	}
	bool lsb = (r->d[0] >> unused) & 1;
	bool inexact = round || sticky;
	bool inc = false;
	switch (rnd) {
	case RZ_FLOAT_RMODE_RNE:
		inc = round && (sticky || lsb);
		break;
	case RZ_FLOAT_RMODE_RNA:
		inc = round;
		break;
	case RZ_FLOAT_RMODE_RTP:
		inc = !sign && inexact;
		break;
	case RZ_FLOAT_RMODE_RTN:
		inc = sign && inexact;
		break;
	default:
		inc = false;
		break;
	}
	if (inc && mpn_add_1(r->d, m, (MpLimb)1 << unused)) {
		mpn_zero(r->d, m);
		r->d[m - 1] = 0x80000000u;
		exp++;
	}
	r->zero = false;
	r->sign = sign;
	r->exp = exp;
	if (!inexact) {
		return 0;
	}
	return (inc != sign) ? 1 : -1;
}

RZ_IPI void rz_mp_init(MpFloat *x, ut32 prec) {
	rz_return_if_fail(x && prec >= 2 && prec <= MP_MAX_PREC);
	memset(x, 0, sizeof(*x));
	x->prec = prec;
	x->zero = true;
}

RZ_IPI void rz_mp_set_zero(MpFloat *x, bool sign) {
	x->zero = true;
	x->sign = sign;
	x->exp = 0;
	mpn_zero(x->d, mp_nlimbs(x->prec));
}

RZ_IPI int rz_mp_set(MpFloat *r, const MpFloat *a, RzFloatRMode rnd) {
	if (a->zero) {
		rz_mp_set_zero(r, a->sign);
		return 0;
	}
	MpLimb buf[MP_MAX_LIMBS];
	ut32 n = mp_nlimbs(a->prec);
	memcpy(buf, a->d, n * sizeof(MpLimb));
	return mp_round_buf(r, a->sign, a->exp, buf, n, false, rnd);
}

RZ_IPI int rz_mp_set_ui(MpFloat *r, ut64 v, RzFloatRMode rnd) {
	MpLimb buf[2] = { (MpLimb)v, (MpLimb)(v >> MP_LIMB_BITS) };
	if (!v) {
		rz_mp_set_zero(r, false);
		return 0;
	}
	return mp_round_buf(r, false, 2 * MP_LIMB_BITS, buf, 2, false, rnd);
}

RZ_IPI int rz_mp_set_si(MpFloat *r, st64 v, RzFloatRMode rnd) {
	ut64 mag = v < 0 ? (ut64)0 - (ut64)v : (ut64)v;
	MpLimb buf[2] = { (MpLimb)mag, (MpLimb)(mag >> MP_LIMB_BITS) };
	if (!v) {
		rz_mp_set_zero(r, false);
		return 0;
	}
	return mp_round_buf(r, v < 0, 2 * MP_LIMB_BITS, buf, 2, false, rnd);
}

/** r = v * 2^e */
RZ_IPI int rz_mp_set_2exp(MpFloat *r, st64 v, st64 e, RzFloatRMode rnd) {
	int t = rz_mp_set_si(r, v, rnd);
	rz_mp_mul_2si(r, e);
	return t;
}

RZ_IPI void rz_mp_mul_2si(MpFloat *x, st64 k) {
	if (!x->zero) {
		x->exp += k;
	}
}

RZ_IPI void rz_mp_neg(MpFloat *x) {
	x->sign = !x->sign;
}

RZ_IPI void rz_mp_abs(MpFloat *x) {
	x->sign = false;
}

RZ_IPI int rz_mp_cmp_abs(const MpFloat *a, const MpFloat *b) {
	if (a->zero || b->zero) {
		return (a->zero ? 0 : 1) - (b->zero ? 0 : 1);
	}
	if (a->exp != b->exp) {
		return a->exp < b->exp ? -1 : 1;
	}
	ut32 na = mp_nlimbs(a->prec);
	ut32 nb = mp_nlimbs(b->prec);
	ut32 n = RZ_MAX(na, nb);
	for (ut32 i = 0; i < n; i++) {
		MpLimb la = i < na ? a->d[na - 1 - i] : 0;
		MpLimb lb = i < nb ? b->d[nb - 1 - i] : 0;
		if (la != lb) {
			return la < lb ? -1 : 1;
		}
	}
	return 0;
}

RZ_IPI int rz_mp_cmp(const MpFloat *a, const MpFloat *b) {
	if (a->zero && b->zero) {
		return 0;
	}
	bool sa = a->zero ? !b->sign : a->sign;
	bool sb = b->zero ? !a->sign : b->sign;
	if (sa != sb) {
		return sa ? -1 : 1;
	}
	int c = rz_mp_cmp_abs(a, b);
	return sa ? -c : c;
}

RZ_IPI int rz_mp_cmp_si(const MpFloat *a, st64 v) {
	MpFloat t;
	rz_mp_init(&t, 64);
	rz_mp_set_si(&t, v, RZ_FLOAT_RMODE_RNE);
	return rz_mp_cmp(a, &t);
}

/* |r| = |a| + |b| or |a| - |b| with |a| >= |b|, sign of the result given. */
static int mp_add_abs(MpFloat *r, const MpFloat *a, const MpFloat *b, bool subtract, bool sign, RzFloatRMode rnd) {
	MpLimb bufa[MP_BUF_LIMBS];
	MpLimb bufb[MP_BUF_LIMBS];
	ut32 na = mp_nlimbs(a->prec);
	ut32 nb = mp_nlimbs(b->prec);
	ut64 diff = (ut64)(a->exp - b->exp);
	ut64 limit = (ut64)RZ_MAX(r->prec, a->prec) + 2 * MP_LIMB_BITS;
	if (diff > limit) {
		/* b only decides the direction: model it as a sticky amount
		 * below the precision of both a and r. */
		ut32 n = RZ_MAX(na, mp_nlimbs(r->prec)) + 2;
		mpn_zero(bufa, n);
		memcpy(bufa + (n - na), a->d, na * sizeof(MpLimb));
		if (subtract) {
			mpn_sub_1(bufa, n, 1);
		}
		return mp_round_buf(r, sign, a->exp, bufa, n, true, rnd);
	}
	/* Place both significands on a common grid: the result spans
	 * from a's top bit down to the lowest bit of either operand. */
	ut64 bits_a = (ut64)na * MP_LIMB_BITS;
	ut64 span = RZ_MAX(bits_a, diff + (ut64)nb * MP_LIMB_BITS);
	ut32 n = (ut32)((span + MP_LIMB_BITS - 1) / MP_LIMB_BITS) + 1;
	mpn_zero(bufa, n);
	mpn_zero(bufb, n);
	/* a occupies the top na limbs below one guard limb */
	memcpy(bufa + (n - 1 - na), a->d, na * sizeof(MpLimb));
	memcpy(bufb + (n - 1 - nb), b->d, nb * sizeof(MpLimb));
	if (diff) {
		mpn_rshift_bits(bufb, bufb, n, diff);
	}
	if (subtract) {
		mpn_sub_n(bufa, bufa, bufb, n);
	} else {
		mpn_add_n(bufa, bufa, bufb, n);
	}
	return mp_round_buf(r, sign, a->exp + MP_LIMB_BITS, bufa, n, false, rnd);
}

RZ_IPI int rz_mp_add(MpFloat *r, const MpFloat *a, const MpFloat *b, RzFloatRMode rnd) {
	if (a->zero && b->zero) {
		bool sign = rnd == RZ_FLOAT_RMODE_RTN ? (a->sign || b->sign) : (a->sign && b->sign);
		rz_mp_set_zero(r, sign);
		return 0;
	}
	if (a->zero) {
		return rz_mp_set(r, b, rnd);
	}
	if (b->zero) {
		return rz_mp_set(r, a, rnd);
	}
	int c = rz_mp_cmp_abs(a, b);
	if (a->sign == b->sign) {
		return c >= 0 ? mp_add_abs(r, a, b, false, a->sign, rnd) : mp_add_abs(r, b, a, false, a->sign, rnd);
	}
	if (!c) {
		rz_mp_set_zero(r, rnd == RZ_FLOAT_RMODE_RTN);
		return 0;
	}
	return c > 0 ? mp_add_abs(r, a, b, true, a->sign, rnd) : mp_add_abs(r, b, a, true, b->sign, rnd);
}

RZ_IPI int rz_mp_sub(MpFloat *r, const MpFloat *a, const MpFloat *b, RzFloatRMode rnd) {
	MpFloat nb = *b;
	nb.sign = !nb.sign;
	return rz_mp_add(r, a, &nb, rnd);
}

RZ_IPI int rz_mp_mul(MpFloat *r, const MpFloat *a, const MpFloat *b, RzFloatRMode rnd) {
	bool sign = a->sign != b->sign;
	if (a->zero || b->zero) {
		rz_mp_set_zero(r, sign);
		return 0;
	}
	MpLimb buf[2 * MP_MAX_LIMBS];
	ut32 na = mp_nlimbs(a->prec);
	ut32 nb = mp_nlimbs(b->prec);
	mpn_mul(buf, a->d, na, b->d, nb);
	return mp_round_buf(r, sign, a->exp + b->exp, buf, na + nb, false, rnd);
}

RZ_IPI int rz_mp_div(MpFloat *r, const MpFloat *a, const MpFloat *b, RzFloatRMode rnd) {
	bool sign = a->sign != b->sign;
	rz_return_val_if_fail(!b->zero, 0);
	if (a->zero) {
		rz_mp_set_zero(r, sign);
		return 0;
	}
	MpLimb num[MP_BUF_LIMBS];
	MpLimb q[MP_BUF_LIMBS];
	ut32 na = mp_nlimbs(a->prec);
	ut32 nb = mp_nlimbs(b->prec);
	ut32 k = nb + mp_nlimbs(r->prec) + 1;
	ut32 nn = na + k;
	mpn_zero(num, nn);
	memcpy(num + k, a->d, na * sizeof(MpLimb));
	ut32 dn = nb;
	while (dn > 1 && !b->d[nb - dn]) {
		/* drop low zero limbs of the divisor by shifting the dividend */
		dn--;
	}
	const MpLimb *den = b->d + (nb - dn);
	ut32 skip = nb - dn;
	/* num / (den * 2^(32 skip)) = (num >> 32 skip) / den, the shifted out
	 * limbs of num are zero for skip <= k */
	bool sticky = mpn_divrem(q, num + skip, nn - skip, den, dn);
	ut32 nq = nn - skip - dn + 1;
	/* value = q * 2^(32 (nb - na - k)) * 2^(a.exp - b.exp), with q of nq limbs */
	st64 exp = a->exp - b->exp + (st64)MP_LIMB_BITS * ((st64)nb - na - k + nq);
	return mp_round_buf(r, sign, exp, q, nq, sticky, rnd);
}

RZ_IPI int rz_mp_sqrt(MpFloat *r, const MpFloat *a, RzFloatRMode rnd) {
	rz_return_val_if_fail(a->zero || !a->sign, 0);
	if (a->zero) {
		rz_mp_set_zero(r, a->sign);
		return 0;
	}
	MpLimb n[MP_BUF_LIMBS];
	MpLimb s[MP_BUF_LIMBS];
	ut32 na = mp_nlimbs(a->prec);
	/* N = 0.d * 2^(32 nn) holds at least 2 (prec + 2) bits and the scale
	 * exponent a.exp - 32 nn must be even. */
	ut32 nn = 2 * (mp_nlimbs(r->prec) + 1);
	if (nn < na + 1) {
		nn = na + 1;
	}
	nn += nn & 1;
	mpn_zero(n, nn);
	memcpy(n + (nn - na), a->d, na * sizeof(MpLimb));
	st64 scale = a->exp - (st64)nn * MP_LIMB_BITS;
	if (scale & 1) {
		/* make it even: N >>= 1 keeps the bits as N is left aligned with
		 * free room below */
		bool lost = mpn_rshift_bits(n, n, nn, 1);
		rz_warn_if_fail(!lost);
		scale++;
	}
	bool sticky = mpn_sqrtrem(s, n, nn);
	ut32 ns = nn / 2;
	/* sqrt(a) = sqrt(N) * 2^(scale / 2) = 0.s * 2^(32 ns + scale / 2) */
	return mp_round_buf(r, false, (st64)ns * MP_LIMB_BITS + scale / 2, s, ns, sticky, rnd);
}

RZ_IPI int rz_mp_add_si(MpFloat *r, const MpFloat *a, st64 v, RzFloatRMode rnd) {
	MpFloat t;
	rz_mp_init(&t, 64);
	rz_mp_set_si(&t, v, RZ_FLOAT_RMODE_RNE);
	return rz_mp_add(r, a, &t, rnd);
}

RZ_IPI int rz_mp_mul_si(MpFloat *r, const MpFloat *a, st64 v, RzFloatRMode rnd) {
	MpFloat t;
	rz_mp_init(&t, 64);
	rz_mp_set_si(&t, v, RZ_FLOAT_RMODE_RNE);
	return rz_mp_mul(r, a, &t, rnd);
}

RZ_IPI int rz_mp_div_si(MpFloat *r, const MpFloat *a, st64 v, RzFloatRMode rnd) {
	MpFloat t;
	rz_mp_init(&t, 64);
	rz_mp_set_si(&t, v, RZ_FLOAT_RMODE_RNE);
	return rz_mp_div(r, a, &t, rnd);
}

/** Number of trailing zero bits of the significand integer (0.d scaled to an integer). */
RZ_IPI ut64 rz_mp_trailing_zeros(const MpFloat *a) {
	ut32 n = mp_nlimbs(a->prec);
	ut64 tz = 0;
	for (ut32 i = 0; i < n; i++) {
		if (a->d[i]) {
			return tz + limb_ctz(a->d[i]);
		}
		tz += MP_LIMB_BITS;
	}
	return tz;
}

RZ_IPI bool rz_mp_is_integer(const MpFloat *a) {
	if (a->zero) {
		return true;
	}
	ut64 total = (ut64)mp_nlimbs(a->prec) * MP_LIMB_BITS;
	/* the lowest set bit has weight 2^(exp - total + tz) */
	return a->exp - (st64)total + (st64)rz_mp_trailing_zeros(a) >= 0;
}

/** r = a rounded to an integer in the given mode. r needs enough precision for the result. */
RZ_IPI int rz_mp_round_int(MpFloat *r, const MpFloat *a, RzFloatRMode rnd) {
	if (a->zero || rz_mp_is_integer(a)) {
		return rz_mp_set(r, a, rnd);
	}
	MpLimb buf[MP_MAX_LIMBS + 2];
	ut32 n = mp_nlimbs(a->prec);
	ut64 total = (ut64)n * MP_LIMB_BITS;
	bool round = false;
	bool sticky = false;
	bool lsb = false;
	st64 exp = a->exp;
	if (exp <= 0) {
		/* |a| < 1: the whole significand is fraction */
		round = exp == 0;
		sticky = exp < 0 || rz_mp_trailing_zeros(a) + 1 < total;
		mpn_zero(buf, n + 1);
		exp = 1;
	} else {
		/* exp < total because a is not an integer */
		ut64 frac_bits = total - (ut64)exp;
		buf[n] = 0;
		memcpy(buf, a->d, n * sizeof(MpLimb));
		ut64 rb = frac_bits - 1;
		round = (buf[rb / MP_LIMB_BITS] >> (rb % MP_LIMB_BITS)) & 1;
		for (ut64 i = 0; i < rb; i++) {
			if ((buf[i / MP_LIMB_BITS] >> (i % MP_LIMB_BITS)) & 1) {
				sticky = true;
				break;
			}
		}
		for (ut64 i = 0; i < frac_bits; i++) {
			buf[i / MP_LIMB_BITS] &= ~(1u << (i % MP_LIMB_BITS));
		}
		lsb = (buf[frac_bits / MP_LIMB_BITS] >> (frac_bits % MP_LIMB_BITS)) & 1;
	}
	bool inc = false;
	switch (rnd) {
	case RZ_FLOAT_RMODE_RNE:
		inc = round && (sticky || lsb);
		break;
	case RZ_FLOAT_RMODE_RNA:
		inc = round;
		break;
	case RZ_FLOAT_RMODE_RTP:
		inc = !a->sign;
		break;
	case RZ_FLOAT_RMODE_RTN:
		inc = a->sign;
		break;
	default:
		break;
	}
	if (a->exp <= 0) {
		if (inc) {
			/* 1 = 0.1 * 2^1 */
			buf[n - 1] = 0x80000000u;
		}
	} else if (inc) {
		ut64 unit = total - (ut64)a->exp;
		ut64 c = (ut64)1 << (unit % MP_LIMB_BITS);
		mpn_add_1(buf + unit / MP_LIMB_BITS, n + 1 - (ut32)(unit / MP_LIMB_BITS), (MpLimb)c);
	}
	if (mpn_is_zero(buf, n + 1)) {
		rz_mp_set_zero(r, a->sign);
	} else {
		/* buf[n] is a carry limb above the significand */
		mp_round_buf(r, a->sign, exp + MP_LIMB_BITS, buf, n + 1, false, RZ_FLOAT_RMODE_RNE);
	}
	return (inc != a->sign) ? 1 : -1;
}

/** Integer value of a (truncated), saturating to +-2^62. */
RZ_IPI st64 rz_mp_get_si(const MpFloat *a) {
	if (a->zero || a->exp <= 0) {
		return 0;
	}
	if (a->exp > 62) {
		return a->sign ? -(1ll << 62) : (1ll << 62);
	}
	ut32 n = mp_nlimbs(a->prec);
	ut64 v = 0;
	for (st64 bit = 0; bit < a->exp; bit++) {
		ut64 pos = (ut64)n * MP_LIMB_BITS - 1 - bit;
		v = (v << 1) | ((a->d[pos / MP_LIMB_BITS] >> (pos % MP_LIMB_BITS)) & 1);
	}
	return a->sign ? -(st64)v : (st64)v;
}

static void mp_const_from_table(MpFloat *r, const ut8 *table, st64 exp) {
	MpLimb buf[MP_MAX_LIMBS + 2];
	ut32 n = mp_nlimbs(r->prec) + 2;
	rz_return_if_fail((ut64)n * MP_LIMB_BITS <= MP_CONST_BITS);
	for (ut32 i = 0; i < n; i++) {
		const ut8 *b = table + 4 * (n - 1 - i);
		buf[i] = ((MpLimb)b[0] << 24) | ((MpLimb)b[1] << 16) | ((MpLimb)b[2] << 8) | b[3];
	}
	/* the constants are irrational: the truncated tail is nonzero */
	mp_round_buf(r, false, exp, buf, n, true, RZ_FLOAT_RMODE_RNE);
}

RZ_IPI void rz_mp_const_pi(MpFloat *r) {
	mp_const_from_table(r, mp_const_pi_bits, MP_CONST_PI_EXP);
}

RZ_IPI void rz_mp_const_ln2(MpFloat *r) {
	mp_const_from_table(r, mp_const_ln2_bits, MP_CONST_LN2_EXP);
}

RZ_IPI void rz_mp_const_ln10(MpFloat *r) {
	mp_const_from_table(r, mp_const_ln10_bits, MP_CONST_LN10_EXP);
}

/**
 * Copy bits [first_bit, first_bit + 32 nlimbs) of floor(2/pi * 2^N), counted
 * from its most significant bit (bit 0 is the 2^-1 digit of 2/pi), into out,
 * most significant first in the usual little-endian limb order. Bits before
 * the binary point (negative positions) are zero.
 */
RZ_IPI bool rz_mp_two_over_pi_window(MpLimb *out, ut32 nlimbs, st64 first_bit) {
	ut64 total = (ut64)nlimbs * MP_LIMB_BITS;
	if (first_bit + (st64)total > MP_TWO_OVER_PI_BITS) {
		return false;
	}
	mpn_zero(out, nlimbs);
	for (ut64 i = 0; i < total; i++) {
		st64 pos = first_bit + (st64)i;
		if (pos < 0) {
			continue;
		}
		bool bit = (mp_two_over_pi_bits[pos / 8] >> (7 - pos % 8)) & 1;
		if (bit) {
			ut64 dst = total - 1 - i;
			out[dst / MP_LIMB_BITS] |= 1u << (dst % MP_LIMB_BITS);
		}
	}
	return true;
}

/**
 * \name Conversion from and to RzFloat
 * \{
 */

/** Significand precision of a binary format, counting the leading bit. */
RZ_IPI ut32 rz_mp_format_prec(RzFloatFormat format) {
	ut32 man = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	return format == RZ_FLOAT_IEEE754_BIN_80 ? man : man + 1;
}

static bool float_bit(const RzFloat *f, ut32 i) {
	return rz_bv_get(f->s, i);
}

/** r = f exactly; r->prec must be at least the format precision. f must be finite. */
RZ_IPI bool rz_mp_set_float(MpFloat *r, const RzFloat *f) {
	RzFloatFormat format = f->r;
	ut32 total = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	st64 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	rz_return_val_if_fail(r->prec >= rz_mp_format_prec(format), false);
	bool sign = float_bit(f, total - 1);
	ut64 e = 0;
	for (ut32 i = 0; i < exp_len; i++) {
		e |= (ut64)float_bit(f, man_len + i) << i;
	}
	if (e == ((1ull << exp_len) - 1)) {
		return false;
	}
	/* integer significand of man_len (+ hidden) bits */
	MpLimb buf[5] = { 0 };
	for (ut32 i = 0; i < man_len; i++) {
		if (float_bit(f, i)) {
			buf[i / MP_LIMB_BITS] |= 1u << (i % MP_LIMB_BITS);
		}
	}
	bool explicit_int = format == RZ_FLOAT_IEEE754_BIN_80;
	ut32 frac_bits = explicit_int ? man_len - 1 : man_len;
	if (!explicit_int && e) {
		buf[man_len / MP_LIMB_BITS] |= 1u << (man_len % MP_LIMB_BITS);
	}
	/* value = sig * 2^(max(e, 1) - bias - frac_bits); sig fits in 5 limbs */
	st64 scale = (e ? (st64)e : 1) - bias - frac_bits;
	if (mpn_is_zero(buf, 5)) {
		rz_mp_set_zero(r, sign);
		return true;
	}
	mp_round_buf(r, sign, scale + 5 * MP_LIMB_BITS, buf, 5, false, RZ_FLOAT_RMODE_RNE);
	return true;
}

static void float_set_bits(RzFloat *f, bool sign, ut64 biased, const MpLimb *sig, ut32 sig_bits) {
	ut32 total = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_TOTAL_LEN);
	ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	rz_bv_set_all(f->s, false);
	for (ut32 i = 0; i < man_len && i < sig_bits; i++) {
		rz_bv_set(f->s, i, (sig[i / MP_LIMB_BITS] >> (i % MP_LIMB_BITS)) & 1);
	}
	for (ut32 i = 0; i < exp_len; i++) {
		rz_bv_set(f->s, man_len + i, (biased >> i) & 1);
	}
	rz_bv_set(f->s, total - 1, sign);
}

static RzFloat *float_overflow(RzFloatFormat format, bool sign, RzFloatRMode rnd) {
	RzFloat *ret = rz_float_new(format);
	if (!ret) {
		return NULL;
	}
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	bool to_inf = rnd == RZ_FLOAT_RMODE_RNE || rnd == RZ_FLOAT_RMODE_RNA ||
		(!sign && rnd == RZ_FLOAT_RMODE_RTP) || (sign && rnd == RZ_FLOAT_RMODE_RTN);
	MpLimb sig[5] = { 0 };
	ut64 biased = (1ull << exp_len) - 1;
	if (to_inf) {
		if (format == RZ_FLOAT_IEEE754_BIN_80) {
			sig[1] = 0x80000000u;
		}
	} else {
		biased--;
		for (ut32 i = 0; i < man_len; i++) {
			sig[i / MP_LIMB_BITS] |= 1u << (i % MP_LIMB_BITS);
		}
	}
	float_set_bits(ret, sign, biased, sig, man_len);
	ret->exception = RZ_FLOAT_E_OVERFLOW | RZ_FLOAT_E_INEXACT;
	return ret;
}

/**
 * Round x to \p format in mode \p rnd, with the exponent range of the format
 * (gradual underflow, overflow to infinity or the largest finite value).
 * Sets the inexact, overflow and underflow exceptions; underflow means tiny
 * and inexact, with tininess detected as configured for SoftFloat.
 */
RZ_IPI RZ_OWN RzFloat *rz_mp_get_float(const MpFloat *x, RzFloatFormat format, RzFloatRMode rnd) {
	ut32 p = rz_mp_format_prec(format);
	st64 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	st64 emin = 1 - bias; // min normal is 2^emin
	st64 emax = bias; // max finite < 2^(emax + 1)
	bool explicit_int = format == RZ_FLOAT_IEEE754_BIN_80;
	RzFloat *ret = rz_float_new(format);
	if (!ret) {
		return NULL;
	}
	if (x->zero) {
		MpLimb zero[5] = { 0 };
		float_set_bits(ret, x->sign, 0, zero, 0);
		return ret;
	}
	/* Round to a multiple of the target ulp 2^q: x * 2^-q to an integer. */
	st64 q = RZ_MAX(x->exp - (st64)p, emin - (st64)p + 1);
	MpFloat t;
	MpFloat s = *x;
	rz_mp_init(&t, 128);
	rz_mp_mul_2si(&s, -q);
	int tern = rz_mp_round_int(&t, &s, rnd);
	rz_mp_mul_2si(&t, q);
	if (!t.zero && t.exp - 1 > emax) {
		rz_float_free(ret);
		return float_overflow(format, x->sign, rnd);
	}
	/* tininess */
	bool tiny;
	if (softfloat_detectTininess == softfloat_tininess_beforeRounding) {
		tiny = x->exp - 1 < emin;
	} else {
		MpFloat u;
		rz_mp_init(&u, p);
		rz_mp_set(&u, x, rnd);
		tiny = u.exp - 1 < emin;
	}
	MpLimb sig[5] = { 0 };
	ut64 biased = 0;
	if (!t.zero) {
		/* integer significand = |t| / 2^qq, renormalized after a carry */
		st64 qq = t.exp - 1 >= emin ? t.exp - (st64)p : emin - (st64)p + 1;
		st64 sh = t.exp - qq; // number of significant bits of the integer
		ut32 n = mp_nlimbs(t.prec);
		for (st64 i = 0; i < sh; i++) {
			ut64 pos = (ut64)n * MP_LIMB_BITS - sh + i;
			if ((t.d[pos / MP_LIMB_BITS] >> (pos % MP_LIMB_BITS)) & 1) {
				sig[i / MP_LIMB_BITS] |= 1u << (i % MP_LIMB_BITS);
			}
		}
		if (t.exp - 1 >= emin) {
			biased = (ut64)(t.exp - 1 + bias);
			if (!explicit_int) {
				/* drop the hidden bit */
				sig[(p - 1) / MP_LIMB_BITS] &= ~(1u << ((p - 1) % MP_LIMB_BITS));
			}
		}
	}
	float_set_bits(ret, x->sign, biased, sig, p);
	if (tern) {
		ret->exception |= RZ_FLOAT_E_INEXACT;
		if (tiny) {
			ret->exception |= RZ_FLOAT_E_UNDERFLOW;
		}
	}
	return ret;
}

/** \} */
