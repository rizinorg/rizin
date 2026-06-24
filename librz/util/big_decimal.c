// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Arbitrary-precision base-10 decimal (RzBigDecimal).
 *
 * A decimal value is stored as an arbitrary-precision integer mantissa
 * times 10^(-scale), with the sign carried by the mantissa and scale
 * kept >= 0. Addition, subtraction and multiplication are exact;
 * division is computed to a bounded number of significant digits because
 * a finite base-10 expansion cannot represent ratios such as 1/3.
 *
 * Built on RzNumBig (which is integer-only); the base-10 scale and the
 * fractional formatting live here.
 */

#include <rz_util/rz_big.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_assert.h>
#include <stdlib.h>
#include <string.h>

// ---- small RzNumBig helpers -------------------------------------------------

static RzNumBig *big_zero(void) {
	RzNumBig *b = rz_big_new();
	if (b) {
		rz_big_from_int(b, 0);
	}
	return b;
}

static RzNumBig *big_from_i64(st64 v) {
	RzNumBig *b = rz_big_new();
	if (b) {
		rz_big_from_int(b, v);
	}
	return b;
}

static RzNumBig *big_clone(RZ_NONNULL RzNumBig *src) {
	RzNumBig *b = rz_big_new();
	if (b) {
		rz_big_assign(b, src);
	}
	return b;
}

// out = 10^k (k >= 0). Returns NULL on allocation failure.
static RzNumBig *big_pow10(ut32 k) {
	RzNumBig *out = rz_big_new();
	RzNumBig *ten = big_from_i64(10);
	RzNumBig *exp = big_from_i64((st64)k);
	if (!out || !ten || !exp) {
		rz_big_free(out);
		rz_big_free(ten);
		rz_big_free(exp);
		return NULL;
	}
	rz_big_pow(out, ten, exp);
	rz_big_free(ten);
	rz_big_free(exp);
	return out;
}

// out = m * 10^k (k >= 0). Returns a new RzNumBig or NULL.
static RzNumBig *big_scale_up(RZ_NONNULL RzNumBig *m, ut32 k) {
	if (k == 0) {
		return big_clone(m);
	}
	RzNumBig *p = big_pow10(k);
	RzNumBig *out = rz_big_new();
	if (!p || !out) {
		rz_big_free(p);
		rz_big_free(out);
		return NULL;
	}
	rz_big_mul(out, m, p);
	rz_big_free(p);
	return out;
}

// Number of base-10 digits of |m| (0 counts as 1). -1 on failure.
static int big_digit_count(RZ_NONNULL RzNumBig *m) {
	char *s = rz_big_to_decstr(m);
	if (!s) {
		return -1;
	}
	const char *p = s;
	if (*p == '-') {
		p++;
	}
	int n = (int)strlen(p);
	free(s);
	return n < 1 ? 1 : n;
}

// abs into a fresh RzNumBig.
static RzNumBig *big_abs(RZ_NONNULL RzNumBig *m) {
	RzNumBig *zero = big_zero();
	if (!zero) {
		return NULL;
	}
	RzNumBig *out;
	if (rz_big_cmp(m, zero) < 0) {
		out = rz_big_new();
		if (out) {
			rz_big_sub(out, zero, m); // out = -m
		}
	} else {
		out = big_clone(m);
	}
	rz_big_free(zero);
	return out;
}

// ---- RzBigDecimal construction ----------------------------------------------

static RzBigDecimal *bd_new(RZ_OWN RzNumBig *mantissa, st32 scale) {
	if (!mantissa) {
		return NULL;
	}
	RzBigDecimal *d = RZ_NEW0(RzBigDecimal);
	if (!d) {
		rz_big_free(mantissa);
		return NULL;
	}
	d->mantissa = mantissa;
	d->scale = scale;
	return d;
}

void rz_big_decimal_free(RzBigDecimal *d) {
	if (!d) {
		return;
	}
	rz_big_free(d->mantissa);
	free(d);
}

RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_dup(RZ_NONNULL const RzBigDecimal *d) {
	rz_return_val_if_fail(d, NULL);
	return bd_new(big_clone(d->mantissa), d->scale);
}

RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_new_from_int(st64 v) {
	return bd_new(big_from_i64(v), 0);
}

// Parse "[+-]ddd[.ddd][eE[+-]ddd]" into mantissa * 10^(-scale), scale >= 0.
RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_new_from_str(RZ_NONNULL const char *str) {
	rz_return_val_if_fail(str, NULL);
	const char *p = str;
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	bool neg = false;
	if (*p == '+' || *p == '-') {
		neg = (*p == '-');
		p++;
	}
	// Collect integer and fractional digit runs (no point).
	RzStrBuf digits;
	rz_strbuf_init(&digits);
	st32 frac_len = 0;
	bool seen_digit = false;
	while (*p >= '0' && *p <= '9') {
		rz_strbuf_append_n(&digits, p, 1);
		seen_digit = true;
		p++;
	}
	if (*p == '.') {
		p++;
		while (*p >= '0' && *p <= '9') {
			rz_strbuf_append_n(&digits, p, 1);
			frac_len++;
			seen_digit = true;
			p++;
		}
	}
	if (!seen_digit) {
		rz_strbuf_fini(&digits);
		return NULL;
	}
	// Optional exponent.
	st32 exp = 0;
	if (*p == 'e' || *p == 'E') {
		p++;
		bool eneg = false;
		if (*p == '+' || *p == '-') {
			eneg = (*p == '-');
			p++;
		}
		if (*p < '0' || *p > '9') {
			rz_strbuf_fini(&digits);
			return NULL;
		}
		while (*p >= '0' && *p <= '9') {
			exp = exp * 10 + (*p - '0');
			p++;
		}
		if (eneg) {
			exp = -exp;
		}
	}
	// Trailing junk is not a decimal.
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	if (*p != '\0') {
		rz_strbuf_fini(&digits);
		return NULL;
	}

	char *ds = rz_strbuf_drain_nofree(&digits);
	if (!ds) {
		return NULL;
	}
	// Build the mantissa from the digit string (digit-by-digit; RzNumBig
	// has no decimal-string constructor).
	RzNumBig *m = big_zero();
	RzNumBig *ten = big_from_i64(10);
	RzNumBig *tmp = rz_big_new();
	RzNumBig *dig = rz_big_new();
	if (!m || !ten || !tmp || !dig) {
		rz_big_free(m);
		rz_big_free(ten);
		rz_big_free(tmp);
		rz_big_free(dig);
		free(ds);
		return NULL;
	}
	for (char *c = ds; *c; c++) {
		rz_big_mul(tmp, m, ten);
		rz_big_from_int(dig, *c - '0');
		rz_big_add(m, tmp, dig);
	}
	free(ds);
	rz_big_free(ten);
	rz_big_free(tmp);
	rz_big_free(dig);

	if (neg) {
		RzNumBig *zero = big_zero();
		RzNumBig *nm = rz_big_new();
		if (!zero || !nm) {
			rz_big_free(zero);
			rz_big_free(nm);
			rz_big_free(m);
			return NULL;
		}
		rz_big_sub(nm, zero, m); // nm = -m
		rz_big_free(zero);
		rz_big_free(m);
		m = nm;
	}

	// value = digits * 10^(exp) * 10^(-frac_len) = m * 10^(-(frac_len - exp))
	st32 scale = frac_len - exp;
	if (scale < 0) {
		// Fold the negative scale into the mantissa to keep scale >= 0.
		RzNumBig *up = big_scale_up(m, (ut32)(-scale));
		rz_big_free(m);
		if (!up) {
			return NULL;
		}
		m = up;
		scale = 0;
	}
	return bd_new(m, scale);
}

// ---- arithmetic -------------------------------------------------------------

// Bring a and b to a common scale; outputs new mantissas and the scale.
static bool bd_align(const RzBigDecimal *a, const RzBigDecimal *b,
	RzNumBig **out_a, RzNumBig **out_b, st32 *out_scale) {
	st32 s = a->scale > b->scale ? a->scale : b->scale;
	RzNumBig *ma = big_scale_up(a->mantissa, (ut32)(s - a->scale));
	RzNumBig *mb = big_scale_up(b->mantissa, (ut32)(s - b->scale));
	if (!ma || !mb) {
		rz_big_free(ma);
		rz_big_free(mb);
		return false;
	}
	*out_a = ma;
	*out_b = mb;
	*out_scale = s;
	return true;
}

RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_add(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b) {
	rz_return_val_if_fail(a && b, NULL);
	RzNumBig *ma, *mb;
	st32 s;
	if (!bd_align(a, b, &ma, &mb, &s)) {
		return NULL;
	}
	RzNumBig *r = rz_big_new();
	if (r) {
		rz_big_add(r, ma, mb);
	}
	rz_big_free(ma);
	rz_big_free(mb);
	return bd_new(r, s);
}

RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_sub(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b) {
	rz_return_val_if_fail(a && b, NULL);
	RzNumBig *ma, *mb;
	st32 s;
	if (!bd_align(a, b, &ma, &mb, &s)) {
		return NULL;
	}
	RzNumBig *r = rz_big_new();
	if (r) {
		rz_big_sub(r, ma, mb);
	}
	rz_big_free(ma);
	rz_big_free(mb);
	return bd_new(r, s);
}

RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_mul(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b) {
	rz_return_val_if_fail(a && b, NULL);
	RzNumBig *r = rz_big_new();
	if (r) {
		rz_big_mul(r, a->mantissa, b->mantissa);
	}
	return bd_new(r, a->scale + b->scale);
}

RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_neg(RZ_NONNULL const RzBigDecimal *a) {
	rz_return_val_if_fail(a, NULL);
	RzNumBig *zero = big_zero();
	RzNumBig *r = rz_big_new();
	if (!zero || !r) {
		rz_big_free(zero);
		rz_big_free(r);
		return NULL;
	}
	rz_big_sub(r, zero, a->mantissa);
	rz_big_free(zero);
	return bd_new(r, a->scale);
}

// Round |q| (with q's sign) to `keep` significant digits by dropping
// `drop` low digits, half-up. Returns a new RzNumBig.
static RzNumBig *big_round_drop(RZ_NONNULL RzNumBig *q, ut32 drop) {
	if (drop == 0) {
		return big_clone(q);
	}
	RzNumBig *zero = big_zero();
	bool neg = zero && rz_big_cmp(q, zero) < 0;
	RzNumBig *aq = big_abs(q);
	RzNumBig *divisor = big_pow10(drop);
	RzNumBig *half = big_pow10(drop - 1); // *5 below
	RzNumBig *five = big_from_i64(5);
	RzNumBig *tmp = rz_big_new();
	RzNumBig *bumped = rz_big_new();
	RzNumBig *res = rz_big_new();
	if (!zero || !aq || !divisor || !half || !five || !tmp || !bumped || !res) {
		rz_big_free(zero);
		rz_big_free(aq);
		rz_big_free(divisor);
		rz_big_free(half);
		rz_big_free(five);
		rz_big_free(tmp);
		rz_big_free(bumped);
		rz_big_free(res);
		return NULL;
	}
	rz_big_mul(tmp, half, five); // tmp = 5 * 10^(drop-1)
	rz_big_add(bumped, aq, tmp); // |q| + half
	rz_big_div(res, bumped, divisor); // floor((|q|+half)/10^drop)
	if (neg) {
		RzNumBig *nres = rz_big_new();
		if (nres) {
			rz_big_sub(nres, zero, res);
			rz_big_free(res);
			res = nres;
		}
	}
	rz_big_free(zero);
	rz_big_free(aq);
	rz_big_free(divisor);
	rz_big_free(half);
	rz_big_free(five);
	rz_big_free(tmp);
	rz_big_free(bumped);
	return res;
}

RZ_API RZ_OWN RzBigDecimal *rz_big_decimal_div(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b, ut32 precision) {
	rz_return_val_if_fail(a && b, NULL);
	if (rz_big_is_zero(b->mantissa)) {
		return NULL; // division by zero
	}
	if (precision == 0) {
		precision = RZ_BIG_DECIMAL_DEFAULT_PREC;
	}
	if (rz_big_is_zero(a->mantissa)) {
		return rz_big_decimal_new_from_int(0);
	}
	int da = big_digit_count(a->mantissa);
	int db = big_digit_count(b->mantissa);
	if (da < 0 || db < 0) {
		return NULL;
	}
	// Choose a shift so the integer quotient carries ~precision+1 digits.
	st32 shift = (st32)precision + 1 - da + db;
	if (shift < 0) {
		shift = 0;
	}
	RzNumBig *num = big_scale_up(a->mantissa, (ut32)shift);
	RzNumBig *q = rz_big_new();
	if (!num || !q) {
		rz_big_free(num);
		rz_big_free(q);
		return NULL;
	}
	rz_big_div(q, num, b->mantissa); // truncated toward zero
	rz_big_free(num);

	st32 result_scale = shift + a->scale - b->scale;
	int dq = big_digit_count(q);
	if (dq < 0) {
		rz_big_free(q);
		return NULL;
	}
	if ((ut32)dq > precision) {
		ut32 drop = (ut32)dq - precision;
		RzNumBig *rounded = big_round_drop(q, drop);
		rz_big_free(q);
		if (!rounded) {
			return NULL;
		}
		q = rounded;
		result_scale -= (st32)drop;
	}
	if (result_scale < 0) {
		RzNumBig *up = big_scale_up(q, (ut32)(-result_scale));
		rz_big_free(q);
		if (!up) {
			return NULL;
		}
		q = up;
		result_scale = 0;
	}
	return bd_new(q, result_scale);
}

// ---- comparison / predicates ------------------------------------------------

RZ_API int rz_big_decimal_cmp(RZ_NONNULL const RzBigDecimal *a, RZ_NONNULL const RzBigDecimal *b) {
	rz_return_val_if_fail(a && b, 0);
	RzNumBig *ma, *mb;
	st32 s;
	if (!bd_align(a, b, &ma, &mb, &s)) {
		return 0;
	}
	int c = rz_big_cmp(ma, mb);
	rz_big_free(ma);
	rz_big_free(mb);
	return c;
}

RZ_API bool rz_big_decimal_is_zero(RZ_NONNULL const RzBigDecimal *d) {
	rz_return_val_if_fail(d, true);
	return rz_big_is_zero(d->mantissa) != 0;
}

// ---- formatting / projection ------------------------------------------------

RZ_API RZ_OWN char *rz_big_decimal_to_str(RZ_NONNULL const RzBigDecimal *d) {
	rz_return_val_if_fail(d, NULL);
	char *digits = rz_big_to_decstr(d->mantissa);
	if (!digits) {
		return NULL;
	}
	if (d->scale == 0) {
		return digits;
	}
	bool neg = (digits[0] == '-');
	const char *ds = neg ? digits + 1 : digits;
	size_t dlen = strlen(ds);
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	if (neg) {
		rz_strbuf_append(&sb, "-");
	}
	if (dlen > (size_t)d->scale) {
		size_t intlen = dlen - (size_t)d->scale;
		rz_strbuf_append_n(&sb, ds, intlen);
		rz_strbuf_append(&sb, ".");
		rz_strbuf_append(&sb, ds + intlen);
	} else {
		rz_strbuf_append(&sb, "0.");
		for (size_t i = 0; i < (size_t)d->scale - dlen; i++) {
			rz_strbuf_append(&sb, "0");
		}
		rz_strbuf_append(&sb, ds);
	}
	free(digits);
	char *out = rz_strbuf_drain_nofree(&sb);
	if (!out) {
		return NULL;
	}
	// Strip trailing fractional zeros (and a dangling point) for display.
	size_t len = strlen(out);
	while (len && out[len - 1] == '0') {
		out[--len] = '\0';
	}
	if (len && out[len - 1] == '.') {
		out[--len] = '\0';
	}
	return out;
}

RZ_API ut64 rz_big_decimal_to_ut64(RZ_NONNULL const RzBigDecimal *d) {
	rz_return_val_if_fail(d, 0);
	if (d->scale == 0) {
		return (ut64)rz_big_to_int(d->mantissa);
	}
	RzNumBig *pow = big_pow10((ut32)d->scale);
	RzNumBig *q = rz_big_new();
	if (!pow || !q) {
		rz_big_free(pow);
		rz_big_free(q);
		return 0;
	}
	rz_big_div(q, d->mantissa, pow); // truncate toward zero
	ut64 r = (ut64)rz_big_to_int(q);
	rz_big_free(pow);
	rz_big_free(q);
	return r;
}

RZ_API double rz_big_decimal_to_double(RZ_NONNULL const RzBigDecimal *d) {
	rz_return_val_if_fail(d, 0.0);
	char *s = rz_big_decimal_to_str(d);
	if (!s) {
		return 0.0;
	}
	double r = strtod(s, NULL);
	free(s);
	return r;
}
