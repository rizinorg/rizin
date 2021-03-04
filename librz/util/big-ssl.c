// SPDX-FileCopyrightText: 2010 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API RNumBig *rz_big_new(void) {
	return BN_new();
}

RZ_API void rz_big_free(RNumBig *b) {
	BN_free(b);
}

RZ_API void rz_big_init(RNumBig *b) {
	BN_zero(b);
}

RZ_API void rz_big_fini(RNumBig *b) {
	BN_clear(b);
}

RZ_API void rz_big_from_int(RNumBig *b, st64 v) {
	if (v < 0) {
		BN_set_word(b, -v);
		BN_set_negative(b, v);
	} else {
		BN_set_word(b, v);
	}
}

RZ_API st64 rz_big_to_int(RNumBig *b) {
	BN_ULONG maxx = 0;
	maxx = ~maxx;
	BN_ULONG res = BN_get_word(b);
	if (res == maxx) {
		RNumBig *B = rz_big_new();
		rz_big_assign(B, b);
		BN_mask_bits(B, BN_BYTES * 8 - 1);
		res = BN_get_word(B);
		rz_big_free(B);
	}
	res *= (BN_is_negative(b) ? -1 : 1);
	return res;
}

RZ_API void rz_big_from_hexstr(RNumBig *b, const char *str) {
	if (rz_str_startswith(str, "0x")) {
		str += 2;
		BN_hex2bn(&b, str);
	} else if (rz_str_startswith(str, "-0x")) {
		str += 3;
		BN_hex2bn(&b, str);
		BN_set_negative(b, -1);
	}
}

RZ_API char *rz_big_to_hexstr(RNumBig *b) {
	char *tmp = BN_bn2hex(b);
	char *res;
	if (tmp[0] == '-') {
		res = rz_str_newf("-0x%s", &tmp[1]);
	} else {
		res = rz_str_newf("0x%s", tmp);
	}
	OPENSSL_free(tmp);
	for (size_t i = 0; res[i]; i++) {
		res[i] = tolower(res[i]);
	}
	return res;
}

RZ_API void rz_big_assign(RNumBig *dst, RNumBig *src) {
	BN_copy(dst, src);
}

RZ_API void rz_big_add(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_add(c, a, b);
}

RZ_API void rz_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_sub(c, a, b);
}

RZ_API void rz_big_mul(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_mul(c, a, b, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_div(c, NULL, a, b, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_mod(c, a, b, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_divmod(RNumBig *c, RNumBig *d, RNumBig *a, RNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_div(c, d, a, b, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_and(RNumBig *c, RNumBig *a, RNumBig *b) {
	RNumBig *A = rz_big_new();
	RNumBig *B = rz_big_new();
	RNumBig *C = rz_big_new();
	RNumBig *addition = rz_big_new();

	size_t step = 4 * 8, move = 0;
	ut32 tmp = 0;
	rz_big_assign(A, a);
	rz_big_assign(B, b);

	while (!rz_big_is_zero(A) || !rz_big_is_zero(B)) {
		tmp = rz_big_to_int(A);
		tmp &= rz_big_to_int(B);
		rz_big_rshift(A, A, step);
		rz_big_rshift(B, B, step);
		rz_big_from_int(addition, tmp);
		rz_big_lshift(addition, addition, move);
		rz_big_add(C, C, addition);

		move += step;
	}

	rz_big_assign(c, C);

	rz_big_free(A);
	rz_big_free(B);
	rz_big_free(C);
	rz_big_free(addition);
}

RZ_API void rz_big_or(RNumBig *c, RNumBig *a, RNumBig *b) {
	RNumBig *A = rz_big_new();
	RNumBig *B = rz_big_new();
	RNumBig *C = rz_big_new();
	RNumBig *addition = rz_big_new();

	size_t step = 4 * 8, move = 0;
	ut32 tmp = 0;
	rz_big_assign(A, a);
	rz_big_assign(B, b);

	while (!rz_big_is_zero(A) || !rz_big_is_zero(B)) {
		tmp = rz_big_to_int(A);
		tmp |= rz_big_to_int(B);
		rz_big_rshift(A, A, step);
		rz_big_rshift(B, B, step);
		rz_big_from_int(addition, tmp);
		rz_big_lshift(addition, addition, move);
		rz_big_add(C, C, addition);

		move += step;
	}

	rz_big_assign(c, C);

	rz_big_free(A);
	rz_big_free(B);
	rz_big_free(C);
	rz_big_free(addition);
}

RZ_API void rz_big_xor(RNumBig *c, RNumBig *a, RNumBig *b) {
	RNumBig *A = rz_big_new();
	RNumBig *B = rz_big_new();
	RNumBig *C = rz_big_new();
	RNumBig *addition = rz_big_new();

	size_t step = 4 * 8, move = 0;
	ut32 tmp = 0;
	rz_big_assign(A, a);
	rz_big_assign(B, b);

	while (!rz_big_is_zero(A) || !rz_big_is_zero(B)) {
		tmp = rz_big_to_int(A);
		tmp ^= rz_big_to_int(B);
		rz_big_rshift(A, A, step);
		rz_big_rshift(B, B, step);
		rz_big_from_int(addition, tmp);
		rz_big_lshift(addition, addition, move);
		rz_big_add(C, C, addition);

		move += step;
	}

	rz_big_assign(c, C);

	rz_big_free(A);
	rz_big_free(B);
	rz_big_free(C);
	rz_big_free(addition);
}

RZ_API void rz_big_lshift(RNumBig *c, RNumBig *a, size_t nbits) {
	BN_lshift(c, a, nbits);
}

RZ_API void rz_big_rshift(RNumBig *c, RNumBig *a, size_t nbits) {
	BN_rshift(c, a, nbits);
}

RZ_API int rz_big_cmp(RNumBig *a, RNumBig *b) {
	return BN_cmp(a, b);
}

RZ_API int rz_big_is_zero(RNumBig *a) {
	return BN_is_zero(a);
}

RZ_API void rz_big_inc(RNumBig *a) {
	BN_add_word(a, 1);
}

RZ_API void rz_big_dec(RNumBig *a) {
	BN_sub_word(a, 1);
}

RZ_API void rz_big_powm(RNumBig *c, RNumBig *a, RNumBig *b, RNumBig *m) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_mod_exp(c, a, b, m, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_isqrt(RNumBig *b, RNumBig *a) {
	RNumBig *tmp = rz_big_new();
	RNumBig *low = rz_big_new();
	RNumBig *high = rz_big_new();
	RNumBig *mid = rz_big_new();

	rz_big_assign(high, a);
	rz_big_rshift(mid, high, 1);
	rz_big_inc(mid);

	while (rz_big_cmp(high, low) > 0) {
		rz_big_mul(tmp, mid, mid);
		if (rz_big_cmp(tmp, a) > 0) {
			rz_big_assign(high, mid);
			rz_big_dec(high);
		} else {
			rz_big_assign(low, mid);
		}
		rz_big_sub(mid, high, low);
		rz_big_rshift(mid, mid, 1);
		rz_big_add(mid, mid, low);
		rz_big_inc(mid);
	}
	rz_big_assign(b, low);

	rz_big_free(tmp);
	rz_big_free(low);
	rz_big_free(high);
	rz_big_free(mid);
}
