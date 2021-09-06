// SPDX-FileCopyrightText: 2010 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API RzNumBig *rz_big_new(void) {
	return BN_new();
}

RZ_API void rz_big_free(RzNumBig *b) {
	BN_free(b);
}

RZ_API void rz_big_init(RzNumBig *b) {
	BN_zero(b);
}

RZ_API void rz_big_fini(RzNumBig *b) {
	BN_clear(b);
}

RZ_API void rz_big_from_int(RzNumBig *b, st64 v) {
	if (v < 0) {
		BN_set_word(b, -v);
		BN_set_negative(b, v);
	} else {
		BN_set_word(b, v);
	}
}

RZ_API st64 rz_big_to_int(RzNumBig *b) {
	BN_ULONG maxx = 0;
	maxx = ~maxx;
	BN_ULONG res = BN_get_word(b);
	if (res == maxx) {
		RzNumBig *B = rz_big_new();
		rz_big_assign(B, b);
		BN_mask_bits(B, BN_BYTES * 8 - 1);
		res = BN_get_word(B);
		rz_big_free(B);
	}
	res *= (BN_is_negative(b) ? -1 : 1);
	return res;
}

RZ_API void rz_big_from_hexstr(RzNumBig *b, const char *str) {
	if (rz_str_startswith(str, "0x")) {
		str += 2;
		BN_hex2bn(&b, str);
	} else if (rz_str_startswith(str, "-0x")) {
		str += 3;
		BN_hex2bn(&b, str);
		BN_set_negative(b, -1);
	}
}

RZ_API char *rz_big_to_hexstr(RzNumBig *b) {
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

RZ_API void rz_big_assign(RzNumBig *dst, RzNumBig *src) {
	BN_copy(dst, src);
}

RZ_API void rz_big_add(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	BN_add(c, a, b);
}

RZ_API void rz_big_sub(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	BN_sub(c, a, b);
}

RZ_API void rz_big_mul(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_mul(c, a, b, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_div(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_div(c, NULL, a, b, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_mod(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_mod(c, a, b, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_divmod(RzNumBig *c, RzNumBig *d, RzNumBig *a, RzNumBig *b) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_div(c, d, a, b, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_and(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	RzNumBig *A = rz_big_new();
	RzNumBig *B = rz_big_new();
	RzNumBig *C = rz_big_new();
	RzNumBig *addition = rz_big_new();

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

RZ_API void rz_big_or(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	RzNumBig *A = rz_big_new();
	RzNumBig *B = rz_big_new();
	RzNumBig *C = rz_big_new();
	RzNumBig *addition = rz_big_new();

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

RZ_API void rz_big_xor(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	RzNumBig *A = rz_big_new();
	RzNumBig *B = rz_big_new();
	RzNumBig *C = rz_big_new();
	RzNumBig *addition = rz_big_new();

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

RZ_API void rz_big_lshift(RzNumBig *c, RzNumBig *a, size_t nbits) {
	BN_lshift(c, a, nbits);
}

RZ_API void rz_big_rshift(RzNumBig *c, RzNumBig *a, size_t nbits) {
	BN_rshift(c, a, nbits);
}

RZ_API int rz_big_cmp(RzNumBig *a, RzNumBig *b) {
	return BN_cmp(a, b);
}

RZ_API int rz_big_is_zero(RzNumBig *a) {
	return BN_is_zero(a);
}

RZ_API void rz_big_inc(RzNumBig *a) {
	BN_add_word(a, 1);
}

RZ_API void rz_big_dec(RzNumBig *a) {
	BN_sub_word(a, 1);
}

RZ_API void rz_big_powm(RzNumBig *c, RzNumBig *a, RzNumBig *b, RzNumBig *m) {
	BN_CTX *bn_ctx = BN_CTX_new();
	BN_mod_exp(c, a, b, m, bn_ctx);
	BN_CTX_free(bn_ctx);
}

RZ_API void rz_big_isqrt(RzNumBig *b, RzNumBig *a) {
	RzNumBig *tmp = rz_big_new();
	RzNumBig *low = rz_big_new();
	RzNumBig *high = rz_big_new();
	RzNumBig *mid = rz_big_new();

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
