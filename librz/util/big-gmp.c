// SPDX-FileCopyrightText: 2010 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

RZ_API RzNumBig *rz_big_new(void) {
	RzNumBig *n = RZ_NEW(RzNumBig);
	if (n) {
		mpz_init(*n);
	}
	return n;
}

RZ_API void rz_big_free(RzNumBig *b) {
	mpz_clear(*b);
	free(b);
}

RZ_API void rz_big_init(RzNumBig *b) {
	mpz_init(*b);
}

RZ_API void rz_big_fini(RzNumBig *b) {
	mpz_clear(*b);
}

RZ_API void rz_big_from_int(RzNumBig *b, st64 v) {
	mpz_set_si(*b, v);
}

RZ_API st64 rz_big_to_int(RzNumBig *b) {
	return mpz_get_si(*b);
}

RZ_API void rz_big_from_hexstr(RzNumBig *b, const char *str) {
	if (rz_str_startswith(str, "0x")) {
		str += 2;
		mpz_set_str(*b, str, 16);
	} else if (rz_str_startswith(str, "-0x")) {
		str += 3;
		mpz_set_str(*b, str, 16);
		mpz_mul_si(*b, *b, -1);
	}
}

RZ_API char *rz_big_to_hexstr(RzNumBig *b) {
	char *tmp = mpz_get_str(NULL, 16, *b);
	char *res;
	if (tmp[0] == '-') {
		res = rz_str_newf("-0x%s", &tmp[1]);
	} else {
		res = rz_str_newf("0x%s", tmp);
	}
	free(tmp);
	return res;
}

RZ_API void rz_big_assign(RzNumBig *dst, RzNumBig *src) {
	mpz_set(*dst, *src);
}

RZ_API void rz_big_add(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	mpz_add(*c, *a, *b);
}

RZ_API void rz_big_sub(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	mpz_sub(*c, *a, *b);
}

RZ_API void rz_big_mul(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	mpz_mul(*c, *a, *b);
}

RZ_API void rz_big_div(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	mpz_tdiv_q(*c, *a, *b);
}

RZ_API void rz_big_mod(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	mpz_mod(*c, *a, *b);
}

RZ_API void rz_big_divmod(RzNumBig *c, RzNumBig *d, RzNumBig *a, RzNumBig *b) {
	mpz_tdiv_qr(*c, *d, *a, *b);
}

RZ_API void rz_big_and(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	mpz_and(*c, *a, *b);
}

RZ_API void rz_big_or(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	mpz_ior(*c, *a, *b);
}

RZ_API void rz_big_xor(RzNumBig *c, RzNumBig *a, RzNumBig *b) {
	mpz_xor(*c, *a, *b);
}

RZ_API void rz_big_lshift(RzNumBig *c, RzNumBig *a, size_t nbits) {
	mpz_mul_2exp(*c, *a, nbits);
}

RZ_API void rz_big_rshift(RzNumBig *c, RzNumBig *a, size_t nbits) {
	mpz_tdiv_q_2exp(*c, *a, nbits);
}

RZ_API int rz_big_cmp(RzNumBig *a, RzNumBig *b) {
	int res = mpz_cmp(*a, *b);
	if (res > 0) {
		return 1;
	} else if (res < 0) {
		return -1;
	} else {
		return 0;
	}
}

RZ_API int rz_big_is_zero(RzNumBig *a) {
	return mpz_cmp_ui(*a, 0) == 0;
}

RZ_API void rz_big_inc(RzNumBig *a) {
	RzNumBig tmp;
	mpz_init_set_si(tmp, 1);
	mpz_add(*a, *a, tmp);
}

RZ_API void rz_big_dec(RzNumBig *a) {
	RzNumBig tmp;
	mpz_init_set_si(tmp, 1);
	mpz_sub(*a, *a, tmp);
}

RZ_API void rz_big_powm(RzNumBig *c, RzNumBig *a, RzNumBig *b, RzNumBig *m) {
	mpz_powm(*c, *a, *b, *m);
}

RZ_API void rz_big_isqrt(RzNumBig *c, RzNumBig *a) {
	mpz_sqrt(*c, *a);
}
