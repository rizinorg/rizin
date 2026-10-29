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
	bool negative = false;
	if (*str == '-') {
		negative = true;
		str++;
	}
	if (rz_str_startswith(str, "0x")) {
		str += 2;
	}

	mpz_set_ui(*b, 0);
	mpz_set_str(*b, str, 16);
	if (negative) {
		mpz_neg(*b, *b);
	}
}

RZ_API RZ_OWN char *rz_big_to_hexstr(RZ_NONNULL RzNumBig *b) {
	rz_return_val_if_fail(b, NULL);

	char *tmp = mpz_get_str(NULL, 16, *b);
	if (!tmp) {
		return NULL;
	}
	char *res;
	if (tmp[0] == '-') {
		res = rz_str_newf("-0x%s", &tmp[1]);
	} else {
		res = rz_str_newf("0x%s", tmp);
	}
	free(tmp);
	return res;
}

RZ_API RZ_OWN char *rz_big_to_decstr(RZ_NONNULL RzNumBig *b) {
	rz_return_val_if_fail(b, NULL);

	return mpz_get_str(NULL, 10, *b);
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
	mpz_add_ui(*a, *a, 1);
}

RZ_API void rz_big_dec(RzNumBig *a) {
	mpz_sub_ui(*a, *a, 1);
}

RZ_API void rz_big_powm(RzNumBig *c, RzNumBig *a, RzNumBig *b, RzNumBig *m) {
	mpz_powm(*c, *a, *b, *m);
}

RZ_API void rz_big_pow(RZ_NONNULL RzNumBig *c, RZ_NONNULL RzNumBig *a, RZ_NONNULL RzNumBig *b) {
	rz_return_if_fail(a && b && c);

	if (mpz_sgn(*b) < 0) {
		mpz_set_ui(*c, 0);
		return;
	}

	// fast path
	if (mpz_fits_ulong_p(*b)) {
		mpz_pow_ui(*c, *a, mpz_get_ui(*b));
		return;
	}

	RzNumBig base, exp;
	mpz_init_set(base, *a);
	mpz_init_set(exp, *b);
	mpz_set_ui(*c, 1);
	while (mpz_sgn(exp) > 0) {
		if (mpz_odd_p(exp)) {
			mpz_mul(*c, *c, base);
		}
		mpz_fdiv_q_2exp(exp, exp, 1);
		if (mpz_sgn(exp) > 0) {
			mpz_mul(base, base, base);
		}
	}
	mpz_clear(base);
	mpz_clear(exp);
}

RZ_API void rz_big_isqrt(RzNumBig *c, RzNumBig *a) {
	mpz_sqrt(*c, *a);
}
