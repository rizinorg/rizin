// SPDX-FileCopyrightText: 2020 FXTi <zjxiang1998@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/* Based on https://github.com/kokke/tiny-bignum-c.
 * Enjoy it --FXTi
 */

#include <rz_util.h>

/* Functions for shifting number in-place. */
static void _lshift_one_bit(RNumBig *a);
static void _rshift_one_bit(RNumBig *a);
static void _lshift_word(RNumBig *a, int nwords);
static void _rshift_word(RNumBig *a, int nwords);
static void _r_big_zero_out(RNumBig *n);

RZ_API RNumBig *rz_big_new(void) {
	RNumBig *n = RZ_NEW(RNumBig);
	if (n) {
		_r_big_zero_out(n);
	}
	return n;
}

RZ_API void rz_big_free(RNumBig *b) {
	free(b);
}

RZ_API void rz_big_init(RNumBig *b) {
	_r_big_zero_out(b);
}

RZ_API void rz_big_fini(RNumBig *b) {
	_r_big_zero_out(b);
}

RZ_API void rz_big_from_int(RNumBig *b, st64 n) {
	rz_return_if_fail(b);

	_r_big_zero_out(b);
	b->sign = (n < 0) ? -1 : 1;
	RZ_BIG_DTYPE_TMP v = n * b->sign;

	/* Endianness issue if machine is not little-endian? */
#ifdef RZ_BIG_WORD_SIZE
#if (RZ_BIG_WORD_SIZE == 1)
	b->array[0] = (v & 0x000000ff);
	b->array[1] = (v & 0x0000ff00) >> 8;
	b->array[2] = (v & 0x00ff0000) >> 16;
	b->array[3] = (v & 0xff000000) >> 24;
#elif (RZ_BIG_WORD_SIZE == 2)
	b->array[0] = (v & 0x0000ffff);
	b->array[1] = (v & 0xffff0000) >> 16;
#elif (RZ_BIG_WORD_SIZE == 4)
	b->array[0] = v;
	RZ_BIG_DTYPE_TMP num_32 = 32;
	RZ_BIG_DTYPE_TMP tmp = v >> num_32;
	b->array[1] = tmp;
#endif
#endif
}

static void rz_big_from_unsigned(RNumBig *b, ut64 v) {
	rz_return_if_fail(b);

	_r_big_zero_out(b);

	/* Endianness issue if machine is not little-endian? */
#ifdef RZ_BIG_WORD_SIZE
#if (RZ_BIG_WORD_SIZE == 1)
	b->array[0] = (v & 0x000000ff);
	b->array[1] = (v & 0x0000ff00) >> 8;
	b->array[2] = (v & 0x00ff0000) >> 16;
	b->array[3] = (v & 0xff000000) >> 24;
#elif (RZ_BIG_WORD_SIZE == 2)
	b->array[0] = (v & 0x0000ffff);
	b->array[1] = (v & 0xffff0000) >> 16;
#elif (RZ_BIG_WORD_SIZE == 4)
	b->array[0] = v;
	RZ_BIG_DTYPE_TMP num_32 = 32;
	RZ_BIG_DTYPE_TMP tmp = v >> num_32;
	b->array[1] = tmp;
#endif
#endif
}

RZ_API st64 rz_big_to_int(RNumBig *b) {
	rz_return_val_if_fail(b, 0);

	RZ_BIG_DTYPE_TMP ret = 0;

	/* Endianness issue if machine is not little-endian? */
#if (RZ_BIG_WORD_SIZE == 1)
	ret += b->array[0];
	ret += b->array[1] << 8;
	ret += b->array[2] << 16;
	ret += b->array[3] << 24;
#elif (RZ_BIG_WORD_SIZE == 2)
	ret += b->array[0];
	ret += b->array[1] << 16;
#elif (RZ_BIG_WORD_SIZE == 4)
	ret += b->array[1];
	ret <<= 32;
	ret += b->array[0];
#endif

	if (b->sign < 0) {
		return -ret;
	}
	return ret;
}

RZ_API void rz_big_from_hexstr(RNumBig *n, const char *str) {
	rz_return_if_fail(n);
	rz_return_if_fail(str);
	int nbytes = strlen(str);

	_r_big_zero_out(n);

	if (str[0] == '-') {
		n->sign = -1;
		str += 1;
		nbytes -= 1;
	}

	if (str[0] == '0' && str[1] == 'x') {
		str += 2;
		nbytes -= 2;
	}
	rz_return_if_fail(nbytes > 0);

	RZ_BIG_DTYPE tmp;
	int i = nbytes - (2 * RZ_BIG_WORD_SIZE); /* index into string */
	int j = 0; /* index into array */

	while (i >= 0) {
		tmp = 0;
		sscanf(&str[i], RZ_BIG_SSCANF_FORMAT_STR, &tmp);
		n->array[j] = tmp;
		i -= (2 * RZ_BIG_WORD_SIZE); /* step RZ_BIG_WORD_SIZE hex-byte(s) back in the string. */
		j += 1; /* step one element forward in the array. */
	}

	if (-2 * RZ_BIG_WORD_SIZE < i) {
		char buffer[2 * RZ_BIG_WORD_SIZE];
		memset(buffer, 0, sizeof(buffer));
		i += 2 * RZ_BIG_WORD_SIZE - 1;
		for (; i >= 0; i--) {
			buffer[i] = str[i];
		}
		tmp = 0;
		sscanf(buffer, RZ_BIG_SSCANF_FORMAT_STR, &tmp);
		n->array[j] = tmp;
	}
}

RZ_API char *rz_big_to_hexstr(RNumBig *b) {
	rz_return_val_if_fail(b, NULL);

	int j = RZ_BIG_ARRAY_SIZE - 1; /* index into array - reading "MSB" first -> big-endian */
	size_t i = 0; /* index into string representation. */
	size_t k = 0; /* Leading zero's amount */
	size_t z, last_z = 2 * RZ_BIG_WORD_SIZE;

	for (; b->array[j] == 0 && j >= 0; j--) {
	}
	if (j == -1) {
		return "0x0";
	}

	size_t size = 3 + 2 * RZ_BIG_WORD_SIZE * (j + 1) + ((b->sign > 0) ? 0 : 1);
	char *ret_str = calloc(size, sizeof(char));
	if (!ret_str) {
		return NULL;
	}

	if (b->sign < 0) {
		ret_str[i++] = '-';
	}
	ret_str[i++] = '0';
	ret_str[i++] = 'x';

	rz_snprintf(ret_str + i, RZ_BIG_FORMAT_STR_LEN, RZ_BIG_SPRINTF_FORMAT_STR, b->array[j--]);
	for (; ret_str[i + k] == '0' && k < 2 * RZ_BIG_WORD_SIZE; k++) {
	}
	for (z = k; ret_str[i + z] && z < last_z; z++) {
		ret_str[i + z - k] = ret_str[i + z];
	}
	i += z - k;
	ret_str[i] = '\x00'; // Truncate string for case(j < 0)

	for (; j >= 0; j--) {
		rz_snprintf(ret_str + i, RZ_BIG_FORMAT_STR_LEN, RZ_BIG_SPRINTF_FORMAT_STR, b->array[j]);
		i += 2 * RZ_BIG_WORD_SIZE;
	}

	return ret_str;
}

RZ_API void rz_big_assign(RNumBig *dst, RNumBig *src) {
	rz_return_if_fail(dst);
	rz_return_if_fail(src);

	memcpy(dst, src, sizeof(RNumBig));
}

static void rz_big_add_inner(RNumBig *c, RNumBig *a, RNumBig *b) {
	RZ_BIG_DTYPE_TMP tmp;
	int carry = 0;
	int i;
	for (i = 0; i < RZ_BIG_ARRAY_SIZE; i++) {
		tmp = (RZ_BIG_DTYPE_TMP)a->array[i] + b->array[i] + carry;
		carry = (tmp > RZ_BIG_MAX_VAL);
		c->array[i] = (tmp & RZ_BIG_MAX_VAL);
	}
}

static void rz_big_sub_inner(RNumBig *c, RNumBig *a, RNumBig *b) {
	RZ_BIG_DTYPE_TMP res;
	RNumBig *tmp;
	RZ_BIG_DTYPE_TMP tmp1;
	RZ_BIG_DTYPE_TMP tmp2;
	int borrow = 0;
	int sign = rz_big_cmp(a, b);
	c->sign = (sign >= 0 ? 1 : -1);
	if (sign < 0) {
		tmp = a;
		a = b;
		b = tmp;
	}
	int i;
	for (i = 0; i < RZ_BIG_ARRAY_SIZE; i++) {
		tmp1 = (RZ_BIG_DTYPE_TMP)a->array[i] + (RZ_BIG_MAX_VAL + 1); /* + number_base */
		tmp2 = (RZ_BIG_DTYPE_TMP)b->array[i] + borrow;

		res = (tmp1 - tmp2);
		c->array[i] = (RZ_BIG_DTYPE)(res & RZ_BIG_MAX_VAL); /* "modulo number_base" == "% (number_base - 1)" if nu    mber_base is 2^N */
		borrow = (res <= RZ_BIG_MAX_VAL);
	}
}

RZ_API void rz_big_add(RNumBig *c, RNumBig *a, RNumBig *b) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);

	if (a->sign >= 0 && b->sign >= 0) {
		rz_big_add_inner(c, a, b);
		c->sign = 1;
		return;
	}
	if (a->sign >= 0 && b->sign < 0) {
		rz_big_sub_inner(c, a, b);
		return;
	}
	if (a->sign < 0 && b->sign >= 0) {
		rz_big_sub_inner(c, b, a);
		return;
	}
	if (a->sign < 0 && b->sign < 0) {
		rz_big_add_inner(c, a, b);
		c->sign = -1;
		return;
	}
}

RZ_API void rz_big_sub(RNumBig *c, RNumBig *a, RNumBig *b) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);

	if (a->sign >= 0 && b->sign >= 0) {
		rz_big_sub_inner(c, a, b);
		return;
	}
	if (a->sign >= 0 && b->sign < 0) {
		rz_big_add_inner(c, a, b);
		c->sign = 1;
		return;
	}
	if (a->sign < 0 && b->sign >= 0) {
		rz_big_add_inner(c, a, b);
		c->sign = -1;
		return;
	}
	if (a->sign < 0 && b->sign < 0) {
		rz_big_sub_inner(c, b, a);
		return;
	}
}

RZ_API void rz_big_mul(RNumBig *c, RNumBig *a, RNumBig *b) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);

	RNumBig *row = rz_big_new();
	RNumBig *tmp = rz_big_new();
	RNumBig *res = rz_big_new();
	int i, j;

	for (i = 0; i < RZ_BIG_ARRAY_SIZE; i++) {
		_r_big_zero_out(row);

		for (j = 0; j < RZ_BIG_ARRAY_SIZE; j++) {
			if (i + j < RZ_BIG_ARRAY_SIZE) {
				_r_big_zero_out(tmp);
				RZ_BIG_DTYPE_TMP intermediate = ((RZ_BIG_DTYPE_TMP)a->array[i] * (RZ_BIG_DTYPE_TMP)b->array[j]);
				rz_big_from_unsigned(tmp, intermediate);
				_lshift_word(tmp, i + j);
				rz_big_add(row, row, tmp);
			}
		}
		rz_big_add(res, row, res);
	}

	res->sign = a->sign * b->sign;
	if (rz_big_is_zero(res)) {
		res->sign = 1; // For -1 * 0 case
	}
	rz_big_assign(c, res);

	rz_big_free(row);
	rz_big_free(tmp);
	rz_big_free(res);
}

RZ_API void rz_big_div(RNumBig *c, RNumBig *a, RNumBig *b) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);
	rz_return_if_fail(!rz_big_is_zero(b));

	RNumBig *current = rz_big_new();
	RNumBig *denom = rz_big_new();
	;
	RNumBig *tmp = rz_big_new();
	int sign = a->sign * b->sign;

	rz_big_from_int(current, 1); // int current = 1;
	rz_big_assign(denom, b); // denom = b
	denom->sign = 1;
	rz_big_assign(tmp, denom); // tmp = denom = b
	_lshift_one_bit(tmp); // tmp <= 1

	while (rz_big_cmp(tmp, a) != 1) { // while (tmp <= a)
		if ((denom->array[RZ_BIG_ARRAY_SIZE - 1] >> (RZ_BIG_WORD_SIZE * 8 - 1)) == 1) {
			break; // Reach the max value
		}
		_lshift_one_bit(tmp); // tmp <= 1
		_lshift_one_bit(denom); // denom <= 1
		_lshift_one_bit(current); // current <= 1
	}

	rz_big_assign(tmp, a); // tmp = a
	tmp->sign = 1;
	_r_big_zero_out(c); // int answer = 0;

	while (!rz_big_is_zero(current)) // while (current != 0)
	{
		if (rz_big_cmp(tmp, denom) != -1) //   if (dividend >= denom)
		{
			rz_big_sub(tmp, tmp, denom); //     dividend -= denom;
			rz_big_or(c, current, c); //     answer |= current;
		}
		_rshift_one_bit(current); //   current >>= 1;
		_rshift_one_bit(denom); //   denom >>= 1;
	} // return answer;

	c->sign = sign;
	if (rz_big_is_zero(c)) {
		c->sign = 1; // For -1 * 0 case
	}
	rz_big_free(current);
	rz_big_free(denom);
	rz_big_free(tmp);
}

RZ_API void rz_big_mod(RNumBig *c, RNumBig *a, RNumBig *b) {
	/*  
    Take divmod and throw away div part
    */
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);
	rz_return_if_fail(!rz_big_is_zero(b));

	RNumBig *tmp = rz_big_new();

	rz_big_divmod(tmp, c, a, b);

	rz_big_free(tmp);
}

RZ_API void rz_big_divmod(RNumBig *c, RNumBig *d, RNumBig *a, RNumBig *b) {
	/*
    Puts a%b in d 
    and a/b in c
        
    mod(a,b) = a - ((a / b) * b)
    
    example:
      mod(8, 3) = 8 - ((8 / 3) * 3) = 2
    */
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);
	rz_return_if_fail(!rz_big_is_zero(b));

	RNumBig *tmp = rz_big_new();

	/* c = (a / b) */
	rz_big_div(c, a, b);

	/* tmp = (c * b) */
	rz_big_mul(tmp, c, b);

	/* d = a - tmp */
	rz_big_sub(d, a, tmp);

	rz_big_free(tmp);
}

RZ_API void rz_big_and(RNumBig *c, RNumBig *a, RNumBig *b) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);
	rz_return_if_fail(a->sign > 0);
	rz_return_if_fail(b->sign > 0);

	int i;
	for (i = 0; i < RZ_BIG_ARRAY_SIZE; i++) {
		c->array[i] = (a->array[i] & b->array[i]);
	}
}

RZ_API void rz_big_or(RNumBig *c, RNumBig *a, RNumBig *b) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);
	rz_return_if_fail(a->sign > 0);
	rz_return_if_fail(b->sign > 0);

	int i;
	for (i = 0; i < RZ_BIG_ARRAY_SIZE; i++) {
		c->array[i] = (a->array[i] | b->array[i]);
	}
}

RZ_API void rz_big_xor(RNumBig *c, RNumBig *a, RNumBig *b) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);
	rz_return_if_fail(a->sign > 0);
	rz_return_if_fail(b->sign > 0);

	int i;
	for (i = 0; i < RZ_BIG_ARRAY_SIZE; i++) {
		c->array[i] = (a->array[i] ^ b->array[i]);
	}
}

RZ_API void rz_big_lshift(RNumBig *b, RNumBig *a, size_t nbits) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(a->sign > 0);
	rz_return_if_fail(b->sign > 0);

	rz_big_assign(b, a);
	/* Handle shift in multiples of word-size */
	const int nbits_pr_word = (RZ_BIG_WORD_SIZE * 8);
	int nwords = nbits / nbits_pr_word;
	if (nwords != 0) {
		_lshift_word(b, nwords);
		nbits -= (nwords * nbits_pr_word);
	}

	if (nbits != 0) {
		int i;
		for (i = (RZ_BIG_ARRAY_SIZE - 1); i > 0; i--) {
			b->array[i] = (b->array[i] << nbits) | (b->array[i - 1] >> ((8 * RZ_BIG_WORD_SIZE) - nbits));
		}
		b->array[i] <<= nbits;
	}
}

RZ_API void rz_big_rshift(RNumBig *b, RNumBig *a, size_t nbits) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(a->sign > 0);
	rz_return_if_fail(b->sign > 0);

	rz_big_assign(b, a);
	/* Handle shift in multiples of word-size */
	const int nbits_pr_word = (RZ_BIG_WORD_SIZE * 8);
	int nwords = nbits / nbits_pr_word;
	if (nwords != 0) {
		_rshift_word(b, nwords);
		nbits -= (nwords * nbits_pr_word);
	}

	if (nbits != 0) {
		int i;
		for (i = 0; i < (RZ_BIG_ARRAY_SIZE - 1); i++) {
			b->array[i] = (b->array[i] >> nbits) | (b->array[i + 1] << ((8 * RZ_BIG_WORD_SIZE) - nbits));
		}
		b->array[i] >>= nbits;
	}
}

RZ_API int rz_big_cmp(RNumBig *a, RNumBig *b) {
	rz_return_val_if_fail(a, 0);
	rz_return_val_if_fail(b, 0);

	if (a->sign != b->sign)
		return a->sign > 0 ? 1 : -1;

	int i = RZ_BIG_ARRAY_SIZE;
	do {
		i -= 1; /* Decrement first, to start with last array element */
		if (a->array[i] > b->array[i]) {
			return 1 * a->sign;
		}
		if (a->array[i] < b->array[i]) {
			return -1 * a->sign;
		}
	} while (i != 0);

	return 0;
}

RZ_API int rz_big_is_zero(RNumBig *a) {
	rz_return_val_if_fail(a, -1);

	int i;
	for (i = 0; i < RZ_BIG_ARRAY_SIZE; i++) {
		if (a->array[i]) {
			return 0;
		}
	}

	return 1;
}

RZ_API void rz_big_inc(RNumBig *a) {
	rz_return_if_fail(a);
	RNumBig *tmp = rz_big_new();

	rz_big_from_int(tmp, 1);
	rz_big_add(a, a, tmp);

	rz_big_free(tmp);
}

RZ_API void rz_big_dec(RNumBig *a) {
	rz_return_if_fail(a);
	RNumBig *tmp = rz_big_new();

	rz_big_from_int(tmp, 1);
	rz_big_sub(a, a, tmp);

	rz_big_free(tmp);
}

RZ_API void rz_big_powm(RNumBig *c, RNumBig *a, RNumBig *b, RNumBig *m) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);
	rz_return_if_fail(c);
	rz_return_if_fail(m);

	RNumBig *bcopy = rz_big_new();
	RNumBig *acopy = rz_big_new();

	rz_big_assign(bcopy, b);
	rz_big_assign(acopy, a);
	rz_big_mod(acopy, acopy, m);
	rz_big_from_int(c, 1);

	while (!rz_big_is_zero(bcopy)) {
		if (rz_big_to_int(bcopy) % 2 == 1) {
			rz_big_mul(c, c, acopy);
			rz_big_mod(c, c, m);
		}
		_rshift_one_bit(bcopy);
		rz_big_mul(acopy, acopy, acopy);
		rz_big_mod(acopy, acopy, m);
	}

	rz_big_free(bcopy);
	rz_big_free(acopy);
}

RZ_API void rz_big_isqrt(RNumBig *b, RNumBig *a) {
	rz_return_if_fail(a);
	rz_return_if_fail(b);

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
		_rshift_one_bit(mid);
		rz_big_add(mid, mid, low);
		rz_big_inc(mid);
	}
	rz_big_assign(b, low);

	rz_big_free(tmp);
	rz_big_free(low);
	rz_big_free(high);
	rz_big_free(mid);
}

/* Private / Static functions. */
static void _rshift_word(RNumBig *a, int nwords) {
	/* Naive method: */
	rz_return_if_fail(a);
	rz_return_if_fail(nwords >= 0);

	size_t i;
	if (nwords >= RZ_BIG_ARRAY_SIZE) {
		for (i = 0; i < RZ_BIG_ARRAY_SIZE; i++) {
			a->array[i] = 0;
		}
		return;
	}

	for (i = 0; i < RZ_BIG_ARRAY_SIZE - nwords; i++) {
		a->array[i] = a->array[i + nwords];
	}
	for (; i < RZ_BIG_ARRAY_SIZE; i++) {
		a->array[i] = 0;
	}
}

static void _lshift_word(RNumBig *a, int nwords) {
	rz_return_if_fail(a);
	rz_return_if_fail(nwords >= 0);

	int i;
	/* Shift whole words */
	for (i = (RZ_BIG_ARRAY_SIZE - 1); i >= nwords; i--) {
		a->array[i] = a->array[i - nwords];
	}
	/* Zero pad shifted words. */
	for (; i >= 0; i--) {
		a->array[i] = 0;
	}
}

static void _lshift_one_bit(RNumBig *a) {
	rz_return_if_fail(a);

	int i;
	for (i = (RZ_BIG_ARRAY_SIZE - 1); i > 0; i--) {
		a->array[i] = (a->array[i] << 1) | (a->array[i - 1] >> ((8 * RZ_BIG_WORD_SIZE) - 1));
	}
	a->array[0] <<= 1;
}

static void _rshift_one_bit(RNumBig *a) {
	rz_return_if_fail(a);

	int i;
	for (i = 0; i < (RZ_BIG_ARRAY_SIZE - 1); i++) {
		a->array[i] = (a->array[i] >> 1) | (a->array[i + 1] << ((8 * RZ_BIG_WORD_SIZE) - 1));
	}
	a->array[RZ_BIG_ARRAY_SIZE - 1] >>= 1;
}

static void _r_big_zero_out(RNumBig *a) {
	rz_return_if_fail(a);

	size_t i;
	for (i = 0; i < RZ_BIG_ARRAY_SIZE; i++) {
		a->array[i] = 0;
	}
	a->sign = 1; /* hack to avoid -0 */
}
