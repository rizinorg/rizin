// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

#define is_equal_bv(x, y) (!rz_bv_cmp(x, y))

bool test_rz_bv_init32(void) {
	char *s = NULL;

	// create by given unsigned 32 bit
	RzBitVector *bits = rz_bv_new_from_ut64(32, 100);
	RzBitVector *bits_cmp = rz_bv_new(32);

	// 100 = 64 + 32 + 4 == 0b 0000 0000 0000 0000 0000 0000 0110 0100
	rz_bv_set(bits_cmp, 2, true);
	rz_bv_set(bits_cmp, 5, true);
	rz_bv_set(bits_cmp, 6, true);
	mu_assert("new from 32", is_equal_bv(bits, bits_cmp));

	// dup
	RzBitVector *bits_dup = rz_bv_dup(bits);
	mu_assert("dup from bits 32", is_equal_bv(bits_dup, bits));

	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "00000000000000000000000001100100", "string bit value of bv");

	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0x00000064", "string hex value of bv");

	rz_bv_free(bits);
	rz_bv_free(bits_cmp);
	rz_bv_free(bits_dup);
	mu_end;
}

bool test_rz_bv_init64(void) {
	char *s = NULL;

	// create by given unsigned 64 bits
	RzBitVector *bits = rz_bv_new_from_ut64(64, 100);
	RzBitVector *bits_cmp = rz_bv_new(64);

	// 100 = 64 + 32 + 4 == 0b 0000 0000 0000 0000 0000 0000 0110 0100
	rz_bv_set(bits_cmp, 2, true);
	rz_bv_set(bits_cmp, 5, true);
	rz_bv_set(bits_cmp, 6, true);
	mu_assert("new from 64", is_equal_bv(bits, bits_cmp));

	// dup
	RzBitVector *bits_dup = rz_bv_dup(bits);
	mu_assert("dup from bits 64", is_equal_bv(bits_dup, bits));

	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0x0000000000000064", "string hex value of bv");

	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "0000000000000000000000000000000000000000000000000000000001100100", "string bit value of bv");

	rz_bv_free(bits);
	rz_bv_free(bits_cmp);
	rz_bv_free(bits_dup);
	mu_end;
}

bool test_rz_bv_init128(void) {
	char *s = NULL;

	// create by given unsigned 128 bits
	RzBitVector *bits = rz_bv_new_from_ut64(128, 100);
	RzBitVector *bits_cmp = rz_bv_new(128);

	// 100 = 64 + 32 + 4 == 0b 0000 0000 0000 0000 0000 0000 0110 0100
	rz_bv_set(bits_cmp, 2, true);
	rz_bv_set(bits_cmp, 5, true);
	rz_bv_set(bits_cmp, 6, true);
	mu_assert("new from 128", is_equal_bv(bits, bits_cmp));

	// dup
	RzBitVector *bits_dup = rz_bv_dup(bits);
	mu_assert("dup from bits 128", is_equal_bv(bits_dup, bits));

	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001100100", "string bit value of bv");

	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0x00000000000000000000000000000064", "string hex value of bv");

	rz_bv_free(bits);
	rz_bv_free(bits_cmp);
	rz_bv_free(bits_dup);
	mu_end;
}

bool test_rz_bv_init_signed(void) {
	char *s = NULL;
	RzBitVector *bits = NULL;

	// create by given signed 10 bits
	bits = rz_bv_new_from_st64(10, -100);
	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "1110011100", "string bit value of bv");
	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0x39c", "string hex value of bv");
	rz_bv_free(bits);

	// create by given signed 16 bits
	bits = rz_bv_new_from_st64(16, -100);
	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "1111111110011100", "string bit value of bv");
	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0xff9c", "string hex value of bv");
	rz_bv_free(bits);

	// create by given signed 24 bits
	bits = rz_bv_new_from_st64(24, -100);
	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "111111111111111110011100", "string bit value of bv");
	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0xffff9c", "string hex value of bv");
	rz_bv_free(bits);

	// create by given signed 32 bits
	bits = rz_bv_new_from_st64(32, -100);
	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "11111111111111111111111110011100", "string bit value of bv");
	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0xffffff9c", "string hex value of bv");
	rz_bv_free(bits);

	// create by given signed 64 bits
	bits = rz_bv_new_from_st64(64, -100);
	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "1111111111111111111111111111111111111111111111111111111110011100", "string bit value of bv");
	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0xffffffffffffff9c", "string hex value of bv");
	rz_bv_free(bits);

	// create by given signed 128 bits
	bits = rz_bv_new_from_st64(128, -100);
	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110011100", "string bit value of bv");
	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0xffffffffffffffffffffffffffffff9c", "string hex value of bv");
	rz_bv_free(bits);
	mu_end;
}

bool test_rz_bv_logic(void) {
	RzBitVector *x, *y;
	RzBitVector *result;
	RzBitVector *and, * or, *xor, *neg, *not, *ls, *rs, *ls_fill, *rs_fill;

	// x : 0101 0101
	x = rz_bv_new(8);
	rz_bv_set(x, 0, true);
	rz_bv_set(x, 2, true);
	rz_bv_set(x, 4, true);
	rz_bv_set(x, 6, true);

	// y : 1010 1001
	y = rz_bv_new(8);
	rz_bv_set(y, 0, true);
	rz_bv_set(y, 3, true);
	rz_bv_set(y, 5, true);
	rz_bv_set(y, 7, true);

	// and : 0000 0001
	and = rz_bv_new(8);
	rz_bv_set(and, 0, true);

	// xor : 1111 1100
	xor = rz_bv_new(8);
	rz_bv_toggle_all(xor);
	rz_bv_set(xor, 0, false);
	rz_bv_set(xor, 1, false);

	// or : 1111 1101
	or = rz_bv_new(8);
	rz_bv_toggle_all(or);
	rz_bv_set(or, 1, false);

	// not of x : 1010 1010
	not = rz_bv_new(8);
	rz_bv_set(not, 1, true);
	rz_bv_set(not, 3, true);
	rz_bv_set(not, 5, true);
	rz_bv_set(not, 7, true);

	// neg of x : 1010 1011
	neg = rz_bv_new(8);
	rz_bv_set(neg, 0, true);
	rz_bv_set(neg, 1, true);
	rz_bv_set(neg, 3, true);
	rz_bv_set(neg, 5, true);
	rz_bv_set(neg, 7, true);

	// left shift (3 bits) of y : 0100 1000
	ls = rz_bv_new(8);
	rz_bv_set(ls, 3, true);
	rz_bv_set(ls, 6, true);

	// left shift (3 bits) of y : 0100 1111
	ls_fill = rz_bv_new(8);
	rz_bv_set(ls_fill, 0, true);
	rz_bv_set(ls_fill, 1, true);
	rz_bv_set(ls_fill, 2, true);
	rz_bv_set(ls_fill, 3, true);
	rz_bv_set(ls_fill, 6, true);

	// right shift (3 bits) of y : 0001 0101
	rs = rz_bv_new(8);
	rz_bv_set(rs, 0, true);
	rz_bv_set(rs, 2, true);
	rz_bv_set(rs, 4, true);

	// right shift (3 bits) of y : 1111 0101
	rs_fill = rz_bv_new(8);
	rz_bv_toggle_all(rs_fill);
	rz_bv_set(rs_fill, 1, false);
	rz_bv_set(rs_fill, 3, false);

	// test and
	result = rz_bv_and(x, y);
	mu_assert("and x y", is_equal_bv(result, and));
	rz_bv_free(result);
	rz_bv_free(and);

	result = rz_bv_or(x, y);
	mu_assert("or x y", is_equal_bv(result, or));
	rz_bv_free(result);
	rz_bv_free(or);

	result = rz_bv_xor(x, y);
	mu_assert("xor x y", is_equal_bv(result, xor));
	rz_bv_free(result);
	rz_bv_free(xor);

	result = rz_bv_not(x);
	mu_assert("not x", is_equal_bv(result, not ));
	rz_bv_free(result);
	rz_bv_free(not );

	result = rz_bv_neg(x);
	mu_assert("neg x", is_equal_bv(result, neg));
	rz_bv_free(result);
	rz_bv_free(neg);

	result = rz_bv_dup(y);
	rz_bv_lshift(result, 3);
	mu_assert("left shift y", is_equal_bv(result, ls));
	rz_bv_free(result);
	rz_bv_free(ls);

	result = rz_bv_dup(y);
	rz_bv_lshift_fill(result, 3, true);
	mu_assert("left shift y filling 1", is_equal_bv(result, ls_fill));
	rz_bv_free(result);
	rz_bv_free(ls_fill);

	result = rz_bv_dup(y);
	rz_bv_rshift(result, 3);
	mu_assert("right shift y", is_equal_bv(result, rs));
	rz_bv_free(result);
	rz_bv_free(rs);

	result = rz_bv_dup(y);
	rz_bv_rshift_fill(result, 3, true);
	mu_assert("right shift y", is_equal_bv(result, rs_fill));
	rz_bv_free(result);
	rz_bv_free(rs_fill);

	rz_bv_free(x);
	rz_bv_free(y);
	mu_end;
}

bool test_rz_bv_algorithm32(void) {
	RzBitVector *x, *y;
	RzBitVector *result;
	RzBitVector *add, *sub, *mul, *div, *mod;
	x = rz_bv_new_from_ut64(32, 121);
	y = rz_bv_new_from_ut64(32, 33);

	add = rz_bv_new_from_ut64(32, 154);
	sub = rz_bv_new_from_ut64(32, 121 - 33);
	div = rz_bv_new_from_ut64(32, 121 / 33);
	mul = rz_bv_new_from_ut64(32, 121 * 33);
	mod = rz_bv_new_from_ut64(32, 121 % 33);

	result = rz_bv_add(x, y, NULL);
	mu_assert("Add x y", rz_bv_cmp(result, add) == 0);
	rz_bv_free(result);

	result = rz_bv_sub(x, y, NULL);
	mu_assert("Sub x y", rz_bv_cmp(result, sub) == 0);
	rz_bv_free(result);

	result = rz_bv_mul(x, y);
	mu_assert("Mul x y", rz_bv_cmp(result, mul) == 0);
	rz_bv_free(result);

	result = rz_bv_div(x, y);
	mu_assert("Div x y", rz_bv_cmp(result, div) == 0);
	rz_bv_free(result);

	result = rz_bv_mod(x, y);
	mu_assert("Mod x y", rz_bv_cmp(result, mod) == 0);
	rz_bv_free(result);

	rz_bv_free(x);
	rz_bv_free(y);
	rz_bv_free(add);
	rz_bv_free(sub);
	rz_bv_free(div);
	rz_bv_free(mul);
	rz_bv_free(mod);
	mu_end;
}

bool test_rz_bv_algorithm128(void) {
	RzBitVector *x, *y;
	RzBitVector *result;
	RzBitVector *add, *sub, *mul, *div, *mod;
	x = rz_bv_new_from_ut64(128, 121);
	y = rz_bv_new_from_ut64(128, 33);

	add = rz_bv_new_from_ut64(128, 154);
	sub = rz_bv_new_from_ut64(128, 121 - 33);
	div = rz_bv_new_from_ut64(128, 121 / 33);
	mul = rz_bv_new_from_ut64(128, 121 * 33);
	mod = rz_bv_new_from_ut64(128, 121 % 33);

	result = rz_bv_add(x, y, NULL);
	mu_assert("Add x y", rz_bv_cmp(result, add) == 0);
	rz_bv_free(result);

	result = rz_bv_sub(x, y, NULL);
	mu_assert("Sub x y", rz_bv_cmp(result, sub) == 0);
	rz_bv_free(result);

	result = rz_bv_mul(x, y);
	mu_assert("Mul x y", rz_bv_cmp(result, mul) == 0);
	rz_bv_free(result);

	result = rz_bv_div(x, y);
	mu_assert("Div x y", rz_bv_cmp(result, div) == 0);
	rz_bv_free(result);

	result = rz_bv_mod(x, y);
	mu_assert("Mod x y", rz_bv_cmp(result, mod) == 0);
	rz_bv_free(result);

	rz_bv_free(x);
	rz_bv_free(y);
	rz_bv_free(add);
	rz_bv_free(sub);
	rz_bv_free(div);
	rz_bv_free(mul);
	rz_bv_free(mod);
	mu_end;
}

bool test_rz_bv_cmp(void) {
	RzBitVector *x, *y;

	// x : 1000 0111, y : 0000 0111
	x = rz_bv_new(8);
	rz_bv_set(x, 0, true);
	rz_bv_set(x, 1, true);
	rz_bv_set(x, 2, true);
	rz_bv_set(x, 7, true);

	y = rz_bv_new(8);
	rz_bv_set(y, 0, true);
	rz_bv_set(y, 1, true);
	rz_bv_set(y, 2, true);

	// get msb and lsb of y
	bool msb, lsb;
	msb = rz_bv_msb(y);
	lsb = rz_bv_lsb(y);

	mu_assert("msb", msb == false);
	mu_assert("lsb", lsb == true);

	mu_assert("Unsigned : x > y", !rz_bv_ule(x, y));
	mu_assert("Signed : x < y", rz_bv_sle(x, y));

	rz_bv_free(x);
	rz_bv_free(y);

	mu_end;
}

bool test_rz_bv_operation(void) {
	RzBitVector *x, *y, *res, *prep, *append, *cut_h, *cut_t, *concat;
	char *s;

	// 0000 1000
	x = rz_bv_new(8);
	rz_bv_set(x, 3, true);

	// prepend 3 : 000 0000 1000
	prep = rz_bv_new(11);
	rz_bv_set(prep, 3, true);

	// append 5 : 0000 1000 0000 0
	append = rz_bv_new(13);
	rz_bv_set(append, 8, true);

	// cut head 2: 00 1000
	cut_h = rz_bv_new(6);
	rz_bv_set(cut_h, 3, true);

	// cut tail 4: 0000
	cut_t = rz_bv_new(4);

	// y : 1011
	y = rz_bv_new(4);
	rz_bv_set(y, 0, true);
	rz_bv_set(y, 1, true);
	rz_bv_set(y, 3, true);
	concat = rz_bv_new(12);
	rz_bv_set(concat, 0, true);
	rz_bv_set(concat, 1, true);
	rz_bv_set(concat, 3, true);
	rz_bv_set(concat, 7, true);

	res = rz_bv_prepend_zero(x, 3);
	mu_assert("prepend 3 zero", is_equal_bv(res, prep));
	s = rz_bv_as_string(res);
	mu_assert_streq_free(s, "00000001000", "string bit value of bv");
	s = rz_bv_as_hex_string(res, true);
	mu_assert_streq_free(s, "0x008", "string hex value of bv");
	rz_bv_free(res);

	res = rz_bv_append_zero(x, 5);
	mu_assert("append 5 zero", is_equal_bv(res, append));
	s = rz_bv_as_string(res);
	mu_assert_streq_free(s, "0000100000000", "string bit value of bv");
	s = rz_bv_as_hex_string(res, true);
	mu_assert_streq_free(s, "0x0100", "string hex value of bv");
	rz_bv_free(res);

	res = rz_bv_cut_head(x, 2);
	mu_assert("cut head 2 zero", is_equal_bv(res, cut_h));
	s = rz_bv_as_string(res);
	mu_assert_streq_free(s, "001000", "string bit value of bv");
	s = rz_bv_as_hex_string(res, true);
	mu_assert_streq_free(s, "0x08", "string hex value of bv");
	rz_bv_free(res);

	res = rz_bv_cut_tail(x, 4);
	mu_assert("cut tail 4 zero", is_equal_bv(res, cut_t));
	s = rz_bv_as_string(res);
	mu_assert_streq_free(s, "0000", "string bit value of bv");
	s = rz_bv_as_hex_string(res, true);
	mu_assert_streq_free(s, "0x0", "string hex value of bv");
	rz_bv_free(res);

	res = rz_bv_append(x, y);
	mu_assert("append x and y", is_equal_bv(res, concat));
	s = rz_bv_as_string(res);
	mu_assert_streq_free(s, "000010001011", "string bit value of bv");
	s = rz_bv_as_hex_string(res, true);
	mu_assert_streq_free(s, "0x08b", "string hex value of bv");
	rz_bv_free(res);

	rz_bv_free(prep);
	rz_bv_free(append);
	rz_bv_free(cut_h);
	rz_bv_free(cut_t);
	rz_bv_free(concat);
	rz_bv_free(x);
	rz_bv_free(y);

	mu_end;
}

bool test_rz_bv_cast(void) {
	ut32 normal, shadow;
	normal = 2021;
	RzBitVector *bv = rz_bv_new_from_ut64(32, normal);
	shadow = rz_bv_to_ut32(bv);
	rz_bv_free(bv);

	mu_assert("cast bv<->ut32", normal == shadow);
	mu_end;
}

bool test_rz_bv_set_from_bytes_be(void) {
	const ut8 data[0x10] = {
		0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe
	};
	RzBitVector bv;
	rz_bv_init(&bv, 64);
	rz_bv_set_from_bytes_be(&bv, data, 0, 64);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xefcdab8967452301", "aligned 64");
	rz_bv_set_from_bytes_be(&bv, data, 0, 62);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xefcdab8967452300", "aligned 64, padding");
	rz_bv_set_from_bytes_be(&bv, data, 0, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xefcdab8967452301", "aligned 64, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 42);
	rz_bv_set_from_bytes_be(&bv, data, 0, 42);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x3bf36ae259d", "aligned 42");
	rz_bv_set_from_bytes_be(&bv, data, 0, 40);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x3bf36ae259c", "aligned 42, padding");
	rz_bv_set_from_bytes_be(&bv, data, 0, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x3bf36ae259d", "aligned 42, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 80);
	rz_bv_set_from_bytes_be(&bv, data, 0, 80);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xefcdab89674523011032", "aligned 80");
	rz_bv_set_from_bytes_be(&bv, data, 0, 78);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xefcdab89674523011030", "aligned 80, padding");
	rz_bv_set_from_bytes_be(&bv, data, 0, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xefcdab89674523011032", "aligned 80, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 64);
	rz_bv_set_from_bytes_be(&bv, data, 1, 64);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xdf9b5712ce8a4602", "off+1 64");
	rz_bv_set_from_bytes_be(&bv, data, 1, 62);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xdf9b5712ce8a4600", "off+1, padding");
	rz_bv_set_from_bytes_be(&bv, data, 1, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xdf9b5712ce8a4602", "off+1 64, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 42);
	rz_bv_set_from_bytes_be(&bv, data, 1, 42);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x37e6d5c4b3a", "off+1 42");
	rz_bv_set_from_bytes_be(&bv, data, 1, 40);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x37e6d5c4b38", "off+1 42, padding");
	rz_bv_set_from_bytes_be(&bv, data, 1, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x37e6d5c4b3a", "off+1 42, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 80);
	rz_bv_set_from_bytes_be(&bv, data, 1, 80);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xdf9b5712ce8a46022064", "off+1 80");
	rz_bv_set_from_bytes_be(&bv, data, 1, 78);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xdf9b5712ce8a46022064", "off+1 80, padding");
	rz_bv_set_from_bytes_be(&bv, data, 1, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xdf9b5712ce8a46022064", "off+1 80, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 64);
	rz_bv_set_from_bytes_be(&bv, data, 7, 64);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe6d5c4b3a2918088", "off+7 64");
	rz_bv_set_from_bytes_be(&bv, data, 7, 62);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe6d5c4b3a2918088", "off+7, padding");
	rz_bv_set_from_bytes_be(&bv, data, 7, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe6d5c4b3a2918088", "off+7 64, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 42);
	rz_bv_set_from_bytes_be(&bv, data, 7, 42);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x39b5712ce8a", "off+7 42");
	rz_bv_set_from_bytes_be(&bv, data, 7, 40);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x39b5712ce88", "off+7 42, padding");
	rz_bv_set_from_bytes_be(&bv, data, 7, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x39b5712ce8a", "off+7 42, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 80);
	rz_bv_set_from_bytes_be(&bv, data, 7, 80);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe6d5c4b3a2918088192a", "off+7 80");
	rz_bv_set_from_bytes_be(&bv, data, 7, 78);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe6d5c4b3a29180881928", "off+7 80, padding");
	rz_bv_set_from_bytes_be(&bv, data, 7, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe6d5c4b3a2918088192a", "off+7 80, cut off");
	rz_bv_fini(&bv);

	RzBitVector *hbv = rz_bv_new_from_bytes_be(data, 0, 64);
	mu_assert_streq_free(rz_bv_as_hex_string(hbv, true), "0xefcdab8967452301", "aligned 64");
	rz_bv_free(hbv);

	mu_end;
}

bool test_rz_bv_set_from_bytes_le(void) {
	const ut8 data[0x10] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
	};
	RzBitVector bv;
	rz_bv_init(&bv, 64);
	rz_bv_set_from_bytes_le(&bv, data, 0, 64);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xefcdab8967452301", "aligned 64");
	rz_bv_set_from_bytes_le(&bv, data, 0, 62);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x2fcdab8967452301", "aligned 64, padding");
	rz_bv_set_from_bytes_le(&bv, data, 0, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xefcdab8967452301", "aligned 64, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 42);
	rz_bv_set_from_bytes_le(&bv, data, 0, 42);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x38967452301", "aligned 42");
	rz_bv_set_from_bytes_le(&bv, data, 0, 40);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x08967452301", "aligned 42, padding");
	rz_bv_set_from_bytes_le(&bv, data, 0, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x38967452301", "aligned 42, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 80);
	rz_bv_set_from_bytes_le(&bv, data, 0, 80);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xdcfeefcdab8967452301", "aligned 80");
	rz_bv_set_from_bytes_le(&bv, data, 0, 78);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x1cfeefcdab8967452301", "aligned 80, padding");
	rz_bv_set_from_bytes_le(&bv, data, 0, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xdcfeefcdab8967452301", "aligned 80, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 64);
	rz_bv_set_from_bytes_le(&bv, data, 1, 64);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x77e6d5c4b3a29180", "off+1 64");
	rz_bv_set_from_bytes_le(&bv, data, 1, 62);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x37e6d5c4b3a29180", "off+1, padding");
	rz_bv_set_from_bytes_le(&bv, data, 1, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x77e6d5c4b3a29180", "off+1 64, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 42);
	rz_bv_set_from_bytes_le(&bv, data, 1, 42);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x1c4b3a29180", "off+1 42");
	rz_bv_set_from_bytes_le(&bv, data, 1, 40);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x0c4b3a29180", "off+1 42, padding");
	rz_bv_set_from_bytes_le(&bv, data, 1, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x1c4b3a29180", "off+1 42, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 80);
	rz_bv_set_from_bytes_le(&bv, data, 1, 80);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x6e7f77e6d5c4b3a29180", "off+1 80");
	rz_bv_set_from_bytes_le(&bv, data, 1, 78);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x2e7f77e6d5c4b3a29180", "off+1 80, padding");
	rz_bv_set_from_bytes_le(&bv, data, 1, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x6e7f77e6d5c4b3a29180", "off+1 80, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 64);
	rz_bv_set_from_bytes_le(&bv, data, 7, 64);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xfddf9b5712ce8a46", "off+7 64");
	rz_bv_set_from_bytes_le(&bv, data, 7, 62);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x3ddf9b5712ce8a46", "off+7, padding");
	rz_bv_set_from_bytes_le(&bv, data, 7, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xfddf9b5712ce8a46", "off+7 64, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 42);
	rz_bv_set_from_bytes_le(&bv, data, 7, 42);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x35712ce8a46", "off+7 42");
	rz_bv_set_from_bytes_le(&bv, data, 7, 40);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x05712ce8a46", "off+7 42, padding");
	rz_bv_set_from_bytes_le(&bv, data, 7, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x35712ce8a46", "off+7 42, cut off");
	rz_bv_fini(&bv);
	rz_bv_init(&bv, 80);
	rz_bv_set_from_bytes_le(&bv, data, 7, 80);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x75b9fddf9b5712ce8a46", "off+7 80");
	rz_bv_set_from_bytes_le(&bv, data, 7, 78);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x35b9fddf9b5712ce8a46", "off+7 80, padding");
	rz_bv_set_from_bytes_le(&bv, data, 7, 100);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x75b9fddf9b5712ce8a46", "off+7 80, cut off");
	rz_bv_fini(&bv);

	RzBitVector *hbv = rz_bv_new_from_bytes_le(data, 0, 64);
	mu_assert_streq_free(rz_bv_as_hex_string(hbv, true), "0xefcdab8967452301", "aligned 64");
	rz_bv_free(hbv);

	mu_end;
}

bool test_rz_bv_as_hex_string(void) {
	char *s = NULL;

	// small
	RzBitVector *bv = rz_bv_new_from_ut64(32, 42);
	s = rz_bv_as_hex_string(bv, true);
	mu_assert_streq_free(s, "0x0000002a", "string hex value of bv");
	s = rz_bv_as_hex_string(bv, false);
	mu_assert_streq_free(s, "0x2a", "string hex value of bv");

	rz_bv_set_from_ut64(bv, 0x32a);
	s = rz_bv_as_hex_string(bv, true);
	mu_assert_streq_free(s, "0x0000032a", "string hex value of bv");
	s = rz_bv_as_hex_string(bv, false);
	mu_assert_streq_free(s, "0x32a", "string hex value of bv");
	rz_bv_free(bv);

	// big
	bv = rz_bv_new_from_ut64(128, 100);
	rz_bv_set(bv, 2, true);
	rz_bv_set(bv, 5, true);
	rz_bv_set(bv, 6, true);

	s = rz_bv_as_hex_string(bv, true);
	mu_assert_streq_free(s, "0x00000000000000000000000000000064", "string hex value of bv");
	s = rz_bv_as_hex_string(bv, false);
	mu_assert_streq_free(s, "0x64", "string hex value of bv");

	rz_bv_set(bv, 16, true);

	s = rz_bv_as_hex_string(bv, true);
	mu_assert_streq_free(s, "0x00000000000000000000000000010064", "string hex value of bv");
	s = rz_bv_as_hex_string(bv, false);
	mu_assert_streq_free(s, "0x10064", "string hex value of bv");

	rz_bv_free(bv);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_bv_init32);
	mu_run_test(test_rz_bv_init64);
	mu_run_test(test_rz_bv_init128);
	mu_run_test(test_rz_bv_init_signed);
	mu_run_test(test_rz_bv_cmp);
	mu_run_test(test_rz_bv_cast);
	mu_run_test(test_rz_bv_operation);
	mu_run_test(test_rz_bv_logic);
	mu_run_test(test_rz_bv_algorithm32);
	mu_run_test(test_rz_bv_algorithm128);
	mu_run_test(test_rz_bv_set_from_bytes_le);
	mu_run_test(test_rz_bv_set_from_bytes_be);
	mu_run_test(test_rz_bv_as_hex_string);
	return tests_passed != tests_run;
}

mu_main(all_tests)
