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

bool test_rz_bv_init70(void) {
	char *s = NULL;

	// create by given unsigned 70 bits
	RzBitVector *bits = rz_bv_new_from_ut64(70, 100);
	RzBitVector *bits_cmp = rz_bv_new(70);

	// 100 = 64 + 32 + 4 == 0b 0000 0000 0000 0000 0000 0000 0110 0100
	rz_bv_set(bits_cmp, 2, true);
	rz_bv_set(bits_cmp, 5, true);
	rz_bv_set(bits_cmp, 6, true);
	mu_assert("new from 70", is_equal_bv(bits, bits_cmp));

	// dup
	RzBitVector *bits_dup = rz_bv_dup(bits);
	mu_assert("dup from bits 70", is_equal_bv(bits_dup, bits));

	s = rz_bv_as_string(bits);
	mu_assert_streq_free(s, "0000000000000000000000000000000000000000000000000000000000000001100100", "string bit value of bv");

	s = rz_bv_as_hex_string(bits, true);
	mu_assert_streq_free(s, "0x000000000000000064", "string hex value of bv");

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

bool test_rz_bv_logic_large(void) {
	RzBitVector *x, *y, *z;
	RzBitVector *result;
	const ut8 array_128[128] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	const ut8 array_128_01[128] = {
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
	};
	const ut8 array_128_10[128] = {
		0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10
	};

	// Expected
	const char *not = "0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"; // ~x
	const char *and = "0x00010001000100010001000100010001"; // x & y
	const char *or = "0x101112131415161718191a1b1c1d1e1f"; // x | z
	const char *xor = "0x010003020504070609080b0a0d0c0f0e"; // x ^ y
	const char *neg = "0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f1"; // -x

	x = rz_bv_new_from_bytes_be(array_128, 0, 128);
	y = rz_bv_new_from_bytes_be(array_128_01, 0, 128);
	z = rz_bv_new_from_bytes_be(array_128_10, 0, 128);

	result = rz_bv_not(x);
	mu_assert_streq_free(rz_bv_as_hex_string(result, false), not, "not result off");
	rz_bv_free(result);

	result = rz_bv_and(x, y);
	mu_assert_streq_free(rz_bv_as_hex_string(result, true), and, "and result off");
	rz_bv_free(result);

	result = rz_bv_or(x, z);
	mu_assert_streq_free(rz_bv_as_hex_string(result, true), or, "or result off");
	rz_bv_free(result);

	result = rz_bv_xor(x, y);
	mu_assert_streq_free(rz_bv_as_hex_string(result, true), xor, "xor result off");
	rz_bv_free(result);

	result = rz_bv_neg(x);
	mu_assert_streq_free(rz_bv_as_hex_string(result, true), neg, "neg result off");
	rz_bv_free(result);

	rz_bv_free(x);
	rz_bv_free(y);
	rz_bv_free(z);
	mu_end;
}

bool test_rz_bv_logic(void) {
	RzBitVector *x, *y;
	RzBitVector *result;
	RzBitVector *and, *or, *xor, *neg, *not, *ls, *rs, *ls_fill, *rs_fill;

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
	mu_assert("not x", is_equal_bv(result, not));
	rz_bv_free(result);
	rz_bv_free(not);

	result = rz_bv_neg(x);
	mu_assert("neg x", is_equal_bv(result, neg));
	rz_bv_free(result);
	rz_bv_free(neg);

	result = rz_bv_dup(y);
	mu_assert_true(rz_bv_lshift(result, 3), "Shift failed");
	mu_assert("left shift y", is_equal_bv(result, ls));
	rz_bv_free(result);
	rz_bv_free(ls);

	result = rz_bv_dup(y);
	mu_assert_true(rz_bv_lshift_fill(result, 3, true), "Shift failed");
	mu_assert("left shift y filling 1", is_equal_bv(result, ls_fill));
	rz_bv_free(result);
	rz_bv_free(ls_fill);

	result = rz_bv_dup(y);
	mu_assert_true(rz_bv_rshift(result, 3), "Shift failed");
	mu_assert("right shift y", is_equal_bv(result, rs));
	rz_bv_free(result);
	rz_bv_free(rs);

	result = rz_bv_dup(y);
	mu_assert_true(rz_bv_rshift_fill(result, 3, true), "Shift failed");
	mu_assert("right shift y", is_equal_bv(result, rs_fill));

	ut64 before = rz_bv_to_ut64(result);
	mu_assert_true(rz_bv_rshift_fill(result, 0, true), "Shift failed");
	mu_assert_eq(rz_bv_to_ut64(result), before, "right shift 0 failed");

	mu_assert_true(rz_bv_lshift_fill(result, 0, true), "Shift failed");
	mu_assert_eq(rz_bv_to_ut64(result), before, "left shift 0 failed");

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

/**
 * \brief Reference implementation of rz_bv_add() to test against
 */
static RzBitVector *rz_bv_add_ref(RZ_INOUT RZ_NONNULL RZ_BORROW RzBitVector *x, const RZ_NONNULL RzBitVector *y, RZ_NULLABLE bool *carry) {
	rz_return_val_if_fail(x && y, false);

	if (x->len != y->len || x->len == 0) {
		rz_warn_if_reached();
		return NULL;
	}

	RzBitVector *ret = rz_bv_dup(x);
	bool a = false, b = false, _carry = false;

	for (ut32 pos = 0; pos < ret->len; ++pos) {
		a = rz_bv_get(ret, pos);
		b = rz_bv_get(y, pos);
		rz_bv_set(ret, pos, a ^ b ^ _carry);
		_carry = ((a & b) | (a & _carry)) | (b & _carry);
	}

	if (carry) {
		*carry = _carry;
	}

	return ret;
}

/**
 * \brief This function calls `rz_bv_add()` and it related baseline implementation `rz_bv_add_ref()` and then
 * compares the resultant bitvector and carry flag and returns an error if there is a difference.
 */
static const char *test_rz_bv_add_against_ref(ut64 size, const ut8 *a_bytes, const ut8 *b_bytes) {
	bool carry_a = false;
	bool carry_b = false;
	const char *error = NULL;

	RzBitVector *a = rz_bv_new_from_bytes_be(a_bytes, 0, size);
	RzBitVector *b = rz_bv_new_from_bytes_be(b_bytes, 0, size);
	RzBitVector *result = rz_bv_add(a, b, &carry_a);
	RzBitVector *ref = rz_bv_add_ref(a, b, &carry_b);

	if (rz_bv_cmp(result, ref)) {
		error = "rz_bv_add() result differs from reference";
		goto finally;
	}

	if (carry_a != carry_b) {
		error = "rz_bv_add() carry flag differs from reference";
		goto finally;
	}

finally:
	rz_bv_free(result);
	rz_bv_free(ref);
	rz_bv_free(a);
	rz_bv_free(b);

	return error;
}

bool test_rz_bv_add(void) {
	const char *error = NULL;

	// Add 5-bit vectors with carry
	error = test_rz_bv_add_against_ref(
		5,
		(ut8[1]){ 0x1f },
		(ut8[1]){ 0x01 });
	mu_assert_null(error, error);

	// Add 5-bit vectors without carry
	error = test_rz_bv_add_against_ref(
		5,
		(ut8[1]){ 0x10 },
		(ut8[1]){ 0x01 });
	mu_assert_null(error, error);

	// Add 64-bit vectors with carry
	error = test_rz_bv_add_against_ref(
		64,
		(ut8[8]){ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
		(ut8[8]){ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 });
	mu_assert_null(error, error);

	// Add 64-bit vectors without carry
	error = test_rz_bv_add_against_ref(
		64,
		(ut8[8]){ 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
		(ut8[8]){ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 });
	mu_assert_null(error, error);

	// Add 128-bit vectors with carry
	error = test_rz_bv_add_against_ref(
		128,
		(ut8[16]){ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
		(ut8[16]){ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
	mu_assert_null(error, error);

	// Add 128-bit vectors without carry
	error = test_rz_bv_add_against_ref(
		128,
		(ut8[16]){ 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
		(ut8[16]){ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F });
	mu_assert_null(error, error);

	// Add 125-bit vectors with carry
	error = test_rz_bv_add_against_ref(
		125,
		(ut8[16]){ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F },
		(ut8[16]){ 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
	mu_assert_null(error, error);

	// Add 125-bit vectors without carry
	error = test_rz_bv_add_against_ref(
		125,
		(ut8[16]){ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10 },
		(ut8[16]){ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00 });
	mu_assert_null(error, error);

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
	mu_assert_false(rz_bv_ule(x, y), "ule of -/+");
	mu_assert_true(rz_bv_ule(y, x), "ule of +/-");
	mu_assert_true(rz_bv_sle(x, y), "sle of -/+");
	mu_assert_false(rz_bv_sle(y, x), "sle of +/-");
	rz_bv_free(x);
	rz_bv_free(y);

	x = rz_bv_new_from_st64(32, -42);
	y = rz_bv_new_from_st64(32, -20);
	mu_assert_true(rz_bv_sle(x, y), "sle of -/-");
	mu_assert_false(rz_bv_sle(y, x), "sle of -/-");
	mu_assert_true(rz_bv_ule(x, y), "sle of -/-");
	mu_assert_false(rz_bv_ule(y, x), "sle of -/-");
	rz_bv_free(x);
	rz_bv_free(y);

	x = rz_bv_new_from_st64(32, 42);
	y = rz_bv_new_from_st64(32, 20);
	mu_assert_false(rz_bv_sle(x, y), "sle of +/+");
	mu_assert_true(rz_bv_sle(y, y), "sle of +/+");
	mu_assert_false(rz_bv_ule(x, y), "ule of +/+");
	mu_assert_true(rz_bv_ule(y, y), "ule of +/+");
	rz_bv_free(x);
	rz_bv_free(y);

	x = rz_bv_new_from_st64(32, 42);
	y = rz_bv_new_from_st64(32, 42);
	mu_assert_true(rz_bv_sle(x, y), "sle of ==");
	mu_assert_true(rz_bv_ule(x, y), "ule of ==");
	rz_bv_free(x);
	rz_bv_free(y);

	mu_end;
}

bool test_rz_bv_eq(void) {
	RzBitVector *x = rz_bv_new_from_ut64(8, 42);
	RzBitVector *y = rz_bv_new_from_ut64(8, 42);
	bool r = rz_bv_eq(x, y);
	mu_assert_true(r, "equal");
	rz_bv_free(y);

	y = rz_bv_new_from_ut64(8, 41);
	r = rz_bv_eq(x, y);
	mu_assert_false(r, "not equal");
	rz_bv_free(y);

	y = rz_bv_new_from_ut64(16, 42);
	r = rz_bv_eq(x, y);
	mu_assert_false(r, "not equal");
	rz_bv_free(y);

	rz_bv_free(x);
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

	RzBitVector *one32 = rz_bv_new_one(32);
	RzBitVector *one78 = rz_bv_new_one(78);
	RzBitVector *one32_as78 = rz_bv_cast(one32, 78, 0);
	mu_assert_true(rz_bv_eq(one78, one32_as78), "test one cast");
	rz_bv_free(one32);
	rz_bv_free(one78);
	rz_bv_free(one32_as78);

	RzBitVector *bv32 = rz_bv_new_from_ut64(32, 123);
	RzBitVector *bv32_as64 = rz_bv_cast(bv32, 64, 0);
	RzBitVector *bv64 = rz_bv_new_from_ut64(64, 123);
	mu_assert_true(rz_bv_eq(bv64, bv32_as64), "test 123 from bv32 to bv64");
	rz_bv_free(bv32);
	rz_bv_free(bv32_as64);
	rz_bv_free(bv64);

	// narrow cast
	ut64 val64 = 34017;
	val64 <<= 32;
	val64 |= 202301;
	bv64 = rz_bv_new_from_ut64(64, val64);
	bv32 = rz_bv_new_from_ut64(32, 202301);
	RzBitVector *bv64_as32 = rz_bv_cast(bv64, 32, 0);
	mu_assert_true(rz_bv_eq(bv64_as32, bv32), "test narrow cast from 64 to 32");
	rz_bv_free(bv64);
	rz_bv_free(bv32);
	rz_bv_free(bv64_as32);

	// signed cast
	RzBitVector *neg_one32 = rz_bv_new_minus_one(32);
	RzBitVector *neg_one64 = rz_bv_new_minus_one(64);
	RzBitVector *neg_one32_as64 = rz_bv_signed_cast(neg_one32, 64);
	RzBitVector *neg_one32_asu64 = rz_bv_unsigned_cast(neg_one32, 64);
	mu_assert_true(rz_bv_eq(neg_one64, neg_one32_as64), "test signed cast from 32 to 64");
	mu_assert_eq(rz_bv_to_ut64(neg_one32_asu64), (ut64)(ut32)(-1), "test unsigned cast for -1 from 32-bit to 64-bit");
	mu_assert_eq(rz_bv_to_ut64(neg_one32_asu64),
		rz_bv_to_ut64(neg_one32),
		"test unsigned cast and convert to ut64 val");
	rz_bv_free(neg_one32);
	rz_bv_free(neg_one64);
	rz_bv_free(neg_one32_asu64);
	rz_bv_free(neg_one32_as64);
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
	const ut8 data_4[] = { 0xe };
	rz_bv_init(&bv, 4);
	rz_bv_set_from_bytes_be(&bv, data_4, 0, 4);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe", "off+0  4");
	rz_bv_set_from_bytes_be(&bv, data_4, 0, 2);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x8", "off+0  4, padding");
	rz_bv_set_from_bytes_be(&bv, data_4, 0, 8);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe", "off+0  4, cut off");
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
	rz_bv_init(&bv, 1);
	rz_bv_set_from_bytes_le(&bv, data, 0, 1);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x1", "off+0 1");
	rz_bv_fini(&bv);
	const ut8 data_4[] = { 0xe };
	rz_bv_init(&bv, 4);
	rz_bv_set_from_bytes_le(&bv, data_4, 0, 4);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe", "off+0 4");
	rz_bv_set_from_bytes_le(&bv, data_4, 0, 2);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0x2", "off+0 4, padding");
	rz_bv_set_from_bytes_le(&bv, data_4, 0, 8);
	mu_assert_streq_free(rz_bv_as_hex_string(&bv, true), "0xe", "off+0 4, cut off");
	rz_bv_fini(&bv);

	RzBitVector *hbv = rz_bv_new_from_bytes_le(data, 0, 64);
	mu_assert_streq_free(rz_bv_as_hex_string(hbv, true), "0xefcdab8967452301", "aligned 64");
	rz_bv_free(hbv);

	mu_end;
}

bool test_rz_bv_set_from_buffer_ble(bool big_endian) {
	const ut8 data[0x10] = {
		0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe
	};

	const ut8 len[5] = {
		4, 42, 64, 80, 82
	};

	RzBuffer *buf = rz_buf_new_with_bytes(data, 0x10);
	char *error = NULL;

	for (int i = 0; i < sizeof(len); i++) {
		RzBitVector bv;
		rz_bv_init(&bv, len[i]);

		for (ut32 bits_to_copy = 1; bits_to_copy < bv.len + 10; bits_to_copy++) {
			rz_buf_seek(buf, 0, RZ_BUF_SET);
			rz_bv_set_from_buffer_ble(&bv, buf, bits_to_copy, big_endian);
			char *result = rz_bv_as_hex_string(&bv, true);

			rz_bv_set_from_bytes_ble(&bv, data, 0, bits_to_copy, big_endian);
			char *ref = rz_bv_as_hex_string(&bv, true);

			if (strcmp(result, ref)) {
				error = rz_str_newf(
					"%s result (%s) doesn't match reference (%s) for bit_size: %" PFMT32u " and bitvector length: %" PFMT32u,
					big_endian ? "rz_bv_set_from_buffer_be()" : "rz_bv_set_from_buffer_le()",
					result,
					ref,
					bits_to_copy,
					bv.len);
				mu_fail(error);
			}

			free(result);
			free(ref);
		}

		rz_bv_fini(&bv);
	}

	rz_buf_free(buf);
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

	rz_bv_set_from_ut64(bv, 0x0);
	s = rz_bv_as_hex_string(bv, true);
	mu_assert_streq_free(s, "0x00000000", "string hex value of bv");
	s = rz_bv_as_hex_string(bv, false);
	mu_assert_streq_free(s, "0x0", "string hex value of bv");
	rz_bv_free(bv);

	bv = rz_bv_new_from_ut64(1, 1);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, true), "0x1", "string hex value of bv");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x1", "string hex value of bv");
	rz_bv_set_from_ut64(bv, 0);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, true), "0x0", "string hex value of bv");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "string hex value of bv");
	rz_bv_free(bv);

	bv = rz_bv_new_from_ut64(7, 0x7f);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, true), "0x7f", "string hex value of bv");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x7f", "string hex value of bv");
	rz_bv_set_from_ut64(bv, 0x70);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, true), "0x70", "string hex value of bv");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x70", "string hex value of bv");
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

	rz_bv_set_from_ut64(bv, 0x0);
	s = rz_bv_as_hex_string(bv, true);
	mu_assert_streq_free(s, "0x00000000000000000000000000000000", "string hex value of bv");
	s = rz_bv_as_hex_string(bv, false);
	mu_assert_streq_free(s, "0x0", "string hex value of bv");
	rz_bv_free(bv);

	bv = rz_bv_new_from_st64(64 + 7, -1);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, true), "0x7fffffffffffffffff", "string hex value of bv");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x7fffffffffffffffff", "string hex value of bv");
	rz_bv_set_from_ut64(bv, 0);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, true), "0x000000000000000000", "string hex value of bv");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "string hex value of bv");
	rz_bv_free(bv);

	mu_end;
}

bool test_rz_bv_clz(void) {
#define TEST_CLZ(bva, expect) \
	do { \
		RzBitVector *a = bva; \
		ut32 r = rz_bv_clz(a); \
		mu_assert_eq(r, expect, "clz"); \
		rz_bv_free(a); \
	} while (0)

	TEST_CLZ(rz_bv_new_from_ut64(32, 0x2a), 26);
	TEST_CLZ(rz_bv_new_from_ut64(32, 0x0), 32);
	TEST_CLZ(rz_bv_new_from_ut64(32, 0xffffffff), 0);
	TEST_CLZ(rz_bv_new_from_ut64(64, 0xffffffffffffffff), 0);
	TEST_CLZ(rz_bv_new_from_ut64(64, 0x2a), 58);
	TEST_CLZ(rz_bv_new_from_ut64(74, 0x2a), 68);
	TEST_CLZ(rz_bv_new_from_st64(74, -1), 0);
	TEST_CLZ(rz_bv_new_from_ut64(74, 0), 74);

#undef TEST_CLZ
	mu_end;
}

bool test_rz_bv_ctz(void) {
#define TEST_CTZ(bva, expect) \
	do { \
		RzBitVector *a = bva; \
		ut32 r = rz_bv_ctz(a); \
		mu_assert_eq(r, expect, "clz"); \
		rz_bv_free(a); \
	} while (0)

	TEST_CTZ(rz_bv_new_from_ut64(32, 0x1), 0);
	TEST_CTZ(rz_bv_new_from_ut64(32, 0x0), 32);
	TEST_CTZ(rz_bv_new_from_ut64(32, 0xffffff00), 8);
	TEST_CTZ(rz_bv_new_from_ut64(64, 0xfffffffffffff800), 11);
	TEST_CTZ(rz_bv_new_from_ut64(74, 0x8), 3);
	TEST_CTZ(rz_bv_new_from_st64(74, -1), 0);
	TEST_CTZ(rz_bv_new_from_ut64(74, 0), 74);

#undef TEST_CTZ
	mu_end;
}

bool test_rz_bv_div(void) {
#define TEST_DIV(bva, bvb, sr) \
	do { \
		RzBitVector *a = bva; \
		RzBitVector *b = bvb; \
		RzBitVector *r = rz_bv_div(a, b); \
		mu_assert_notnull(r, "division succes"); \
		mu_assert_eq(rz_bv_len(r), rz_bv_len(a), "division result len"); \
		mu_assert_streq_free(rz_bv_as_hex_string(r, false), sr, "division result"); \
		rz_bv_free(a); \
		rz_bv_free(b); \
		rz_bv_free(r); \
	} while (0)

	// small
	TEST_DIV(rz_bv_new_from_ut64(32, 42), rz_bv_new_from_ut64(32, 3), "0xe");
	TEST_DIV(rz_bv_new_from_ut64(32, 42), rz_bv_new_from_ut64(32, 0), "0xffffffff");
	TEST_DIV(rz_bv_new_from_ut64(32, 0), rz_bv_new_from_ut64(32, 0), "0xffffffff");
	TEST_DIV(rz_bv_new_from_ut64(32, 0xffffffd6), rz_bv_new_from_ut64(32, 42), "0x6186185");
	TEST_DIV(rz_bv_new_from_ut64(32, 42), rz_bv_new_from_ut64(32, 42), "0x1");

	// big
	TEST_DIV(rz_bv_new_from_ut64(70, 42), rz_bv_new_from_ut64(70, 3), "0xe");
	TEST_DIV(rz_bv_new_from_ut64(70, 42), rz_bv_new_from_ut64(70, 0), "0x3fffffffffffffffff");
	TEST_DIV(rz_bv_new_from_ut64(70, 0), rz_bv_new_from_ut64(70, 0), "0x3fffffffffffffffff");
	TEST_DIV(rz_bv_new_from_ut64(70, 0xffffffd6), rz_bv_new_from_ut64(70, 42), "0x6186185");
	TEST_DIV(rz_bv_new_from_ut64(70, 42), rz_bv_new_from_ut64(70, 42), "0x1");
	RzBitVector *superbig = rz_bv_new_from_ut64(80, 42);
	mu_assert_true(rz_bv_lshift(superbig, 70), "Shift failed");
	TEST_DIV(superbig, rz_bv_new_from_ut64(80, 2), "0x5400000000000000000");

#undef TEST_DIV
	mu_end;
}

bool test_rz_bv_mod(void) {
#define TEST_MOD(bva, bvb, sr) \
	do { \
		RzBitVector *a = bva; \
		RzBitVector *b = bvb; \
		RzBitVector *r = rz_bv_mod(a, b); \
		mu_assert_notnull(r, "division succes"); \
		mu_assert_eq(rz_bv_len(r), rz_bv_len(a), "division result len"); \
		mu_assert_streq_free(rz_bv_as_hex_string(r, false), sr, "division result"); \
		rz_bv_free(a); \
		rz_bv_free(b); \
		rz_bv_free(r); \
	} while (0)

	// small
	TEST_MOD(rz_bv_new_from_ut64(32, 42), rz_bv_new_from_ut64(32, 3), "0x0");
	TEST_MOD(rz_bv_new_from_ut64(32, 42), rz_bv_new_from_ut64(32, 0), "0x2a");
	TEST_MOD(rz_bv_new_from_ut64(32, 0), rz_bv_new_from_ut64(32, 0), "0x0");
	TEST_MOD(rz_bv_new_from_ut64(32, 0xffffffd6), rz_bv_new_from_ut64(32, 42), "0x4");
	TEST_MOD(rz_bv_new_from_ut64(32, 42), rz_bv_new_from_ut64(32, 42), "0x0");

	// big
	TEST_MOD(rz_bv_new_from_ut64(70, 42), rz_bv_new_from_ut64(70, 3), "0x0");
	TEST_MOD(rz_bv_new_from_ut64(70, 42), rz_bv_new_from_ut64(70, 0), "0x2a");
	TEST_MOD(rz_bv_new_from_ut64(70, 0), rz_bv_new_from_ut64(70, 0), "0x0");
	TEST_MOD(rz_bv_new_from_ut64(70, 0xffffffd6), rz_bv_new_from_ut64(70, 42), "0x4");
	TEST_MOD(rz_bv_new_from_ut64(70, 42), rz_bv_new_from_ut64(70, 42), "0x0");
	RzBitVector *superbig = rz_bv_new_from_ut64(80, 42);
	mu_assert_true(rz_bv_lshift(superbig, 70), "Shift failed");
	TEST_MOD(rz_bv_dup(superbig), rz_bv_new_from_ut64(80, 2), "0x0");
	rz_bv_set(superbig, 0, true);
	rz_bv_set(superbig, 1, true);
	TEST_MOD(superbig, rz_bv_new_from_ut64(80, 64), "0x3");

#undef TEST_DIV
	mu_end;
}

static bool test_rz_bv_len_bytes(void) {
#define TEST_LEN_BYTES(bits, bytes) \
	do { \
		RzBitVector *bv = rz_bv_new_from_ut64(bits, 0); \
		mu_assert_eq(rz_bv_len_bytes(bv), bytes, "len"); \
		rz_bv_free(bv); \
	} while (0);
	TEST_LEN_BYTES(1, 1);
	TEST_LEN_BYTES(2, 1);
	TEST_LEN_BYTES(3, 1);
	TEST_LEN_BYTES(4, 1);
	TEST_LEN_BYTES(5, 1);
	TEST_LEN_BYTES(6, 1);
	TEST_LEN_BYTES(7, 1);
	TEST_LEN_BYTES(8, 1);
	TEST_LEN_BYTES(9, 2);
	TEST_LEN_BYTES(0x10, 2);
	TEST_LEN_BYTES(0x11, 3);
	TEST_LEN_BYTES(128, 16);
	TEST_LEN_BYTES(129, 17);
#undef TEST_LEN_BYTES
	mu_end;
}

bool test_rz_bv_set_operations(void) {
	RzBitVector *bv = rz_bv_new(43);
	rz_bv_set_all(bv, true);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x7ffffffffff", "set all 1");
	mu_assert_true(rz_bv_is_all_one(bv), "all bits are 1");
	rz_bv_set_all(bv, false);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "set all 0");
	mu_assert_false(rz_bv_is_all_one(bv), "not all 1");
	rz_bv_free(bv);

	bv = rz_bv_new(64);
	rz_bv_set_all(bv, true);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0xffffffffffffffff", "set all 1");
	mu_assert_true(rz_bv_is_all_one(bv), "all bits are 1");
	rz_bv_set_all(bv, false);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "set all 0");
	mu_assert_false(rz_bv_is_all_one(bv), "not all 1");
	rz_bv_free(bv);

	bv = rz_bv_new(73);
	rz_bv_set_all(bv, true);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x1ffffffffffffffffff", "set all 1");
	mu_assert_true(rz_bv_is_all_one(bv), "all bits are 1");
	rz_bv_set_all(bv, false);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "set all 0");
	mu_assert_false(rz_bv_is_all_one(bv), "not all 1");
	rz_bv_free(bv);

	bv = rz_bv_new(80);
	rz_bv_set_all(bv, true);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0xffffffffffffffffffff", "set all 1");
	mu_assert_true(rz_bv_is_all_one(bv), "all bits are 1");
	rz_bv_set_all(bv, false);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "set all 0");
	mu_assert_false(rz_bv_is_all_one(bv), "not all 1");
	rz_bv_free(bv);

	bv = rz_bv_new(42);
	rz_bv_set_range(bv, 0, bv->len - 1, true);
	mu_assert_true(rz_bv_is_all_one(bv), "set all 1 by set_range");
	// 11 1111 1111 1111 1100 0000 0011 1111 1111 1111 1111
	rz_bv_set_range(bv, 18, 25, false);
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x3fffc03ffff", "range set 18~25 to 0");
	rz_bv_free(bv);

	bv = rz_bv_new(16);
	mu_assert_false(rz_bv_set_range(bv, 16, 20, true), "set out of range");
	rz_bv_free(bv);
	mu_end;
}

bool test_rz_bv_set_range_large(void) {
	RzBitVector *bv = rz_bv_new(128);

	// Expect failure on inverted range
	mu_assert_false(rz_bv_set_range(bv, 20, 10, true), "expected failure for inverse range");

	// Bitrange with unalign prefix bits
	mu_assert_true(rz_bv_set_range(bv, 5, 7, true), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0xe0", "range set 5~7 to 1");

	mu_assert_true(rz_bv_set_range(bv, 5, 7, false), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "range set 5~7 to 0");

	// Bitrange with unalign prefix and suffix bits
	mu_assert_true(rz_bv_set_range(bv, 5, 8, true), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x1e0", "range set 5~8 to 1");

	mu_assert_true(rz_bv_set_range(bv, 5, 8, false), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "range set 5~8 to 0");

	// Only suffix bit
	mu_assert_true(rz_bv_set_range(bv, 8, 8, true), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x100", "range set 8~8 to 1");

	mu_assert_true(rz_bv_set_range(bv, 8, 8, false), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "range set 8~8 to 0");

	// Bitrange with unaligned prefix, suffix bits and aligned middle bytes
	mu_assert_true(rz_bv_set_range(bv, 5, 24, true), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x1ffffe0", "range set 5~24 to 1");

	mu_assert_true(rz_bv_set_range(bv, 5, 24, false), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "range set 5~24 to 0");

	// Aligned
	mu_assert_true(rz_bv_set_range(bv, 16, 31, true), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0xffff0000", "range set 16~31 to 1");

	mu_assert_true(rz_bv_set_range(bv, 16, 31, false), "expect rz_bv_set_range() success");
	mu_assert_streq_free(rz_bv_as_hex_string(bv, false), "0x0", "range set 16~31 to 0");

	rz_bv_free(bv);
	mu_end;
}

static bool test_rz_bv_set_to_bytes_le(void) {
	{
		ut8 buf8[8] = { 0 };
		RzBitVector *bv = rz_bv_new_from_ut64(64, 0xc0ffee4201234567);
		rz_bv_set_to_bytes_le(bv, buf8);
		const ut8 expect8[8] = { 0x67, 0x45, 0x23, 0x01, 0x42, 0xee, 0xff, 0xc0 };
		mu_assert_memeq(buf8, expect8, sizeof(expect8), "set to bytes le");
		rz_bv_free(bv);
	}
	{
		ut8 buf4[4] = { 0 };
		RzBitVector *bv = rz_bv_new_from_ut64(32, 0xc0ffee42);
		rz_bv_set_to_bytes_le(bv, buf4);
		const ut8 expect4[4] = { 0x42, 0xee, 0xff, 0xc0 };
		mu_assert_memeq(buf4, expect4, sizeof(expect4), "set to bytes le");
		rz_bv_free(bv);
	}
	{
		ut8 buf2[2] = { 0xff, 0xff }; // make sure these trailing bits are not overwritten
		RzBitVector *bv = rz_bv_new_from_ut64(13, 0x0);
		rz_bv_set_to_bytes_le(bv, buf2);
		const ut8 expect2[2] = { 0x0, 0xe0 };
		mu_assert_memeq(buf2, expect2, sizeof(expect2), "set to bytes le");
		rz_bv_free(bv);
	}
	{
		ut8 buf9[9] = { 0 };
		RzBitVector *bv = rz_bv_new_from_ut64(64 + 8, 0xc0ffee4200000000);
		mu_assert_true(rz_bv_lshift_fill(bv, 8, true), "Shift failed");
		rz_bv_set_to_bytes_le(bv, buf9);
		const ut8 expect9[9] = { 0xff, 0x00, 0x00, 0x00, 0x00, 0x42, 0xee, 0xff, 0xc0 };
		mu_assert_memeq(buf9, expect9, sizeof(expect9), "set to bytes le");
		rz_bv_free(bv);
	}
	{
		ut8 buf9[9] = { 0 };
		buf9[8] = 0xff; // make sure these trailing bits are not overwritten
		RzBitVector *bv = rz_bv_new_from_ut64(64 + 6, 0xffffee00000000);
		mu_assert_true(rz_bv_lshift_fill(bv, 8, true), "Shift failed");
		rz_bv_set_to_bytes_le(bv, buf9);
		const ut8 expect9[9] = { 0xff, 0x00, 0x00, 0x00, 0x00, 0xee, 0xff, 0xff, 0xc0 };
		mu_assert_memeq(buf9, expect9, sizeof(expect9), "set to bytes le");
		rz_bv_free(bv);
	}
	mu_end;
}

bool test_rz_bv_copy_nbits(void) {
	const ut32 size = 20;
	const ut32 part_sz = 8;
	ut32 actual_copy = 0;
	/// 1010 0000 0000 1111 1111
	RzBitVector *src = rz_bv_new(size);
	for (ut32 i = 0; i < part_sz; ++i) {
		rz_bv_set(src, i, true);
	}
	rz_bv_set(src, src->len - 1, true);
	rz_bv_set(src, src->len - 3, true);

	/// copy part of bv to a new one with the same size
	RzBitVector *small = rz_bv_new(part_sz);
	actual_copy = rz_bv_copy_nbits(small, 0, src, 0, part_sz);
	mu_assert_eq(actual_copy, part_sz, "copy part_sz to normal");
	mu_assert_streq_free(rz_bv_as_string(small), "11111111", "copy nbits small bv");

	/// copy part of bv to a new one which has more spaces
	RzBitVector *normal = rz_bv_new(size);
	actual_copy = rz_bv_copy_nbits(normal, 0, src, 0, part_sz);
	mu_assert_eq(actual_copy, part_sz, "copy part_sz bits to normal");
	mu_assert_streq_free(rz_bv_as_string(normal), "00000000000011111111", "copy nbits normal length bv");

	/// copy part of bv to the medium
	RzBitVector *res = rz_bv_new(size);
	actual_copy = rz_bv_copy_nbits(res, 8, src, 0, part_sz);
	mu_assert_eq(actual_copy, part_sz, "copy part_sz bits to medium");
	mu_assert_streq_free(rz_bv_as_string(res), "00001111111100000000", "copy nbits to medium");

	/// copy non-zero, copy last 11 bits of `b` to the head of `a`
	/// dst : a = 0001 0010 0011 ...
	/// src : b = ... .001 1000 0110
	/// expect : 0011 0000 1101 ... = 0x30d45678
	RzBitVector *a = rz_bv_new_from_ut64(32, 0x12345678);
	RzBitVector *b = rz_bv_new_from_ut64(32, 0x1986);
	actual_copy = rz_bv_copy_nbits(a, a->len - 11, b, 0, 11);
	mu_assert_eq(actual_copy, 11, "copy non-zero 11 bits");
	mu_assert_streq_free(rz_bv_as_hex_string(a, false), "0x30d45678", "copy non zero");

	/// would fail (do nothing) if copy overflow is possible
	RzBitVector *too_small = rz_bv_new(part_sz);
	actual_copy = rz_bv_copy_nbits(too_small, 0, src, 0, part_sz + 2);
	mu_assert_eq(actual_copy, 0, "copy 0 bits");
	mu_assert_true(rz_bv_is_zero_vector(too_small), "copy nothing");

	rz_bv_free(src);
	rz_bv_free(small);
	rz_bv_free(normal);
	rz_bv_free(res);
	rz_bv_free(too_small);
	rz_bv_free(a);
	rz_bv_free(b);

	mu_end;
}

bool test_rz_bv_copy_nbits_inplace(void) {
	const ut8 array_128[128] = {
		0x00,
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0a,
		0x0b,
		0x0c,
		0x0d,
		0x0e,
		0x0f,
	};

	const char *large_exp_1 = "0x0e0f02030405060708090a0b0c0d0e0f";
	const char *large_exp_2 = "0x0e0f02030405060708090a0b0c0d0e1f";

	RzBitVector *small_20 = rz_bv_new_from_ut64(20, 0x01234);
	RzBitVector *large_128 = rz_bv_new_from_bytes_be(array_128, 0, 128);

	mu_assert_eq(rz_bv_copy_nbits(small_20, 1, small_20, 5, 7), 7, "wrong num bits copied");
	mu_assert_eq(rz_bv_to_ut64(small_20), 0x01222, "Mismatch in place copy");
	mu_assert_eq(rz_bv_copy_nbits(small_20, 0, small_20, 0, 21), 0, "copy overflow");
	mu_assert_eq(rz_bv_to_ut64(small_20), 0x01222, "Mismatch in place copy");
	mu_assert_eq(rz_bv_copy_nbits(small_20, 1, small_20, 0, 20), 0, "copy overflow");
	mu_assert_eq(rz_bv_to_ut64(small_20), 0x01222, "Mismatch in place copy");
	mu_assert_eq(rz_bv_copy_nbits(small_20, 0, small_20, 1, 20), 0, "copy overflow");
	mu_assert_eq(rz_bv_to_ut64(small_20), 0x01222, "Mismatch in place copy");
	mu_assert_eq(rz_bv_copy_nbits(small_20, 0, small_20, 0, 20), 20, "one to one copy");
	mu_assert_eq(rz_bv_to_ut64(small_20), 0x01222, "Mismatch in place copy");
	mu_assert_eq(rz_bv_copy_nbits(small_20, 0, small_20, 0, 20), 20, "one to one copy");
	mu_assert_eq(rz_bv_to_ut64(small_20), 0x01222, "Mismatch in place copy");

	mu_assert_eq(rz_bv_copy_nbits(large_128, 112, large_128, 0, 16), 16, "wrong num bits copied");
	mu_assert_streq_free(rz_bv_as_hex_string(large_128, true), large_exp_1, "copy to limits aligned");
	mu_assert_eq(rz_bv_copy_nbits(large_128, 2, large_128, 1, 7), 7, "wrong num bits copied");
	mu_assert_streq_free(rz_bv_as_hex_string(large_128, true), large_exp_2, "copy overlap unaligned");

	mu_assert_eq(rz_bv_copy_nbits(large_128, 120, large_128, 0, 16), 0, "wrong num bits copied");

	rz_bv_free(small_20);
	rz_bv_free(large_128);
	mu_end;
}

bool test_rz_bv_cast_inplace(void) {
	const ut8 array_128[128] = {
		0x00,
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0a,
		0x0b,
		0x0c,
		0x0d,
		0x0e,
		0x0f,
	};

	RzBitVector *small = rz_bv_new_from_ut64(20, 0x01234);
	RzBitVector *large = rz_bv_new_from_bytes_be(array_128, 0, 128);

	mu_assert_true(rz_bv_cast_inplace(small, 5, false), "Cast failed");
	mu_assert_eq(rz_bv_to_ut64(small), 0x14, "Mismatch after cast");
	mu_assert_eq(small->len, 5, "New size is off");
	mu_assert_null(small->bits.large_a, "Should have been NULL");
	mu_assert_eq(small->_elem_len, 0, "Should be 0");

	mu_assert_true(rz_bv_cast_inplace(small, 64, false), "Cast failed");
	mu_assert_eq(rz_bv_to_ut64(small), 0x14, "Mismatch after cast");
	mu_assert_eq(small->len, 64, "New size is off");
	mu_assert_null(small->bits.large_a, "Should have been NULL");
	mu_assert_eq(small->_elem_len, 0, "Should be 0");

	mu_assert_true(rz_bv_cast_inplace(small, 65, true), "Cast failed");
	mu_assert_streq_free(rz_bv_as_hex_string(small, false), "0x10000000000000014", "small to large cast failed");
	mu_assert_eq(small->len, 65, "New size is off");
	mu_assert_notnull(small->bits.large_a, "Buffer not set");
	mu_assert_eq(small->_elem_len, 9, "Buffer length wrong");

	// Cast down again
	mu_assert_true(rz_bv_cast_inplace(small, 17, true), "Cast failed");
	mu_assert_eq(rz_bv_to_ut64(small), 0x14, "Mismatch after cast");
	mu_assert_streq_free(rz_bv_as_hex_string(small, true), "0x00014", "small to large cast failed");
	mu_assert_eq(small->len, 17, "New size is off");
	// buffer is not freed
	mu_assert_notnull(small->bits.large_a, "Buffer not set");
	mu_assert_eq(small->_elem_len, 9, "Buffer length wrong");

	mu_assert_true(rz_bv_cast_inplace(small, 66, true), "Cast failed");
	mu_assert_streq_free(rz_bv_as_hex_string(small, true), "0x03fffffffffffe0014", "small to large cast failed");
	mu_assert_eq(small->len, 66, "New size is off");
	mu_assert_notnull(small->bits.large_a, "Buffer not set");
	mu_assert_eq(small->_elem_len, 9, "Buffer length wrong");

	// Cast large to small
	mu_assert_true(rz_bv_cast_inplace(large, 32, true), "Cast failed");
	mu_assert_eq(rz_bv_to_ut64(large), 0x0c0d0e0f, "Mismatch after cast");
	mu_assert_streq_free(rz_bv_as_hex_string(large, true), "0x0c0d0e0f", "small to large cast failed");
	mu_assert_eq(large->len, 32, "New size is off");
	mu_assert_notnull(large->bits.large_a, "Buffer not set");
	mu_assert_eq(large->_elem_len, 16, "Buffer length wrong");

	// Cast small to large
	mu_assert_true(rz_bv_cast_inplace(large, 256, true), "Cast failed");
	mu_assert_streq_free(rz_bv_as_hex_string(large, false), "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff0c0d0e0f", "small to large cast failed");
	mu_assert_eq(large->len, 256, "New size is off");
	mu_assert_notnull(large->bits.large_a, "Buffer not set");
	mu_assert_eq(large->_elem_len, 32, "Buffer length wrong");

	// Cast large 256 bit to 128 bit.
	mu_assert_true(rz_bv_cast_inplace(large, 128, true), "Cast failed");
	mu_assert_streq_free(rz_bv_as_hex_string(large, false), "0xffffffffffffffffffffffff0c0d0e0f", "large to large cast failed");
	mu_assert_eq(large->len, 128, "New size is off");
	mu_assert_notnull(large->bits.large_a, "Buffer not set");
	mu_assert_eq(large->_elem_len, 32, "Buffer length wrong");

	rz_bv_free(small);
	rz_bv_free(large);
	mu_end;
}

/**
 * \brief Reference implementation of rz_bv_copy_nbits() to test against
 */
static ut32 rz_bv_copy_nbits_ref(RzBitVector *dst, ut32 dst_start_pos, const RzBitVector *src, ut32 src_start_pos, ut32 nbit) {
	rz_return_val_if_fail(src && dst, 0);
	ut32 max_nbit = RZ_MIN((src->len - src_start_pos), (dst->len - dst_start_pos));

	// prevent overflow
	if (max_nbit < nbit) {
		return 0;
	}

	for (ut32 i = 0; i < nbit; ++i) {
		rz_bv_set(dst, dst_start_pos + i, rz_bv_get(src, src_start_pos + i));
	}

	return nbit;
}

/**
 * \brief Performs rz_bv_copy_nbits() with actual and reference implementation and compares results
 */
static const char *test_rz_bv_copy_nbits_against_ref(const RzBitVector *src, ut32 src_pos, RzBitVector *dst, ut32 dst_pos, ut32 nbit) {
	RzBitVector *src_copy = rz_bv_new(rz_bv_len(src));
	RzBitVector *dst_copy = rz_bv_new(rz_bv_len(dst));
	RzBitVector *dst_copy_ref = rz_bv_new(rz_bv_len(dst));
	const char *error = NULL;

	rz_bv_copy(src_copy, src);
	rz_bv_copy(dst_copy, dst);
	rz_bv_copy(dst_copy_ref, dst);

	if (rz_bv_copy_nbits(dst_copy, dst_pos, src_copy, src_pos, nbit) != nbit) {
		error = "rz_bv_copy_nbits() incorrect number of bits copied";
		goto finally;
	}

	if (rz_bv_copy_nbits_ref(dst_copy_ref, dst_pos, src_copy, src_pos, nbit) != nbit) {
		error = "rz_bv_copy_nbits_ref() incorrect number of bits copied";
		goto finally;
	}

	if (rz_bv_cmp(dst_copy, dst_copy_ref)) {
		error = "rz_bv_copy_nbits() result differs from reference";
		goto finally;
	}

	// Test with inverted src/dst for extra certainty
	rz_bv_copy(dst_copy, dst);
	rz_bv_toggle_all(src_copy);
	rz_bv_toggle_all(dst_copy);

	if (rz_bv_copy_nbits(dst_copy, dst_pos, src_copy, src_pos, nbit) != nbit) {
		error = "rz_bv_copy_nbits() incorrect number of bits copied";
		goto finally;
	}

	rz_bv_toggle_all(dst_copy);

	if (rz_bv_cmp(dst_copy, dst_copy_ref)) {
		error = "rz_bv_copy_nbits() result differs from reference";
		goto finally;
	}

finally:
	rz_bv_free(src_copy);
	rz_bv_free(dst_copy);
	rz_bv_free(dst_copy_ref);
	return error;
}

bool test_rz_bv_copy_nbits_small(void) {
	RzBitVector *a = rz_bv_new_from_ut64(64, 0x67452301);
	RzBitVector *b = rz_bv_new_from_ut64(64, 0x0);
	const char *error;

	error = test_rz_bv_copy_nbits_against_ref(a, 1, b, 2, 62);
	mu_assert_null(error, error);

	error = test_rz_bv_copy_nbits_against_ref(a, 0, b, 63, 1);
	mu_assert_null(error, error);

	rz_bv_free(a);
	rz_bv_free(b);

	mu_end;
}

bool test_rz_bv_copy_nbits_large_aligned(void) {
	RzBitVector *a = rz_bv_new(128);
	RzBitVector *b = rz_bv_new_from_ut64(128, 0x0);
	const char *error;

	rz_bv_set_all(a, true);

	/// copy same offset at same byte
	error = test_rz_bv_copy_nbits_against_ref(a, 5, b, 5, 3);
	mu_assert_null(error, error);

	/// copy with front/end byte trailing bits, but no middle bytes
	error = test_rz_bv_copy_nbits_against_ref(a, 3, b, 3, 7);
	mu_assert_null(error, error);

	/// copy with front and end trailing bits and middle bytes
	error = test_rz_bv_copy_nbits_against_ref(a, 3, b, 3, 16);
	mu_assert_null(error, error);

	/// copy without front/trailing bits
	error = test_rz_bv_copy_nbits_against_ref(a, 8, b, 8, 32);
	mu_assert_null(error, error);

	/// copy 1 bit
	error = test_rz_bv_copy_nbits_against_ref(a, 13, b, 13, 1);
	mu_assert_null(error, error);

	/// copy all except 1 bit
	error = test_rz_bv_copy_nbits_against_ref(a, 1, b, 1, 127);
	mu_assert_null(error, error);

	/// Copy bits within the same bitvector
	rz_bv_set_from_ut64(b, 0xAAAABBBBCCCCDDDD);
	ut32 actual_copy = rz_bv_copy_nbits(b, 16, b, 8, 32);
	mu_assert_eq(actual_copy, 32, "copy 32 bits");
	mu_assert_streq_free(rz_bv_as_hex_string(b, false), "0xaaaabbccccdddddd", "copy large aligned");

	rz_bv_free(a);
	rz_bv_free(b);

	mu_end;
}

bool test_rz_bv_copy_nbits_large_unaligned(void) {
	RzBitVector *a = rz_bv_new(128);
	RzBitVector *b = rz_bv_new(128);
	const char *error;

	rz_bv_set_all(a, true);

	/// copy different offset but same byte
	error = test_rz_bv_copy_nbits_against_ref(a, 5, b, 2, 20);
	mu_assert_null(error, error);

	/// copy different offset and different byte
	error = test_rz_bv_copy_nbits_against_ref(a, 10, b, 20, 10);
	mu_assert_null(error, error);

	/// copy at bit boundary
	error = test_rz_bv_copy_nbits_against_ref(a, 48, b, 1, 22);
	mu_assert_null(error, error);

	/// copy 1 bit
	error = test_rz_bv_copy_nbits_against_ref(a, 55, b, 13, 1);
	mu_assert_null(error, error);

	/// copy all except 1 bit
	error = test_rz_bv_copy_nbits_against_ref(a, 0, b, 1, 127);
	mu_assert_null(error, error);

	/// Copy bits within the same bitvector
	rz_bv_set_from_ut64(b, 0xAAAABBBBCCCCDDDD);
	ut32 actual_copy = rz_bv_copy_nbits(b, 2, b, 0, 30);
	mu_assert_eq(actual_copy, 30, "copy 30 bits");
	mu_assert_streq_free(rz_bv_as_hex_string(b, false), "0xaaaabbbb33337775", "copy large aligned");

	rz_bv_free(a);
	rz_bv_free(b);

	mu_end;
}

bool test_rz_bv_copy_nbits_large_to_small(void) {
	RzBitVector *a = rz_bv_new_from_ut64(128, 0x67452301);
	RzBitVector *b = rz_bv_new_from_ut64(64, 0x0);
	const char *error;

	/// copy aligned
	error = test_rz_bv_copy_nbits_against_ref(a, 8, b, 8, 16);
	mu_assert_null(error, error);

	/// copy unaligned
	error = test_rz_bv_copy_nbits_against_ref(a, 1, b, 0, 31);
	mu_assert_null(error, error);

	/// copy 1 unaligned bit
	error = test_rz_bv_copy_nbits_against_ref(a, 3, b, 5, 1);
	mu_assert_null(error, error);

	/// copy unaligned with dst start_bits > 0
	error = test_rz_bv_copy_nbits_against_ref(a, 0, b, 1, 31);
	mu_assert_null(error, error);

	/// copy different bit sizes from 8 to 64 bits
	for (ut8 size = 8; size <= 64; size += 8) {
		error = test_rz_bv_copy_nbits_against_ref(a, size - 1, b, 0, size);
		mu_assert_null(error, error);
	}

	rz_bv_free(a);
	rz_bv_free(b);
	mu_end;
}

bool test_rz_bv_copy_nbits_small_to_large(void) {
	RzBitVector *a = rz_bv_new_from_ut64(64, 0x67452301);
	RzBitVector *b = rz_bv_new_from_ut64(128, 0x0);
	const char *error;

	/// copy aligned
	error = test_rz_bv_copy_nbits_against_ref(a, 8, b, 8, 16);
	mu_assert_null(error, error);

	/// copy unaligned
	error = test_rz_bv_copy_nbits_against_ref(a, 1, b, 0, 31);
	mu_assert_null(error, error);

	/// copy 1 unaligned bit
	error = test_rz_bv_copy_nbits_against_ref(a, 3, b, 5, 1);
	mu_assert_null(error, error);

	/// copy unaligned with dst start_bits > 0
	error = test_rz_bv_copy_nbits_against_ref(a, 0, b, 1, 31);
	mu_assert_null(error, error);

	/// copy different bit sizes from 8 to 64 bits
	for (ut8 size = 8; size <= 64; size += 8) {
		error = test_rz_bv_copy_nbits_against_ref(a, 0, b, size - 1, size);
		mu_assert_null(error, error);
	}

	rz_bv_free(a);
	rz_bv_free(b);
	mu_end;
}

bool test_rz_bv_extra_operations(void) {
	// arithmetic rshift
	RzBitVector *bv1 = rz_bv_new_from_ut64(32, 73 * 16);
	rz_bv_arshift(bv1, 4);
	ut32 val1 = rz_bv_to_ut32(bv1);
	mu_assert_eq(73, val1, "test arshift for positive value");

	RzBitVector *bv2 = rz_bv_new_from_st64(32, -73 * 16);
	rz_bv_arshift(bv2, 4);
	st32 val2 = (st32)rz_bv_to_ut32(bv2);
	mu_assert_eq(-73, val2, "test arshift for negative value");

	rz_bv_free(bv1);
	rz_bv_free(bv2);

	// pred and succ
	RzBitVector *x = rz_bv_new_from_ut64(32, 'X');
	RzBitVector *pred_x = rz_bv_pred(x);
	RzBitVector *succ_x = rz_bv_succ(x);
	mu_assert_eq('W', rz_bv_to_ut32(pred_x), "test normal (pred x)");
	mu_assert_eq('Y', rz_bv_to_ut32(succ_x), "test normal (succ x)");

	RzBitVector *mo = rz_bv_new_minus_one(32);
	RzBitVector *pred_mo = rz_bv_pred(mo);
	RzBitVector *succ_mo = rz_bv_succ(mo);
	mu_assert_eq((ut32)(-2), rz_bv_to_ut32(pred_mo), "test (pred -1)");
	mu_assert_eq(0, rz_bv_to_ut32(succ_mo), "test (succ -1)");

	rz_bv_free(pred_x);
	rz_bv_free(succ_x);
	rz_bv_free(pred_mo);
	rz_bv_free(succ_mo);
	rz_bv_free(mo);

	// zero pred and succ
	// forward
	RzBitVector *zero = rz_bv_new_zero(32);
	RzBitVector *zero_pred = rz_bv_pred(zero);
	RzBitVector *zero_pp = rz_bv_pred(zero_pred);
	mu_assert_true(rz_bv_is_all_one(zero_pred), "pred 0 -> 0xffff...");
	mu_assert_eq((st32)rz_bv_to_ut32(zero_pp), -2, "pred -1 -> -2");
	// backward
	RzBitVector *n1 = rz_bv_new_minus_one(32);
	RzBitVector *n1_next = rz_bv_succ(n1);
	mu_assert_true(rz_bv_is_zero_vector(n1_next), "succ -1 -> 0");

	rz_bv_free(zero);
	rz_bv_free(zero_pred);
	rz_bv_free(zero_pp);
	rz_bv_free(n1);
	rz_bv_free(n1_next);

	// test compare
	RzBitVector *y = rz_bv_new_from_ut64(32, 'Y');
	RzBitVector *xx = rz_bv_new_from_ut64(32, 'X');
	mu_assert_true(rz_bv_ult(x, y), "test unsigned X < Y");
	mu_assert_true(rz_bv_ugt(y, x), "test unsigned Y > X");
	mu_assert_true(rz_bv_uge(y, x), "test unsigned Y >= X");
	mu_assert_true(rz_bv_uge(x, xx), "test unsigned X >= X");
	mu_assert_false(rz_bv_ult(y, x), "test unsigned Y < X is false");
	mu_assert_false(rz_bv_ugt(x, y), "test unsgined X > Y is false");
	mu_assert_false(rz_bv_uge(x, y), "test unsigned X >= Y is false");
	mu_assert_false(rz_bv_ult(x, xx), "test unsigned X < X is false");
	mu_assert_false(rz_bv_ugt(x, xx), "test unsigned X > X is false");

	RzBitVector *ny = rz_bv_new_from_ut64(32, -'Y');
	RzBitVector *nx = rz_bv_new_from_ut64(32, -'X');
	mu_assert_true(rz_bv_ult(ny, nx), "test signed -Y < -X");
	mu_assert_true(rz_bv_ugt(nx, ny), "test unsigned -Y < -X");
	mu_assert_true(rz_bv_uge(nx, ny), "test unsigned -X >= -Y");
	mu_assert_false(rz_bv_ult(nx, ny), "test unsigned -X < -Y is false");
	mu_assert_false(rz_bv_ugt(ny, nx), "test unsgined -X < -Y is false");
	mu_assert_false(rz_bv_uge(ny, nx), "test unsigned -X <= -Y is false");

	mu_assert_false(rz_bv_slt(nx, nx), "test signed -X > -X is false");
	mu_assert_false(rz_bv_sgt(nx, nx), "test signed -X < -X is false");
	mu_assert_true(rz_bv_sge(nx, nx), "test signed -X >= -X");
	mu_assert_true(rz_bv_sge(nx, ny), "test signed -X >= -Y");

	mu_assert_true(rz_bv_sge(x, nx), "test signed X >= -X");
	mu_assert_true(rz_bv_sgt(x, nx), "test signed X > -X");
	mu_assert_true(rz_bv_slt(nx, x), "test signed -X < X");
	mu_assert_true(rz_bv_ult(x, nx), "test unsigned X < -X");
	mu_assert_true(rz_bv_ugt(nx, x), "test unsigned -X > X");

	rz_bv_free(x);
	rz_bv_free(y);
	rz_bv_free(xx);
	rz_bv_free(nx);
	rz_bv_free(ny);
	mu_end;
}

bool test_rz_bv_hash(void) {
	RzBitVector *bv_small_1 = rz_bv_new_from_ut64(32, 1);
	RzBitVector *bv_small_2 = rz_bv_new_from_ut64(32, 1);
	RzBitVector *bv_large_1 = rz_bv_new_from_ut64(128, 2);
	RzBitVector *bv_large_2 = rz_bv_new_from_ut64(128, 2);
	mu_assert_eq(rz_bv_hash(bv_small_1), rz_bv_hash(bv_small_2), "Non repeatable hashing small");
	mu_assert_eq(rz_bv_hash(bv_large_1), rz_bv_hash(bv_large_2), "Non repeatable hashing large");
	mu_assert_neq(rz_bv_hash(bv_small_1), rz_bv_hash(bv_large_1), "Size doesn't affect hash but should");
	mu_assert_neq(rz_bv_hash(bv_small_2), rz_bv_hash(bv_large_2), "Size doesn't affect hash but should");
	rz_bv_free(bv_small_1);
	rz_bv_free(bv_small_2);
	rz_bv_free(bv_large_1);
	rz_bv_free(bv_large_2);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_bv_init32);
	mu_run_test(test_rz_bv_init64);
	mu_run_test(test_rz_bv_init128);
	mu_run_test(test_rz_bv_init70);
	mu_run_test(test_rz_bv_init_signed);
	mu_run_test(test_rz_bv_cmp);
	mu_run_test(test_rz_bv_eq);
	mu_run_test(test_rz_bv_cast);
	mu_run_test(test_rz_bv_operation);
	mu_run_test(test_rz_bv_logic);
	mu_run_test(test_rz_bv_logic_large);
	mu_run_test(test_rz_bv_algorithm32);
	mu_run_test(test_rz_bv_algorithm128);
	mu_run_test(test_rz_bv_add);
	mu_run_test(test_rz_bv_set_from_bytes_le);
	mu_run_test(test_rz_bv_set_from_bytes_be);
	mu_run_test(test_rz_bv_set_from_buffer_ble, true);
	mu_run_test(test_rz_bv_set_from_buffer_ble, false);
	mu_run_test(test_rz_bv_as_hex_string);
	mu_run_test(test_rz_bv_clz);
	mu_run_test(test_rz_bv_ctz);
	mu_run_test(test_rz_bv_div);
	mu_run_test(test_rz_bv_mod);
	mu_run_test(test_rz_bv_len_bytes);
	mu_run_test(test_rz_bv_set_operations);
	mu_run_test(test_rz_bv_set_range_large);
	mu_run_test(test_rz_bv_set_to_bytes_le);
	mu_run_test(test_rz_bv_copy_nbits);
	mu_run_test(test_rz_bv_copy_nbits_small);
	mu_run_test(test_rz_bv_copy_nbits_large_aligned);
	mu_run_test(test_rz_bv_copy_nbits_large_unaligned);
	mu_run_test(test_rz_bv_copy_nbits_small_to_large);
	mu_run_test(test_rz_bv_copy_nbits_large_to_small);
	mu_run_test(test_rz_bv_copy_nbits_inplace);
	mu_run_test(test_rz_bv_cast_inplace);
	mu_run_test(test_rz_bv_extra_operations);
	mu_run_test(test_rz_bv_hash);

	return tests_passed != tests_run;
}

mu_main(all_tests)
