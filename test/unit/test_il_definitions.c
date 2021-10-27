// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool is_equal_bv(RzILBitVector *x, RzILBitVector *y) {
	return rz_il_bv_cmp(x, y) == 0;
}

static bool is_equal_bool(RzILBool *x, RzILBool *y) {
	return x->b == y->b;
}

bool test_rzil_bv_init(void) {
	char *s = NULL;
	// create a zero vector
	RzILBitVector *bits_42 = rz_il_bv_new(42);
	mu_assert("init 42-bits vector", bits_42 && (bits_42->len == 42));

	// create by given ut32
	RzILBitVector *bits_32 = rz_il_bv_new_from_ut32(32, 100);
	RzILBitVector *bits_cmp = rz_il_bv_new(32);

	// 100 = 64 + 32 + 4 == 0b 0000 0000 0000 0000 0000 0000 0110 0100
	rz_il_bv_set(bits_cmp, 2, true);
	rz_il_bv_set(bits_cmp, 5, true);
	rz_il_bv_set(bits_cmp, 6, true);
	mu_assert("new from ut32", is_equal_bv(bits_32, bits_cmp));

	// dup
	RzILBitVector *bits_32_dump = rz_il_bv_dup(bits_32);
	mu_assert("dump from bits32", is_equal_bv(bits_32_dump, bits_32));

	s = rz_il_bv_as_string(bits_32);
	mu_assert_streq_free(s, "00000000000000000000000001100100", "string bit value of bv");

	s = rz_il_bv_as_hex_string(bits_32);
	mu_assert_streq_free(s, "0x00000064", "string hex value of bv");

	rz_il_bv_free(bits_42);
	rz_il_bv_free(bits_32);
	rz_il_bv_free(bits_cmp);
	rz_il_bv_free(bits_32_dump);
	mu_end;
}

bool test_rzil_bv_logic(void) {
	RzILBitVector *x, *y;
	RzILBitVector *result;
	RzILBitVector *and, * or, *xor, *neg, *not, *ls, *rs, *ls_fill, *rs_fill;

	// x : 0101 0101
	x = rz_il_bv_new(8);
	rz_il_bv_set(x, 0, true);
	rz_il_bv_set(x, 2, true);
	rz_il_bv_set(x, 4, true);
	rz_il_bv_set(x, 6, true);

	// y : 1010 1001
	y = rz_il_bv_new(8);
	rz_il_bv_set(y, 0, true);
	rz_il_bv_set(y, 3, true);
	rz_il_bv_set(y, 5, true);
	rz_il_bv_set(y, 7, true);

	// and : 0000 0001
	and = rz_il_bv_new(8);
	rz_il_bv_set(and, 0, true);

	// xor : 1111 1100
	xor = rz_il_bv_new(8);
	rz_il_bv_toggle_all(xor);
	rz_il_bv_set(xor, 0, false);
	rz_il_bv_set(xor, 1, false);

	// or : 1111 1101
	or = rz_il_bv_new(8);
	rz_il_bv_toggle_all(or);
	rz_il_bv_set(or, 1, false);

	// not of x : 1010 1010
	not = rz_il_bv_new(8);
	rz_il_bv_set(not, 1, true);
	rz_il_bv_set(not, 3, true);
	rz_il_bv_set(not, 5, true);
	rz_il_bv_set(not, 7, true);

	// neg of x : 1010 1011
	neg = rz_il_bv_new(8);
	rz_il_bv_set(neg, 0, true);
	rz_il_bv_set(neg, 1, true);
	rz_il_bv_set(neg, 3, true);
	rz_il_bv_set(neg, 5, true);
	rz_il_bv_set(neg, 7, true);

	// left shift (3 bits) of y : 0100 1000
	ls = rz_il_bv_new(8);
	rz_il_bv_set(ls, 3, true);
	rz_il_bv_set(ls, 6, true);

	// left shift (3 bits) of y : 0100 1111
	ls_fill = rz_il_bv_new(8);
	rz_il_bv_set(ls_fill, 0, true);
	rz_il_bv_set(ls_fill, 1, true);
	rz_il_bv_set(ls_fill, 2, true);
	rz_il_bv_set(ls_fill, 3, true);
	rz_il_bv_set(ls_fill, 6, true);

	// right shift (3 bits) of y : 0001 0101
	rs = rz_il_bv_new(8);
	rz_il_bv_set(rs, 0, true);
	rz_il_bv_set(rs, 2, true);
	rz_il_bv_set(rs, 4, true);

	// right shift (3 bits) of y : 1111 0101
	rs_fill = rz_il_bv_new(8);
	rz_il_bv_toggle_all(rs_fill);
	rz_il_bv_set(rs_fill, 1, false);
	rz_il_bv_set(rs_fill, 3, false);

	// test and
	result = rz_il_bv_and(x, y);
	mu_assert("and x y", is_equal_bv(result, and));
	rz_il_bv_free(result);
	rz_il_bv_free(and);

	result = rz_il_bv_or(x, y);
	mu_assert("or x y", is_equal_bv(result, or));
	rz_il_bv_free(result);
	rz_il_bv_free(or);

	result = rz_il_bv_xor(x, y);
	mu_assert("xor x y", is_equal_bv(result, xor));
	rz_il_bv_free(result);
	rz_il_bv_free(xor);

	result = rz_il_bv_not(x);
	mu_assert("not x", is_equal_bv(result, not ));
	rz_il_bv_free(result);
	rz_il_bv_free(not );

	result = rz_il_bv_neg(x);
	mu_assert("neg x", is_equal_bv(result, neg));
	rz_il_bv_free(result);
	rz_il_bv_free(neg);

	result = rz_il_bv_dup(y);
	rz_il_bv_lshift(result, 3);
	mu_assert("left shift y", is_equal_bv(result, ls));
	rz_il_bv_free(result);
	rz_il_bv_free(ls);

	result = rz_il_bv_dup(y);
	rz_il_bv_lshift_fill(result, 3, true);
	mu_assert("left shift y filling 1", is_equal_bv(result, ls_fill));
	rz_il_bv_free(result);
	rz_il_bv_free(ls_fill);

	result = rz_il_bv_dup(y);
	rz_il_bv_rshift(result, 3);
	mu_assert("right shift y", is_equal_bv(result, rs));
	rz_il_bv_free(result);
	rz_il_bv_free(rs);

	result = rz_il_bv_dup(y);
	rz_il_bv_rshift_fill(result, 3, true);
	mu_assert("right shift y", is_equal_bv(result, rs_fill));
	rz_il_bv_free(result);
	rz_il_bv_free(rs_fill);

	rz_il_bv_free(x);
	rz_il_bv_free(y);
	mu_end;
}

bool test_rzil_bv_algorithm(void) {
	RzILBitVector *x, *y;
	RzILBitVector *result;
	RzILBitVector *add, *sub, *mul, *div, *mod;
	x = rz_il_bv_new_from_ut32(32, 121);
	y = rz_il_bv_new_from_ut32(32, 33);

	add = rz_il_bv_new_from_ut32(32, 154);
	sub = rz_il_bv_new_from_ut32(32, 121 - 33);
	div = rz_il_bv_new_from_ut32(32, 121 / 33);
	mul = rz_il_bv_new_from_ut32(32, 121 * 33);
	mod = rz_il_bv_new_from_ut32(32, 121 % 33);

	result = rz_il_bv_add(x, y);
	mu_assert("Add x y", rz_il_bv_cmp(result, add) == 0);
	rz_il_bv_free(result);

	result = rz_il_bv_sub(x, y);
	mu_assert("Sub x y", rz_il_bv_cmp(result, sub) == 0);
	rz_il_bv_free(result);

	result = rz_il_bv_mul(x, y);
	mu_assert("Mul x y", rz_il_bv_cmp(result, mul) == 0);
	rz_il_bv_free(result);

	result = rz_il_bv_div(x, y);
	printf("\n");
	mu_assert("Div x y", rz_il_bv_cmp(result, div) == 0);
	rz_il_bv_free(result);

	result = rz_il_bv_mod(x, y);
	mu_assert("Mod x y", rz_il_bv_cmp(result, mod) == 0);
	rz_il_bv_free(result);

	rz_il_bv_free(x);
	rz_il_bv_free(y);
	rz_il_bv_free(add);
	rz_il_bv_free(sub);
	rz_il_bv_free(div);
	rz_il_bv_free(mul);
	rz_il_bv_free(mod);
	mu_end;
}

bool test_rzil_bv_cmp(void) {
	RzILBitVector *x, *y;

	// x : 1000 0111, y : 0000 0111
	x = rz_il_bv_new(8);
	rz_il_bv_set(x, 0, true);
	rz_il_bv_set(x, 1, true);
	rz_il_bv_set(x, 2, true);
	rz_il_bv_set(x, 7, true);

	y = rz_il_bv_new(8);
	rz_il_bv_set(y, 0, true);
	rz_il_bv_set(y, 1, true);
	rz_il_bv_set(y, 2, true);

	// get msb and lsb of y
	bool msb, lsb;
	msb = rz_il_bv_msb(y);
	lsb = rz_il_bv_lsb(y);

	mu_assert("msb", msb == false);
	mu_assert("lsb", lsb == true);

	mu_assert("Unsigned : x > y", !rz_il_bv_ule(x, y));
	mu_assert("Signed : x < y", rz_il_bv_sle(x, y));

	rz_il_bv_free(x);
	rz_il_bv_free(y);

	mu_end;
}

bool test_rzil_bv_operation(void) {
	RzILBitVector *x, *y, *res, *prep, *append, *cut_h, *cut_t, *concat;

	// 0000 1000
	x = rz_il_bv_new(8);
	rz_il_bv_set(x, 3, true);

	// prepend 3 : 000 0000 1000
	prep = rz_il_bv_new(11);
	rz_il_bv_set(prep, 3, true);

	// append 5 : 0000 1000 0000 0
	append = rz_il_bv_new(13);
	rz_il_bv_set(append, 8, true);

	// cut head 2: 00 1000
	cut_h = rz_il_bv_new(6);
	rz_il_bv_set(cut_h, 3, true);

	// cut tail 4: 0000
	cut_t = rz_il_bv_new(4);

	// y : 1011
	y = rz_il_bv_new(4);
	rz_il_bv_set(y, 0, true);
	rz_il_bv_set(y, 1, true);
	rz_il_bv_set(y, 3, true);
	concat = rz_il_bv_new(12);
	rz_il_bv_set(concat, 0, true);
	rz_il_bv_set(concat, 1, true);
	rz_il_bv_set(concat, 3, true);
	rz_il_bv_set(concat, 7, true);

	res = rz_il_bv_prepend_zero(x, 3);
	mu_assert("prepend 3 zero", is_equal_bv(res, prep));
	rz_il_bv_free(res);

	res = rz_il_bv_append_zero(x, 5);
	mu_assert("append 5 zero", is_equal_bv(res, append));
	rz_il_bv_free(res);

	res = rz_il_bv_cut_head(x, 2);
	mu_assert("cut head 2 zero", is_equal_bv(res, cut_h));
	rz_il_bv_free(res);

	res = rz_il_bv_cut_tail(x, 4);
	mu_assert("cut tail 4 zero", is_equal_bv(res, cut_t));
	rz_il_bv_free(res);

	res = rz_il_bv_concat(x, y);
	mu_assert("concat x and y", is_equal_bv(res, concat));
	rz_il_bv_free(res);

	rz_il_bv_free(prep);
	rz_il_bv_free(append);
	rz_il_bv_free(cut_h);
	rz_il_bv_free(cut_t);
	rz_il_bv_free(concat);
	rz_il_bv_free(x);
	rz_il_bv_free(y);

	mu_end;
}

bool test_rzil_bv_cast(void) {
	ut32 normal, shadow;
	normal = 2021;
	RzILBitVector *bv = rz_il_bv_new_from_ut32(32, normal);
	shadow = rz_il_bv_to_ut32(bv);
	rz_il_bv_free(bv);

	mu_assert("cast bv<->ut32", normal == shadow);
	mu_end;
}

bool test_rzil_bool_init(void) {
	RzILBool *b = rz_il_bool_new(true);
	mu_assert_notnull(b, "New RzILBool");
	mu_assert_eq(b->b, true, "bool is true");
	rz_il_bool_free(b);
	mu_end;
}

bool test_rzil_bool_logic(void) {
	RzILBool *t = rz_il_bool_new(true);
	RzILBool *f = rz_il_bool_new(false);
	RzILBool *result;

	// and
	// t and t => true
	// f and f => false
	// t and f => false
	result = rz_il_bool_and(t, t);
	mu_assert("true and true", is_equal_bool(result, t));
	rz_il_bool_free(result);

	result = rz_il_bool_and(t, f);
	mu_assert("true and false", is_equal_bool(result, f));
	rz_il_bool_free(result);

	result = rz_il_bool_and(f, f);
	mu_assert("false and false", is_equal_bool(result, f));
	rz_il_bool_free(result);

	// or
	// t or t => true
	// t or f => true
	// f or f => false
	result = rz_il_bool_or(t, t);
	mu_assert("true or true", is_equal_bool(result, t));
	rz_il_bool_free(result);

	result = rz_il_bool_or(t, f);
	mu_assert("true or false", is_equal_bool(result, t));
	rz_il_bool_free(result);

	result = rz_il_bool_or(f, f);
	mu_assert("false or false", is_equal_bool(result, f));
	rz_il_bool_free(result);

	// not
	// not t => false
	// not f => true
	result = rz_il_bool_not(t);
	mu_assert("not true", is_equal_bool(result, f));
	rz_il_bool_free(result);

	result = rz_il_bool_not(f);
	mu_assert("not false", is_equal_bool(result, t));
	rz_il_bool_free(result);

	// xor
	// t xor t => false
	// f xor f => false
	// t xor f => true
	result = rz_il_bool_xor(t, t);
	mu_assert("t xor t", is_equal_bool(result, f));
	rz_il_bool_free(result);

	result = rz_il_bool_xor(f, f);
	mu_assert("f xor f", is_equal_bool(result, f));
	rz_il_bool_free(result);

	result = rz_il_bool_xor(t, f);
	mu_assert("t xor f", is_equal_bool(result, t));
	rz_il_bool_free(result);

	rz_il_bool_free(t);
	rz_il_bool_free(f);
	mu_end;
}

static bool test_rzil_mem() {
	RzILMem *mem = rz_il_mem_new(8);
	mu_assert_notnull(mem, "Create mem");

	RzILBitVector *addr = rz_il_bv_new_from_ut32(16, 121);
	RzILBitVector *valid_data = rz_il_bv_new_from_ut32(8, 177);
	RzILBitVector *invalid_data = rz_il_bv_new_from_ut32(24, 177);

	RzILMem *result = rz_il_mem_store(mem, addr, valid_data);
	mu_assert_eq(result, mem, "Store successfully");

	result = rz_il_mem_store(mem, addr, invalid_data);
	mu_assert_null(result, "Unmatched type");

	RzILBitVector *data = rz_il_mem_load(mem, addr);
	mu_assert("Load correct data", is_equal_bv(data, valid_data));
	rz_il_bv_free(data);

	rz_il_bv_free(valid_data);
	rz_il_bv_free(invalid_data);
	rz_il_bv_free(addr);
	rz_il_mem_free(mem);

	mu_end;
}

static bool test_rzil_effect() {
	RzILEffect *general_effect = rz_il_effect_new(EFFECT_TYPE_NON);
	mu_assert_notnull(general_effect, "Create Empty General Effect");

	mu_assert_eq(general_effect->effect_type, EFFECT_TYPE_NON, "Empty effect has correct type");
	mu_assert_null(general_effect->next_eff, "Empty doesn't have next effect");
	mu_assert_null(general_effect->ctrl_eff, "Empty doesn't include control effect");
	mu_assert_null(general_effect->data_eff, "Empty doesn't include data effect");
	rz_il_effect_free(general_effect);

	RzILCtrlEffect *c_eff = rz_il_effect_ctrl_new();
	mu_assert_notnull(c_eff, "Create empty control effect");
	mu_assert_null(c_eff->pc, "Empty control effect have no next pc info");

	RzILDataEffect *d_eff = rz_il_effect_data_new();
	mu_assert_notnull(d_eff, "Create empty data effect");
	mu_assert_null(d_eff->var_name, "Empty data effect doesn't have variable name");

	RzILEffect *data_effect, *contrl_effect;
	// wrap data effect
	data_effect = rz_il_wrap_data_effect(d_eff);
	mu_assert_eq(data_effect->effect_type, EFFECT_TYPE_DATA, "Wrap data effect");
	mu_assert_eq(data_effect->data_eff, d_eff, "Get data effect from general one");
	rz_il_effect_free(data_effect);

	contrl_effect = rz_il_wrap_ctrl_effect(c_eff);
	mu_assert_eq(contrl_effect->effect_type, EFFECT_TYPE_CTRL, "Wrap control effect");
	mu_assert_eq(contrl_effect->ctrl_eff, c_eff, "Get control effect from general one");
	rz_il_effect_free(contrl_effect);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rzil_bv_init);
	mu_run_test(test_rzil_bv_cmp);
	mu_run_test(test_rzil_bv_cast);
	mu_run_test(test_rzil_bv_operation);
	mu_run_test(test_rzil_bv_logic);
	mu_run_test(test_rzil_bv_algorithm);

	mu_run_test(test_rzil_bool_init);
	mu_run_test(test_rzil_bool_logic);

	mu_run_test(test_rzil_mem);
	mu_run_test(test_rzil_effect);
	return tests_passed != tests_run;
}

mu_main(all_tests)