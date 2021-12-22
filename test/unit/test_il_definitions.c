// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool is_equal_bv(RzBitVector *x, RzBitVector *y) {
	return rz_bv_cmp(x, y) == 0;
}

static bool is_equal_bool(RzILBool *x, RzILBool *y) {
	return x->b == y->b;
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

	RzBitVector *addr = rz_bv_new_from_ut64(16, 121);
	RzBitVector *valid_data = rz_bv_new_from_ut64(8, 177);
	RzBitVector *invalid_data = rz_bv_new_from_ut64(4, 6);

	RzILMem *result = rz_il_mem_store(mem, addr, valid_data);
	mu_assert_eq(result, mem, "Store successfully");

	result = rz_il_mem_store(mem, addr, invalid_data);
	mu_assert_null(result, "Unmatched type");

	RzBitVector *data = rz_il_mem_load(mem, addr);
	mu_assert("Load correct data", is_equal_bv(data, valid_data));
	rz_bv_free(data);

	rz_bv_free(valid_data);
	rz_bv_free(invalid_data);
	rz_bv_free(addr);
	rz_il_mem_free(mem);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rzil_bool_init);
	mu_run_test(test_rzil_bool_logic);

	mu_run_test(test_rzil_mem);
	return tests_passed != tests_run;
}

mu_main(all_tests)
