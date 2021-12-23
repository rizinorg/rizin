// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

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

static bool test_rzil_mem_load() {
	ut8 data[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x42, 0x0, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	RzILMem *mem = rz_il_mem_new(buf, 16);
	mu_assert_notnull(mem, "Create mem");

	// valid read
	RzBitVector *addr = rz_bv_new_from_ut64(16, 5);
	RzBitVector *val = rz_il_mem_load(mem, addr);
	mu_assert_notnull(val, "load success");
	mu_assert_eq(rz_bv_len(val), 8, "load size");
	mu_assert_eq(rz_bv_to_ut64(val), 0x42, "load val");
	rz_bv_free(val);
	rz_bv_free(addr);

	// invalid key size
	addr = rz_bv_new_from_ut64(8, 1);
	val = rz_il_mem_load(mem, addr);
	mu_assert_null(val, "invalid key size");
	rz_bv_free(addr);

	// valid read (overflow)
	addr = rz_bv_new_from_ut64(16, 100);
	val = rz_il_mem_load(mem, addr);
	mu_assert_notnull(val, "load success");
	mu_assert_eq(rz_bv_len(val), 8, "load size");
	mu_assert_eq(rz_bv_to_ut64(val), 0xaa, "load val");
	rz_bv_free(val);

	rz_bv_free(addr);
	rz_il_mem_free(mem);
	mu_end;
}

static bool test_rzil_mem_store() {
	ut8 data[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x42, 0x0, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	RzILMem *mem = rz_il_mem_new(buf, 16);
	mu_assert_notnull(mem, "Create mem");

	RzBitVector *addr = rz_bv_new_from_ut64(16, 1);

	// valid write
	RzBitVector *val = rz_bv_new_from_ut64(8, 177);
	bool succ = rz_il_mem_store(mem, addr, val);
	rz_bv_free(val);
	mu_assert_true(succ, "Store successfully");
	const ut8 expect0[] = { 0x0, 177, 0x0, 0x0, 0x0, 0x42, 0x0, 0x0 };
	mu_assert_memeq(data, expect0, sizeof(expect0), "stored");

	// invalid data size
	val = rz_bv_new_from_ut64(4, 2);
	succ = rz_il_mem_store(mem, addr, val);
	rz_bv_free(val);
	mu_assert_false(succ, "Unmatched value type");
	mu_assert_memeq(data, expect0, sizeof(expect0), "not stored");

	// invalid key size
	rz_bv_free(addr);
	addr = rz_bv_new_from_ut64(8, 1);
	val = rz_bv_new_from_ut64(8, 177);
	succ = rz_il_mem_store(mem, addr, val);
	rz_bv_free(val);
	mu_assert_false(succ, "invalid key size");
	mu_assert_memeq(data, expect0, sizeof(expect0), "not stored");

	rz_bv_free(addr);
	rz_il_mem_free(mem);
	mu_end;
}

static bool test_rzil_mem_loadw() {
	ut8 data[] = { 0x0, 0x0, 0x0, 0x0, 0x13, 0x37, 0x0, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	RzILMem *mem = rz_il_mem_new(buf, 16);
	mu_assert_notnull(mem, "Create mem");

	// valid read (le)
	RzBitVector *addr = rz_bv_new_from_ut64(16, 4);
	RzBitVector *val = rz_il_mem_loadw(mem, addr, 16, false);
	mu_assert_notnull(val, "loadw success");
	mu_assert_eq(rz_bv_len(val), 16, "loadw size");
	mu_assert_eq(rz_bv_to_ut64(val), 0x3713, "loadw val");
	rz_bv_free(val);

	// valid read (be)
	val = rz_il_mem_loadw(mem, addr, 16, true);
	mu_assert_notnull(val, "loadw success");
	mu_assert_eq(rz_bv_len(val), 16, "loadw size");
	mu_assert_eq(rz_bv_to_ut64(val), 0x1337, "loadw val");
	rz_bv_free(val);

	// invalid key size
	rz_bv_free(addr);
	addr = rz_bv_new_from_ut64(8, 1);
	val = rz_il_mem_loadw(mem, addr, 16, false);
	mu_assert_null(val, "invalid key size");

	// valid read (overflow)
	addr = rz_bv_new_from_ut64(16, 100);
	val = rz_il_mem_loadw(mem, addr, 16, false);
	mu_assert_notnull(val, "load success");
	mu_assert_eq(rz_bv_len(val), 16, "load size");
	mu_assert_eq(rz_bv_to_ut64(val), 0xaaaa, "load val");
	rz_bv_free(val);

	rz_bv_free(addr);
	rz_il_mem_free(mem);
	mu_end;
}

static bool test_rzil_mem_storew() {
	ut8 data[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	RzILMem *mem = rz_il_mem_new(buf, 32);
	mu_assert_notnull(mem, "Create mem");

	// valid write (le)
	RzBitVector *addr = rz_bv_new_from_ut64(32, 4);
	RzBitVector *val = rz_bv_new_from_ut64(16, 0x1337);
	bool succ = rz_il_mem_storew(mem, addr, val, false);
	rz_bv_free(addr);
	mu_assert_true(succ, "storew success");
	const ut8 expect0[] = { 0x0, 0x0, 0x0, 0x0, 0x37, 0x13, 0x0, 0x0 };
	mu_assert_memeq(data, expect0, sizeof(expect0), "stored");

	// valid write (be)
	addr = rz_bv_new_from_ut64(32, 2);
	succ = rz_il_mem_storew(mem, addr, val, true);
	mu_assert_true(succ, "storew success");
	const ut8 expect1[] = { 0x0, 0x0, 0x13, 0x37, 0x37, 0x13, 0x0, 0x0 };
	mu_assert_memeq(data, expect1, sizeof(expect1), "stored");
	rz_bv_free(val);
	rz_bv_free(addr);

	// invalid key size
	addr = rz_bv_new_from_ut64(8, 1);
	val = rz_il_mem_load(mem, addr);
	mu_assert_null(val, "invalid key size");
	mu_assert_memeq(data, expect1, sizeof(expect1), "not stored");
	rz_bv_free(addr);

	rz_il_mem_free(mem);
	mu_end;
}


bool all_tests() {
	mu_run_test(test_rzil_bool_init);
	mu_run_test(test_rzil_bool_logic);
	mu_run_test(test_rzil_mem_load);
	mu_run_test(test_rzil_mem_store);
	mu_run_test(test_rzil_mem_loadw);
	mu_run_test(test_rzil_mem_storew);
	return tests_passed != tests_run;
}

mu_main(all_tests)
