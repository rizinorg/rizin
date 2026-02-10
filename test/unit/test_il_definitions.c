// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool is_equal_bool(RzILBool *x, RzILBool *y) {
	return x->b == y->b;
}

bool test_il_bool_init(void) {
	RzILBool *b = rz_il_bool_new(true);
	mu_assert_notnull(b, "New RzILBool");
	mu_assert_eq(b->b, true, "bool is true");
	rz_il_bool_free(b);
	mu_end;
}

bool test_il_bool_logic(void) {
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

static bool test_il_mem_load() {
	ut8 data[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x42, 0x0, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	RzILMem *mem = rz_il_mem_new_owned(buf, 16);
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

static bool test_il_mem_store() {
	ut8 data[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x42, 0x0, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	RzILMem *mem = rz_il_mem_new_owned(buf, 16);
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

static bool test_il_mem_loadw() {
	ut8 data[] = { 0x0, 0x0, 0x0, 0x0, 0x13, 0x37, 0x0, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	rz_buf_set_overflow_byte(buf, 0xaa);
	RzILMem *mem = rz_il_mem_new_owned(buf, 16);
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
	rz_bv_free(addr);

	// invalid key size
	addr = rz_bv_new_from_ut64(8, 1);
	val = rz_il_mem_loadw(mem, addr, 16, false);
	rz_bv_free(addr);
	mu_assert_null(val, "invalid key size");
	rz_bv_free(val);

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

static bool test_il_mem_storew() {
	ut8 data[] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	RzBuffer *buf = rz_buf_new_with_pointers(data, sizeof(data), false);
	RzILMem *mem = rz_il_mem_new_owned(buf, 32);
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

static bool test_il_seqn() {
	// n = 0 ==> just a nop
	RzILOpEffect *s = rz_il_op_new_seqn(0);
	mu_assert_notnull(s, "seqn 0");
	mu_assert_eq(s->code, RZ_IL_OP_NOP, "seqn 0 nop");
	rz_il_op_effect_free(s);

	// n = 1 ==> just the op
	RzILOpEffect *e0 = rz_il_op_new_goto("beach");
	s = rz_il_op_new_seqn(1, e0);
	mu_assert_notnull(s, "seqn 1");
	mu_assert_ptreq(s, e0, "seqn 1 op");
	rz_il_op_effect_free(s);

	// n = 2 ==> single seq
	// (seq e0 e1)
	e0 = rz_il_op_new_goto("beach");
	RzILOpEffect *e1 = rz_il_op_new_goto("beach2");
	s = rz_il_op_new_seqn(2, e0, e1);
	mu_assert_notnull(s, "seqn 2");
	mu_assert_eq(s->code, RZ_IL_OP_SEQ, "seqn 2 seq");
	mu_assert_ptreq(s->op.seq.x, e0, "seqn 2 first");
	mu_assert_ptreq(s->op.seq.y, e1, "seqn 2 second");
	rz_il_op_effect_free(s);

	// n = 3 ==> nested seq with recursion in the second op:
	// (seq e0 (seq e1 e2))
	e0 = rz_il_op_new_goto("beach");
	e1 = rz_il_op_new_goto("beach2");
	RzILOpEffect *e2 = rz_il_op_new_goto("beach3");
	s = rz_il_op_new_seqn(3, e0, e1, e2);
	mu_assert_notnull(s, "seqn 3");
	mu_assert_eq(s->code, RZ_IL_OP_SEQ, "seqn 3 seq");
	mu_assert_ptreq(s->op.seq.x, e0, "seqn 3 first");
	mu_assert_eq(s->op.seq.y->code, RZ_IL_OP_SEQ, "seqn 3 second seq");
	mu_assert_ptreq(s->op.seq.y->op.seq.x, e1, "seqn 3 second");
	mu_assert_ptreq(s->op.seq.y->op.seq.y, e2, "seqn 3 third");
	rz_il_op_effect_free(s);

	// n = 4 ==> nested seq with recursion in the second op and no confusion:
	// (seq e0 (seq e1 (seq e2 e3)))
	e0 = rz_il_op_new_goto("beach");
	e1 = rz_il_op_new_goto("beach2");
	e2 = rz_il_op_new_goto("beach3");
	RzILOpEffect *e3 = rz_il_op_new_goto("beach3");
	s = rz_il_op_new_seqn(4, e0, e1, e2, e3);
	mu_assert_notnull(s, "seqn 4");
	mu_assert_eq(s->code, RZ_IL_OP_SEQ, "seqn 4 seq");
	mu_assert_ptreq(s->op.seq.x, e0, "seqn 4 first");
	mu_assert_eq(s->op.seq.y->code, RZ_IL_OP_SEQ, "seqn 4 second seq");
	mu_assert_ptreq(s->op.seq.y->op.seq.x, e1, "seqn 4 second");
	mu_assert_eq(s->op.seq.y->op.seq.y->code, RZ_IL_OP_SEQ, "seqn 4 third seq");
	mu_assert_ptreq(s->op.seq.y->op.seq.y->op.seq.x, e2, "seqn 4 third");
	mu_assert_ptreq(s->op.seq.y->op.seq.y->op.seq.y, e3, "seqn 4 fourth");
	rz_il_op_effect_free(s);

	mu_end;
}

static bool test_il_sort_pure_eq() {
	bool r = rz_il_sort_pure_eq(rz_il_sort_pure_bool(), rz_il_sort_pure_bool());
	mu_assert_true(r, "sort eq");
	r = rz_il_sort_pure_eq(rz_il_sort_pure_bv(32), rz_il_sort_pure_bv(32));
	mu_assert_true(r, "sort eq");
	r = rz_il_sort_pure_eq(rz_il_sort_pure_bv(32), rz_il_sort_pure_bv(31));
	mu_assert_false(r, "sort eq");
	r = rz_il_sort_pure_eq(rz_il_sort_pure_bool(), rz_il_sort_pure_bv(32));
	mu_assert_false(r, "sort eq");
	r = rz_il_sort_pure_eq(rz_il_sort_pure_bv(32), rz_il_sort_pure_bool());
	mu_assert_false(r, "sort eq");
	mu_end;
}

static bool test_il_value_eq() {
	RzILVal *b0 = rz_il_value_new_bool(rz_il_bool_new(false));
	RzILVal *b0_dup = rz_il_value_new_bool(rz_il_bool_new(false));
	RzILVal *b1 = rz_il_value_new_bool(rz_il_bool_new(true));
	RzILVal *bv16_42 = rz_il_value_new_bitv(rz_bv_new_from_ut64(16, 42));
	RzILVal *bv16_42_dup = rz_il_value_new_bitv(rz_bv_new_from_ut64(16, 42));
	RzILVal *bv16_43 = rz_il_value_new_bitv(rz_bv_new_from_ut64(16, 43));
	RzILVal *bv8_42 = rz_il_value_new_bitv(rz_bv_new_from_ut64(8, 42));

	mu_assert_true(rz_il_value_eq(b0, b0), "eq");
	mu_assert_true(rz_il_value_eq(b0, b0_dup), "eq");
	mu_assert_true(rz_il_value_eq(bv16_42, bv16_42), "eq");
	mu_assert_true(rz_il_value_eq(bv16_42, bv16_42_dup), "eq");

	mu_assert_false(rz_il_value_eq(b0, b1), "not eq");
	mu_assert_false(rz_il_value_eq(b0, bv16_42), "not eq");
	mu_assert_false(rz_il_value_eq(bv16_42, bv16_43), "not eq");
	mu_assert_false(rz_il_value_eq(bv16_42, bv8_42), "not eq");

	rz_il_value_free(b0);
	rz_il_value_free(b0_dup);
	rz_il_value_free(b1);
	rz_il_value_free(bv16_42);
	rz_il_value_free(bv16_42_dup);
	rz_il_value_free(bv16_43);
	rz_il_value_free(bv8_42);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_il_bool_init);
	mu_run_test(test_il_bool_logic);
	mu_run_test(test_il_mem_load);
	mu_run_test(test_il_mem_store);
	mu_run_test(test_il_mem_loadw);
	mu_run_test(test_il_mem_storew);
	mu_run_test(test_il_seqn);
	mu_run_test(test_il_sort_pure_eq);
	mu_run_test(test_il_value_eq);
	return tests_passed != tests_run;
}

mu_main(all_tests)
