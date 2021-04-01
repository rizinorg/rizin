// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

#include "minunit.h"

const RzAnalysisHint empty_hint = {
	.addr = UT64_MAX,
	.ptr = 0,
	.val = UT64_MAX,
	.jump = UT64_MAX,
	.fail = UT64_MAX,
	.ret = UT64_MAX,
	.arch = 0,
	.opcode = NULL,
	.syntax = NULL,
	.esil = NULL,
	.offset = NULL,
	.type = 0,
	.size = 0,
	.bits = 0,
	.new_bits = 0,
	.immbase = 0,
	.high = 0,
	.nword = 0,
	.stackframe = UT64_MAX,
};

bool hint_equals(const RzAnalysisHint *a, const RzAnalysisHint *b) {
#define CHECK_EQ(member) mu_assert_eq(a->member, b->member, "hint member " #member)
	CHECK_EQ(ptr);
	CHECK_EQ(val);
	CHECK_EQ(jump);
	CHECK_EQ(fail);
	CHECK_EQ(ret);
	CHECK_EQ(type);
	CHECK_EQ(size);
	CHECK_EQ(bits);
	CHECK_EQ(new_bits);
	CHECK_EQ(immbase);
	CHECK_EQ(high);
	CHECK_EQ(nword);
	CHECK_EQ(stackframe);
#undef CHECK_EQ
#define CHECK_STREQ(member) mu_assert_nullable_streq(a->member, b->member, "hint member " #member)
	CHECK_STREQ(arch);
	CHECK_STREQ(opcode);
	CHECK_STREQ(syntax);
	CHECK_STREQ(esil);
	CHECK_STREQ(offset);
#undef CHECK_STREQ
	return true;
}

#define assert_hint_eq(actual, expected) \
	do { \
		if (actual == NULL) \
			mu_assert("hint", expected == &empty_hint); /* TODO: remove this part, only else should be used! */ \
		else \
			mu_assert("hint", hint_equals(actual, expected)); \
	} while (0)

bool test_rz_analysis_addr_hints() {
	RzAnalysis *analysis = rz_analysis_new();
	RzAnalysisHint *hint = rz_analysis_hint_get(analysis, 0x1337);
	assert_hint_eq(hint, &empty_hint);
	rz_analysis_hint_free(hint);

	RzAnalysisHint cur = empty_hint;
#define CHECK \
	hint = rz_analysis_hint_get(analysis, 0x1337); \
	assert_hint_eq(hint, &cur); \
	rz_analysis_hint_free(hint);
	hint = rz_analysis_hint_get(analysis, 0x1338);
	assert_hint_eq(hint, &empty_hint);
	rz_analysis_hint_free(hint);
	hint = rz_analysis_hint_get(analysis, 0x1336);
	assert_hint_eq(hint, &empty_hint);
	rz_analysis_hint_free(hint);

	// set --------

	rz_analysis_hint_set_syntax(analysis, 0x1337, "mysyntax");
	cur.syntax = "mysyntax";
	CHECK

	rz_analysis_hint_set_type(analysis, 0x1337, RZ_ANALYSIS_OP_TYPE_RET);
	cur.type = RZ_ANALYSIS_OP_TYPE_RET;
	CHECK

	rz_analysis_hint_set_jump(analysis, 0x1337, 0xdeadbeef);
	cur.jump = 0xdeadbeef;
	CHECK

	rz_analysis_hint_set_fail(analysis, 0x1337, 0xc0ffee);
	cur.fail = 0xc0ffee;
	CHECK

	rz_analysis_hint_set_nword(analysis, 0x1337, 42);
	cur.nword = 42;
	CHECK

	rz_analysis_hint_set_offset(analysis, 0x1337, "mytypeoff");
	cur.offset = "mytypeoff";
	CHECK

	rz_analysis_hint_set_immbase(analysis, 0x1337, 7);
	cur.immbase = 7;
	CHECK

	rz_analysis_hint_set_size(analysis, 0x1337, 0x123);
	cur.size = 0x123;
	CHECK

	rz_analysis_hint_set_opcode(analysis, 0x1337, "myopcode");
	cur.opcode = "myopcode";
	CHECK

	rz_analysis_hint_set_esil(analysis, 0x1337, "/,-rf,rm");
	cur.esil = "/,-rf,rm";
	CHECK

	rz_analysis_hint_set_pointer(analysis, 0x1337, 0x4242);
	cur.ptr = 0x4242;
	CHECK

	rz_analysis_hint_set_ret(analysis, 0x1337, 0xf00d);
	cur.ret = 0xf00d;
	CHECK

	rz_analysis_hint_set_high(analysis, 0x1337);
	cur.high = true;
	CHECK

	rz_analysis_hint_set_stackframe(analysis, 0x1337, 0x4321);
	cur.stackframe = 0x4321;
	CHECK

	rz_analysis_hint_set_val(analysis, 0x1337, 0x112358d);
	cur.val = 0x112358d;
	CHECK

	rz_analysis_hint_set_newbits(analysis, 0x1337, 16);
	cur.new_bits = 16;
	CHECK

	// unset --------

	rz_analysis_hint_unset_syntax(analysis, 0x1337);
	cur.syntax = NULL;
	CHECK

	rz_analysis_hint_unset_type(analysis, 0x1337);
	cur.type = 0;
	CHECK

	rz_analysis_hint_unset_jump(analysis, 0x1337);
	cur.jump = UT64_MAX;
	CHECK

	rz_analysis_hint_unset_fail(analysis, 0x1337);
	cur.fail = UT64_MAX;
	CHECK

	rz_analysis_hint_unset_nword(analysis, 0x1337);
	cur.nword = 0;
	CHECK

	rz_analysis_hint_unset_offset(analysis, 0x1337);
	cur.offset = NULL;
	CHECK

	rz_analysis_hint_unset_immbase(analysis, 0x1337);
	cur.immbase = 0;
	CHECK

	rz_analysis_hint_unset_size(analysis, 0x1337);
	cur.size = 0;
	CHECK

	rz_analysis_hint_unset_opcode(analysis, 0x1337);
	cur.opcode = NULL;
	CHECK

	rz_analysis_hint_unset_esil(analysis, 0x1337);
	cur.esil = NULL;
	CHECK

	rz_analysis_hint_unset_pointer(analysis, 0x1337);
	cur.ptr = 0;
	CHECK

	rz_analysis_hint_unset_ret(analysis, 0x1337);
	cur.ret = UT64_MAX;
	CHECK

	rz_analysis_hint_unset_high(analysis, 0x1337);
	cur.high = false;
	CHECK

	rz_analysis_hint_unset_stackframe(analysis, 0x1337);
	cur.stackframe = UT64_MAX;
	CHECK

	rz_analysis_hint_unset_val(analysis, 0x1337);
	cur.val = UT64_MAX;
	CHECK

	rz_analysis_hint_unset_newbits(analysis, 0x1337);
	cur.new_bits = 0;
	//CHECK
	hint = rz_analysis_hint_get(analysis, 0x1337);
	assert_hint_eq(hint, &empty_hint);
	rz_analysis_hint_free(hint);

	rz_analysis_free(analysis);
	mu_end;
#undef CHECK
}

#define RANGED_TEST(name, val, resetval, assert_val) \
	bool test_rz_analysis_hints_##name() { \
		RzAnalysis *analysis = rz_analysis_new(); \
\
		ut64 hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1337, &hint_addr), resetval, "no " #name ""); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
\
		rz_analysis_hint_##name##_at(analysis, 0x1337, NULL); /* make sure this does not null-deref */ \
\
		/* -- */ \
		rz_analysis_hint_set_##name(analysis, 0x1337, val); \
\
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1337, &hint_addr), val, #name " at addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1338, &hint_addr), val, #name " after addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, UT64_MAX, &hint_addr), val, #name " after addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1336, &hint_addr), resetval, "no " #name " before addr"); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0, &hint_addr), resetval, "no " #name " before addr"); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
\
		rz_analysis_hint_##name##_at(analysis, 0x1337, NULL); /* make sure this does not null-deref */ \
\
		RzAnalysisHint cur = empty_hint; \
		cur.name = val; \
		RzAnalysisHint *hint = rz_analysis_hint_get(analysis, 0x1337); \
		assert_hint_eq(hint, &cur); \
		rz_analysis_hint_free(hint); \
		hint = rz_analysis_hint_get(analysis, 0x1338); \
		assert_hint_eq(hint, &cur); \
		rz_analysis_hint_free(hint); \
		hint = rz_analysis_hint_get(analysis, 0x1336); \
		assert_hint_eq(hint, &empty_hint); \
		rz_analysis_hint_free(hint); \
\
		/* -- */ \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0xdeadbeef, &hint_addr), val, "before reset " #name " at addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		rz_analysis_hint_set_##name(analysis, 0xdeadbeef, resetval); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0xdeadbeef, &hint_addr), resetval, "reset " #name " at addr"); \
		mu_assert_eq(hint_addr, 0xdeadbeef, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0xdeadbeef + 1, &hint_addr), resetval, "reset " #name " after addr"); \
		mu_assert_eq(hint_addr, 0xdeadbeef, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, UT64_MAX, &hint_addr), resetval, "reset " #name " after addr"); \
		mu_assert_eq(hint_addr, 0xdeadbeef, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0xdeadbeef - 1, &hint_addr), val, "" #name " before addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
\
		/* -- */ \
		rz_analysis_hint_unset_##name(analysis, 0xdeadbeef); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1337, &hint_addr), val, #name " at addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1338, &hint_addr), val, #name " after addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, UT64_MAX, &hint_addr), val, #name " after addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1336, &hint_addr), resetval, "no " #name " before addr"); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0, &hint_addr), resetval, "no " #name " before addr"); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0xdeadbeef, &hint_addr), val, "unset reset " #name " at addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0xdeadbeef + 1, &hint_addr), val, "unset reset " #name " after addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, UT64_MAX, &hint_addr), val, "unset reset " #name " after addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0xdeadbeef - 1, &hint_addr), val, #name " before addr"); \
		mu_assert_eq(hint_addr, 0x1337, "hint addr"); \
\
		/* -- */ \
		rz_analysis_hint_unset_##name(analysis, 0x1337); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1336, &hint_addr), resetval, "unset " #name ""); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0, &hint_addr), resetval, "unset " #name ""); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1337, &hint_addr), resetval, "unset " #name ""); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, 0x1338, &hint_addr), resetval, "unset " #name ""); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
		hint_addr = 0xdead; \
		assert_val(rz_analysis_hint_##name##_at(analysis, UT64_MAX, &hint_addr), resetval, "unset " #name ""); \
		mu_assert_eq(hint_addr, UT64_MAX, "hint addr"); \
		hint_addr = 0xdead; \
\
		rz_analysis_free(analysis); \
		mu_end; \
	}

RANGED_TEST(arch, "6502", NULL, mu_assert_nullable_streq)
RANGED_TEST(bits, 16, 0, mu_assert_eq)

bool all_tests() {
	mu_run_test(test_rz_analysis_addr_hints);
	mu_run_test(test_rz_analysis_hints_arch);
	mu_run_test(test_rz_analysis_hints_bits);
	return tests_passed != tests_run;
}

mu_main(all_tests)