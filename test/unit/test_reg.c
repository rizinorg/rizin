// SPDX-FileCopyrightText: 2020 Khairulmizam Samsudin <xource@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_reg.h>
#include "minunit.h"

bool test_rz_reg_set_name(void) {
	RzReg *reg;

	reg = rz_reg_new();
	mu_assert_notnull(reg, "rz_reg_new () failed");

	rz_reg_set_name(reg, RZ_REG_NAME_PC, "eip");
	const char *name = rz_reg_get_name(reg, RZ_REG_NAME_PC);
	mu_assert_streq(name, "eip", "PC register alias is eip");

	rz_reg_free(reg);
	mu_end;
}

bool test_rz_reg_set_profile_string(void) {
	RzReg *reg;

	reg = rz_reg_new();
	mu_assert_notnull(reg, "rz_reg_new () failed");

	rz_reg_set_profile_string(reg, "=PC eip");
	const char *name = rz_reg_get_name(reg, RZ_REG_NAME_PC);
	mu_assert_streq(name, "eip", "PC register alias is eip");

	mu_assert_eq(rz_reg_set_profile_string(reg, "gpr eax .32 24 0"),
		true, "define eax register");

	mu_assert_eq(rz_reg_setv(reg, "eax", 1234),
		true, "set eax register value to 1234");

	ut64 value = rz_reg_getv(reg, "eax");
	mu_assert_eq(value, 1234, "get eax register value");

	rz_reg_free(reg);
	mu_end;
}

bool test_rz_reg_get_value_gpr(void) {
	RzReg *reg;
	ut64 value;

	reg = rz_reg_new();
	mu_assert_notnull(reg, "rz_reg_new () failed");

	rz_reg_set_profile_string(reg,
		"gpr eax .32 0 0\n\
		gpr	ax	.16	0	0\n\
		gpr	ah	.8	1	0\n\
		gpr	al	.8	0	0\n\
		gpr	ebx	.32	40	0\n\
		gpr	bx	.16	40	0\n\
		gpr	bh	.8	41	0\n\
		gpr	bl	.8	40	0");

	mu_assert_eq(rz_reg_setv(reg, "eax", 0x01234567),
		true, "set eax register value to 0x01234567");

	value = rz_reg_getv(reg, "eax");
	mu_assert_eq(value, 0x01234567, "get eax register value");

	value = rz_reg_getv(reg, "ax");
	mu_assert_eq(value, 0x4567, "get ax register value");

	value = rz_reg_getv(reg, "ah");
	mu_assert_eq(value, 0x45, "get ah register value");

	value = rz_reg_getv(reg, "al");
	mu_assert_eq(value, 0x67, "get al register value");

	mu_assert_eq(rz_reg_setv(reg, "ebx", 0x89ab0000),
		true, "set ebx register value to 0x89ab0000");

	value = rz_reg_getv(reg, "ebx");
	mu_assert_eq(value, 0x89ab0000, "get ebx register value");

	mu_assert_eq(rz_reg_setv(reg, "bh", 0xcd),
		true, "set bh register value to 0xcd");

	mu_assert_eq(rz_reg_setv(reg, "bl", 0xef),
		true, "set bh register value to 0xef");

	value = rz_reg_getv(reg, "bx");
	mu_assert_eq(value, 0xcdef, "get bx register value");

	rz_reg_free(reg);
	mu_end;
}

bool test_rz_reg_get_value_flag(void) {
	RzReg *reg;
	RzRegItem *r;
	ut64 value;

	reg = rz_reg_new();
	mu_assert_notnull(reg, "rz_reg_new () failed");

	rz_reg_set_profile_string(reg,
		"gpr	eflags	.32	0		0	c1p.a.zstido.n.rv\n\
		gpr		flags	.16	0		0\n\
		gpr		cf		.1	.0	0	carry\n\
		gpr		pf		.1	.2	0	parity\n\
		gpr		af		.1	.4	0	adjust\n\
		gpr		zf		.1	.6	0	zero\n\
		gpr		sf		.1	.7	0	sign\n\
		gpr		tf		.1	.8	0	trap\n\
		gpr		if		.1	.9	0	interrupt\n\
		gpr		df		.1	.10	0	direction\n\
		gpr		of		.1	.11	0	overflow");

	r = rz_reg_get(reg, "eflags", RZ_REG_TYPE_FLG);
	rz_reg_set_value(reg, r, 0x00000346);

	value = rz_reg_getv(reg, "cf");
	mu_assert_eq(value, 0, "get cf flag value");

	value = rz_reg_getv(reg, "pf");
	mu_assert_eq(value, 1, "get pf flag value");

	value = rz_reg_getv(reg, "af");
	mu_assert_eq(value, 0, "get af flag value");

	value = rz_reg_getv(reg, "zf");
	mu_assert_eq(value, 1, "get zf flag value");

	value = rz_reg_getv(reg, "sf");
	mu_assert_eq(value, 0, "get sf flag value");

	value = rz_reg_getv(reg, "tf");
	mu_assert_eq(value, 1, "get tf flag value");

	value = rz_reg_getv(reg, "df");
	mu_assert_eq(value, 0, "get df flag value");

	rz_reg_free(reg);
	mu_end;
}

bool test_rz_reg_get(void) {
	RzReg *reg;
	RzRegItem *r;

	reg = rz_reg_new();
	mu_assert_notnull(reg, "rz_reg_new () failed");

	bool success = rz_reg_set_profile_string(reg,
		"gpr	eax		.32	24	0\n\
		fpu		sf0		.32	304	0\n\
		xmm		xmm0	.64	160	4");
	mu_assert_eq(success, true, "define eax, sf0 and xmm0 register");

	r = rz_reg_get(reg, "sf0", RZ_REG_TYPE_FPU);
	mu_assert_streq(r->name, "sf0", "found sf0 as RZ_REG_TYPE_FPU");
	mu_assert_eq(r->type, RZ_REG_TYPE_FPU, "sf0 type is RZ_REG_TYPE_FPU");

	r = rz_reg_get(reg, "xmm0", RZ_REG_TYPE_XMM);
	mu_assert_streq(r->name, "xmm0", "found xmm0 as RZ_REG_TYPE_XMM");
	mu_assert_eq(r->type, RZ_REG_TYPE_XMM, "xmm0 type is RZ_REG_TYPE_XMM");

	r = rz_reg_get(reg, "xmm0", -1);
	mu_assert_streq(r->name, "xmm0", "found xmm0");
	mu_assert_eq(r->type, RZ_REG_TYPE_XMM, "xmm0 type is RZ_REG_TYPE_XMM");

	rz_reg_free(reg);
	mu_end;
}

bool test_rz_reg_get_list(void) {
	RzReg *reg;
	const RzList *l;
	int mask;

	reg = rz_reg_new();
	mu_assert_notnull(reg, "rz_reg_new () failed");

	bool success = rz_reg_set_profile_string(reg,
		"gpr		eax		.32	24	0\n\
		fpu			sf0		.32	304	0\n\
		xmm@fpu		xmm0	.64	160	4");
	mu_assert_eq(success, true, "define eax, sf0 and xmm0 register");

	mask = ((int)1 << RZ_REG_TYPE_XMM);
	mu_assert_eq((reg->regset[RZ_REG_TYPE_FPU].maskregstype & mask), mask,
		"xmm0 stored as RZ_REG_TYPE_FPU");

	l = rz_reg_get_list(reg, RZ_REG_TYPE_XMM);
	mu_assert_eq(rz_list_length(l), 2, "sf0 and xmm0 stored as RZ_REG_TYPE_FPU");

	rz_reg_free(reg);
	mu_end;
}

bool test_rz_reg_get_bv(void) {
	RzReg *reg = rz_reg_new();
	mu_assert_notnull(reg, "rz_reg_new () failed");

	rz_reg_set_profile_string(reg,
		"gpr	eax .32 0 0\n"
		"gpr	ax	.16	0	0\n"
		"gpr	ah	.8	1	0\n"
		"gpr	al	.8	0	0\n"
		"gpr	ebx	.32	40	0\n"
		"gpr	bx	.16	40	0\n"
		"gpr	bh	.8	41	0\n"
		"gpr	bl	.8	40	0\n"
		"gpr	cf	.1	8	0\n"
		"gpr	zf	.1	8.1	0\n");

	rz_reg_setv(reg, "eax", 0x01234567);
	rz_reg_setv(reg, "ebx", 0x89abcdef);

	RzBitVector *bv = rz_reg_get_bv(reg, rz_reg_get(reg, "eax", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 32, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0x01234567, "bv value");
	rz_bv_free(bv);

	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "ax", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 16, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0x4567, "bv value");
	rz_bv_free(bv);

	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "ah", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 8, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0x45, "bv value");
	rz_bv_free(bv);

	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "al", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 8, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0x67, "bv value");
	rz_bv_free(bv);

	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "ebx", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 32, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0x89abcdef, "bv value");
	rz_bv_free(bv);

	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "bx", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 16, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0xcdef, "bv value");
	rz_bv_free(bv);

	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "bh", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 8, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0xcd, "bv value");
	rz_bv_free(bv);

	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "bl", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 8, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0xef, "bv value");
	rz_bv_free(bv);

	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "cf", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 1, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0x0, "bv value");
	rz_bv_free(bv);
	rz_reg_setv(reg, "cf", 0x1);
	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "cf", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 1, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0x1, "bv value");
	rz_bv_free(bv);

	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "zf", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 1, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0x0, "bv value");
	rz_bv_free(bv);
	rz_reg_setv(reg, "zf", 0x1);
	bv = rz_reg_get_bv(reg, rz_reg_get(reg, "zf", RZ_REG_TYPE_ANY));
	mu_assert_notnull(bv, "get bv");
	mu_assert_eq(rz_bv_len(bv), 1, "bv len");
	mu_assert_eq(rz_bv_to_ut64(bv), 0x1, "bv value");
	rz_bv_free(bv);

	rz_reg_free(reg);
	mu_end;
}

bool test_rz_reg_set_bv(void) {
	RzReg *reg = rz_reg_new();
	mu_assert_notnull(reg, "rz_reg_new () failed");

	rz_reg_set_profile_string(reg,
		"gpr	eax .32 0 0\n"
		"gpr	ax	.16	0	0\n"
		"gpr	ah	.8	1	0\n"
		"gpr	al	.8	0	0\n"
		"gpr	ebx	.32	4	0\n"
		"gpr	bx	.16	4	0\n"
		"gpr	bh	.8	5	0\n"
		"gpr	bl	.8	4	0\n"
		"gpr	cf	.1	8	0\n"
		"gpr	zf	.1	8.1	0\n"
		"fpu	f	.8	4	0");

	RzRegArena *gpr = reg->regset[RZ_REG_TYPE_GPR].arena;
	RzRegArena *fpu = reg->regset[RZ_REG_TYPE_FPU].arena;

	const ut8 expect_zero[9] = { 0 };
	mu_assert_eq(gpr->size, 9, "gpr size");
	mu_assert_memeq(gpr->bytes, expect_zero, 8, "gpr init");
	mu_assert_eq(fpu->size, 5, "fpu size");
	mu_assert_memeq(fpu->bytes, expect_zero, 5, "fpu init");

	RzBitVector *bv = rz_bv_new_from_ut64(32, 0x12345678);
	bool succ = rz_reg_set_bv(reg, rz_reg_get(reg, "eax", RZ_REG_TYPE_ANY), bv);
	rz_bv_free(bv);
	mu_assert_true(succ, "set");
	const ut8 expect0_gpr[9] = { 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00 };
	mu_assert_memeq(gpr->bytes, expect0_gpr, 9, "gpr set");
	mu_assert_memeq(fpu->bytes, expect_zero, 5, "fpu untouched");

	bv = rz_bv_new_from_ut64(8, 0xff);
	succ = rz_reg_set_bv(reg, rz_reg_get(reg, "f", RZ_REG_TYPE_ANY), bv);
	rz_bv_free(bv);
	mu_assert_true(succ, "set");
	const ut8 expect1_fpu[5] = { 0x00, 0x00, 0x00, 0x00, 0xff };
	mu_assert_memeq(gpr->bytes, expect0_gpr, 9, "gpr untouched");
	mu_assert_memeq(fpu->bytes, expect1_fpu, 5, "fpu set");

	bv = rz_bv_new_from_ut64(32, 0x9abcdef0);
	succ = rz_reg_set_bv(reg, rz_reg_get(reg, "ebx", RZ_REG_TYPE_ANY), bv);
	rz_bv_free(bv);
	mu_assert_true(succ, "set");
	const ut8 expect2_gpr[9] = { 0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a, 0x00 };
	mu_assert_memeq(gpr->bytes, expect2_gpr, 9, "gpr set");
	mu_assert_memeq(fpu->bytes, expect1_fpu, 5, "fpu untouched");

	bv = rz_bv_new_from_ut64(8, 0x42);
	succ = rz_reg_set_bv(reg, rz_reg_get(reg, "bh", RZ_REG_TYPE_ANY), bv);
	rz_bv_free(bv);
	mu_assert_true(succ, "set");
	const ut8 expect3_gpr[9] = { 0x78, 0x56, 0x34, 0x12, 0xf0, 0x42, 0xbc, 0x9a, 0x00 };
	mu_assert_memeq(gpr->bytes, expect3_gpr, 9, "gpr set");
	mu_assert_memeq(fpu->bytes, expect1_fpu, 5, "fpu untouched");

	bv = rz_bv_new_from_ut64(1, 1);
	succ = rz_reg_set_bv(reg, rz_reg_get(reg, "cf", RZ_REG_TYPE_ANY), bv);
	rz_bv_free(bv);
	mu_assert_true(succ, "set");
	const ut8 expect4_gpr[9] = { 0x78, 0x56, 0x34, 0x12, 0xf0, 0x42, 0xbc, 0x9a, 0x01 };
	mu_assert_memeq(gpr->bytes, expect4_gpr, 9, "gpr set");
	mu_assert_memeq(fpu->bytes, expect1_fpu, 5, "fpu untouched");

	bv = rz_bv_new_from_ut64(1, 1);
	succ = rz_reg_set_bv(reg, rz_reg_get(reg, "zf", RZ_REG_TYPE_ANY), bv);
	rz_bv_free(bv);
	mu_assert_true(succ, "set");
	const ut8 expect5_gpr[9] = { 0x78, 0x56, 0x34, 0x12, 0xf0, 0x42, 0xbc, 0x9a, 0x03 };
	mu_assert_memeq(gpr->bytes, expect5_gpr, 9, "gpr set");
	mu_assert_memeq(fpu->bytes, expect1_fpu, 5, "fpu untouched");

	rz_reg_free(reg);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_reg_set_name);
	mu_run_test(test_rz_reg_set_profile_string);
	mu_run_test(test_rz_reg_get_value_gpr);
	mu_run_test(test_rz_reg_get_value_flag);
	mu_run_test(test_rz_reg_get);
	mu_run_test(test_rz_reg_get_list);
	mu_run_test(test_rz_reg_get_bv);
	mu_run_test(test_rz_reg_set_bv);
	return tests_passed != tests_run;
}

mu_main(all_tests)
