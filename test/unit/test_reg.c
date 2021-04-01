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

bool test_rz_reg_get_pack(void) {
	RzReg *reg;
	RzRegItem *r;
	ut64 value;

	reg = rz_reg_new();
	mu_assert_notnull(reg, "rz_reg_new () failed");

	rz_reg_set_profile_string(reg,
		"xmm    xmm0	.128	0	16\n\
		xmm    xmm0h	.64		0	8\n\
		xmm    xmm0l	.64		8	8\n\
		xmm    xmm1	.128	16	16\n\
		xmm    xmm1h	.64		16	8\n\
		xmm    xmm1l	.64		24	8");

	r = rz_reg_get(reg, "xmm0", RZ_REG_TYPE_XMM);
	rz_reg_set_pack(reg, r, 0, 64, 0x0011223344556677);
	value = rz_reg_get_pack(reg, r, 0, 64);
	mu_assert_eq(value, 0x0011223344556677,
		"get xmm0 value at index 0 and bitsize 64");

	value = rz_reg_get_pack(reg, r, 0, 32);
	mu_assert_eq(value, 0x44556677,
		"get xmm0 value at index 1 and bitsize 32");

	rz_reg_set_pack(reg, r, 2, 32, 0xdeadbeef);
	value = rz_reg_get_pack(reg, r, 2, 32);
	mu_assert_eq(value, 0xdeadbeef,
		"get xmm0 value at index 2 and bitsize 32");

	r = rz_reg_get(reg, "xmm1", RZ_REG_TYPE_XMM);
	rz_reg_set_pack(reg, r, 1, 64, 0x8899aabbccddeeff);
	r = rz_reg_get(reg, "xmm1l", RZ_REG_TYPE_XMM);
	value = rz_reg_get_pack(reg, r, 0, 32);
	mu_assert_eq(value, 0xccddeeff,
		"get xmm1l value at index 0 and bitsize 32");

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
	mu_run_test(test_rz_reg_get_pack);
	return tests_passed != tests_run;
}

mu_main(all_tests)