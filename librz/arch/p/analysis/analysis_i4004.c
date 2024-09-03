// SPDX-FileCopyrightText: 2016-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <i4004/i4004dis.h>

#define AVR_SOFTCAST(x, y) ((x) + ((y)*0x100))

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	PC\n"
		/* syntax not yet supported */
		// "=SP	&PC1\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=R0	r0\n"
		"gpr	r0	.4	0	0\n"
		"gpr	r1	.4	1	0\n"
		"gpr	r2	.4	2	0\n"
		"gpr	r3	.4	3	0\n"
		"gpr	r4	.4	4	0\n"
		"gpr	r5	.4	5	0\n"
		"gpr	r6	.4	6	0\n"
		"gpr	r7	.4	7	0\n"
		"gpr	r8	.4	8	0\n"
		"gpr	r9	.4	9	0\n"
		"gpr	r10	.4	10	0\n"
		"gpr	r11	.4	11	0\n"
		"gpr	r12	.4	12	0\n"
		"gpr	r13	.4	13	0\n"
		"gpr	r14	.4	14	0\n"
		"gpr	r15	.4	15	0\n"
		"gpr	PC	.64	32	0\n"
		/* stack */
		"gpr	PC1	.64	34	0\n"
		"gpr	PC2	.64	34	0\n"
		"gpr	PC3	.64	34	0\n";
	return strdup(p);
}

RzAnalysisPlugin rz_analysis_plugin_i4004 = {
	.name = "i4004",
	.desc = "i4004 code analysis plugin",
	.license = "LGPL3",
	.arch = "i4004",
	.esil = false,
	.bits = 8,
	.op = &i4004_op,
	.get_reg_profile = &get_reg_profile
};
