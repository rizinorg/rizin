// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <h8500/h8500.h>

static int h8500_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	return -1;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	char *p =
		"=PC	pc\n"
		"=SP	r7\n"
		"=A0	r0\n"
		"gpr	r0	.16	0	0\n"
		"gpr	r1	.16	2	0\n"
		"gpr	r2	.16	4	0\n"
		"gpr	r3	.16	6	0\n"
		"gpr	r4	.16	8	0\n"
		"gpr	r5	.16	10	0\n"
		"gpr	r6	.16	12	0\n"
		"gpr	r7	.16	14	0\n"
		"gpr	pc	.24	16	0\n"
		"gpr	ccr	.8	19	0\n"
		"gpr	cp	.8	20	0\n"
		"gpr	dp	.8	21	0\n"
		"gpr	ep	.8	22	0\n"
		"gpr	tp	.8	23	0\n"
		"gpr	br	.8	24	0\n"
		"gpr	N	.1	.147	0\n"
		"gpr	Z	.1	.146	0\n"
		"gpr	V	.1	.145	0\n"
		"gpr	C	.1	.144	0\n";
	return rz_str_dup(p);
}

RzAnalysisPlugin rz_analysis_plugin_h8500 = {
	.name = "h8500",
	.desc = "H8500 code analysis plugin",
	.license = "LGPL3",
	.arch = "h8500",
	.bits = 16,
	.op = &h8500_op,
	.get_reg_profile = get_reg_profile,
	.il_config = NULL,
	.preludes = NULL,
};
