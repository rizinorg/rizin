// SPDX-FileCopyrightText: 2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <spc700/spc700dis.h>

static int op(RzAnalysis *analysis, RzAnalysisOp *rz_op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	// TODO: fill this with the actual info
	size_t dlen = spc700_disas(NULL, 0, buf, len);
	rz_op->size = dlen;
	rz_op->addr = addr;
	rz_op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	return rz_op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=A0	a\n"
		"=A1	x\n"
		"=A2	y\n"
		"gpr	a	.8	0	0\n"
		"gpr	x	.8	1	0\n"
		"gpr	y	.8	2	0\n"
		"gpr	flags	.8	3	0\n"
		"gpr	C	.1	.24	0\n"
		"gpr	Z	.1	.25	0\n"
		"gpr	I	.1	.26	0\n"
		"gpr	H	.1	.27	0\n"
		"gpr	B	.1	.28	0\n"
		"gpr	P	.1	.29	0\n"
		"gpr	V	.1	.30	0\n"
		"gpr	N	.1	.31	0\n"
		"gpr	sp	.8	4	0\n"
		"gpr	pc	.16	5	0\n";
	return rz_str_dup(p);
}

RzAnalysisPlugin rz_analysis_plugin_spc700 = {
	.name = "spc700",
	.desc = "spc700, snes' sound-chip",
	.arch = "spc700",
	.license = "LGPL3",
	.bits = 16,
	.op = &op,
	.get_reg_profile = &get_reg_profile,
};
