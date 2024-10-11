// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_endian.h>
#include <xtensa/xtensa.h>

static int xtensa_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 3;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 8;
		//	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		//		return 2;
		//	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		//		return 0;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static char *xtensa_get_reg_profile(RzAnalysis *analysis) {
	return rz_str_dup(
		// Assuming call0 ABI
		"# a0		return address\n"
		"# a1		stack pointer\n"
		"# a2-a7	arguments\n"
		"# a2-a5	return value (call0 ABI)\n"
		"# a12-a15	callee-saved (call0 ABI)\n"
		"=PC	pc\n"
		"=BP	a14\n"
		"=SP	a1\n"
		"=A0	a2\n"
		"=A1	a3\n"
		"=A2	a4\n"
		"=A3	a5\n"
		"=A4	a6\n"
		"=A5	a7\n"
		"gpr	a0	.32	0	0\n"
		"gpr	a1	.32	4	0\n"
		"gpr	a2	.32	8	0\n"
		"gpr	a3	.32	16	0\n"
		"gpr	a4	.32	20	0\n"
		"gpr	a5	.32	24	0\n"
		"gpr	a6	.32	28	0\n"
		"gpr	a7	.32	32	0\n"
		"gpr	a8	.32	36	0\n"
		"gpr	a9	.32	40	0\n"
		"gpr	a10	.32	44	0\n"
		"gpr	a11	.32	48	0\n"
		"gpr	a12	.32	52	0\n"
		"gpr	a13	.32	56	0\n"
		"gpr	a14	.32	60	0\n"
		"gpr	a15	.32	64	0\n"

		// pc
		"gpr	pc	.32	68	0\n"

		// sr
		"gpr	sar	.32	72	0\n");
}

RzAnalysisILConfig *xtensa_il_config(RzAnalysis *a) {
	rz_return_val_if_fail(a, NULL);

	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	//	cfg->reg_bindings = xtensa_registers;
	return cfg;
}

static RzList /*<RzSearchKeyword *>*/ *xtensa_preludes(RzAnalysis *analysis) {
	return NULL;
}

static int xtensa_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	XtensaContext *ctx = analysis->plugin_data;
	if (!xtensa_open(ctx, analysis->cpu, analysis->big_endian)) {
		goto beach;
	}
	if (!xtensa_disassemble(ctx, buf, len, addr)) {
		goto beach;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf(
			"%s%s%s",
			ctx->insn->mnemonic,
			ctx->insn->op_str[0] ? " " : "",
			ctx->insn->op_str);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		xtensa_analyze_op_esil(ctx, op);
	}

	op->size = ctx->insn->size;
	op->id = ctx->insn->id;
	op->addr = addr;

	xtensa_disassemble_fini(ctx);
	return op->size;
beach:
	xtensa_disassemble_fini(ctx);
	return -1;
}

RzAnalysisPlugin rz_analysis_plugin_xtensa_cs = {
	.name = "xtensa",
	.desc = "Capstone Xtensa analysis plugin",
	.license = "LGPL3",
	.preludes = xtensa_preludes,
	.arch = "xtensa",
	.bits = 32,
	.op = xtensa_op,
	.esil = false,
	.archinfo = xtensa_archinfo,
	.get_reg_profile = xtensa_get_reg_profile,
	.il_config = xtensa_il_config,
	.init = xtensa_init,
	.fini = xtensa_fini,
};
