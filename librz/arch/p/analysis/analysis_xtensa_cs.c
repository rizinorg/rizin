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

static RzTypeCond xtensa_cond(xtensa_insn insn) {
	switch (insn) {
	case XTENSA_INS_BEQI: return RZ_TYPE_COND_EQ;
	case XTENSA_INS_BNEI: return RZ_TYPE_COND_NE;
	case XTENSA_INS_BGEI: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLTI: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BGEUI: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLTUI: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BBCI: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BBSI: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BEQ: return RZ_TYPE_COND_EQ;
	case XTENSA_INS_BNE: return RZ_TYPE_COND_NE;
	case XTENSA_INS_BGE: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLT: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BGEU: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLTU: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BANY:
	case XTENSA_INS_BNONE:
	case XTENSA_INS_BALL:
	case XTENSA_INS_BNALL:
	case XTENSA_INS_BBC:
	case XTENSA_INS_BBS: break;
	case XTENSA_INS_BEQZ: return RZ_TYPE_COND_EQ;
	case XTENSA_INS_BNEZ: return RZ_TYPE_COND_NE;
	case XTENSA_INS_BGEZ: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLTZ: return RZ_TYPE_COND_LT;
	default: break;
	}
	return RZ_TYPE_COND_AL;
}

static void xtensa_analyze_op(RzAnalysis *a, RzAnalysisOp *op, XtensaContext *ctx) {
	switch (ctx->insn->id) {
	case XTENSA_INS_ADD: /* add */
	case XTENSA_INS_ADDX2: /* addx2 */
	case XTENSA_INS_ADDX4: /* addx4 */
	case XTENSA_INS_ADDX8: /* addx8 */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case XTENSA_INS_SUB: /* sub */
	case XTENSA_INS_SUBX2: /* subx2 */
	case XTENSA_INS_SUBX4: /* subx4 */
	case XTENSA_INS_SUBX8: /* subx8 */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case XTENSA_INS_MOVI: /* movi */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
		//	case 0: /* excw */
	case XTENSA_INS_NOP: /* nop.n */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case XTENSA_INS_S32I: /* s32i */
	case XTENSA_INS_S16I: /* s16i */
	case XTENSA_INS_S8I: /* s8i */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case XTENSA_INS_ADDI: /* addi */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case XTENSA_INS_RET: /* ret */
		op->eob = true;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case XTENSA_INS_L16UI: /* l16ui */
	case XTENSA_INS_L16SI: /* l16si */
	case XTENSA_INS_L32I: /* l32i */
	case XTENSA_INS_L8UI: /* l8ui */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case XTENSA_INS_L32R: /* l32r */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case XTENSA_INS_ADDMI: /* addmi */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case XTENSA_INS_AND: /* and */
	case XTENSA_INS_OR: /* or */
	case XTENSA_INS_XOR: /* xor */
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case XTENSA_INS_BEQI: /* beqi */
	case XTENSA_INS_BNEI: /* bnei */
	case XTENSA_INS_BGEI: /* bgei */
	case XTENSA_INS_BLTI: /* blti */
	case XTENSA_INS_BGEUI: /* bgeui */
	case XTENSA_INS_BLTUI: /* bltui */
	case XTENSA_INS_BBCI: /* bbci */
	case XTENSA_INS_BBSI: /* bbsi */
	case XTENSA_INS_BEQ: /* beq */
	case XTENSA_INS_BNE: /* bne */
	case XTENSA_INS_BGE: /* bge */
	case XTENSA_INS_BLT: /* blt */
	case XTENSA_INS_BGEU: /* bgeu */
	case XTENSA_INS_BLTU: /* bltu */
	case XTENSA_INS_BANY: /* bany */
	case XTENSA_INS_BNONE: /* bnone */
	case XTENSA_INS_BALL: /* ball */
	case XTENSA_INS_BNALL: /* bnall */
	case XTENSA_INS_BBC: /* bbc */
	case XTENSA_INS_BBS: /* bbs */
	case XTENSA_INS_BEQZ: /* beqz */
	case XTENSA_INS_BNEZ: /* bnez */
	case XTENSA_INS_BGEZ: /* bgez */
	case XTENSA_INS_BLTZ: /* bltz */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = ctx->insn->address + IMM(2);
		op->fail = ctx->insn->address + ctx->insn->size;
		op->cond = xtensa_cond(ctx->insn->id);
		break;
	case XTENSA_INS_EXTUI: /* extui */
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case XTENSA_INS_J: /* j */
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = ctx->insn->address + IMM(0);
		op->fail = ctx->insn->address + ctx->insn->size;
		break;
	case XTENSA_INS_CALLX0: /* callx0 */
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->reg = REGO(0);
		break;
	case XTENSA_INS_MOVEQZ: /* moveqz */
	case XTENSA_INS_MOVNEZ: /* movnez */
	case XTENSA_INS_MOVLTZ: /* movltz */
	case XTENSA_INS_MOVGEZ: /* movgez */
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;
	case XTENSA_INS_ABS: /* abs */
		op->type = RZ_ANALYSIS_OP_TYPE_ABS;
		break;
	case XTENSA_INS_NEG: /* neg */
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		break;
	case XTENSA_INS_SSR: /* ssr */
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case XTENSA_INS_SSL: /* ssl */
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case XTENSA_INS_SLLI: /* slli */
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case XTENSA_INS_SRLI: /* srli */
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case XTENSA_INS_SSAI: /* ssai */
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case XTENSA_INS_SLL: /* sll */
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case XTENSA_INS_SRL: /* srl */
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	}
}

static int xtensa_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	XtensaContext *ctx = analysis->plugin_data;
	if (!xtensa_open(ctx, analysis->cpu, analysis->big_endian)) {
		goto beach;
	}
	if (!xtensa_disassemble(ctx, buf, len, addr)) {
		goto beach;
	}

	xtensa_analyze_op(analysis, op, ctx);

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
