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
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 6;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return 1;
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
		"=R0	a2\n"
		"=R1	a3\n"
		"=R2	a4\n"
		"=R3	a5\n"
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

static void xop_to_rval(RzAnalysis *a, XtensaContext *ctx, cs_xtensa_op *xop, RzAnalysisValue **prv) {
	RzAnalysisValue *rv = rz_analysis_value_new();
	if (!rv) {
		return;
	}

	if (xop->access & CS_AC_WRITE) {
		rv->access |= RZ_ANALYSIS_ACC_W;
	}
	if (xop->access & CS_AC_READ) {
		rv->access |= RZ_ANALYSIS_ACC_R;
	}
	switch (xop->type) {
	case XTENSA_OP_REG:
		rv->reg = rz_reg_get(a->reg, cs_reg_name(ctx->handle, xop->reg), RZ_REG_TYPE_ANY);
		rv->type = RZ_ANALYSIS_VAL_REG;
		break;
	case XTENSA_OP_IMM:
		rv->imm = xop->imm;
		rv->type = RZ_ANALYSIS_VAL_IMM;
		break;
	case XTENSA_OP_MEM:
		rv->reg = rz_reg_get(a->reg, cs_reg_name(ctx->handle, xop->mem.base), RZ_REG_TYPE_ANY);
		rv->delta = xop->mem.disp;
		rv->type = RZ_ANALYSIS_VAL_MEM;
		break;
	case XTENSA_OP_L32R:
		rv->reg = rz_reg_get(a->reg, "pc", RZ_REG_TYPE_ANY);
		rv->delta = xop->imm;
		rv->type = RZ_ANALYSIS_VAL_MEM;
		break;
	default:
		rv->type = RZ_ANALYSIS_VAL_UNK;
		break;
	}
	if (*prv) {
		rz_analysis_value_free(*prv);
	}
	*prv = rv;
}

static void xtensa_analyze_op(RzAnalysis *a, RzAnalysisOp *op, XtensaContext *ctx) {
	int src_count = 0;
	for (int i = 0; i < ctx->insn->detail->xtensa.op_count; ++i) {
		cs_xtensa_op *xop = XOP(i);
		if (xop->access & CS_AC_WRITE) {
			xop_to_rval(a, ctx, xop, &op->dst);
		}
		if (xop->access & CS_AC_READ) {
			xop_to_rval(a, ctx, xop, &op->src[src_count++]);
		}
	}

	switch (ctx->insn->id) {
	case XTENSA_INS_ADD: /* add */
	case XTENSA_INS_ADDX2: /* addx2 */
	case XTENSA_INS_ADDX4: /* addx4 */
	case XTENSA_INS_ADDX8: /* addx8 */
	case XTENSA_INS_ADD_N:
	case XTENSA_INS_ADD_S:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case XTENSA_INS_SUB: /* sub */
	case XTENSA_INS_SUBX2: /* subx2 */
	case XTENSA_INS_SUBX4: /* subx4 */
	case XTENSA_INS_SUBX8: /* subx8 */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case XTENSA_INS_MOVI:
	case XTENSA_INS_MOVI_N:
	case XTENSA_INS_MOV_S:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case XTENSA_INS_EXCW:
	case XTENSA_INS_NOP: /* nop.n */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case XTENSA_INS_S32I: /* s32i */
	case XTENSA_INS_S16I: /* s16i */
	case XTENSA_INS_S8I: /* s8i */
	case XTENSA_INS_S32I_N:
	case XTENSA_INS_S32C1I:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		if (XOP(1)->type == XTENSA_OP_MEM && MEM(1)->base == XTENSA_REG_SP) {
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		}
		break;
	case XTENSA_INS_ADDI: /* addi */
	case XTENSA_INS_ADDI_N: {
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		// a1 = stack
		if (REGI(0) == XTENSA_REG_SP && REGI(1) == XTENSA_REG_SP) {
			op->val = IMM(2);
			op->stackptr = -IMM(2);
			op->stackop = RZ_ANALYSIS_STACK_INC;
		}
		break;
	}
	case XTENSA_INS_RET: /* ret */
	case XTENSA_INS_RET_N:
	case XTENSA_INS_RETW_N:
		op->eob = true;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case XTENSA_INS_L16UI: /* l16ui */
	case XTENSA_INS_L16SI: /* l16si */
	case XTENSA_INS_L32I: /* l32i */
	case XTENSA_INS_L8UI: /* l8ui */
	case XTENSA_INS_L32I_N:
	case XTENSA_INS_L32R:
	case XTENSA_INS_L32E:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		if (XOP(1)->type == XTENSA_OP_MEM && MEM(1)->base == XTENSA_REG_SP) {
			op->type = RZ_ANALYSIS_OP_TYPE_POP;
		}
		break;
	case XTENSA_INS_ADDMI: /* addmi */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case XTENSA_INS_AND: /* and */
	case XTENSA_INS_OR: /* or */
	case XTENSA_INS_XOR: /* xor */
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case XTENSA_INS_BEQZ: /* beqz */
	case XTENSA_INS_BNEZ: /* bnez */
	case XTENSA_INS_BGEZ: /* bgez */
	case XTENSA_INS_BLTZ: /* bltz */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = ctx->insn->address + IMM(1);
		op->fail = ctx->insn->address + ctx->insn->size;
		op->cond = xtensa_cond(ctx->insn->id);
		break;
	case XTENSA_INS_BEQ:
	case XTENSA_INS_BNE:
	case XTENSA_INS_BGE:
	case XTENSA_INS_BLT:
	case XTENSA_INS_BGEU: /* bgeu */
	case XTENSA_INS_BLTU: /* bltu */
	case XTENSA_INS_BEQI: /* beqi */
	case XTENSA_INS_BNEI: /* bnei */
	case XTENSA_INS_BGEI: /* bgei */
	case XTENSA_INS_BLTI: /* blti */
	case XTENSA_INS_BGEUI: /* bgeui */
	case XTENSA_INS_BLTUI: /* bltui */
	case XTENSA_INS_BANY: /* bany */
	case XTENSA_INS_BNONE: /* bnone */
	case XTENSA_INS_BALL: /* ball */
	case XTENSA_INS_BNALL: /* bnall */
	case XTENSA_INS_BBCI: /* bbci */
	case XTENSA_INS_BBSI: /* bbsi */
	case XTENSA_INS_BBC: /* bbc */
	case XTENSA_INS_BBS: /* bbs */
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
	case XTENSA_INS_CALLX4:
	case XTENSA_INS_CALLX8:
	case XTENSA_INS_CALLX12:
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->reg = REGN(0);
		break;
	case XTENSA_INS_CALL0: /* call0 */
	case XTENSA_INS_CALL4:
	case XTENSA_INS_CALL8:
	case XTENSA_INS_CALL12:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = ctx->insn->address + IMM(0);
		op->fail = ctx->insn->address + ctx->insn->size;
		break;
	case XTENSA_INS_MOVEQZ: /* moveqz */
	case XTENSA_INS_MOVNEZ: /* movnez */
	case XTENSA_INS_MOVLTZ: /* movltz */
	case XTENSA_INS_MOVGEZ: /* movgez */
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;
	case XTENSA_INS_ABS: /* abs */
	case XTENSA_INS_ABS_S:
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
	.author = "billow",
	.license = "LGPL3",
	.arch = "xtensa",
	.bits = 8,
	.op = xtensa_op,
	.esil = true,
	.archinfo = xtensa_archinfo,
	.get_reg_profile = xtensa_get_reg_profile,
	.init = xtensa_init,
	.fini = xtensa_fini,
};
