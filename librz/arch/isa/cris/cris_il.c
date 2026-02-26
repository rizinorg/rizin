// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file cris_il.c
 * \brief RzIL lifting for CRIS instructions.
 */

#include "cris.h"
#include <rz_il/rz_il_opbuilder_begin.h>

static const char *il_gpr(ut8 reg, CrisIsaVersion ver) {
	return (ver == CRIS_ISA_V32) ? cris_gpr_names_v32[reg & 0xF]
				     : cris_gpr_names[reg & 0xF];
}

#define GPR(n)	 VARG(il_gpr(n, ctx->ver))
#define SETGPR(n, v) SETG(il_gpr(n, ctx->ver), v)
#define PC_VAL	 U32(ctx->pc)
#define IMM32(x) U32((ut32)(x))
#define SIMM32(x) S32((st32)(x))

/**
 * Set NZVC flags from a 32-bit result.
 */
static RzILOpEffect *update_flags_nzvc(RzILOpBitVector *result, RzILOpBitVector *op1, RzILOpBitVector *op2, bool is_sub) {
	// N = result[31]
	RzILOpEffect *set_n = SETG("N", MSB(DUP(result)));
	// Z = (result == 0)
	RzILOpEffect *set_z = SETG("Z", IS_ZERO(DUP(result)));

	return SEQ2(set_n, set_z);
}

/**
 * Set NZ flags only.
 */
static RzILOpEffect *update_flags_nz(RzILOpBitVector *result) {
	RzILOpEffect *set_n = SETG("N", MSB(DUP(result)));
	RzILOpEffect *set_z = SETG("Z", IS_ZERO(DUP(result)));
	return SEQ2(set_n, set_z);
}

RzAnalysisLiftedILOp cris_il_op(const CrisILContext *ctx) {
	const CrisInsn *insn = &ctx->insn;

	switch (insn->type) {
	// Quick immediate
	case CRIS_INSN_ADDQ: {
		RzILOpBitVector *result = ADD(GPR(insn->reg2), IMM32(insn->immediate));
		return (SEQ2(
			SETGPR(insn->reg2, result),
			update_flags_nz(GPR(insn->reg2))));
	}
	case CRIS_INSN_SUBQ: {
		RzILOpBitVector *result = SUB(GPR(insn->reg2), IMM32(insn->immediate));
		return (SEQ2(
			SETGPR(insn->reg2, result),
			update_flags_nz(GPR(insn->reg2))));
	}
	case CRIS_INSN_MOVEQ:
		return (SETGPR(insn->reg2, SIMM32(insn->immediate)));
	case CRIS_INSN_CMPQ: {
		RzILOpBitVector *result = SUB(GPR(insn->reg2), IMM32(insn->immediate));
		return (SEQ3(
			SETL("_result", result),
			SETG("N", MSB(VARL("_result"))),
			SETG("Z", IS_ZERO(VARL("_result")))));
	}
	case CRIS_INSN_ANDQ:
		return (SEQ2(
			SETGPR(insn->reg2, LOGAND(GPR(insn->reg2), IMM32(insn->immediate))),
			update_flags_nz(GPR(insn->reg2))));
	case CRIS_INSN_ORQ:
		return (SEQ2(
			SETGPR(insn->reg2, LOGOR(GPR(insn->reg2), IMM32(insn->immediate))),
			update_flags_nz(GPR(insn->reg2))));

	// Register-register
	case CRIS_INSN_ADD:
		return (SEQ2(
			SETGPR(insn->reg2, ADD(GPR(insn->reg2), GPR(insn->reg1))),
			update_flags_nz(GPR(insn->reg2))));
	case CRIS_INSN_SUB:
		return (SEQ2(
			SETGPR(insn->reg2, SUB(GPR(insn->reg2), GPR(insn->reg1))),
			update_flags_nz(GPR(insn->reg2))));
	case CRIS_INSN_CMP: {
		return (SEQ3(
			SETL("_result", SUB(GPR(insn->reg2), GPR(insn->reg1))),
			SETG("N", MSB(VARL("_result"))),
			SETG("Z", IS_ZERO(VARL("_result")))));
	}
	case CRIS_INSN_AND:
		return (SEQ2(
			SETGPR(insn->reg2, LOGAND(GPR(insn->reg2), GPR(insn->reg1))),
			update_flags_nz(GPR(insn->reg2))));
	case CRIS_INSN_OR:
		return (SEQ2(
			SETGPR(insn->reg2, LOGOR(GPR(insn->reg2), GPR(insn->reg1))),
			update_flags_nz(GPR(insn->reg2))));
	case CRIS_INSN_XOR:
		return (SEQ2(
			SETGPR(insn->reg2, LOGXOR(GPR(insn->reg2), GPR(insn->reg1))),
			update_flags_nz(GPR(insn->reg2))));
	case CRIS_INSN_MOVE_R:
		return (SETGPR(insn->reg2, GPR(insn->reg1)));
	case CRIS_INSN_NOT:
		return (SEQ2(
			SETGPR(insn->reg1, LOGNOT(GPR(insn->reg1))),
			update_flags_nz(GPR(insn->reg1))));
	case CRIS_INSN_NEG:
		return (SEQ2(
			SETGPR(insn->reg2, SUB(U32(0), GPR(insn->reg1))),
			update_flags_nz(GPR(insn->reg2))));

	// Shifts
	case CRIS_INSN_ASRQ:
		return (SEQ2(
			SETGPR(insn->reg2, SHIFTRA(GPR(insn->reg2), UN(5, insn->immediate))),
			update_flags_nz(GPR(insn->reg2))));
	case CRIS_INSN_LSLQ:
		return (SEQ2(
			SETGPR(insn->reg2, SHIFTL0(GPR(insn->reg2), UN(5, insn->immediate))),
			update_flags_nz(GPR(insn->reg2))));
	case CRIS_INSN_LSRQ:
		return (SEQ2(
			SETGPR(insn->reg2, SHIFTR0(GPR(insn->reg2), UN(5, insn->immediate))),
			update_flags_nz(GPR(insn->reg2))));

	// Branch
	case CRIS_INSN_BCC_8:
	case CRIS_INSN_BCC_16: {
		ut32 target = ctx->pc + insn->immediate;
		if (insn->cond == CRIS_CC_A) {
			return (JMP(U32(target)));
		}
		RzILOpBool *cond = NULL;
		switch (insn->cond) {
		case CRIS_CC_EQ: cond = VARG("Z"); break;
		case CRIS_CC_NE: cond = INV(VARG("Z")); break;
		case CRIS_CC_CC: cond = INV(VARG("C")); break;
		case CRIS_CC_CS: cond = VARG("C"); break;
		case CRIS_CC_PL: cond = INV(VARG("N")); break;
		case CRIS_CC_MI: cond = VARG("N"); break;
		case CRIS_CC_GE: cond = INV(XOR(VARG("N"), VARG("V"))); break;
		case CRIS_CC_LT: cond = XOR(VARG("N"), VARG("V")); break;
		case CRIS_CC_GT: cond = INV(OR(XOR(VARG("N"), VARG("V")), VARG("Z"))); break;
		case CRIS_CC_LE: cond = OR(XOR(VARG("N"), VARG("V")), VARG("Z")); break;
		case CRIS_CC_HI: cond = INV(OR(VARG("C"), VARG("Z"))); break;
		case CRIS_CC_LS: cond = OR(VARG("C"), VARG("Z")); break;
		default: cond = IL_FALSE; break;
		}
		return (BRANCH(cond, JMP(U32(target)), NOP()));
	}
	case CRIS_INSN_BA_DWORD:
		return (JMP(U32(ctx->pc + insn->immediate)));

	// Jump
	case CRIS_INSN_JUMP_R:
		return (JMP(GPR(insn->reg1)));
	case CRIS_INSN_JUMP_N:
		return (JMP(IMM32(insn->immediate)));
	case CRIS_INSN_JSR_R:
		return (SEQ2(
			SETG("srp", U32(ctx->pc + insn->size)),
			JMP(GPR(insn->reg1))));
	case CRIS_INSN_JSR_N:
		return (SEQ2(
			SETG("srp", U32(ctx->pc + insn->size)),
			JMP(IMM32(insn->immediate))));
	case CRIS_INSN_BSR:
		return (SEQ2(
			SETG("srp", U32(ctx->pc + insn->size)),
			JMP(U32(ctx->pc + insn->immediate))));

	// Return
	case CRIS_INSN_RET:
		return (JMP(VARG("srp")));

	// Memory
	case CRIS_INSN_MOVE_MR:
		if (insn->autoincr && insn->reg1 == 0xF) {
			return (SETGPR(insn->reg2, IMM32(insn->immediate)));
		} else {
			int width = (insn->sz == CRIS_SIZE_BYTE) ? 8
				: (insn->sz == CRIS_SIZE_WORD)	 ? 16
								 : 32;
			RzILOpEffect *load = SETGPR(insn->reg2,
				(width == 32) ? LOADW(32, GPR(insn->reg1))
					      : UNSIGNED(32, LOADW(width, GPR(insn->reg1))));
			if (insn->autoincr) {
				return (SEQ2(load,
					SETGPR(insn->reg1, ADD(GPR(insn->reg1), U32(width / 8)))));
			}
			return (load);
		}

	// NOP
	case CRIS_INSN_NOP:
		return (NOP());

	default:
		return (NOP());
	}
}

RzAnalysisILConfig *cris_il_config(RzAnalysis *a) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	return cfg;
}

#include <rz_il/rz_il_opbuilder_end.h>
