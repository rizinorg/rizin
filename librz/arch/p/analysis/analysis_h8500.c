// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <h8500/h8500.h>

#define NEXT_PC          (ctx->aop->addr + ctx->ins->size)
#define NOPS             (ctx->ins->num_operands)
#define IOP(I)           (ctx->ins->operands + (I))
#define IARG_MATCH(I, M) (ARG_MODE(ctx->ins->opcode_describe->args[I]) == M)

typedef struct {
	RzAnalysis *analysis;
	H8500Instruction *ins;
	RzAnalysisOp *aop;
} AContext;

static const H8500Operand *real_ea(const AContext *ctx) {
	return ctx->ins->ea_describe
		? &ctx->ins->ea
		: ctx->ins->num_operands == 1
		? IOP(0)
		: NULL;
}

static ut64 pc_relative(AContext *ctx) {
	const H8500Operand *ea = real_ea(ctx);
	if (!(ea && ARG_MODE(ea->flags) == AddrPCRel)) {
		rz_warn_if_reached();
		return NEXT_PC;
	}
	return (NEXT_PC + ea->disp);
}

static void h8500_op2val(AContext *ctx, RzAnalysisValue *av, H8500Operand *iop) {
	switch (iop->flags & ARG_MASK_AddressingMode) {
	case AddrREG:
		av->type = RZ_ANALYSIS_VAL_REG;
		av->reg = rz_reg_get(ctx->analysis->reg, h8500_reg_name(iop, iop->rn), RZ_REG_TYPE_ANY);
		break;
	case AddrIMM:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = iop->imm;
		break;
	case AddrAbs:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->absolute = iop->imm;
		break;
	case AddrPCRel:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->base =
			av->delta = iop->disp;
		break;
	case AddrRIDisp:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->reg = rz_reg_get(ctx->analysis->reg, h8500_reg_name(iop, iop->ri_disp.rn), RZ_REG_TYPE_ANY);
		av->delta = iop->ri_disp.disp;
		break;
	case AddrRI:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->reg = rz_reg_get(ctx->analysis->reg, h8500_reg_name(iop, iop->rn), RZ_REG_TYPE_ANY);
		break;
	case AddrRIPostInc:
	case AddrRIPreDec:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->reg = rz_reg_get(ctx->analysis->reg, h8500_reg_name(iop, iop->rn), RZ_REG_TYPE_ANY);
		break;
	default: break;
	}
}

static void h8500_analyze_val(AContext *ctx) {
	uint8_t srci = 0;

	for (uint8_t i = 0; i < NOPS; ++i) {
		H8500Operand *iop = IOP(i);
		RzAnalysisValue *av = rz_analysis_value_new();
		if (!av) {
			rz_warn_if_reached();
			return;
		}
		h8500_op2val(ctx, av, iop);
		if (NOPS > 1 && i < NOPS - 1) {
			av->access |= RZ_ANALYSIS_ACC_R;
			ctx->aop->src[srci++] = av;
		}
		if (NOPS == 1 || i == NOPS - 1) {
			av->access |= RZ_ANALYSIS_ACC_W;
			if (ctx->aop->dst) {
				rz_warn_if_reached();
			}
			if (srci > 0 && av == ctx->aop->src[srci - 1]) {
				av = rz_mem_dup(av, sizeof(RzAnalysisValue));
			}
			ctx->aop->dst = av;
		}
	}
}

static void h8500_analyze(AContext *ctx) {
	const H8500Operand *ea = NULL;
	switch (ctx->ins->opcode_describe->id) {
	case ADD_Q:
	case ADDS:
	case ADDX:
	case DADD:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case AND:
	case ANDC:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case Bcc:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		ctx->aop->jump = pc_relative(ctx);
		ctx->aop->fail = NEXT_PC;
		break;
	case BSR:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_CALL;
		ctx->aop->jump = pc_relative(ctx);
		ctx->aop->fail = NEXT_PC;
		break;
	case BCLR:
	case BNOT:
	case BSET:
	case BTST:
	case CLR:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case CMP:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case DIVXU:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case EXTS:
	case EXTU:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case JMP:
	case PJMP:
		ctx->aop->fail = NEXT_PC;
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_JMP;
		ea = real_ea(ctx);
		if (!ea) {
			rz_warn_if_reached();
			return;
		}
		switch (ARG_MODE(ea->flags)) {
		case AddrAbs:
			ctx->aop->jump = ea->aa;
			break;
		case AddrRI:
			ctx->aop->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
			ctx->aop->reg = h8500_reg_name(ea, ea->rn);
			break;
		case AddrRIDisp:
			ctx->aop->type = RZ_ANALYSIS_OP_TYPE_MJMP;
			ctx->aop->reg = h8500_reg_name(ea, ea->ri_disp.rn);
			ctx->aop->disp = ea->ri_disp.disp;
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		break;
	case JSR:
	case PJSR:
		ctx->aop->fail = NEXT_PC;
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_CALL;
		ea = real_ea(ctx);
		if (!ea) {
			rz_warn_if_reached();
			return;
		}
		switch (ARG_MODE(ea->flags)) {
		case AddrAbs:
			ctx->aop->jump = ea->aa;
			break;
		case AddrRI:
			ctx->aop->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
			ctx->aop->reg = h8500_reg_name(ea, ea->rn);
			break;
		case AddrRIDisp:
			ctx->aop->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			ctx->aop->reg = h8500_reg_name(ea, ea->ri_disp.rn);
			ctx->aop->disp = ea->ri_disp.disp;
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		break;
	case LDC:
	case LDM:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case LINK:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		ctx->aop->stackop = RZ_ANALYSIS_STACK_INC;
		ctx->aop->stackptr = (st64)IOP(0)->disp;
		break;
	case UNLK:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		ctx->aop->stackop = RZ_ANALYSIS_STACK_INC;
		ctx->aop->stackptr = 2;
		break;
	case MOV:
	case MOVFPE:
	case MOVTPE:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_MOV;
		if (ctx->ins->ea_describe && ARG_MODE(ctx->ins->ea.flags) == AddrRIDisp && ctx->ins->ea.ri_disp.rn == H8500_FP) {
			// match mov @(xx,fp), ri
			ctx->aop->type = RZ_ANALYSIS_OP_TYPE_POP;
		} else if (IARG_MATCH(0, AddrRIDisp) && IOP(0)->ri_disp.rn == H8500_FP && NOPS == 2) {
			// match mov @(xx,fp), ri
			ctx->aop->type = RZ_ANALYSIS_OP_TYPE_POP;
		} else if (IARG_MATCH(1, AddrRIDisp) && IOP(1)->ri_disp.rn == H8500_FP && NOPS == 2) {
			// match mov ri, @(xx,fp)
			ctx->aop->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		}
		break;
	case MULXU:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case NOP:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case NEG:
	case NOT:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case OR:
	case ORC:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;

	case PRTD:
	case PRTS:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_RET;
		ctx->aop->stackop = RZ_ANALYSIS_STACK_INC;
		ctx->aop->stackptr = (st64)IOP(0)->imm + 4;
		break;
	case ROTL:
	case ROTXL:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case ROTR:
	case ROTXR:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case RTD:
	case RTE:
	case RTS:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case SCB_F:
	case SCB_NE:
	case SCB_EQ:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case SHAL:
	case SHLL:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case SHAR:
	case SHLR:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case SLEEP:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case STC:
	case STM:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case SUB:
	case SUBS:
	case SUBX:
	case DSUB:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case SWAP:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case TAS:
	case TST:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case TRAPA:
	case TRAP_VS:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case XCH:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case XOR:
	case XORC:
		ctx->aop->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	}
}

static int h8500_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	H8500Instruction ins = { 0 };
	if (!h8500_instruction_parse(buf, len, &ins)) {
		return -1;
	}

	AContext ctx = {
		.analysis = analysis,
		.ins = &ins,
		.aop = op
	};
	op->addr = addr;
	h8500_analyze(&ctx);

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		H8500InstructionOpstr opstr = { 0 };
		if (h8500_instruction_get_opstr(&ins, &opstr)) {
			ctx.aop->mnemonic = rz_str_newf("%s%s%s", opstr.mnemonic, RZ_STR_ISEMPTY(opstr.ops_str) ? "" : " ", opstr.ops_str);
		}
	}

	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		h8500_analyze_val(&ctx);
	}

	op->size = ins.size;
	return ins.size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	char *p =
		"=PC	pc\n"
		"=SP	r7\n"
		"=BP	r6\n"
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

static int archinfo(RzAnalysis *analysis, RzAnalysisInfoType query) {

	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 6;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_h8500 = {
	.name = "h8500",
	.desc = "H8500 code analysis plugin",
	.license = "LGPL3",
	.arch = "h8500",
	.author = "billow",
	.bits = 16,
	.op = &h8500_op,
	.get_reg_profile = get_reg_profile,
	.archinfo = archinfo,
	.il_config = NULL,
	.preludes = NULL,
};
