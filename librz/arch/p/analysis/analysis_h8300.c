// SPDX-FileCopyrightText: 2012-2015 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2015 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2012-2015 Bhootravi <ravi2809@gmail.com>
// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>

#include <h8300/h8300_disas.h>

#define INS_OP(I) (cmd.ops[(I)])

static void h8300_op2val(RzAnalysis *analysis, H8300Instruction *cmd, RzAnalysisValue *av, H8300Operand *iop) {
	switch (iop->typ) {
	case H8300_OP_NONE: break;
	case H8300_OP_R8:
	case H8300_OP_R16:
	case H8300_OP_R32:
		av->type = RZ_ANALYSIS_VAL_REG;
		av->reg = rz_reg_get(analysis->reg, h8300_get_register_name(iop->reg), RZ_REG_TYPE_ANY);
		break;
	case H8300_OP_IMM:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = iop->imm;
		break;
	case H8300_OP_ABS:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->absolute = iop->imm;
		break;
	case H8300_OP_PCREL:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->base = cmd->pc;
		av->delta = iop->disp;
		break;
	case H8300_OP_MI8:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->memref = iop->imm;
		break;
	case H8300_OP_RD:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->reg = rz_reg_get(analysis->reg, h8300_get_register_name(iop->rd.reg), RZ_REG_TYPE_ANY);
		av->delta = iop->rd.disp;
		break;
	case H8300_OP_RI:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->reg = rz_reg_get(analysis->reg, h8300_get_register_name(iop->reg), RZ_REG_TYPE_ANY);
		break;
	case H8300_OP_RPOSTINC:
	case H8300_OP_RPREDEC:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->reg = rz_reg_get(analysis->reg, h8300_get_register_name(iop->reg), RZ_REG_TYPE_ANY);
		break;
	case H8300_OP_CCR:
		av->type = RZ_ANALYSIS_VAL_REG;
		av->reg = rz_reg_get(analysis->reg, "ccr", RZ_REG_TYPE_ANY);
		break;
	}
}

static void h8300_analyze_val(RzAnalysis *analysis, RzAnalysisOp *aop, H8300Instruction *cmd) {
	uint8_t srci = 0;
	for (uint8_t i = 0; i < cmd->ops_count; ++i) {
		H8300Operand *iop = cmd->ops + i;
		RzAnalysisValue *av = rz_analysis_value_new();
		if (!av) {
			rz_warn_if_reached();
			return;
		}
		h8300_op2val(analysis, cmd, av, iop);
		if (cmd->ops_count > 1 && i < cmd->ops_count - 1) {
			av->access |= RZ_ANALYSIS_ACC_R;
			aop->src[srci++] = av;
		}
		if (cmd->ops_count == 1 || i == cmd->ops_count - 1) {
			av->access |= RZ_ANALYSIS_ACC_W;
			if (aop->dst) {
				rz_warn_if_reached();
			}
			if (srci > 0 && av == aop->src[srci - 1]) {
				av = rz_mem_dup(av, sizeof(RzAnalysisValue));
			}
			aop->dst = av;
		}
	}
}

static int h8300_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int ret;
	H8300Instruction cmd = { 0 };

	if (!op) {
		return 2;
	}

	op->addr = addr;
	ret = op->size = h8300_decode_command(buf, len, &cmd, addr, analysis->cpu);

	if (ret < 0) {
		return ret;
	}

	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->id = cmd.id;

	switch (cmd.id) {
	case H8300_INSN_MOV_B:
	case H8300_INSN_MOV_W:
	case H8300_INSN_MOV_L:
	case H8300_INSN_EEPMOV_B:
	case H8300_INSN_EEPMOV_W:
	case H8300_INSN_MOVFPE:
	case H8300_INSN_MOVTPE:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		if (cmd.ops_count == 2) {
			H8300Operand *dst = &INS_OP(1);
			if (dst->typ == H8300_OP_R32 && dst->reg == 7) {
				op->stackop = RZ_ANALYSIS_STACK_SET;
			}
		}
		break;
	case H8300_INSN_LDC_B:
	case H8300_INSN_LDC_W:
	case H8300_INSN_BLD:
	case H8300_INSN_BILD:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case H8300_INSN_STC_B:
	case H8300_INSN_STC_W:
	case H8300_INSN_BST:
	case H8300_INSN_BIST:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case H8300_INSN_CMP_B:
	case H8300_INSN_CMP_W:
	case H8300_INSN_CMP_L:
	case H8300_INSN_BTST:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case H8300_INSN_AND_B:
	case H8300_INSN_AND_W:
	case H8300_INSN_AND_L:
	case H8300_INSN_ANDC:
	case H8300_INSN_BAND:
	case H8300_INSN_BIAND:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case H8300_INSN_RTS:
	case H8300_INSN_RTE:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 4;
		break;
	case H8300_INSN_SHAL_B:
	case H8300_INSN_SHAL_W:
	case H8300_INSN_SHAL_L:
		op->type = RZ_ANALYSIS_OP_TYPE_SAL;
		break;
	case H8300_INSN_SHAR_B:
	case H8300_INSN_SHAR_W:
	case H8300_INSN_SHAR_L:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case H8300_INSN_SHLL_B:
	case H8300_INSN_SHLL_W:
	case H8300_INSN_SHLL_L:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case H8300_INSN_SHLR_B:
	case H8300_INSN_SHLR_W:
	case H8300_INSN_SHLR_L:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case H8300_INSN_XOR_B:
	case H8300_INSN_XOR_W:
	case H8300_INSN_XOR_L:
	case H8300_INSN_XORC:
	case H8300_INSN_BXOR:
	case H8300_INSN_BIXOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case H8300_INSN_OR_B:
	case H8300_INSN_OR_W:
	case H8300_INSN_OR_L:
	case H8300_INSN_ORC:
	case H8300_INSN_BOR:
	case H8300_INSN_BIOR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case H8300_INSN_ADD_B:
	case H8300_INSN_ADD_W:
	case H8300_INSN_ADD_L:
	case H8300_INSN_ADDS:
	case H8300_INSN_ADDX:
	case H8300_INSN_INC_B:
	case H8300_INSN_INC_W:
	case H8300_INSN_INC_L:
	case H8300_INSN_DAA:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case H8300_INSN_SUB_B:
	case H8300_INSN_SUB_W:
	case H8300_INSN_SUB_L:
	case H8300_INSN_SUBS:
	case H8300_INSN_SUBX:
	case H8300_INSN_DEC_B:
	case H8300_INSN_DEC_W:
	case H8300_INSN_DEC_L:
	case H8300_INSN_DAS:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case H8300_INSN_MULXU_B:
	case H8300_INSN_MULXU_W:
	case H8300_INSN_MULXS_B:
	case H8300_INSN_MULXS_W:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case H8300_INSN_DIVXS_B:
	case H8300_INSN_DIVXS_W:
	case H8300_INSN_DIVXU_B:
	case H8300_INSN_DIVXU_W:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case H8300_INSN_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case H8300_INSN_BSR:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = cmd.pc + cmd.size + INS_OP(0).disp;
		break;
	case H8300_INSN_JSR:
		switch (cmd.fmt) {
		case H8300_INSN_FORMAT_RI:
			op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
			op->ireg = h8300_get_register_name(INS_OP(0).reg);
			break;
		case H8300_INSN_FORMAT_ABS:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = INS_OP(0).imm;
			break;
		case H8300_INSN_FORMAT_MI8:
			op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
			op->ptr = INS_OP(0).imm;
			op->disp = INS_OP(0).imm;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
			break;
		}
		op->fail = addr + cmd.size;
		op->stackop = RZ_ANALYSIS_STACK_DEC;
		op->stackptr = 4;
		break;
	case H8300_INSN_JMP:
		switch (cmd.fmt) {
		case H8300_INSN_FORMAT_RI:
			op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
			op->ireg = h8300_get_register_name(INS_OP(0).reg);
			break;
		case H8300_INSN_FORMAT_ABS:
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->jump = INS_OP(0).imm;
			break;
		case H8300_INSN_FORMAT_MI8:
			op->type = RZ_ANALYSIS_OP_TYPE_MJMP;
			op->ptr = INS_OP(0).imm;
			op->disp = INS_OP(0).imm;
			break;
		default: break;
		}
		op->fail = addr + cmd.size;
		break;
	case H8300_INSN_BRA:
	case H8300_INSN_BRN:
	case H8300_INSN_BHI:
	case H8300_INSN_BLS:
	case H8300_INSN_BCC:
	case H8300_INSN_BCS:
	case H8300_INSN_BNE:
	case H8300_INSN_BEQ:
	case H8300_INSN_BVC:
	case H8300_INSN_BVS:
	case H8300_INSN_BPL:
	case H8300_INSN_BMI:
	case H8300_INSN_BGE:
	case H8300_INSN_BLT:
	case H8300_INSN_BGT:
	case H8300_INSN_BLE:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + cmd.size + INS_OP(0).disp;
		op->fail = addr + cmd.size;
		break;
	case H8300_INSN_ROTR_B:
	case H8300_INSN_ROTXR_B:
	case H8300_INSN_ROTR_W:
	case H8300_INSN_ROTXR_W:
	case H8300_INSN_ROTR_L:
	case H8300_INSN_ROTXR_L:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case H8300_INSN_ROTL_B:
	case H8300_INSN_ROTL_W:
	case H8300_INSN_ROTL_L:
	case H8300_INSN_ROTXL_B:
	case H8300_INSN_ROTXL_W:
	case H8300_INSN_ROTXL_L:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case H8300_INSN_NEG_B:
	case H8300_INSN_NEG_W:
	case H8300_INSN_NEG_L:
	case H8300_INSN_NOT_B:
	case H8300_INSN_NOT_W:
	case H8300_INSN_NOT_L:
	case H8300_INSN_BNOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case H8300_INSN_EXTS_W:
	case H8300_INSN_EXTS_L:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case H8300_INSN_EXTU_W:
	case H8300_INSN_EXTU_L:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case H8300_INSN_POP_W:
	case H8300_INSN_POP_L:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = op->id == H8300_INSN_PUSH_W ? 2 : 4;
		break;
	case H8300_INSN_PUSH_W:
	case H8300_INSN_PUSH_L:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		op->stackop = RZ_ANALYSIS_STACK_DEC;
		op->stackptr = op->id == H8300_INSN_PUSH_W ? 2 : 4;
		break;
	case H8300_INSN_TRAPA:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case H8300_INSN_SLEEP:
	case H8300_INSN_BSET:
	case H8300_INSN_BCLR:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;

	case H8300_INSN_INVALID: break;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		H8300InstructionStr ins_str = { 0 };
		if (h8300_make_opstr(&cmd, &ins_str)) {
			op->mnemonic = rz_str_newf("%s%s%s", ins_str.instr, RZ_STR_ISEMPTY(ins_str.ops_str) ? "" : " ", ins_str.ops_str);
		} else {
			op->mnemonic = rz_str_dup("invalid");
		}
	}

	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		h8300_analyze_val(analysis, op, &cmd);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		h8300_analyze_op_esil(analysis, op, addr, buf);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		h8300_analyze_op_il(analysis, op, &cmd);
	}

	return ret;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	if (h8300_cpu_type(analysis->cpu) == CPU_H8300H) {
		char *p =
			"=PC	pc\n"
			"=SP	er7\n"
			"=A0	r0\n"
			"gpr	er0	.32	0	0\n"
			"gpr	r0	.16	0	0\n"
			"gpr	r0h	.8	0	0\n"
			"gpr	r0l	.8	1	0\n"
			"gpr	e0	.16	2	0\n"

			"gpr	er1	.32	4	0\n"
			"gpr	r1	.16	4	0\n"
			"gpr	r1h	.8	4	0\n"
			"gpr	r1l	.8	5	0\n"
			"gpr	e1	.16	6	0\n"

			"gpr	er2	.32	8	0\n"
			"gpr	r2	.16	8	0\n"
			"gpr	r2h	.8	8	0\n"
			"gpr	r2l	.8	9	0\n"
			"gpr	e2	.16	10	0\n"

			"gpr	er3	.32	12	0\n"
			"gpr	r3	.16	12	0\n"
			"gpr	r3h	.8	12	0\n"
			"gpr	r3l	.8	13	0\n"
			"gpr	e3	.16	14	0\n"

			"gpr	er4	.32	16	0\n"
			"gpr	r4	.16	16	0\n"
			"gpr	r4h	.8	16	0\n"
			"gpr	r4l	.8	17	0\n"
			"gpr	e4	.16	18	0\n"

			"gpr	er5	.32	20	0\n"
			"gpr	r5	.16	20	0\n"
			"gpr	r5h	.8	20	0\n"
			"gpr	r5l	.8	21	0\n"
			"gpr	e5	.16	22	0\n"

			"gpr	er6	.32	24	0\n"
			"gpr	r6	.16	24	0\n"
			"gpr	r6h	.8	24	0\n"
			"gpr	r6l	.8	25	0\n"
			"gpr	e6	.16	26	0\n"

			"gpr	er7	.32	28	0\n"
			"gpr	r7	.16	28	0\n"
			"gpr	r7h	.8	28	0\n"
			"gpr	r7l	.8	29	0\n"
			"gpr	e7	.16	30	0\n"

			"gpr	pc	.24	32	0\n"
			"gpr	ccr	.8	35	0\n"
			"gpr	I	.1	.287	0\n"
			"gpr	U1	.1	.286	0\n"
			"gpr	H	.1	.285	0\n"
			"gpr	U2	.1	.284	0\n"
			"gpr	N	.1	.283	0\n"
			"gpr	Z	.1	.282	0\n"
			"gpr	V	.1	.281	0\n"
			"gpr	C	.1	.280	0\n";
		return strdup(p);
	}
	char *p =
		"=PC	pc\n"
		"=SP	r7\n"
		"=A0	r0\n"
		"gpr	r0	.16	0	0\n"
		"gpr	r0h	.8	0	0\n"
		"gpr	r0l	.8	1	0\n"
		"gpr	r1	.16	2	0\n"
		"gpr	r1h	.8	2	0\n"
		"gpr	r1l	.8	3	0\n"
		"gpr	r2	.16	4	0\n"
		"gpr	r2h	.8	4	0\n"
		"gpr	r2l	.8	5	0\n"
		"gpr	r3	.16	6	0\n"
		"gpr	r3h	.8	6	0\n"
		"gpr	r3l	.8	7	0\n"
		"gpr	r4	.16	8	0\n"
		"gpr	r4h	.8	8	0\n"
		"gpr	r4l	.8	9	0\n"
		"gpr	r5	.16	10	0\n"
		"gpr	r5h	.8	10	0\n"
		"gpr	r5l	.8	11	0\n"
		"gpr	r6	.16	12	0\n"
		"gpr	r6h	.8	12	0\n"
		"gpr	r6l	.8	13	0\n"
		"gpr	r7	.16	14	0\n"
		"gpr	r7h	.8	14	0\n"
		"gpr	r7l	.8	15	0\n"
		"gpr	pc	.16	16	0\n"
		"gpr	ccr	.8	18	0\n"
		"gpr	I	.1	.151	0\n"
		"gpr	U1	.1	.150	0\n"
		"gpr	H	.1	.149	0\n"
		"gpr	U2	.1	.148	0\n"
		"gpr	N	.1	.147	0\n"
		"gpr	Z	.1	.146	0\n"
		"gpr	V	.1	.145	0\n"
		"gpr	C	.1	.144	0\n";
	return rz_str_dup(p);
}

static RzList /*<RzSearchKeyword *>*/ *h8300_preludes(RzAnalysis *analysis) {
#define KW(d, m) rz_list_append(kws, rz_search_keyword_new_hexmask(d, m))
	RzList *kws = rz_list_newf((RzListFree)rz_search_keyword_free);
	if (!kws) {
		return kws;
	}
	KW("01006df6", "ffffffff");
	return kws;
}

RzAnalysisPlugin rz_analysis_plugin_h8300 = {
	.name = "h8300",
	.desc = "H8300 code analysis plugin",
	.license = "LGPL3",
	.arch = "h8300",
	.bits = 16,
	.op = &h8300_op,
	.esil = true,
	.get_reg_profile = get_reg_profile,
	.il_config = h8300_il_config,
	.preludes = h8300_preludes,
};
