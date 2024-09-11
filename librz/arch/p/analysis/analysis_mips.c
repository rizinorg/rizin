// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <mips/mips_internal.h>

static ut64 t9_pre = UT64_MAX;
// http://www.mrc.uidaho.edu/mrc/people/jff/digital/MIPSir.html

#define OPERAND(x)  insn->detail->mips.operands[x]
#define REGID(x)    insn->detail->mips.operands[x].reg
#define REG(x)      cs_reg_name(*handle, insn->detail->mips.operands[x].reg)
#define IMM(x)      insn->detail->mips.operands[x].imm
#define MEMBASE(x)  cs_reg_name(*handle, insn->detail->mips.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->mips.operands[x].mem.index
#define MEMDISP(x)  insn->detail->mips.operands[x].mem.disp
#define OPCOUNT()   insn->detail->mips.op_count
// TODO scale and disp

#define SET_VAL(op, i) \
	if ((i) < OPCOUNT() && OPERAND(i).type == MIPS_OP_IMM) { \
		(op)->val = OPERAND(i).imm; \
	}

#define CREATE_SRC_DST_3(op) \
	(op)->src[0] = rz_analysis_value_new(); \
	(op)->src[1] = rz_analysis_value_new(); \
	(op)->dst = rz_analysis_value_new();

#define CREATE_SRC_DST_2(op) \
	(op)->src[0] = rz_analysis_value_new(); \
	(op)->dst = rz_analysis_value_new();

#define SET_SRC_DST_3_REGS(op) \
	CREATE_SRC_DST_3(op); \
	(op)->dst->reg = rz_reg_get(analysis->reg, REG(0), RZ_REG_TYPE_GPR); \
	(op)->dst->type = RZ_ANALYSIS_VAL_REG; \
	(op)->src[0]->reg = rz_reg_get(analysis->reg, REG(1), RZ_REG_TYPE_GPR); \
	(op)->src[0]->type = RZ_ANALYSIS_VAL_REG; \
	(op)->src[1]->reg = rz_reg_get(analysis->reg, REG(2), RZ_REG_TYPE_GPR); \
	(op)->src[1]->type = RZ_ANALYSIS_VAL_REG;

#define SET_SRC_DST_3_IMM(op) \
	CREATE_SRC_DST_3(op); \
	(op)->dst->reg = rz_reg_get(analysis->reg, REG(0), RZ_REG_TYPE_GPR); \
	(op)->dst->type = RZ_ANALYSIS_VAL_REG; \
	(op)->src[0]->reg = rz_reg_get(analysis->reg, REG(1), RZ_REG_TYPE_GPR); \
	(op)->src[0]->type = RZ_ANALYSIS_VAL_REG; \
	(op)->src[1]->imm = IMM(2); \
	(op)->src[1]->type = RZ_ANALYSIS_VAL_IMM;

#define SET_SRC_DST_2_REGS(op) \
	CREATE_SRC_DST_2(op); \
	(op)->dst->reg = rz_reg_get(analysis->reg, REG(0), RZ_REG_TYPE_GPR); \
	(op)->src[0]->reg = rz_reg_get(analysis->reg, REG(1), RZ_REG_TYPE_GPR);

#define SET_SRC_DST_3_REG_OR_IMM(op) \
	if (OPERAND(2).type == MIPS_OP_IMM) { \
		SET_SRC_DST_3_IMM(op); \
	} else if (OPERAND(2).type == MIPS_OP_REG) { \
		SET_SRC_DST_3_REGS(op); \
	}

static void opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_mips *x = &insn->detail->mips;
	for (i = 0; i < x->op_count; i++) {
		cs_mips_op *op = x->operands + i;
		pj_o(pj);
		switch (op->type) {
		case MIPS_OP_REG:
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		case MIPS_OP_IMM:
			pj_ks(pj, "type", "imm");
			pj_kN(pj, "value", op->imm);
			break;
		case MIPS_OP_MEM:
			pj_ks(pj, "type", "mem");
			if (op->mem.base != MIPS_REG_INVALID) {
				pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			}
			pj_kN(pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks(pj, "type", "invalid");
			break;
		}
		pj_end(pj); /* o operand */
	}
	pj_end(pj); /* a operands */
	pj_end(pj);

	rz_strbuf_init(buf);
	rz_strbuf_append(buf, pj_string(pj));
	pj_free(pj);
}

static int parse_reg_name(RzRegItem *reg, csh handle, cs_insn *insn, int reg_num) {
	if (!reg) {
		return -1;
	}
	switch (OPERAND(reg_num).type) {
	case MIPS_OP_REG:
		reg->name = (char *)cs_reg_name(handle, OPERAND(reg_num).reg);
		break;
	case MIPS_OP_MEM:
		if (OPERAND(reg_num).mem.base != MIPS_REG_INVALID) {
			reg->name = (char *)cs_reg_name(handle, OPERAND(reg_num).mem.base);
		}
	default:
		break;
	}
	return 0;
}

typedef struct {
	RzRegItem reg;
} MIPSContext;

static bool mips_init(void **user) {
	MIPSContext *ctx = RZ_NEW0(MIPSContext);
	rz_return_val_if_fail(ctx, false);
	*user = ctx;
	return true;
}

static void op_fillval(RzAnalysis *analysis, RzAnalysisOp *op, csh *handle, cs_insn *insn) {
	MIPSContext *ctx = (MIPSContext *)analysis->plugin_data;
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		if (OPERAND(1).type == MIPS_OP_MEM) {
			ZERO_FILL(ctx->reg);
			op->src[0] = rz_analysis_value_new();
			op->src[0]->type = RZ_ANALYSIS_VAL_MEM;
			op->src[0]->reg = &ctx->reg;
			parse_reg_name(op->src[0]->reg, *handle, insn, 1);
			op->src[0]->delta = OPERAND(1).mem.disp;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		if (OPERAND(1).type == MIPS_OP_MEM) {
			ZERO_FILL(ctx->reg);
			op->dst = rz_analysis_value_new();
			op->dst->type = RZ_ANALYSIS_VAL_MEM;
			op->dst->reg = &ctx->reg;
			parse_reg_name(op->dst->reg, *handle, insn, 1);
			op->dst->delta = OPERAND(1).mem.disp;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_SHL:
	case RZ_ANALYSIS_OP_TYPE_SHR:
	case RZ_ANALYSIS_OP_TYPE_SAR:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_OR:
		SET_SRC_DST_3_REG_OR_IMM(op);
		break;
	case RZ_ANALYSIS_OP_TYPE_MOV:
		if (OPCOUNT() == 2 && OPERAND(0).type == MIPS_OP_REG && OPERAND(1).type == MIPS_OP_REG) {
			SET_SRC_DST_2_REGS(op);
		} else {
			SET_SRC_DST_3_REG_OR_IMM(op);
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_DIV: // UDIV
		if (OPERAND(0).type == MIPS_OP_REG && OPERAND(1).type == MIPS_OP_REG && OPERAND(2).type == MIPS_OP_REG) {
			SET_SRC_DST_3_REGS(op);
		} else if (OPERAND(0).type == MIPS_OP_REG && OPERAND(1).type == MIPS_OP_REG) {
			SET_SRC_DST_2_REGS(op);
		} else {
			RZ_LOG_ERROR("mips: unknown div opcode at 0x%08" PFMT64x "\n", op->addr);
		}
		break;
	}
	if (insn && (insn->id == MIPS_INS_SLTI || insn->id == MIPS_INS_SLTIU)) {
		SET_SRC_DST_3_IMM(op);
	}
}

static void set_opdir(RzAnalysisOp *op) {
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		break;
	case RZ_ANALYSIS_OP_TYPE_LEA:
		op->direction = RZ_ANALYSIS_OP_DIR_REF;
		break;
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
		op->direction = RZ_ANALYSIS_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

static int analyze_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int n = 0, opsize = -1;
	csh hndl = 0;
	cs_insn *insn = NULL;
	cs_mode mode = 0;
	if (!cs_mode_from_cpu(analysis->cpu, analysis->features, analysis->bits, analysis->big_endian, &mode)) {
		return -1;
	}

	op->addr = addr;
	if (len < 4) {
		return -1;
	}
	op->size = 4;

	if (cs_open(CS_ARCH_MIPS, mode, &hndl) != CS_ERR_OK) {
		return -1;
	}
	cs_option(hndl, CS_OPT_DETAIL, CS_OPT_ON);

	n = cs_disasm(hndl, (ut8 *)buf, len, addr, 1, &insn);
	if (n < 1 || insn->size < 1) {
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("invalid");
		}
		goto beach;
	}
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s",
			insn->mnemonic,
			insn->op_str[0] ? " " : "",
			insn->op_str);
	}
	op->id = insn->id;
	opsize = op->size = insn->size;
	op->refptr = 0;
	switch (insn->id) {
	case MIPS_INS_INVALID:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	case MIPS_INS_LB:
	case MIPS_INS_LBU:
	case MIPS_INS_LBUX:
		op->refptr = 1;
		/* fallthrough */
	case MIPS_INS_LW:
	case MIPS_INS_LWC1:
	case MIPS_INS_LWC2:
	case MIPS_INS_LWL:
	case MIPS_INS_LWR:
	case MIPS_INS_LWXC1:
		if (!op->refptr) {
			op->refptr = 4;
		}
		/* fallthrough */
	case MIPS_INS_LD:
	case MIPS_INS_LDC1:
	case MIPS_INS_LDC2:
	case MIPS_INS_LDL:
	case MIPS_INS_LDR:
	case MIPS_INS_LDXC1:
		op->delay = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		if (!op->refptr) {
			op->refptr = 8;
		}
		switch (OPERAND(1).type) {
		case MIPS_OP_MEM:
#if CS_NEXT_VERSION < 6
			if (OPERAND(1).mem.base == MIPS_REG_GP) {
				op->ptr = analysis->gp + OPERAND(1).mem.disp;
				if (REGID(0) == MIPS_REG_T9) {
					t9_pre = op->ptr;
				}
			} else if (REGID(0) == MIPS_REG_T9) {
				t9_pre = UT64_MAX;
			}
#else
			if (OPERAND(1).mem.base == MIPS_REG_GP ||
				OPERAND(1).mem.base == MIPS_REG_GP_64) {
				op->ptr = analysis->gp + OPERAND(1).mem.disp;
				if (REGID(0) == MIPS_REG_T9 ||
					REGID(0) == MIPS_REG_T9_64) {
					t9_pre = op->ptr;
				}
			} else if (REGID(0) == MIPS_REG_T9 ||
				REGID(0) == MIPS_REG_T9_64) {
				t9_pre = UT64_MAX;
			}
#endif
			break;
		case MIPS_OP_IMM:
			op->ptr = OPERAND(1).imm;
			break;
		case MIPS_OP_REG:
			break;
		default:
			break;
		}
		break;
	case MIPS_INS_SD:
	case MIPS_INS_SW:
	case MIPS_INS_SB:
	case MIPS_INS_SH:
	case MIPS_INS_SWC1:
	case MIPS_INS_SWC2:
	case MIPS_INS_SWL:
	case MIPS_INS_SWR:
	case MIPS_INS_SWXC1:
		op->delay = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case MIPS_INS_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case MIPS_INS_SYSCALL:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
	case MIPS_INS_BREAK:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
#if CS_NEXT_VERSION > 5
	case MIPS_INS_JALR_HB:
	case MIPS_INS_JALRC:
	case MIPS_INS_JALRC_HB:
	case MIPS_INS_JALRS:
	case MIPS_INS_JALRS16:
#endif /* CS_NEXT_VERSION */
	case MIPS_INS_JALR:
		op->delay = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
#if CS_NEXT_VERSION < 6
		if (REGID(0) == MIPS_REG_25) {
			op->jump = t9_pre;
			t9_pre = UT64_MAX;
			op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		}
#else
		if (REGID(0) == MIPS_REG_T9 ||
			REGID(0) == MIPS_REG_T9_64) {
			op->jump = t9_pre;
			t9_pre = UT64_MAX;
			op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		}
#endif
		break;
#if CS_NEXT_VERSION >= 6
	case MIPS_INS_JRCADDIUSP:
		op->delay = 0;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = IMM(0);
		break;
#endif
	case MIPS_INS_JAL:
	case MIPS_INS_JALS:
	case MIPS_INS_JALX:
	case MIPS_INS_JRADDIUSP:
	case MIPS_INS_BAL:
		op->delay = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = IMM(0);
		break;
	case MIPS_INS_JIALC:
		op->delay = 0;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = IMM(0);
		break;
	case MIPS_INS_BGEZAL: // Branch on >=0 and link
	case MIPS_INS_BLTZAL: // Branch on <0 and link
	case MIPS_INS_BLTZALL: // "likely" versions
	case MIPS_INS_BGEZALL:
		op->delay = 1;
		if (OPERAND(0).type == MIPS_OP_IMM) {
			// this is a JAL
			op->jump = IMM(0);
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		} else {
			op->jump = IMM(1);
			op->fail = addr + (insn->size << 1);
			op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
		}
		break;
	case MIPS_INS_BGEZALC:
	case MIPS_INS_BLTZALC:
	case MIPS_INS_BLEZALC:
	case MIPS_INS_BGTZALC:
		// compact versions
		op->delay = 0;
		if (OPERAND(0).type == MIPS_OP_IMM) {
			// this is a JAL
			op->jump = IMM(0);
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		} else {
			op->jump = IMM(1);
			op->fail = addr + (insn->size << 1);
			op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
		}
		break;
	case MIPS_INS_LI:
	case MIPS_INS_LUI:
		SET_VAL(op, 1);
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case MIPS_INS_MOVE:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case MIPS_INS_ADD:
	case MIPS_INS_ADDI:
	case MIPS_INS_ADDU:
	case MIPS_INS_ADDIU:
	case MIPS_INS_DADD:
	case MIPS_INS_DADDI:
	case MIPS_INS_DADDIU:
		SET_VAL(op, 2);
		op->sign = (insn->id == MIPS_INS_ADDI || insn->id == MIPS_INS_ADD);
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (REGID(0) == MIPS_REG_T9) {
			t9_pre += IMM(2);
		}
		if (REGID(0) == MIPS_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -IMM(2);
		}
		break;
	case MIPS_INS_SUB:
	case MIPS_INS_SUBU:
	case MIPS_INS_DSUBU:
	case MIPS_INS_DSUB:
#if CS_NEXT_VERSION < 6
	case MIPS_INS_SUBV:
	case MIPS_INS_SUBVI:
	case MIPS_INS_FSUB:
	case MIPS_INS_FMSUB:
	case MIPS_INS_SUBS_S:
	case MIPS_INS_SUBS_U:
	case MIPS_INS_SUBUH:
	case MIPS_INS_SUBUH_R:
#else
	case MIPS_INS_SUBV_B:
	case MIPS_INS_SUBV_D:
	case MIPS_INS_SUBV_H:
	case MIPS_INS_SUBV_W:
	case MIPS_INS_SUBVI_B:
	case MIPS_INS_SUBVI_D:
	case MIPS_INS_SUBVI_H:
	case MIPS_INS_SUBVI_W:
	case MIPS_INS_FSUB_D:
	case MIPS_INS_FSUB_W:
	case MIPS_INS_FMSUB_D:
	case MIPS_INS_FMSUB_W:
	case MIPS_INS_SUBS_S_B:
	case MIPS_INS_SUBS_S_D:
	case MIPS_INS_SUBS_S_H:
	case MIPS_INS_SUBS_S_W:
	case MIPS_INS_SUBS_U_B:
	case MIPS_INS_SUBS_U_D:
	case MIPS_INS_SUBS_U_H:
	case MIPS_INS_SUBS_U_W:
	case MIPS_INS_SUBUH_QB:
	case MIPS_INS_SUBUH_R_QB:
#endif /* CS_NEXT_VERSION */
		SET_VAL(op, 2);
		op->sign = insn->id == MIPS_INS_SUB;
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
#if CS_NEXT_VERSION < 6
	case MIPS_INS_MULV:
	case MIPS_INS_MULSA:
	case MIPS_INS_FMUL:
#else
	case MIPS_INS_MULV_B:
	case MIPS_INS_MULV_D:
	case MIPS_INS_MULV_H:
	case MIPS_INS_MULV_W:
	case MIPS_INS_MULSA_W_PH:
	case MIPS_INS_MULSAQ_S_W_PH:
	case MIPS_INS_FMUL_D:
	case MIPS_INS_FMUL_W:
#endif /* CS_NEXT_VERSION */
	case MIPS_INS_MULT:
	case MIPS_INS_MUL:
	case MIPS_INS_DMULT:
	case MIPS_INS_DMULTU:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case MIPS_INS_XOR:
	case MIPS_INS_XORI:
		SET_VAL(op, 2);
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case MIPS_INS_AND:
	case MIPS_INS_ANDI:
		SET_VAL(op, 2);
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		if (REGID(0) == MIPS_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_ALIGN;
		}
		break;
	case MIPS_INS_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case MIPS_INS_OR:
	case MIPS_INS_ORI:
		SET_VAL(op, 2);
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case MIPS_INS_DIV:
	case MIPS_INS_DIVU:
	case MIPS_INS_DDIV:
	case MIPS_INS_DDIVU:
#if CS_NEXT_VERSION < 6
	case MIPS_INS_FDIV:
	case MIPS_INS_DIV_U:
#else
	case MIPS_INS_FDIV_D:
	case MIPS_INS_FDIV_W:
	case MIPS_INS_DIV_U_B:
	case MIPS_INS_DIV_U_D:
	case MIPS_INS_DIV_U_H:
	case MIPS_INS_DIV_U_W:
#endif /* CS_NEXT_VERSION */
	case MIPS_INS_DIV_S:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
#if CS_NEXT_VERSION < 6
	case MIPS_INS_CMPU:
	case MIPS_INS_CMPGU:
	case MIPS_INS_CMPGDU:
#else
	case MIPS_INS_CMPU_EQ_QB:
	case MIPS_INS_CMPGU_EQ_QB:
	case MIPS_INS_CMPGDU_EQ_QB:
#endif /* CS_NEXT_VERSION */
	case MIPS_INS_CMPI:
	case MIPS_INS_CMP:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case MIPS_INS_JIC:
		op->delay = 0;
		op->jump = IMM(0);
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		break;
	case MIPS_INS_J:
		op->delay = 1;
		op->jump = IMM(0);
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		break;
#if CS_NEXT_VERSION < 6
	case MIPS_INS_BZ:
	case MIPS_INS_BNZ:
	case MIPS_INS_BNEG:
	case MIPS_INS_BNEGI:
#else
	case MIPS_INS_BZ_B:
	case MIPS_INS_BZ_D:
	case MIPS_INS_BZ_H:
	case MIPS_INS_BZ_V:
	case MIPS_INS_BZ_W:
	case MIPS_INS_BNZ_B:
	case MIPS_INS_BNZ_D:
	case MIPS_INS_BNZ_H:
	case MIPS_INS_BNZ_V:
	case MIPS_INS_BNZ_W:
	case MIPS_INS_BNEG_B:
	case MIPS_INS_BNEG_D:
	case MIPS_INS_BNEG_H:
	case MIPS_INS_BNEG_W:
	case MIPS_INS_BNEGI_B:
	case MIPS_INS_BNEGI_D:
	case MIPS_INS_BNEGI_H:
	case MIPS_INS_BNEGI_W:
	case MIPS_INS_BGE:
	case MIPS_INS_BGEL:
	case MIPS_INS_BGEU:
	case MIPS_INS_BGEUL:
	case MIPS_INS_BGT:
	case MIPS_INS_BGTL:
	case MIPS_INS_BGTU:
	case MIPS_INS_BGTUL:
	case MIPS_INS_BLE:
	case MIPS_INS_BLEL:
	case MIPS_INS_BLEU:
	case MIPS_INS_BLEUL:
	case MIPS_INS_BLT:
	case MIPS_INS_BLTL:
	case MIPS_INS_BLTU:
	case MIPS_INS_BLTUL:
	case MIPS_INS_B16:
	case MIPS_INS_BADDU:
	case MIPS_INS_BALC:
	case MIPS_INS_BALIGN:
	case MIPS_INS_BALRSC:
	case MIPS_INS_BBEQZC:
	case MIPS_INS_BBIT0:
	case MIPS_INS_BBIT032:
	case MIPS_INS_BBIT1:
	case MIPS_INS_BBIT132:
	case MIPS_INS_BBNEZC:
	case MIPS_INS_BC:
	case MIPS_INS_BC16:
	case MIPS_INS_BC1EQZ:
	case MIPS_INS_BC1EQZC:
	case MIPS_INS_BC1F:
	case MIPS_INS_BC1FL:
	case MIPS_INS_BC1NEZ:
	case MIPS_INS_BC1NEZC:
	case MIPS_INS_BC1T:
	case MIPS_INS_BC1TL:
	case MIPS_INS_BC2EQZ:
	case MIPS_INS_BC2EQZC:
	case MIPS_INS_BC2NEZ:
	case MIPS_INS_BC2NEZC:
	case MIPS_INS_BCLRI_B:
	case MIPS_INS_BCLRI_D:
	case MIPS_INS_BCLRI_H:
	case MIPS_INS_BCLRI_W:
	case MIPS_INS_BCLR_B:
	case MIPS_INS_BCLR_D:
	case MIPS_INS_BCLR_H:
	case MIPS_INS_BCLR_W:
	case MIPS_INS_BEQC:
	case MIPS_INS_BEQIC:
	case MIPS_INS_BEQZ16:
	case MIPS_INS_BEQZALC:
	case MIPS_INS_BEQZC:
	case MIPS_INS_BEQZC16:
	case MIPS_INS_BGEC:
	case MIPS_INS_BGEIC:
	case MIPS_INS_BGEIUC:
	case MIPS_INS_BGEUC:
	case MIPS_INS_BGEZALS:
	case MIPS_INS_BLTC:
	case MIPS_INS_BLTIC:
	case MIPS_INS_BLTIUC:
	case MIPS_INS_BLTUC:
	case MIPS_INS_BLTZALS:
	case MIPS_INS_BMNZI_B:
	case MIPS_INS_BMNZ_V:
	case MIPS_INS_BMZI_B:
	case MIPS_INS_BMZ_V:
	case MIPS_INS_BNEC:
	case MIPS_INS_BNEIC:
	case MIPS_INS_BNEZ16:
	case MIPS_INS_BNEZALC:
	case MIPS_INS_BNEZC:
	case MIPS_INS_BNEZC16:
	case MIPS_INS_BNVC:
	case MIPS_INS_BOVC:
	case MIPS_INS_BPOSGE32:
	case MIPS_INS_BPOSGE32C:
	case MIPS_INS_BREAK16:
	case MIPS_INS_BRSC:
#endif /* CS_NEXT_VERSION */
	case MIPS_INS_B:
	case MIPS_INS_BEQ:
	case MIPS_INS_BNE:
	case MIPS_INS_BNEL:
	case MIPS_INS_BEQL:
	case MIPS_INS_BEQZ:
	case MIPS_INS_BNEZ:
	case MIPS_INS_BTEQZ:
	case MIPS_INS_BTNEZ:
	case MIPS_INS_BLTZ:
	case MIPS_INS_BLTZL:
	case MIPS_INS_BLEZ:
	case MIPS_INS_BLEZL:
	case MIPS_INS_BGEZ:
	case MIPS_INS_BGEZL:
	case MIPS_INS_BGTZ:
	case MIPS_INS_BGTZL:
	case MIPS_INS_BLEZC:
	case MIPS_INS_BGEZC:
	case MIPS_INS_BLTZC:
	case MIPS_INS_BGTZC:
		if (OPERAND(0).type == MIPS_OP_IMM) {
			op->jump = IMM(0);
		} else if (OPERAND(1).type == MIPS_OP_IMM) {
			op->jump = IMM(1);
		} else if (OPERAND(2).type == MIPS_OP_IMM) {
			op->jump = IMM(2);
		}
		op->fail = addr + insn->size;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->delay = 1;

		switch (insn->id) {
#if CS_NEXT_VERSION >= 6
		case MIPS_INS_B16:
#endif
		case MIPS_INS_B:
			op->fail = UT64_MAX;
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			break;
		case MIPS_INS_BEQ:
			if (OPCOUNT() == 1) {
				// BEQ $zero $zero is B
				op->fail = UT64_MAX;
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			}
			break;
#if CS_NEXT_VERSION >= 6
		case MIPS_INS_BALC:
		case MIPS_INS_BC16:
		case MIPS_INS_BEQC:
		case MIPS_INS_BEQIC:
		case MIPS_INS_BEQZALC:
		case MIPS_INS_BEQZC:
		case MIPS_INS_BGEC:
		case MIPS_INS_BGEIC:
		case MIPS_INS_BGEIUC:
		case MIPS_INS_BGEUC:
		case MIPS_INS_BLTC:
		case MIPS_INS_BLTIC:
		case MIPS_INS_BLTIUC:
		case MIPS_INS_BLTUC:
		case MIPS_INS_BNEC:
		case MIPS_INS_BNEIC:
		case MIPS_INS_BNEZALC:
		case MIPS_INS_BNEZC:
		case MIPS_INS_BNVC:
		case MIPS_INS_BOVC:
		case MIPS_INS_BRSC:
		case MIPS_INS_BEQZC16:
		case MIPS_INS_BNEZC16:
#endif
		case MIPS_INS_BLEZC:
		case MIPS_INS_BGEZC:
		case MIPS_INS_BLTZC:
		case MIPS_INS_BGTZC:
			// compact versions (no delay)
			op->delay = 0;
			break;
		default:
			break;
		}

		break;
#if CS_NEXT_VERSION >= 6
	case MIPS_INS_JRC16:
	case MIPS_INS_JR16:
	case MIPS_INS_JR_HB:
#endif
	case MIPS_INS_JR:
	case MIPS_INS_JRC:
#if CS_NEXT_VERSION < 6
		if (insn->id == MIPS_INS_JRC) {
#else
		if (insn->id == MIPS_INS_JRC ||
			insn->id == MIPS_INS_JRC16) {
#endif
			// compact versions (no delay)
			op->delay = 0;
		} else {
			op->delay = 1;
		}
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		// register is $ra, so jmp is a return
		if (insn->detail->mips.operands[0].reg == MIPS_REG_RA) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			t9_pre = UT64_MAX;
		}
#if CS_NEXT_VERSION < 6
		if (REGID(0) == MIPS_REG_25) {
#else
		if (REGID(0) == MIPS_REG_T9 ||
			REGID(0) == MIPS_REG_T9_64) {
#endif
			op->jump = t9_pre;
			t9_pre = UT64_MAX;
		}

		break;
	case MIPS_INS_SLT:
	case MIPS_INS_SLTI:
		op->sign = true;
		SET_VAL(op, 2);
		break;
	case MIPS_INS_SLTIU:
		SET_VAL(op, 2);
		break;
	case MIPS_INS_SRA:
#if CS_NEXT_VERSION < 6
	case MIPS_INS_SHRAV:
	case MIPS_INS_SHRAV_R:
	case MIPS_INS_SHRA:
	case MIPS_INS_SHRA_R:
#else
	case MIPS_INS_SHRA_PH:
	case MIPS_INS_SHRA_QB:
	case MIPS_INS_SHRA_R_PH:
	case MIPS_INS_SHRA_R_QB:
	case MIPS_INS_SHRA_R_W:
	case MIPS_INS_SHRAV_PH:
	case MIPS_INS_SHRAV_QB:
	case MIPS_INS_SHRAV_R_PH:
	case MIPS_INS_SHRAV_R_QB:
	case MIPS_INS_SHRAV_R_W:
	case MIPS_INS_SRA_B:
	case MIPS_INS_SRA_D:
	case MIPS_INS_SRA_H:
	case MIPS_INS_SRA_W:
	case MIPS_INS_SRAI_B:
	case MIPS_INS_SRAI_D:
	case MIPS_INS_SRAI_H:
	case MIPS_INS_SRAI_W:
	case MIPS_INS_SRAR_B:
	case MIPS_INS_SRAR_D:
	case MIPS_INS_SRAR_H:
	case MIPS_INS_SRAR_W:
	case MIPS_INS_SRARI_B:
	case MIPS_INS_SRARI_D:
	case MIPS_INS_SRARI_H:
	case MIPS_INS_SRARI_W:
	case MIPS_INS_SRAV:
#endif /* CS_NEXT_VERSION */
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		SET_VAL(op, 2);
		break;
#if CS_NEXT_VERSION < 6
	case MIPS_INS_SHRL:
#else
	case MIPS_INS_SHRL_PH:
	case MIPS_INS_SHRL_QB:
	case MIPS_INS_SHRLV_PH:
	case MIPS_INS_SHRLV_QB:
#endif /* CS_NEXT_VERSION */
	case MIPS_INS_SRLV:
	case MIPS_INS_SRL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		SET_VAL(op, 2);
		break;
	case MIPS_INS_SLLV:
	case MIPS_INS_SLL:
#if CS_NEXT_VERSION >= 6
		op->delay = 0;
		if (REGID(0) == MIPS_REG_INVALID) {
			// NOP
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		}
#endif /* CS_NEXT_VERSION */
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		SET_VAL(op, 2);
		break;
	}
beach:
	set_opdir(op);
	if (insn && mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		opex(&op->opex, hndl, insn);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		if (analyze_op_esil(analysis, op, addr, buf, len, &hndl, insn) != 0) {
			rz_strbuf_fini(&op->esil);
		}
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		op_fillval(analysis, op, &hndl, insn);
	}

	cs_free(insn, n);
	cs_close(&hndl);
	return opsize;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p = NULL;
	switch (analysis->bits) {
	default:
	case 32:
		p =
			"=PC    pc\n"
			"=SP    sp\n"
			"=BP    fp\n"
			"=SN    v0\n"
			"=A0    a0\n"
			"=A1    a1\n"
			"=A2    a2\n"
			"=A3    a3\n"
			"=R0    v0\n"
			"=R1    v1\n"
			"gpr	zero	.32	?	0\n"
			"gpr	at	.32	4	0\n"
			"gpr	v0	.32	8	0\n"
			"gpr	v1	.32	12	0\n"
			"gpr	a0	.32	16	0\n"
			"gpr	a1	.32	20	0\n"
			"gpr	a2	.32	24	0\n"
			"gpr	a3	.32	28	0\n"
			"gpr	t0	.32	32	0\n"
			"gpr	t1	.32	36	0\n"
			"gpr	t2 	.32	40	0\n"
			"gpr	t3 	.32	44	0\n"
			"gpr	t4 	.32	48	0\n"
			"gpr	t5 	.32	52	0\n"
			"gpr	t6 	.32	56	0\n"
			"gpr	t7 	.32	60	0\n"
			"gpr	s0	.32	64	0\n"
			"gpr	s1	.32	68	0\n"
			"gpr	s2	.32	72	0\n"
			"gpr	s3	.32	76	0\n"
			"gpr	s4 	.32	80	0\n"
			"gpr	s5 	.32	84	0\n"
			"gpr	s6 	.32	88	0\n"
			"gpr	s7 	.32	92	0\n"
			"gpr	t8 	.32	96	0\n"
			"gpr	t9 	.32	100	0\n"
			"gpr	k0 	.32	104	0\n"
			"gpr	k1 	.32	108	0\n"
			"gpr	gp 	.32	112	0\n"
			"gpr	sp	.32	116	0\n"
			"gpr	fp	.32	120	0\n"
			"gpr	ra	.32	124	0\n"
			"gpr	pc	.32	128	0\n"
			"gpr	hi	.32	132	0\n"
			"gpr	lo	.32	136	0\n"
			"gpr	t	.32	140	0\n";
		break;
	case 64:
		p =
			"=PC    pc\n"
			"=SP    sp\n"
			"=BP    fp\n"
			"=A0    a0\n"
			"=A1    a1\n"
			"=A2    a2\n"
			"=A3    a3\n"
			"=SN    v0\n"
			"=R0    v0\n"
			"=R1    v1\n"
			"gpr	zero	.64	?	0\n"
			"gpr	at	.64	8	0\n"
			"gpr	v0	.64	16	0\n"
			"gpr	v1	.64	24	0\n"
			"gpr	a0	.64	32	0\n"
			"gpr	a1	.64	40	0\n"
			"gpr	a2	.64	48	0\n"
			"gpr	a3	.64	56	0\n"
			"gpr	t0	.64	64	0\n"
			"gpr	t1	.64	72	0\n"
			"gpr	t2 	.64	80	0\n"
			"gpr	t3 	.64	88	0\n"
			"gpr	t4 	.64	96	0\n"
			"gpr	t5 	.64	104	0\n"
			"gpr	t6 	.64	112	0\n"
			"gpr	t7 	.64	120	0\n"
			"gpr	s0	.64	128	0\n"
			"gpr	s1	.64	136	0\n"
			"gpr	s2	.64	144	0\n"
			"gpr	s3	.64	152	0\n"
			"gpr	s4 	.64	160	0\n"
			"gpr	s5 	.64	168	0\n"
			"gpr	s6 	.64	176	0\n"
			"gpr	s7 	.64	184	0\n"
			"gpr	t8 	.64	192	0\n"
			"gpr	t9 	.64	200	0\n"
			"gpr	k0 	.64	208	0\n"
			"gpr	k1 	.64	216	0\n"
			"gpr	gp 	.64	224	0\n"
			"gpr	sp	.64	232	0\n"
			"gpr	fp	.64	240	0\n"
			"gpr	ra	.64	248	0\n"
			"gpr	pc	.64	256	0\n"
			"gpr	hi	.64	264	0\n"
			"gpr	lo	.64	272	0\n"
			"gpr	t	.64	280	0\n";
		break;
	}
	return rz_str_dup(p);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		// mips-16, micromips, nanomips uses 16-bits
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		// nanomips uses 48-bits
		return 6;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static RzList /*<RzSearchKeyword *>*/ *analysis_preludes(RzAnalysis *analysis) {
#define KW(d, ds, m, ms) rz_list_append(l, rz_search_keyword_new((const ut8 *)d, ds, (const ut8 *)m, ms, NULL))
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	KW("\x27\xbd\x00", 3, NULL, 0);
	return l;
}

static bool mips_fini(void *user) {
	MIPSContext *ctx = (MIPSContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_mips = {
	.name = "mips",
	.desc = "Capstone MIPS analyzer",
	.license = "BSD",
	.esil = true,
	.arch = "mips",
	.get_reg_profile = get_reg_profile,
	.archinfo = archinfo,
	.preludes = analysis_preludes,
	.bits = 16 | 32 | 64,
	.op = &analyze_op,
	.init = mips_init,
	.fini = mips_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_mips,
	.version = RZ_VERSION
};
#endif
