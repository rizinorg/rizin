// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_analysis.h>
#include "rz_reg.h"
#include "rz_util/rz_log.h"
#include <rz_asm.h>
#include <rz_lib.h>

#include <capstone/capstone.h>
#include <capstone/riscv.h>

#include "analysis_riscv_utils.h"
#include <rz_util/rz_str.h>

#define OPERAND(x)  insn->detail->riscv.operands[x]
#define REGID(x)    insn->detail->riscv.operands[x].reg
#define REG(x)      cs_reg_name(*handle, insn->detail->riscv.operands[x].reg)
#define IMM(x)      insn->detail->riscv.operands[x].imm
#define MEMBASE(x)  cs_reg_name(*handle, insn->detail->riscv.operands[x].mem.base)
#define MEMINDEX(x) insn->detail->riscv.operands[x].mem.index
#define MEMDISP(x)  insn->detail->riscv.operands[x].mem.disp
#define OPCOUNT()   insn->detail->riscv.op_count
// TODO scale and disp

#define NEXT_ADDRESS(op) (op->addr + op->size)

#define CREATE_SRC_DST_3(op) \
	(op)->src[0] = rz_analysis_value_new(); \
	(op)->src[1] = rz_analysis_value_new(); \
	(op)->dst = rz_analysis_value_new();

#define CREATE_SRC_DST_2(op) \
	(op)->src[0] = rz_analysis_value_new(); \
	(op)->dst = rz_analysis_value_new();

#define SET_SRC_DST_3_REGS(op) \
	CREATE_SRC_DST_3(op); \
	(op)->dst->reg = riscv_reg_get(analysis->reg, REG(0), RZ_REG_TYPE_GPR); \
	(op)->src[0]->reg = riscv_reg_get(analysis->reg, REG(1), RZ_REG_TYPE_GPR); \
	(op)->src[1]->reg = riscv_reg_get(analysis->reg, REG(2), RZ_REG_TYPE_GPR);

#define SET_SRC_DST_3_IMM(op) \
	CREATE_SRC_DST_3(op); \
	(op)->dst->reg = riscv_reg_get(analysis->reg, REG(0), RZ_REG_TYPE_GPR); \
	(op)->src[0]->reg = riscv_reg_get(analysis->reg, REG(1), RZ_REG_TYPE_GPR); \
	(op)->src[1]->imm = IMM(2);

#define SET_SRC_DST_2_REGS(op) \
	CREATE_SRC_DST_2(op); \
	(op)->dst->reg = riscv_reg_get(analysis->reg, REG(0), RZ_REG_TYPE_GPR); \
	(op)->src[0]->reg = riscv_reg_get(analysis->reg, REG(1), RZ_REG_TYPE_GPR);

#define SET_SRC_DST_3_REG_OR_IMM(op) \
	if (OPERAND(2).type == RISCV_OP_IMM) { \
		SET_SRC_DST_3_IMM(op); \
	} else if (OPERAND(2).type == RISCV_OP_REG) { \
		SET_SRC_DST_3_REGS(op); \
	}

static void set_stack_effect(RzAnalysisOp *op, cs_insn *insn);

static RzRegItem *riscv_reg_get(const RzReg *reg, const char *name, int type) {
	if (!reg || RZ_STR_ISEMPTY(name)) {
		RZ_LOG_DEBUG("riscv: reg (%p) or name (%p) is null (type %d)\n", reg, name, type);
		return NULL;
	}
	return rz_reg_get(reg, name, type);
}

static RzStructuredData *riscv_opex(csh handle, cs_insn *insn) {
	if (!insn->detail) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzStructuredData *opex = rz_structured_data_map_add_map(root, "opex");
	if (!opex) {
		rz_structured_data_free(root);
		return NULL;
	}

	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");
	cs_riscv *x = &insn->detail->riscv;
	for (st32 i = 0; i < x->op_count; i++) {
		cs_riscv_op *op = x->operands + i;
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
		switch (op->type) {
		case RISCV_OP_REG:
			rz_structured_data_map_add_string(operand, "type", "reg");
			rz_structured_data_map_add_string(operand, "value", cs_reg_name(handle, op->reg));
			break;
		case RISCV_OP_IMM:
			rz_structured_data_map_add_string(operand, "type", "imm");
			rz_structured_data_map_add_signed(operand, "value", op->imm);
			break;
		case RISCV_OP_MEM:
			rz_structured_data_map_add_string(operand, "type", "mem");
			if (op->mem.base != RISCV_REG_INVALID) {
				rz_structured_data_map_add_string(operand, "base", cs_reg_name(handle, op->mem.base));
			}
			rz_structured_data_map_add_signed(operand, "disp", op->mem.disp);
			break;
		default:
			rz_structured_data_map_add_string(operand, "type", "invalid");
			break;
		}
	}

	return root;
}

static int parse_reg_name(RzRegItem *reg, csh handle, cs_insn *insn, int reg_num) {
	if (!reg) {
		return -1;
	}
	switch (OPERAND(reg_num).type) {
	case RISCV_OP_REG:
		reg->name = (char *)cs_reg_name(handle, OPERAND(reg_num).reg);
		break;
	case RISCV_OP_MEM:
		if (OPERAND(reg_num).mem.base != RISCV_REG_INVALID) {
			reg->name = (char *)cs_reg_name(handle, OPERAND(reg_num).mem.base);
		}
	default:
		break;
	}
	return 0;
}

typedef struct {
	RzRegItem reg;
	csh hndl;
	int omode;
	int obits;
} RiscvContext;

static bool riscv_init(void **user) {
	RiscvContext *ctx = RZ_NEW0(RiscvContext);
	rz_return_val_if_fail(ctx, false);
	ctx->hndl = 0;
	ctx->omode = -1;
	ctx->obits = 32;
	*user = ctx;
	return true;
}

static void op_fillval(RzAnalysis *analysis, RzAnalysisOp *op, csh *handle, cs_insn *insn) {
	RiscvContext *ctx = (RiscvContext *)analysis->plugin_data;
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		if (OPERAND(1).type == RISCV_OP_MEM) {
			ZERO_FILL(ctx->reg);
			op->dst = rz_analysis_value_new();
			op->dst->type = RZ_ANALYSIS_VAL_REG;
			op->dst->reg = riscv_reg_get(analysis->reg, cs_reg_name(*handle, FIRST_WRITTEN_REGID(insn)), RZ_REG_TYPE_GPR);
			op->src[0] = rz_analysis_value_new();
			op->src[0]->type = RZ_ANALYSIS_VAL_MEM;
			op->src[0]->reg = &ctx->reg;
			parse_reg_name(op->src[0]->reg, *handle, insn, 1);
			op->src[0]->delta = OPERAND(1).mem.disp;
			op->src[0]->memref = op->refptr;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		if (OPERAND(1).type == RISCV_OP_MEM) {
			ZERO_FILL(ctx->reg);
			op->dst = rz_analysis_value_new();
			op->dst->type = RZ_ANALYSIS_VAL_MEM;
			op->dst->reg = &ctx->reg;
			parse_reg_name(op->dst->reg, *handle, insn, 1);
			op->dst->delta = OPERAND(1).mem.disp;
			op->dst->memref = op->refptr;
			op->src[0] = rz_analysis_value_new();
			op->src[0]->type = RZ_ANALYSIS_VAL_REG;
			op->src[0]->reg = riscv_reg_get(analysis->reg, cs_reg_name(*handle, FIRST_READ_REGID(insn)), RZ_REG_TYPE_GPR);
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
		SET_SRC_DST_3_REG_OR_IMM(op);
		break;
	case RZ_ANALYSIS_OP_TYPE_DIV: // UDIV
		if (OPERAND(0).type == RISCV_OP_REG && OPERAND(1).type == RISCV_OP_REG && OPERAND(2).type == RISCV_OP_REG) {
			SET_SRC_DST_3_REGS(op);
		} else if (OPERAND(0).type == RISCV_OP_REG && OPERAND(1).type == RISCV_OP_REG) {
			SET_SRC_DST_2_REGS(op);
		} else {
			RZ_LOG_ERROR("riscv: unknown div opcode at 0x%08" PFMT64x "\n", op->addr);
		}
		break;
	}
	if (insn && (insn->id == RISCV_INS_SLTI || insn->id == RISCV_INS_SLTIU)) {
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

static inline bool group_exists_in(uint8_t *groups, uint8_t groups_count, uint8_t group) {
	for (int i = 0; i < groups_count; i++) {
		if (groups[i] == group) {
			return true;
		}
	}
	return false;
}

static void set_op_sign(RzAnalysisOp *op, cs_insn *insn) {
	switch (insn->id) {
	// Signed loads
	case RISCV_INS_LB:
	case RISCV_INS_LH:
	case RISCV_INS_LW:
	case RISCV_INS_LD:
	case RISCV_INS_TH_LRB:
	case RISCV_INS_TH_LRH:
	case RISCV_INS_TH_LRW:
	case RISCV_INS_TH_LRD:
	// Core-V loads
	case RISCV_INS_CV_LB:
	case RISCV_INS_CV_LBU:
	case RISCV_INS_CV_LH:
	case RISCV_INS_CV_LHU:
	case RISCV_INS_CV_LW:
		op->sign = true;
		break;
	// Signed Arithmetic & Comparison
	case RISCV_INS_DIV:
	case RISCV_INS_DIVW:
	case RISCV_INS_REM:
	case RISCV_INS_REMW:
	case RISCV_INS_MULH:
	case RISCV_INS_MULHSU:
	case RISCV_INS_SLT:
	case RISCV_INS_SLTI:
	case RISCV_INS_SRA:
	case RISCV_INS_SRAI:
	case RISCV_INS_SRAW:
	case RISCV_INS_SRAIW:
	case RISCV_INS_C_SRAI64:
	case RISCV_INS_BLT:
	case RISCV_INS_BGE:
	// Atomic signed (AMOMIN/MAX)
	case RISCV_INS_AMOMAX_W:
	case RISCV_INS_AMOMAX_D:
	case RISCV_INS_AMOMIN_W:
	case RISCV_INS_AMOMIN_D:
	// Bitmanip signed
	case RISCV_INS_MIN:
	case RISCV_INS_MAX:
	// Core-V signs
	case RISCV_INS_CV_ABS:
	case RISCV_INS_CV_ABS_B:
	case RISCV_INS_CV_ABS_H:
	case RISCV_INS_CV_ADD_B:
	case RISCV_INS_CV_ADD_H:
	case RISCV_INS_CV_AVG_B:
	case RISCV_INS_CV_AVG_H:
	case RISCV_INS_CV_MAX_B:
	case RISCV_INS_CV_MAX_H:
	case RISCV_INS_CV_MIN_B:
	case RISCV_INS_CV_MIN_H:
	case RISCV_INS_CV_SUB_B:
	case RISCV_INS_CV_SUB_H:
		op->sign = true;
		break;
	// RV64 "W" instructions (result is sign-extended to 64 bits)
	case RISCV_INS_ADDW:
	case RISCV_INS_ADDIW:
	case RISCV_INS_SUBW:
	case RISCV_INS_MULW:
	case RISCV_INS_C_ADDW:
	case RISCV_INS_C_ADDIW:
	case RISCV_INS_C_SUBW:
		op->sign = true;
		break;
	// FP Comparison & Sign-Aware Ops
	case RISCV_INS_FEQ_S:
	case RISCV_INS_FLT_S:
	case RISCV_INS_FLE_S:
	case RISCV_INS_FEQ_D:
	case RISCV_INS_FLT_D:
	case RISCV_INS_FLE_D:
	case RISCV_INS_FEQ_H:
	case RISCV_INS_FLT_H:
	case RISCV_INS_FLE_H:
	case RISCV_INS_FMIN_S:
	case RISCV_INS_FMAX_S:
	case RISCV_INS_FMIN_D:
	case RISCV_INS_FMAX_D:
	case RISCV_INS_FMIN_H:
	case RISCV_INS_FMAX_H:
		op->sign = true;
		break;
	// Explicit sign extensions
	case RISCV_INS_SEXT_B:
	case RISCV_INS_SEXT_H:
	case RISCV_INS_C_SEXT_B:
	case RISCV_INS_C_SEXT_H:
		op->sign = true;
		break;
	default:
		break;
	}
}

static void set_op_data_size(RzAnalysisOp *op, cs_insn *insn) {
	switch (insn->id) {
	// 1 byte
	case RISCV_INS_LB:
	case RISCV_INS_LBU:
	case RISCV_INS_SB:
	case RISCV_INS_C_LBU:
	case RISCV_INS_C_SB:
	case RISCV_INS_TH_LRB:
	case RISCV_INS_TH_LRBU:
		op->refptr = 1;
		break;
	// 2 bytes
	case RISCV_INS_LH:
	case RISCV_INS_LHU:
	case RISCV_INS_SH:
	case RISCV_INS_FLH:
	case RISCV_INS_FSH:
	case RISCV_INS_C_LH:
	case RISCV_INS_C_LHU:
	case RISCV_INS_C_SH:
	case RISCV_INS_TH_LRH:
	case RISCV_INS_TH_LRHU:
		op->refptr = 2;
		break;
	// 4 bytes
	case RISCV_INS_LW:
	case RISCV_INS_LWU:
	case RISCV_INS_SW:
	case RISCV_INS_FLW:
	case RISCV_INS_FSW:
	case RISCV_INS_C_LW:
	case RISCV_INS_C_LWSP:
	case RISCV_INS_C_SW:
	case RISCV_INS_C_SWSP:
	case RISCV_INS_C_FLW:
	case RISCV_INS_C_FLWSP:
	case RISCV_INS_C_FSW:
	case RISCV_INS_C_FSWSP:
	case RISCV_INS_TH_LRW:
	case RISCV_INS_TH_LRWU:
	case RISCV_INS_LR_W:
	case RISCV_INS_LR_W_AQ:
	case RISCV_INS_LR_W_AQRL:
	case RISCV_INS_LR_W_RL:
	case RISCV_INS_SC_W:
	case RISCV_INS_SC_W_AQ:
	case RISCV_INS_SC_W_AQRL:
	case RISCV_INS_SC_W_RL:
	// Atomic 4-byte
	case RISCV_INS_AMOSWAP_W:
	case RISCV_INS_AMOADD_W:
	case RISCV_INS_AMOAND_W:
	case RISCV_INS_AMOOR_W:
	case RISCV_INS_AMOXOR_W:
	case RISCV_INS_AMOMAX_W:
	case RISCV_INS_AMOMIN_W:
	case RISCV_INS_AMOMAXU_W:
	case RISCV_INS_AMOMINU_W:
	case RISCV_INS_AMOCAS_W:
		op->refptr = 4;
		break;
	// 8 bytes
	case RISCV_INS_LD:
	case RISCV_INS_SD:
	case RISCV_INS_FLD:
	case RISCV_INS_FSD:
	case RISCV_INS_C_LD:
	case RISCV_INS_C_LDSP:
	case RISCV_INS_C_SD:
	case RISCV_INS_C_SDSP:
	case RISCV_INS_C_FLD:
	case RISCV_INS_C_FLDSP:
	case RISCV_INS_C_FSD:
	case RISCV_INS_C_FSDSP:
	case RISCV_INS_TH_LRD:
	case RISCV_INS_LR_D:
	case RISCV_INS_LR_D_AQ:
	case RISCV_INS_LR_D_AQRL:
	case RISCV_INS_LR_D_RL:
	case RISCV_INS_SC_D:
	case RISCV_INS_SC_D_AQ:
	case RISCV_INS_SC_D_AQRL:
	case RISCV_INS_SC_D_RL:
	// Atomic 8-byte
	case RISCV_INS_AMOSWAP_D:
	case RISCV_INS_AMOADD_D:
	case RISCV_INS_AMOAND_D:
	case RISCV_INS_AMOOR_D:
	case RISCV_INS_AMOXOR_D:
	case RISCV_INS_AMOMAX_D:
	case RISCV_INS_AMOMIN_D:
	case RISCV_INS_AMOMAXU_D:
	case RISCV_INS_AMOMINU_D:
	case RISCV_INS_AMOCAS_D:
		op->refptr = 8;
		break;
	// 16 bytes
	case RISCV_INS_AMOCAS_Q:
		op->refptr = 16;
		break;
	default:
		break;
	}
}

static void set_op_val(RzAnalysisOp *op, cs_insn *insn) {
	if (!insn->detail) {
		return;
	}

	uint8_t *groups = insn->detail->groups;
	uint8_t groups_count = insn->detail->groups_count;
	if (group_exists_in(groups, groups_count, RISCV_GRP_JUMP) ||
		group_exists_in(groups, groups_count, RISCV_GRP_CALL) ||
		group_exists_in(groups, groups_count, RISCV_GRP_BRANCH_RELATIVE)) {
		return;
	}

	// Exclude instructions where the immediate is a configuration bitfield
	// to prevent misleading ASCII hints
	switch (insn->id) {
	case RISCV_INS_VSETVLI:
	case RISCV_INS_VSETIVLI:
		return;
	}

	st64 imm = FIRST_IMM(insn);
	if (imm != INT64_MAX) {
		switch (insn->id) {
		case RISCV_INS_LUI:
		case RISCV_INS_C_LUI:
		case RISCV_INS_AUIPC:
			op->val = imm << 12;
			break;
		default:
			op->val = imm;
			break;
		}
	}
}

static void set_op_eob(RzAnalysisOp *op, cs_insn *insn) {
	switch (insn->id) {
	case RISCV_INS_JAL:
	case RISCV_INS_JALR:
	case RISCV_INS_TAIL:
	case RISCV_INS_JUMP:
	case RISCV_INS_BEQ:
	case RISCV_INS_BNE:
	case RISCV_INS_BLT:
	case RISCV_INS_BGE:
	case RISCV_INS_BLTU:
	case RISCV_INS_BGEU:
	case RISCV_INS_ECALL:
	case RISCV_INS_EBREAK:
	case RISCV_INS_MRET:
	case RISCV_INS_SRET:
	case RISCV_INS_DRET:
	case RISCV_INS_WFI:
	case RISCV_INS_CM_POPRET:
	case RISCV_INS_CM_POPRETZ:
	case RISCV_INS_CM_JT:
	case RISCV_INS_CM_JALT:
	case RISCV_INS_C_J:
	case RISCV_INS_C_JR:
	case RISCV_INS_C_JAL:
	case RISCV_INS_C_JALR:
	case RISCV_INS_C_BEQZ:
	case RISCV_INS_C_BNEZ:
	case RISCV_INS_C_EBREAK:
	// Core-V branches
	case RISCV_INS_CV_BEQIMM:
	case RISCV_INS_CV_BNEIMM:
		op->eob = true;
		break;
	default:
		break;
	}
}

static void set_op_cond(RzAnalysisOp *op, cs_insn *insn) {
	switch (insn->id) {
	case RISCV_INS_BEQ:
	case RISCV_INS_C_BEQZ:
	case RISCV_INS_CV_BEQIMM:
		op->cond = RZ_TYPE_COND_EQ;
		break;
	case RISCV_INS_BNE:
	case RISCV_INS_C_BNEZ:
	case RISCV_INS_CV_BNEIMM:
		op->cond = RZ_TYPE_COND_NE;
		break;
	case RISCV_INS_BLT:
		op->cond = RZ_TYPE_COND_LT;
		break;
	case RISCV_INS_BGE:
		op->cond = RZ_TYPE_COND_GE;
		break;
	case RISCV_INS_BLTU:
		op->cond = RZ_TYPE_COND_LO;
		break;
	case RISCV_INS_BGEU:
		op->cond = RZ_TYPE_COND_HS;
		break;
	default:
		op->cond = RZ_TYPE_COND_AL;
		break;
	}
}

static void set_op_family(RzAnalysisOp *op, cs_insn *insn) {
	if (op->type & RZ_ANALYSIS_OP_TYPE_SIMD) {
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
		return;
	}
	if (op->type & RZ_ANALYSIS_OP_TYPE_CRYPTO) {
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
		return;
	}

	if (op->type & RZ_ANALYSIS_OP_TYPE_SYNC) {
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD;
		return;
	}

	switch (insn->id) {
	// Virtualization
	case RISCV_INS_HFENCE_GVMA:
	case RISCV_INS_HFENCE_VVMA:
	case RISCV_INS_HLV_B:
	case RISCV_INS_HLV_BU:
	case RISCV_INS_HLV_D:
	case RISCV_INS_HLV_H:
	case RISCV_INS_HLV_HU:
	case RISCV_INS_HLV_W:
	case RISCV_INS_HLV_WU:
	case RISCV_INS_HLVX_HU:
	case RISCV_INS_HLVX_WU:
	case RISCV_INS_HSV_B:
	case RISCV_INS_HSV_D:
	case RISCV_INS_HSV_H:
	case RISCV_INS_HSV_W:
		op->family = RZ_ANALYSIS_OP_FAMILY_VIRT;
		break;
	// Crypto (if not already handled by type check)
	case RISCV_INS_AES32DSI:
	case RISCV_INS_AES32DSMI:
	case RISCV_INS_AES32ESI:
	case RISCV_INS_AES32ESMI:
	case RISCV_INS_AES64DS:
	case RISCV_INS_AES64DSM:
	case RISCV_INS_AES64ES:
	case RISCV_INS_AES64ESM:
	case RISCV_INS_AES64IM:
	case RISCV_INS_AES64KS1I:
	case RISCV_INS_AES64KS2:
	case RISCV_INS_SHA256SIG0:
	case RISCV_INS_SHA256SIG1:
	case RISCV_INS_SHA256SUM0:
	case RISCV_INS_SHA256SUM1:
	case RISCV_INS_SHA512SIG0:
	case RISCV_INS_SHA512SIG0H:
	case RISCV_INS_SHA512SIG0L:
	case RISCV_INS_SHA512SIG1:
	case RISCV_INS_SHA512SIG1H:
	case RISCV_INS_SHA512SIG1L:
	case RISCV_INS_SHA512SUM0:
	case RISCV_INS_SHA512SUM0R:
	case RISCV_INS_SHA512SUM1:
	case RISCV_INS_SHA512SUM1R:
	case RISCV_INS_SM3P0:
	case RISCV_INS_SM3P1:
	case RISCV_INS_SM4ED:
	case RISCV_INS_SM4KS:
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
		break;
	// Floating Point
	case RISCV_INS_FADD_S:
	case RISCV_INS_FADD_D:
	case RISCV_INS_FADD_H:
	case RISCV_INS_FSUB_S:
	case RISCV_INS_FSUB_D:
	case RISCV_INS_FSUB_H:
	case RISCV_INS_FMUL_S:
	case RISCV_INS_FMUL_D:
	case RISCV_INS_FMUL_H:
	case RISCV_INS_FDIV_S:
	case RISCV_INS_FDIV_D:
	case RISCV_INS_FDIV_H:
	case RISCV_INS_FSQRT_S:
	case RISCV_INS_FSQRT_D:
	case RISCV_INS_FSQRT_H:
	case RISCV_INS_FMIN_S:
	case RISCV_INS_FMIN_D:
	case RISCV_INS_FMIN_H:
	case RISCV_INS_FMAX_S:
	case RISCV_INS_FMAX_D:
	case RISCV_INS_FMAX_H:
	case RISCV_INS_FEQ_S:
	case RISCV_INS_FEQ_D:
	case RISCV_INS_FEQ_H:
	case RISCV_INS_FLT_S:
	case RISCV_INS_FLT_D:
	case RISCV_INS_FLT_H:
	case RISCV_INS_FLE_S:
	case RISCV_INS_FLE_D:
	case RISCV_INS_FLE_H:
	case RISCV_INS_FMADD_S:
	case RISCV_INS_FMADD_D:
	case RISCV_INS_FMADD_H:
	case RISCV_INS_FMSUB_S:
	case RISCV_INS_FMSUB_D:
	case RISCV_INS_FMSUB_H:
	case RISCV_INS_FNMADD_S:
	case RISCV_INS_FNMADD_D:
	case RISCV_INS_FNMADD_H:
	case RISCV_INS_FNMSUB_S:
	case RISCV_INS_FNMSUB_D:
	case RISCV_INS_FNMSUB_H:
	case RISCV_INS_FCVT_S_D:
	case RISCV_INS_FCVT_D_S:
	case RISCV_INS_FCVT_W_S:
	case RISCV_INS_FCVT_WU_S:
	case RISCV_INS_FCVT_S_W:
	case RISCV_INS_FCVT_S_WU:
	case RISCV_INS_FLW:
	case RISCV_INS_FSW:
	case RISCV_INS_FLD:
	case RISCV_INS_FSD:
	case RISCV_INS_FLH:
	case RISCV_INS_FSH:
	case RISCV_INS_C_FLW:
	case RISCV_INS_C_FLWSP:
	case RISCV_INS_C_FSW:
	case RISCV_INS_C_FSWSP:
	case RISCV_INS_C_FLD:
	case RISCV_INS_C_FLDSP:
	case RISCV_INS_C_FSD:
	case RISCV_INS_C_FSDSP:
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		break;
	// Privileged / System
	case RISCV_INS_ECALL:
	case RISCV_INS_EBREAK:
	case RISCV_INS_MRET:
	case RISCV_INS_SRET:
	case RISCV_INS_DRET:
	case RISCV_INS_WFI:
	case RISCV_INS_CSRRW:
	case RISCV_INS_CSRRS:
	case RISCV_INS_CSRRC:
	case RISCV_INS_CSRRWI:
	case RISCV_INS_CSRRSI:
	case RISCV_INS_CSRRCI:
	case RISCV_INS_SFENCE_VMA:
	case RISCV_INS_SINVAL_VMA:
	case RISCV_INS_SFENCE_W_INVAL:
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		break;
	// Atomic (Thread/Sync)
	case RISCV_INS_FENCE:
	case RISCV_INS_FENCE_I:
	case RISCV_INS_FENCE_TSO:
	case RISCV_INS_ALIAS_PAUSE:
	case RISCV_INS_LR_W:
	case RISCV_INS_LR_D:
	case RISCV_INS_SC_W:
	case RISCV_INS_SC_D:
	case RISCV_INS_AMOSWAP_W:
	case RISCV_INS_AMOSWAP_D:
	case RISCV_INS_AMOADD_W:
	case RISCV_INS_AMOADD_D:
	case RISCV_INS_AMOAND_W:
	case RISCV_INS_AMOAND_D:
	case RISCV_INS_AMOOR_W:
	case RISCV_INS_AMOOR_D:
	case RISCV_INS_AMOXOR_W:
	case RISCV_INS_AMOXOR_D:
	case RISCV_INS_AMOMAX_W:
	case RISCV_INS_AMOMAX_D:
	case RISCV_INS_AMOMIN_W:
	case RISCV_INS_AMOMIN_D:
	case RISCV_INS_AMOMAXU_W:
	case RISCV_INS_AMOMAXU_D:
	case RISCV_INS_AMOMINU_W:
	case RISCV_INS_AMOMINU_D:
	case RISCV_INS_AMOCAS_W:
	case RISCV_INS_AMOCAS_D:
	case RISCV_INS_AMOCAS_Q:
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD;
		break;
	default:
		op->family = RZ_ANALYSIS_OP_FAMILY_CPU;
		break;
	}
}

static void set_op_extra_metadata(RzAnalysis *analysis, RzAnalysisOp *op, csh handle, cs_insn *insn) {
	if (!insn->detail) {
		return;
	}
	// Set destination register name
	if (insn->detail->riscv.op_count > 0 && insn->detail->riscv.operands[0].type == RISCV_OP_REG && (insn->detail->riscv.operands[0].access & CS_AC_WRITE)) {
		op->reg = cs_reg_name(handle, insn->detail->riscv.operands[0].reg);
	}

	// Set indirect register name (base for loads/stores)
	for (int i = 0; i < insn->detail->riscv.op_count; i++) {
		if (insn->detail->riscv.operands[i].type == RISCV_OP_MEM) {
			op->ireg = cs_reg_name(handle, insn->detail->riscv.operands[i].mem.base);
			op->disp = insn->detail->riscv.operands[i].mem.disp;
			break;
		}
	}

	// Set datatype
	if (op->family == RZ_ANALYSIS_OP_FAMILY_FPU) {
		op->datatype = RZ_ANALYSIS_DATATYPE_FLOAT;
	} else if (op->type & RZ_ANALYSIS_OP_TYPE_LOAD || op->type & RZ_ANALYSIS_OP_TYPE_STORE) {
		switch (op->refptr) {
		case 2: op->datatype = RZ_ANALYSIS_DATATYPE_INT16; break;
		case 4: op->datatype = RZ_ANALYSIS_DATATYPE_INT32; break;
		case 8: op->datatype = RZ_ANALYSIS_DATATYPE_INT64; break;
		default: break;
		}
	}
}

int analyze_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	RiscvContext *ctx = (RiscvContext *)analysis->plugin_data;
	int n, ret, opsize = -1;
	cs_insn *insn;
	cs_mode mode = (analysis->bits == 64) ? CS_MODE_RISCV64 : CS_MODE_RISCV32;
	mode |= mode_from_arch_string(analysis->cpu);

	if (mode != ctx->omode || analysis->bits != ctx->obits || cs_option(ctx->hndl, CS_OPT_DETAIL, CS_OPT_ON | CS_OPT_DETAIL_REAL) != CS_ERR_OK) {
		cs_close(&ctx->hndl);
		ctx->hndl = 0;
		ctx->omode = mode;
		ctx->obits = analysis->bits;
	}

	op->addr = addr;
	if (len < 2) {
		return -1;
	}
	op->size = 4;
	if (ctx->hndl == 0) {
		ret = cs_open(CS_ARCH_RISCV, mode, &ctx->hndl);
		if (ret != CS_ERR_OK) {
			goto fin;
		}
		cs_option(ctx->hndl, CS_OPT_DETAIL, CS_OPT_ON);
	}
	n = cs_disasm(ctx->hndl, (ut8 *)buf, len, addr, 1, &insn);

	if (n < 1 || insn->size < 1) {
		goto beach;
	}
	op->id = insn->id;
	opsize = op->size = insn->size;

	switch (insn->id) {
	case RISCV_INS_C_NOP:
	case RISCV_INS_CMOP_1:
	case RISCV_INS_CMOP_3:
	case RISCV_INS_CMOP_5:
	case RISCV_INS_CMOP_7:
	case RISCV_INS_CMOP_9:
	case RISCV_INS_CMOP_11:
	case RISCV_INS_CMOP_13:
	case RISCV_INS_CMOP_15:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;

	case RISCV_INS_INVALID:
	case RISCV_INS_UNIMP:
	case RISCV_INS_C_UNIMP:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;

	case RISCV_INS_C_JALR:
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->fail = UINT64_MAX;
		break;

	case RISCV_INS_C_JR:
		if (group_exists_in(insn->detail->groups, insn->detail->groups_count, RISCV_GRP_RET)) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		}
		op->fail = UINT64_MAX;
		break;

	case RISCV_INS_JUMP:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		break;

	case RISCV_INS_C_J:
	case RISCV_INS_C_JAL: {
		bool is_call = insn->id == RISCV_INS_C_JAL;
		op->type = is_call ? RZ_ANALYSIS_OP_TYPE_CALL : RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = SINGLE_IMM(insn);
		op->fail = UINT64_MAX;
		break;
	}

	case RISCV_INS_JALR:
		if (group_exists_in(insn->detail->groups, insn->detail->groups_count, RISCV_GRP_RET)) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			break;
		}
		// no fallthrough
		op->fail = UINT64_MAX;
		// special case: known base register, namely the always-0 register
		bool is_known_base = FIRST_READ_REGID(insn) == RISCV_REG_X0;

		if (group_exists_in(insn->detail->groups, insn->detail->groups_count, RISCV_GRP_CALL)) {
			op->type = is_known_base ? RZ_ANALYSIS_OP_TYPE_CALL : RZ_ANALYSIS_OP_TYPE_RCALL;
		} else {
			op->type = is_known_base ? RZ_ANALYSIS_OP_TYPE_JMP : RZ_ANALYSIS_OP_TYPE_RJMP;
		}
		if (is_known_base) {
			op->jump = SINGLE_IMM(insn);
		}
		break;

	case RISCV_INS_JAL: {
		bool is_call = group_exists_in(insn->detail->groups, insn->detail->groups_count, RISCV_GRP_CALL);
		op->type = is_call ? RZ_ANALYSIS_OP_TYPE_CALL : RZ_ANALYSIS_OP_TYPE_JMP;

		op->jump = SINGLE_IMM(insn);
		op->fail = UINT64_MAX;
		break;
	}

	case RISCV_INS_CM_JALT:
		op->type = RZ_ANALYSIS_OP_TYPE_ICALL;
		break;

	case RISCV_INS_CM_JT:
		op->type = RZ_ANALYSIS_OP_TYPE_IJMP;
		break;

	case RISCV_INS_AUIPC:
	case RISCV_INS_ADD:
	case RISCV_INS_ADDW:
	case RISCV_INS_ADDI:
	case RISCV_INS_ADDIW:
	case RISCV_INS_C_ADD:
	case RISCV_INS_C_ADDI:
	case RISCV_INS_C_ADDW:
	case RISCV_INS_C_ADDIW:
	case RISCV_INS_C_ADDI16SP:
	case RISCV_INS_C_ADDI4SPN:
	case RISCV_INS_FADD_H:
	case RISCV_INS_FADD_S:
	case RISCV_INS_FADD_D:
	case RISCV_INS_TH_ADDSL:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case RISCV_INS_SUB:
	case RISCV_INS_SUBW:
	case RISCV_INS_C_SUB:
	case RISCV_INS_C_SUBW:
	case RISCV_INS_FSUB_H:
	case RISCV_INS_FSUB_S:
	case RISCV_INS_FSUB_D:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case RISCV_INS_MUL:
	case RISCV_INS_MULW:
	case RISCV_INS_MULH:
	case RISCV_INS_MULHU:
	case RISCV_INS_MULHSU:
	case RISCV_INS_C_MUL:
	case RISCV_INS_FMUL_H:
	case RISCV_INS_FMUL_S:
	case RISCV_INS_FMUL_D:
	case RISCV_INS_CLMUL:
	case RISCV_INS_CLMULH:
	case RISCV_INS_CLMULR:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;

	case RISCV_INS_DIV:
	case RISCV_INS_DIVU:
	case RISCV_INS_DIVW:
	case RISCV_INS_DIVUW:
	case RISCV_INS_FDIV_H:
	case RISCV_INS_FDIV_S:
	case RISCV_INS_FDIV_D:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case RISCV_INS_REM:
	case RISCV_INS_REMU:
	case RISCV_INS_REMW:
	case RISCV_INS_REMUW:
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;

	case RISCV_INS_C_MV:
	case RISCV_INS_LUI:
	case RISCV_INS_LI:
	case RISCV_INS_LA:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	// normal loads of various sizes
	case RISCV_INS_LB:
	case RISCV_INS_LBU:
	case RISCV_INS_LH:
	case RISCV_INS_LHU:
	case RISCV_INS_LW:
	case RISCV_INS_LWU:
	case RISCV_INS_LD:
	case RISCV_INS_C_LBU:
	case RISCV_INS_C_LH:
	case RISCV_INS_C_LHU:
	case RISCV_INS_C_LW:
	case RISCV_INS_C_LWSP:
	case RISCV_INS_C_LD:
	case RISCV_INS_C_LDSP:
	// FP loads
	case RISCV_INS_FLH:
	case RISCV_INS_FLW:
	case RISCV_INS_FLD:
	case RISCV_INS_C_FLD:
	case RISCV_INS_C_FLDSP:
	case RISCV_INS_C_FLW:
	case RISCV_INS_C_FLWSP:
	// atomic loads
	case RISCV_INS_LR_D:
	case RISCV_INS_LR_D_AQ:
	case RISCV_INS_LR_D_AQRL:
	case RISCV_INS_LR_D_RL:
	case RISCV_INS_LR_W:
	case RISCV_INS_LR_W_AQ:
	case RISCV_INS_LR_W_AQRL:
	case RISCV_INS_LR_W_RL:
	// T-Head loads
	case RISCV_INS_TH_LRB:
	case RISCV_INS_TH_LRBU:
	case RISCV_INS_TH_LRD:
	case RISCV_INS_TH_LRH:
	case RISCV_INS_TH_LRHU:
	case RISCV_INS_TH_LRW:
	case RISCV_INS_TH_LRWU:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;

	case RISCV_INS_SB:
	case RISCV_INS_SH:
	case RISCV_INS_SW:
	case RISCV_INS_SD:
	case RISCV_INS_FSH:
	case RISCV_INS_FSW:
	case RISCV_INS_FSD:
	case RISCV_INS_C_FSD:
	case RISCV_INS_C_FSDSP:
	case RISCV_INS_C_FSW:
	case RISCV_INS_C_FSWSP:
	case RISCV_INS_C_SB:
	case RISCV_INS_C_SH:
	case RISCV_INS_C_SW:
	case RISCV_INS_C_SD:
	case RISCV_INS_C_SWSP:
	case RISCV_INS_C_SDSP:
	case RISCV_INS_SC_D:
	case RISCV_INS_SC_D_AQ:
	case RISCV_INS_SC_D_AQRL:
	case RISCV_INS_SC_D_RL:
	case RISCV_INS_SC_W:
	case RISCV_INS_SC_W_AQ:
	case RISCV_INS_SC_W_AQRL:
	case RISCV_INS_SC_W_RL:

	case RISCV_INS_WRS_NTO:
	case RISCV_INS_WRS_STO:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case RISCV_INS_AND:
	case RISCV_INS_ANDI:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case RISCV_INS_OR:
	case RISCV_INS_ORI:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;

	case RISCV_INS_XOR:
	case RISCV_INS_XORI:
	case RISCV_INS_C_NOT:
	case RISCV_INS_XNOR:
	case RISCV_INS_C_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;

	case RISCV_INS_SLL:
	case RISCV_INS_SLLI:
	case RISCV_INS_SLLW:
	case RISCV_INS_SLLIW:
	case RISCV_INS_C_SLLI64:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case RISCV_INS_SRL:
	case RISCV_INS_SRLI:
	case RISCV_INS_SRLW:
	case RISCV_INS_SRLIW:
	case RISCV_INS_C_SRLI64:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case RISCV_INS_SRA:
	case RISCV_INS_SRAI:
	case RISCV_INS_SRAW:
	case RISCV_INS_SRAIW:
	case RISCV_INS_C_SRAI64:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;

	case RISCV_INS_ROL:
	case RISCV_INS_ROLW:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;

	case RISCV_INS_ROR:
	case RISCV_INS_RORI:
	case RISCV_INS_RORIW:
	case RISCV_INS_RORW:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case RISCV_INS_BCLR:
	case RISCV_INS_BCLRI:
	case RISCV_INS_CV_BCLR:
	case RISCV_INS_CV_BCLRR:
		op->type = RZ_ANALYSIS_OP_TYPE_AND; // Clear bit is like AND with mask
		break;

	case RISCV_INS_BSET:
	case RISCV_INS_BSETI:
	case RISCV_INS_CV_BSET:
	case RISCV_INS_CV_BSETR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR; // Set bit is like OR with mask
		break;

	case RISCV_INS_BINV:
	case RISCV_INS_BINVI:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR; // Invert bit is like XOR with mask
		break;

	case RISCV_INS_BEXT:
	case RISCV_INS_BEXTI:
	case RISCV_INS_CV_EXTRACT:
	case RISCV_INS_CV_EXTRACTR:
	case RISCV_INS_CV_EXTRACTU:
	case RISCV_INS_CV_EXTRACTUR:
	case RISCV_INS_CV_EXTRACT_B:
	case RISCV_INS_CV_EXTRACT_H:
	case RISCV_INS_CV_EXTRACTU_B:
	case RISCV_INS_CV_EXTRACTU_H:
	case RISCV_INS_TH_EXT:
	case RISCV_INS_TH_EXTU:
		op->type = RZ_ANALYSIS_OP_TYPE_AND; // Extract is masking operation
		break;

	case RISCV_INS_CV_INSERT:
	case RISCV_INS_CV_INSERTR:
	case RISCV_INS_CV_INSERT_B:
	case RISCV_INS_CV_INSERT_H:

	case RISCV_INS_ORC_B:

	case RISCV_INS_TH_TSTNBZ:
	case RISCV_INS_TH_TST:
		op->type = RZ_ANALYSIS_OP_TYPE_OR; // Insert is OR-ing bits
		break;

	case RISCV_INS_CLZ:
	case RISCV_INS_CLZW:
	case RISCV_INS_CTZ:
	case RISCV_INS_CTZW:
	case RISCV_INS_CPOP:
	case RISCV_INS_CPOPW:
	case RISCV_INS_CV_CNT:
	case RISCV_INS_CV_CLB:
	case RISCV_INS_CV_FF1:
	case RISCV_INS_CV_FL1:
	case RISCV_INS_TH_FF0:
	case RISCV_INS_TH_FF1:
		op->type = RZ_ANALYSIS_OP_TYPE_BCNT;
		break;

	case RISCV_INS_VCLZ_V:
	case RISCV_INS_VCPOP_V:
	case RISCV_INS_VCTZ_V:
		op->type = RZ_ANALYSIS_OP_TYPE_BCNT;
		break;

	case RISCV_INS_REV8:
	case RISCV_INS_BREV8:
	case RISCV_INS_CV_BITREV:
	case RISCV_INS_TH_REV:
	case RISCV_INS_TH_REVW:
		op->type = RZ_ANALYSIS_OP_TYPE_REV;
		break;

	case RISCV_INS_PACK:
	case RISCV_INS_PACKH:
	case RISCV_INS_PACKW:
	case RISCV_INS_CV_PACK:
	case RISCV_INS_CV_PACK_H:
	case RISCV_INS_CV_PACKHI_B:
	case RISCV_INS_CV_PACKLO_B:
	case RISCV_INS_UNZIP:
	case RISCV_INS_ZIP:
		op->type = RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_MIN:
	case RISCV_INS_MINU:
	case RISCV_INS_MAX:
	case RISCV_INS_MAXU:
	case RISCV_INS_CV_MIN:
	case RISCV_INS_CV_MINU:
	case RISCV_INS_CV_MAX:
	case RISCV_INS_CV_MAXU:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case RISCV_INS_FMIN_S:
	case RISCV_INS_FMIN_D:
	case RISCV_INS_FMIN_H:
	case RISCV_INS_FMAX_S:
	case RISCV_INS_FMAX_D:
	case RISCV_INS_FMAX_H:
	case RISCV_INS_FMINM_S:
	case RISCV_INS_FMINM_D:
	case RISCV_INS_FMINM_H:
	case RISCV_INS_FMAXM_S:
	case RISCV_INS_FMAXM_D:
	case RISCV_INS_FMAXM_H:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	case RISCV_INS_FLEQ_D:
	case RISCV_INS_FLEQ_H:
	case RISCV_INS_FLEQ_S:
	case RISCV_INS_FLTQ_D:
	case RISCV_INS_FLTQ_H:
	case RISCV_INS_FLTQ_S:
	case RISCV_INS_FEQ_D:
	case RISCV_INS_FEQ_H:
	case RISCV_INS_FEQ_S:
	case RISCV_INS_FLE_H:
	case RISCV_INS_FLT_H:
	case RISCV_INS_VMFLE_VF:
	case RISCV_INS_VMFLT_VF:
	case RISCV_INS_VMFNE_VF:
	case RISCV_INS_VMFGE_VF:
	case RISCV_INS_VMFGT_VF:
	case RISCV_INS_VMFEQ_VF:
	case RISCV_INS_VMFLE_VV:
	case RISCV_INS_VMFLT_VV:
	case RISCV_INS_VMFNE_VV:
	case RISCV_INS_VMFEQ_VV:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	case RISCV_INS_FSGNJ_S:
	case RISCV_INS_FSGNJ_D:
	case RISCV_INS_FSGNJ_H:
	case RISCV_INS_FSGNJN_S:
	case RISCV_INS_FSGNJN_D:
	case RISCV_INS_FSGNJN_H:
	case RISCV_INS_FSGNJX_S:
	case RISCV_INS_FSGNJX_D:
	case RISCV_INS_FSGNJX_H:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;

	case RISCV_INS_FCVT_W_S:
	case RISCV_INS_FCVT_WU_S:
	case RISCV_INS_FCVT_L_S:
	case RISCV_INS_FCVT_LU_S:
	case RISCV_INS_FCVT_W_D:
	case RISCV_INS_FCVT_WU_D:
	case RISCV_INS_FCVT_L_D:
	case RISCV_INS_FCVT_LU_D:
	case RISCV_INS_FCVT_W_H:
	case RISCV_INS_FCVT_WU_H:
	case RISCV_INS_FCVT_L_H:
	case RISCV_INS_FCVT_LU_H:
	case RISCV_INS_FCVT_S_W:
	case RISCV_INS_FCVT_S_WU:
	case RISCV_INS_FCVT_S_L:
	case RISCV_INS_FCVT_S_LU:
	case RISCV_INS_FCVT_D_W:
	case RISCV_INS_FCVT_D_WU:
	case RISCV_INS_FCVT_D_L:
	case RISCV_INS_FCVT_D_LU:
	case RISCV_INS_FCVT_H_W:
	case RISCV_INS_FCVT_H_WU:
	case RISCV_INS_FCVT_H_L:
	case RISCV_INS_FCVT_H_LU:
	case RISCV_INS_FCVT_S_D:
	case RISCV_INS_FCVT_D_S:
	case RISCV_INS_FCVT_S_H:
	case RISCV_INS_FCVT_H_S:
	case RISCV_INS_FCVT_D_H:
	case RISCV_INS_FCVT_H_D:
	case RISCV_INS_FCVT_S_BF16:
	case RISCV_INS_FCVT_BF16_S:
	case RISCV_INS_FCVTMOD_W_D:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	case RISCV_INS_FCLASS_S:
	case RISCV_INS_FCLASS_D:
	case RISCV_INS_FCLASS_H:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	case RISCV_INS_FROUND_S:
	case RISCV_INS_FROUND_D:
	case RISCV_INS_FROUND_H:
	case RISCV_INS_FROUNDNX_S:
	case RISCV_INS_FROUNDNX_D:
	case RISCV_INS_FROUNDNX_H:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	case RISCV_INS_SLT:
	case RISCV_INS_SLTI:
	case RISCV_INS_SLTU:
	case RISCV_INS_SLTIU:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;

	case RISCV_INS_BEQ:
	case RISCV_INS_BNE:
	case RISCV_INS_BLT:
	case RISCV_INS_BGE:
	case RISCV_INS_BLTU:
	case RISCV_INS_BGEU:
	case RISCV_INS_C_BEQZ:
	case RISCV_INS_C_BNEZ:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		if (insn->id == RISCV_INS_C_BEQZ || insn->id == RISCV_INS_C_BNEZ) {
			op->jump = IMM(1);
		} else {
			op->jump = IMM(2);
		}
		op->fail = NEXT_ADDRESS(op);
		break;

	case RISCV_INS_ECALL:
	case RISCV_INS_C_EBREAK:
	case RISCV_INS_EBREAK:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		break;

	case RISCV_INS_FENCE:
	case RISCV_INS_FENCE_I:
	case RISCV_INS_FENCE_TSO:
	case RISCV_INS_HFENCE_GVMA:
	case RISCV_INS_HFENCE_VVMA:
	case RISCV_INS_SFENCE_INVAL_IR:
	case RISCV_INS_SFENCE_VMA:
	case RISCV_INS_SFENCE_W_INVAL:
	case RISCV_INS_TH_SFENCE_VMAS:
	case RISCV_INS_HINVAL_GVMA:
	case RISCV_INS_HINVAL_VVMA:
	case RISCV_INS_SINVAL_VMA:
	case RISCV_INS_WFI:
	case RISCV_INS_CBO_CLEAN:
	case RISCV_INS_CBO_FLUSH:
	case RISCV_INS_CBO_INVAL:
	case RISCV_INS_CBO_ZERO:
	case RISCV_INS_TH_DCACHE_CALL:
	case RISCV_INS_TH_DCACHE_CIALL:
	case RISCV_INS_TH_DCACHE_CIPA:
	case RISCV_INS_TH_DCACHE_CISW:
	case RISCV_INS_TH_DCACHE_CIVA:
	case RISCV_INS_TH_DCACHE_CPA:
	case RISCV_INS_TH_DCACHE_CPAL1:
	case RISCV_INS_TH_DCACHE_CSW:
	case RISCV_INS_TH_DCACHE_CVA:
	case RISCV_INS_TH_DCACHE_CVAL1:
	case RISCV_INS_TH_DCACHE_IALL:
	case RISCV_INS_TH_DCACHE_IPA:
	case RISCV_INS_TH_DCACHE_ISW:
	case RISCV_INS_TH_DCACHE_IVA:
	case RISCV_INS_TH_ICACHE_IALL:
	case RISCV_INS_TH_ICACHE_IALLS:
	case RISCV_INS_TH_ICACHE_IPA:
	case RISCV_INS_TH_ICACHE_IVA:
	case RISCV_INS_TH_L2CACHE_CALL:
	case RISCV_INS_TH_L2CACHE_CIALL:
	case RISCV_INS_TH_L2CACHE_IALL:
		op->type = RZ_ANALYSIS_OP_TYPE_SYNC;
		break;

	case RISCV_INS_AES32DSI:
	case RISCV_INS_AES32DSMI:
	case RISCV_INS_AES32ESI:
	case RISCV_INS_AES32ESMI:
	case RISCV_INS_AES64DS:
	case RISCV_INS_AES64DSM:
	case RISCV_INS_AES64ES:
	case RISCV_INS_AES64ESM:
	case RISCV_INS_AES64IM:
	case RISCV_INS_AES64KS1I:
	case RISCV_INS_AES64KS2:
	case RISCV_INS_SHA256SIG0:
	case RISCV_INS_SHA256SIG1:
	case RISCV_INS_SHA256SUM0:
	case RISCV_INS_SHA256SUM1:
	case RISCV_INS_SHA512SIG0:
	case RISCV_INS_SHA512SIG0H:
	case RISCV_INS_SHA512SIG0L:
	case RISCV_INS_SHA512SIG1:
	case RISCV_INS_SHA512SIG1H:
	case RISCV_INS_SHA512SIG1L:
	case RISCV_INS_SHA512SUM0:
	case RISCV_INS_SHA512SUM0R:
	case RISCV_INS_SHA512SUM1:
	case RISCV_INS_SHA512SUM1R:
		op->type = RZ_ANALYSIS_OP_TYPE_CRYPTO;
		break;

	case RISCV_INS_SEXT_B:
	case RISCV_INS_SEXT_H:
	case RISCV_INS_C_SEXT_B:
	case RISCV_INS_C_SEXT_H:
	case RISCV_INS_CV_EXTHS:
	case RISCV_INS_CV_EXTBS:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	case RISCV_INS_ZEXT_H:
	case RISCV_INS_ZEXT_W:
	case RISCV_INS_C_ZEXT_B:
	case RISCV_INS_C_ZEXT_H:
	case RISCV_INS_C_ZEXT_W:
	case RISCV_INS_CV_EXTHZ:
	case RISCV_INS_CV_EXTBZ:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;

	case RISCV_INS_CM_PUSH:
	case RISCV_INS_C_SSPUSH:
	case RISCV_INS_SSPUSH:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;

	case RISCV_INS_CM_POP:
	case RISCV_INS_C_SSPOPCHK:
	case RISCV_INS_SSPOPCHK:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;

	case RISCV_INS_VSETVL:
	case RISCV_INS_VSETVLI:
	case RISCV_INS_VSETIVLI:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;
	// ============================================================
	// VECTOR LOADS
	// ============================================================
	case RISCV_INS_VLE8_V:
	case RISCV_INS_VLE16_V:
	case RISCV_INS_VLE32_V:
	case RISCV_INS_VLE64_V:
	case RISCV_INS_VLE8FF_V:
	case RISCV_INS_VLE16FF_V:
	case RISCV_INS_VLE32FF_V:
	case RISCV_INS_VLE64FF_V:
	case RISCV_INS_VLSE8_V:
	case RISCV_INS_VLSE16_V:
	case RISCV_INS_VLSE32_V:
	case RISCV_INS_VLSE64_V:
	case RISCV_INS_VLOXEI8_V:
	case RISCV_INS_VLOXEI16_V:
	case RISCV_INS_VLOXEI32_V:
	case RISCV_INS_VLOXEI64_V:
	case RISCV_INS_VLUXEI8_V:
	case RISCV_INS_VLUXEI16_V:
	case RISCV_INS_VLUXEI32_V:
	case RISCV_INS_VLUXEI64_V:
	case RISCV_INS_VLM_V:
	case RISCV_INS_VL1RE8_V:
	case RISCV_INS_VL1RE16_V:
	case RISCV_INS_VL1RE32_V:
	case RISCV_INS_VL1RE64_V:
	case RISCV_INS_VL2RE8_V:
	case RISCV_INS_VL2RE16_V:
	case RISCV_INS_VL2RE32_V:
	case RISCV_INS_VL2RE64_V:
	case RISCV_INS_VL4RE8_V:
	case RISCV_INS_VL4RE16_V:
	case RISCV_INS_VL4RE32_V:
	case RISCV_INS_VL4RE64_V:
	case RISCV_INS_VL8RE8_V:
	case RISCV_INS_VL8RE16_V:
	case RISCV_INS_VL8RE32_V:
	case RISCV_INS_VL8RE64_V:
	// vector segment loads
	case RISCV_INS_VLSEG2E8_V:
	case RISCV_INS_VLSEG2E16_V:
	case RISCV_INS_VLSEG2E32_V:
	case RISCV_INS_VLSEG2E64_V:
	case RISCV_INS_VLSEG3E8_V:
	case RISCV_INS_VLSEG3E16_V:
	case RISCV_INS_VLSEG3E32_V:
	case RISCV_INS_VLSEG3E64_V:
	case RISCV_INS_VLSEG4E8_V:
	case RISCV_INS_VLSEG4E16_V:
	case RISCV_INS_VLSEG4E32_V:
	case RISCV_INS_VLSEG4E64_V:
	case RISCV_INS_VLSEG5E8_V:
	case RISCV_INS_VLSEG5E16_V:
	case RISCV_INS_VLSEG5E32_V:
	case RISCV_INS_VLSEG5E64_V:
	case RISCV_INS_VLSEG6E8_V:
	case RISCV_INS_VLSEG6E16_V:
	case RISCV_INS_VLSEG6E32_V:
	case RISCV_INS_VLSEG6E64_V:
	case RISCV_INS_VLSEG7E8_V:
	case RISCV_INS_VLSEG7E16_V:
	case RISCV_INS_VLSEG7E32_V:
	case RISCV_INS_VLSEG7E64_V:
	case RISCV_INS_VLSEG8E8_V:
	case RISCV_INS_VLSEG8E16_V:
	case RISCV_INS_VLSEG8E32_V:
	case RISCV_INS_VLSEG8E64_V:

	case RISCV_INS_HLVX_HU:
	case RISCV_INS_HLVX_WU:
	case RISCV_INS_HLV_B:
	case RISCV_INS_HLV_BU:
	case RISCV_INS_HLV_D:
	case RISCV_INS_HLV_H:
	case RISCV_INS_HLV_HU:
	case RISCV_INS_HLV_W:
	case RISCV_INS_HLV_WU:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR STORES
	// ============================================================
	case RISCV_INS_VSE8_V:
	case RISCV_INS_VSE16_V:
	case RISCV_INS_VSE32_V:
	case RISCV_INS_VSE64_V:
	case RISCV_INS_VSSE8_V:
	case RISCV_INS_VSSE16_V:
	case RISCV_INS_VSSE32_V:
	case RISCV_INS_VSSE64_V:
	case RISCV_INS_VSOXEI8_V:
	case RISCV_INS_VSOXEI16_V:
	case RISCV_INS_VSOXEI32_V:
	case RISCV_INS_VSOXEI64_V:
	case RISCV_INS_VSUXEI8_V:
	case RISCV_INS_VSUXEI16_V:
	case RISCV_INS_VSUXEI32_V:
	case RISCV_INS_VSUXEI64_V:
	case RISCV_INS_VSM_V:
	case RISCV_INS_VS1R_V:
	case RISCV_INS_VS2R_V:
	case RISCV_INS_VS4R_V:
	case RISCV_INS_VS8R_V:
	case RISCV_INS_VSSEG2E8_V:
	case RISCV_INS_VSSEG2E16_V:
	case RISCV_INS_VSSEG2E32_V:
	case RISCV_INS_VSSEG2E64_V:
	case RISCV_INS_VSSEG3E8_V:
	case RISCV_INS_VSSEG3E16_V:
	case RISCV_INS_VSSEG3E32_V:
	case RISCV_INS_VSSEG3E64_V:
	case RISCV_INS_VSSEG4E8_V:
	case RISCV_INS_VSSEG4E16_V:
	case RISCV_INS_VSSEG4E32_V:
	case RISCV_INS_VSSEG4E64_V:
	case RISCV_INS_VSSEG5E8_V:
	case RISCV_INS_VSSEG5E16_V:
	case RISCV_INS_VSSEG5E32_V:
	case RISCV_INS_VSSEG5E64_V:
	case RISCV_INS_VSSEG6E8_V:
	case RISCV_INS_VSSEG6E16_V:
	case RISCV_INS_VSSEG6E32_V:
	case RISCV_INS_VSSEG6E64_V:
	case RISCV_INS_VSSEG7E8_V:
	case RISCV_INS_VSSEG7E16_V:
	case RISCV_INS_VSSEG7E32_V:
	case RISCV_INS_VSSEG7E64_V:
	case RISCV_INS_VSSEG8E8_V:
	case RISCV_INS_VSSEG8E16_V:
	case RISCV_INS_VSSEG8E32_V:
	case RISCV_INS_VSSEG8E64_V:
	case RISCV_INS_HSV_B:
	case RISCV_INS_HSV_D:
	case RISCV_INS_HSV_H:
	case RISCV_INS_HSV_W:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR ARITHMETIC - ADD/SUB
	// ============================================================
	case RISCV_INS_VADD_VV:
	case RISCV_INS_VADD_VX:
	case RISCV_INS_VADD_VI:
	case RISCV_INS_VWADDU_VV:
	case RISCV_INS_VWADDU_VX:
	case RISCV_INS_VWADDU_WV:
	case RISCV_INS_VWADDU_WX:
	case RISCV_INS_VWADD_VV:
	case RISCV_INS_VWADD_VX:
	case RISCV_INS_VWADD_WV:
	case RISCV_INS_VWADD_WX:
	case RISCV_INS_VSADDU_VV:
	case RISCV_INS_VSADDU_VX:
	case RISCV_INS_VSADDU_VI:
	case RISCV_INS_VSADD_VV:
	case RISCV_INS_VSADD_VX:
	case RISCV_INS_VSADD_VI:
	case RISCV_INS_VAADD_VV:
	case RISCV_INS_VAADD_VX:
	case RISCV_INS_VAADDU_VV:
	case RISCV_INS_VAADDU_VX:

	case RISCV_INS_VADC_VIM:
	case RISCV_INS_VADC_VVM:
	case RISCV_INS_VADC_VXM:
	case RISCV_INS_VMADC_VI:
	case RISCV_INS_VMADC_VIM:
	case RISCV_INS_VMADC_VV:
	case RISCV_INS_VMADC_VVM:
	case RISCV_INS_VMADC_VX:
	case RISCV_INS_VMADC_VXM:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VSUB_VV:
	case RISCV_INS_VSUB_VX:
	case RISCV_INS_VWSUBU_VV:
	case RISCV_INS_VWSUBU_VX:
	case RISCV_INS_VWSUBU_WV:
	case RISCV_INS_VWSUBU_WX:
	case RISCV_INS_VWSUB_VV:
	case RISCV_INS_VWSUB_VX:
	case RISCV_INS_VWSUB_WV:
	case RISCV_INS_VWSUB_WX:
	case RISCV_INS_VSSUBU_VV:
	case RISCV_INS_VSSUBU_VX:
	case RISCV_INS_VSSUB_VV:
	case RISCV_INS_VSSUB_VX:
	case RISCV_INS_VASUB_VV:
	case RISCV_INS_VASUB_VX:
	case RISCV_INS_VASUBU_VV:
	case RISCV_INS_VASUBU_VX:
	case RISCV_INS_VRSUB_VX:
	case RISCV_INS_VRSUB_VI:

	case RISCV_INS_VMSBC_VV:
	case RISCV_INS_VMSBC_VVM:
	case RISCV_INS_VMSBC_VX:
	case RISCV_INS_VMSBC_VXM:
	case RISCV_INS_VSBC_VVM:
	case RISCV_INS_VSBC_VXM:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR ARITHMETIC - MULTIPLY
	// ============================================================
	case RISCV_INS_VMUL_VV:
	case RISCV_INS_VMUL_VX:
	case RISCV_INS_VMULH_VV:
	case RISCV_INS_VMULH_VX:
	case RISCV_INS_VMULHU_VV:
	case RISCV_INS_VMULHU_VX:
	case RISCV_INS_VMULHSU_VV:
	case RISCV_INS_VMULHSU_VX:
	case RISCV_INS_VWMUL_VV:
	case RISCV_INS_VWMUL_VX:
	case RISCV_INS_VWMULU_VV:
	case RISCV_INS_VWMULU_VX:
	case RISCV_INS_VWMULSU_VV:
	case RISCV_INS_VWMULSU_VX:
	case RISCV_INS_VSMUL_VV:
	case RISCV_INS_VSMUL_VX:
	case RISCV_INS_VMACC_VV:
	case RISCV_INS_VMACC_VX:
	case RISCV_INS_VMADD_VV:
	case RISCV_INS_VMADD_VX:
	case RISCV_INS_VNMSAC_VV:
	case RISCV_INS_VNMSAC_VX:
	case RISCV_INS_VNMSUB_VV:
	case RISCV_INS_VNMSUB_VX:
	case RISCV_INS_VWMACC_VV:
	case RISCV_INS_VWMACC_VX:
	case RISCV_INS_VWMACCU_VV:
	case RISCV_INS_VWMACCU_VX:
	case RISCV_INS_VWMACCSU_VV:
	case RISCV_INS_VWMACCSU_VX:
	case RISCV_INS_VWMACCUS_VX:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR ARITHMETIC - DIVIDE
	// ============================================================
	case RISCV_INS_VDIVU_VV:
	case RISCV_INS_VDIVU_VX:
	case RISCV_INS_VDIV_VV:
	case RISCV_INS_VDIV_VX:
	case RISCV_INS_VFREC7_V:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VREMU_VV:
	case RISCV_INS_VREMU_VX:
	case RISCV_INS_VREM_VV:
	case RISCV_INS_VREM_VX:
		op->type = RZ_ANALYSIS_OP_TYPE_MOD | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;
	// ============================================================
	// VECTOR LOGICAL
	// ============================================================
	case RISCV_INS_VAND_VV:
	case RISCV_INS_VAND_VX:
	case RISCV_INS_VAND_VI:
	case RISCV_INS_VANDN_VV:
	case RISCV_INS_VANDN_VX:
		op->type = RZ_ANALYSIS_OP_TYPE_AND | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VOR_VV:
	case RISCV_INS_VOR_VX:
	case RISCV_INS_VOR_VI:
		op->type = RZ_ANALYSIS_OP_TYPE_OR | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VXOR_VV:
	case RISCV_INS_VXOR_VX:
	case RISCV_INS_VXOR_VI:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR SHIFT
	// ============================================================
	case RISCV_INS_VSLL_VV:
	case RISCV_INS_VSLL_VX:
	case RISCV_INS_VSLL_VI:
	case RISCV_INS_VWSLL_VV:
	case RISCV_INS_VWSLL_VX:
	case RISCV_INS_VWSLL_VI:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VSRL_VV:
	case RISCV_INS_VSRL_VX:
	case RISCV_INS_VSRL_VI:
	case RISCV_INS_VNSRL_WV:
	case RISCV_INS_VNSRL_WX:
	case RISCV_INS_VNSRL_WI:
	case RISCV_INS_VSSRL_VV:
	case RISCV_INS_VSSRL_VX:
	case RISCV_INS_VSSRL_VI:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VSRA_VV:
	case RISCV_INS_VSRA_VX:
	case RISCV_INS_VSRA_VI:
	case RISCV_INS_VNSRA_WV:
	case RISCV_INS_VNSRA_WX:
	case RISCV_INS_VNSRA_WI:
	case RISCV_INS_VSSRA_VV:
	case RISCV_INS_VSSRA_VX:
	case RISCV_INS_VSSRA_VI:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR ROTATE
	// ============================================================
	case RISCV_INS_VROR_VV:
	case RISCV_INS_VROR_VX:
	case RISCV_INS_VROR_VI:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VROL_VV:
	case RISCV_INS_VROL_VX:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR COMPARE
	// ============================================================
	case RISCV_INS_VMSEQ_VV:
	case RISCV_INS_VMSEQ_VX:
	case RISCV_INS_VMSEQ_VI:
	case RISCV_INS_VMSNE_VV:
	case RISCV_INS_VMSNE_VX:
	case RISCV_INS_VMSNE_VI:
	case RISCV_INS_VMSLTU_VV:
	case RISCV_INS_VMSLTU_VX:
	case RISCV_INS_VMSLT_VV:
	case RISCV_INS_VMSLT_VX:
	case RISCV_INS_VMSLEU_VV:
	case RISCV_INS_VMSLEU_VX:
	case RISCV_INS_VMSLEU_VI:
	case RISCV_INS_VMSLE_VV:
	case RISCV_INS_VMSLE_VX:
	case RISCV_INS_VMSLE_VI:
	case RISCV_INS_VMSGTU_VX:
	case RISCV_INS_VMSGTU_VI:
	case RISCV_INS_VMSGT_VX:
	case RISCV_INS_VMSGT_VI:
	case RISCV_INS_VMSGEU_VX:
	case RISCV_INS_VMSGEU_VI:
	case RISCV_INS_VMSGE_VX:
	case RISCV_INS_VMSGE_VI:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR MIN/MAX
	// ============================================================
	case RISCV_INS_VMIN_VV:
	case RISCV_INS_VMIN_VX:
	case RISCV_INS_VMINU_VV:
	case RISCV_INS_VMINU_VX:
	case RISCV_INS_VMAX_VV:
	case RISCV_INS_VMAX_VX:
	case RISCV_INS_VMAXU_VV:
	case RISCV_INS_VMAXU_VX:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR MOVE/MERGE
	// ============================================================
	case RISCV_INS_VMV_V_V:
	case RISCV_INS_VMV_V_X:
	case RISCV_INS_VMV_V_I:
	case RISCV_INS_VMV_X_S:
	case RISCV_INS_VMV_S_X:
	case RISCV_INS_VMV1R_V:
	case RISCV_INS_VMV2R_V:
	case RISCV_INS_VMV4R_V:
	case RISCV_INS_VMV8R_V:
	case RISCV_INS_VMERGE_VVM:
	case RISCV_INS_VMERGE_VXM:
	case RISCV_INS_VMERGE_VIM:
	case RISCV_INS_VFMV_F_S:
	case RISCV_INS_VFMV_S_F:
	case RISCV_INS_VFMV_V_F:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;
	// ============================================================
	// VECTOR MASK OPERATIONS
	// ============================================================
	case RISCV_INS_VMAND_MM:
	case RISCV_INS_VMANDN_MM:
		op->type = RZ_ANALYSIS_OP_TYPE_AND | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VMOR_MM:
	case RISCV_INS_VMORN_MM:
	case RISCV_INS_VMNOR_MM:
		op->type = RZ_ANALYSIS_OP_TYPE_OR | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VMXOR_MM:
	case RISCV_INS_VMXNOR_MM:
	case RISCV_INS_VMNAND_MM:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	// ============================================================
	// VECTOR REDUCTIONS
	// ============================================================
	case RISCV_INS_VREDSUM_VS:
	case RISCV_INS_VREDMAXU_VS:
	case RISCV_INS_VREDMAX_VS:
	case RISCV_INS_VREDMINU_VS:
	case RISCV_INS_VREDMIN_VS:
	case RISCV_INS_VREDAND_VS:
	case RISCV_INS_VREDOR_VS:
	case RISCV_INS_VREDXOR_VS:
	case RISCV_INS_VWREDSUM_VS:
		op->type = RZ_ANALYSIS_OP_TYPE_REDUCE | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;
	// ============================================================
	// VECTOR CRYPTO
	// ============================================================
	case RISCV_INS_VCLMUL_VV:
	case RISCV_INS_VCLMUL_VX:
	case RISCV_INS_VCLMULH_VV:
	case RISCV_INS_VCLMULH_VX:
	case RISCV_INS_VAESDF_VS:
	case RISCV_INS_VAESDF_VV:
	case RISCV_INS_VAESDM_VS:
	case RISCV_INS_VAESDM_VV:
	case RISCV_INS_VAESEF_VS:
	case RISCV_INS_VAESEF_VV:
	case RISCV_INS_VAESEM_VS:
	case RISCV_INS_VAESEM_VV:
	case RISCV_INS_VAESKF1_VI:
	case RISCV_INS_VAESKF2_VI:
	case RISCV_INS_VAESZ_VS:
	case RISCV_INS_VSHA2CH_VV:
	case RISCV_INS_VSHA2CL_VV:
	case RISCV_INS_VSHA2MS_VV:
	case RISCV_INS_VSM3C_VI:
	case RISCV_INS_VSM3ME_VV:
	case RISCV_INS_VSM4K_VI:
	case RISCV_INS_VSM4R_VS:
	case RISCV_INS_VSM4R_VV:
	case RISCV_INS_VGHSH_VV:
	case RISCV_INS_VGMUL_VV:
		op->type = RZ_ANALYSIS_OP_TYPE_CRYPTO | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_VFCVT_F_XU_V:
	case RISCV_INS_VFCVT_F_X_V:
	case RISCV_INS_VFCVT_RTZ_XU_F_V:
	case RISCV_INS_VFCVT_RTZ_X_F_V:
	case RISCV_INS_VFCVT_XU_F_V:
	case RISCV_INS_VFCVT_X_F_V:
	case RISCV_INS_VFWCVT_F_F_V:
	case RISCV_INS_VFWCVT_F_XU_V:
	case RISCV_INS_VFWCVT_F_X_V:
	case RISCV_INS_VFWCVT_RTZ_XU_F_V:
	case RISCV_INS_VFWCVT_RTZ_X_F_V:
	case RISCV_INS_VFWCVT_XU_F_V:
	case RISCV_INS_VFWCVT_X_F_V:
	case RISCV_INS_VFNCVT_F_F_W:
	case RISCV_INS_VFNCVT_F_XU_W:
	case RISCV_INS_VFNCVT_F_X_W:
	case RISCV_INS_VFNCVT_ROD_F_F_W:
	case RISCV_INS_VFNCVT_RTZ_XU_F_W:
	case RISCV_INS_VFNCVT_RTZ_X_F_W:
	case RISCV_INS_VFNCVT_XU_F_W:
	case RISCV_INS_VFNCVT_X_F_W:
	case RISCV_INS_VFNCVTBF16_F_F_W:
	case RISCV_INS_VFWCVTBF16_F_F_V:
		op->type = RZ_ANALYSIS_OP_TYPE_CAST | RZ_ANALYSIS_OP_TYPE_SIMD;
		break;

	case RISCV_INS_CZERO_EQZ:
	case RISCV_INS_CZERO_NEZ:
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;

	case RISCV_INS_CM_POPRET:
	case RISCV_INS_CM_POPRETZ:
	case RISCV_INS_MRET:
	case RISCV_INS_SRET:
	case RISCV_INS_DRET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	}
beach:
	if (insn) {
		set_op_sign(op, insn);
		set_op_data_size(op, insn);
		set_op_val(op, insn);
		set_op_eob(op, insn);
		set_op_cond(op, insn);
		set_op_family(op, insn);
		set_op_extra_metadata(analysis, op, ctx->hndl, insn);
		set_stack_effect(op, insn);
	}
	set_opdir(op);
	if (insn && mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = riscv_opex(ctx->hndl, insn);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		op_fillval(analysis, op, &ctx->hndl, insn);
	}
	cs_free(insn, n);
	// cs_close (&handle);
fin:
	return opsize;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p = NULL;
	switch (analysis->bits) {
	case 32:
		p =
			"=PC	pc\n"
			"=SP	sp\n" // ABI: stack pointer
			"=LR	ra\n" // ABI: return address
			"=BP	s0\n" // ABI: frame pointer
			"=A0	a0\n"
			"=A1	a1\n"
			"=A2	a2\n"
			"=A3	a3\n"
			"=A4	a4\n"
			"=A5	a5\n"
			"=A6	a6\n"
			"=A7	a7\n"

			"gpr	pc	.32	0	0\n"
			// RV32I regs (ABI names)
			// From user-Level ISA Specification, section 2.1
			// "zero" has been left out as it ignores writes and always reads as zero
			"gpr	ra	.32	4	0\n" // =x1
			"gpr	sp	.32	8	0\n" // =x2
			"gpr	gp	.32	12	0\n" // =x3
			"gpr	tp	.32	16	0\n" // =x4
			"gpr	t0	.32	20	0\n" // =x5
			"gpr	t1	.32	24	0\n" // =x6
			"gpr	t2	.32	28	0\n" // =x7
			"gpr	s0	.32	32	0\n" // =x8
			"gpr	s1	.32	36	0\n" // =x9
			"gpr	a0	.32	40	0\n" // =x10
			"gpr	a1	.32	44	0\n" // =x11
			"gpr	a2	.32	48	0\n" // =x12
			"gpr	a3	.32	52	0\n" // =x13
			"gpr	a4	.32	56	0\n" // =x14
			"gpr	a5	.32	60	0\n" // =x15
			"gpr	a6	.32	64	0\n" // =x16
			"gpr	a7	.32	68	0\n" // =x17
			"gpr	s2	.32	72	0\n" // =x18
			"gpr	s3	.32	76	0\n" // =x19
			"gpr	s4	.32	80	0\n" // =x20
			"gpr	s5	.32	84	0\n" // =x21
			"gpr	s6	.32	88	0\n" // =x22
			"gpr	s7	.32	92	0\n" // =x23
			"gpr	s8	.32	96	0\n" // =x24
			"gpr	s9	.32	100	0\n" // =x25
			"gpr	s10	.32	104	0\n" // =x26
			"gpr	s11	.32	108	0\n" // =x27
			"gpr	t3	.32	112	0\n" // =x28
			"gpr	t4	.32	116	0\n" // =x29
			"gpr	t5	.32	120	0\n" // =x30
			"gpr	t6	.32	124	0\n" // =x31
			// RV32F/D regs (ABI names)
			// From user-Level ISA Specification, section 8.1 and 9.1
			"gpr	ft0	.64	128	0\n" // =f0
			"gpr	ft1	.64	136	0\n" // =f1
			"gpr	ft2	.64	144	0\n" // =f2
			"gpr	ft3	.64	152	0\n" // =f3
			"gpr	ft4	.64	160	0\n" // =f4
			"gpr	ft5	.64	168	0\n" // =f5
			"gpr	ft6	.64	176	0\n" // =f6
			"gpr	ft7	.64	184	0\n" // =f7
			"gpr	fs0	.64	192	0\n" // =f8
			"gpr	fs1	.64	200	0\n" // =f9
			"gpr	fa0	.64	208	0\n" // =f10
			"gpr	fa1	.64	216	0\n" // =f11
			"gpr	fa2	.64	224	0\n" // =f12
			"gpr	fa3	.64	232	0\n" // =f13
			"gpr	fa4	.64	240	0\n" // =f14
			"gpr	fa5	.64	248	0\n" // =f15
			"gpr	fa6	.64	256	0\n" // =f16
			"gpr	fa7	.64	264	0\n" // =f17
			"gpr	fs2	.64	272	0\n" // =f18
			"gpr	fs3	.64	280	0\n" // =f19
			"gpr	fs4	.64	288	0\n" // =f20
			"gpr	fs5	.64	296	0\n" // =f21
			"gpr	fs6	.64	304	0\n" // =f22
			"gpr	fs7	.64	312	0\n" // =f23
			"gpr	fs8	.64	320	0\n" // =f24
			"gpr	fs9	.64	328	0\n" // =f25
			"gpr	fs10	.64	336	0\n" // =f26
			"gpr	fs11	.64	344	0\n" // =f27
			"gpr	ft8	.64	352	0\n" // =f28
			"gpr	ft9	.64	360	0\n" // =f29
			"gpr	ft10	.64	368	0\n" // =f30
			"gpr	ft11	.64	376	0\n" // =f31
			"gpr	fcsr	.32	384	0\n"
			"flg	nx	.1	3072	0\n"
			"flg	uf	.1	3073	0\n"
			"flg	of	.1	3074	0\n"
			"flg	dz	.1	3075	0\n"
			"flg	nv	.1	3076	0\n"
			"flg	frm	.3	3077	0\n"
			// vector registers
			// assume each register is 512 bits (64 bytes) for maximum compatibility
			// TODO: make the width accurately reflect the exact width defined in the binary
			"gpr    v0   .512 4096   0\n"
			"gpr    v1   .512 4160   0\n"
			"gpr    v2   .512 4224   0\n"
			"gpr    v3   .512 4288   0\n"
			"gpr    v4   .512 4352   0\n"
			"gpr    v5   .512 4416   0\n"
			"gpr    v6   .512 4480   0\n"
			"gpr    v7   .512 4544   0\n"
			"gpr    v8   .512 4608   0\n"
			"gpr    v9   .512 4672   0\n"
			"gpr    v10  .512 4736   0\n"
			"gpr    v11  .512 4800   0\n"
			"gpr    v12  .512 4864   0\n"
			"gpr    v13  .512 4928   0\n"
			"gpr    v14  .512 4992   0\n"
			"gpr    v15  .512 5056   0\n"
			"gpr    v16  .512 5120   0\n"
			"gpr    v17  .512 5184   0\n"
			"gpr    v18  .512 5248   0\n"
			"gpr    v19  .512 5312   0\n"
			"gpr    v20  .512 5376   0\n"
			"gpr    v21  .512 5440   0\n"
			"gpr    v22  .512 5504   0\n"
			"gpr    v23  .512 5568   0\n"
			"gpr    v24  .512 5632   0\n"
			"gpr    v25  .512 5696   0\n"
			"gpr    v26  .512 5760   0\n"
			"gpr    v27  .512 5824   0\n"
			"gpr    v28  .512 5888   0\n"
			"gpr    v29  .512 5952   0\n"
			"gpr    v30  .512 6016   0\n"
			"gpr    v31  .512 6080   0\n";
		break;
	case 64:
		p =
			"=PC	pc\n"
			"=SP	sp\n" // ABI: stack pointer
			"=LR	ra\n" // ABI: return address
			"=BP	s0\n" // ABI: frame pointer
			"=A0	a0\n"
			"=A1	a1\n"
			"=A2	a2\n"
			"=A3	a3\n"
			"=A4	a4\n"
			"=A5	a5\n"
			"=A6	a6\n"
			"=A7	a7\n"

			"gpr	pc	.64	0	0\n"
			// RV64I regs (ABI names)
			// From user-Level ISA Specification, section 2.1 and 4.1
			// "zero" has been left out as it ignores writes and always reads as zero
			"gpr	ra	.64	8	0\n" // =x1
			"gpr	sp	.64	16	0\n" // =x2
			"gpr	gp	.64	24	0\n" // =x3
			"gpr	tp	.64	32	0\n" // =x4
			"gpr	t0	.64	40	0\n" // =x5
			"gpr	t1	.64	48	0\n" // =x6
			"gpr	t2	.64	56	0\n" // =x7
			"gpr	s0	.64	64	0\n" // =x8
			"gpr	s1	.64	72	0\n" // =x9
			"gpr	a0	.64	80	0\n" // =x10
			"gpr	a1	.64	88	0\n" // =x11
			"gpr	a2	.64	96	0\n" // =x12
			"gpr	a3	.64	104	0\n" // =x13
			"gpr	a4	.64	112	0\n" // =x14
			"gpr	a5	.64	120	0\n" // =x15
			"gpr	a6	.64	128	0\n" // =x16
			"gpr	a7	.64	136	0\n" // =x17
			"gpr	s2	.64	144	0\n" // =x18
			"gpr	s3	.64	152	0\n" // =x19
			"gpr	s4	.64	160	0\n" // =x20
			"gpr	s5	.64	168	0\n" // =x21
			"gpr	s6	.64	176	0\n" // =x22
			"gpr	s7	.64	184	0\n" // =x23
			"gpr	s8	.64	192	0\n" // =x24
			"gpr	s9	.64	200	0\n" // =x25
			"gpr	s10	.64	208	0\n" // =x26
			"gpr	s11	.64	216	0\n" // =x27
			"gpr	t3	.64	224	0\n" // =x28
			"gpr	t4	.64	232	0\n" // =x29
			"gpr	t5	.64	240	0\n" // =x30
			"gpr	t6	.64	248	0\n" // =x31
			// RV64F/D regs (ABI names)
			"gpr	ft0	.64	256	0\n" // =f0
			"gpr	ft1	.64	264	0\n" // =f1
			"gpr	ft2	.64	272	0\n" // =f2
			"gpr	ft3	.64	280	0\n" // =f3
			"gpr	ft4	.64	288	0\n" // =f4
			"gpr	ft5	.64	296	0\n" // =f5
			"gpr	ft6	.64	304	0\n" // =f6
			"gpr	ft7	.64	312	0\n" // =f7
			"gpr	fs0	.64	320	0\n" // =f8
			"gpr	fs1	.64	328	0\n" // =f9
			"gpr	fa0	.64	336	0\n" // =f10
			"gpr	fa1	.64	344	0\n" // =f11
			"gpr	fa2	.64	352	0\n" // =f12
			"gpr	fa3	.64	360	0\n" // =f13
			"gpr	fa4	.64	368	0\n" // =f14
			"gpr	fa5	.64	376	0\n" // =f15
			"gpr	fa6	.64	384	0\n" // =f16
			"gpr	fa7	.64	392	0\n" // =f17
			"gpr	fs2	.64	400	0\n" // =f18
			"gpr	fs3	.64	408	0\n" // =f19
			"gpr	fs4	.64	416	0\n" // =f20
			"gpr	fs5	.64	424	0\n" // =f21
			"gpr	fs6	.64	432	0\n" // =f22
			"gpr	fs7	.64	440	0\n" // =f23
			"gpr	fs8	.64	448	0\n" // =f24
			"gpr	fs9	.64	456	0\n" // =f25
			"gpr	fs10	.64	464	0\n" // =f26
			"gpr	fs11	.64	472	0\n" // =f27
			"gpr	ft8	.64	480	0\n" // =f28
			"gpr	ft9	.64	488	0\n" // =f29
			"gpr	ft10	.64	496	0\n" // =f30
			"gpr	ft11	.64	504	0\n" // =f31
			"gpr	fcsr	.32	512	0\n"
			// vector registers
			// assume each register is 512 bits (64 bytes) for maximum compatibility
			// TODO: make the width accurately reflect the exact width defined in the binary
			"gpr    v0   .512 1024   0\n"
			"gpr    v1   .512 1088   0\n"
			"gpr    v2   .512 1152   0\n"
			"gpr    v3   .512 1216   0\n"
			"gpr    v4   .512 1280   0\n"
			"gpr    v5   .512 1344   0\n"
			"gpr    v6   .512 1408   0\n"
			"gpr    v7   .512 1472   0\n"
			"gpr    v8   .512 1536   0\n"
			"gpr    v9   .512 1600   0\n"
			"gpr    v10  .512 1664   0\n"
			"gpr    v11  .512 1728   0\n"
			"gpr    v12  .512 1792   0\n"
			"gpr    v13  .512 1856   0\n"
			"gpr    v14  .512 1920   0\n"
			"gpr    v15  .512 1984   0\n"
			"gpr    v16  .512 2048   0\n"
			"gpr    v17  .512 2112   0\n"
			"gpr    v18  .512 2176   0\n"
			"gpr    v19  .512 2240   0\n"
			"gpr    v20  .512 2304   0\n"
			"gpr    v21  .512 2368   0\n"
			"gpr    v22  .512 2432   0\n"
			"gpr    v23  .512 2496   0\n"
			"gpr    v24  .512 2560   0\n"
			"gpr    v25  .512 2624   0\n"
			"gpr    v26  .512 2688   0\n"
			"gpr    v27  .512 2752   0\n"
			"gpr    v28  .512 2816   0\n"
			"gpr    v29  .512 2880   0\n"
			"gpr    v30  .512 2944   0\n"
			"gpr    v31  .512 3008   0\n"
			"flg	nx	.1	4096	0\n"
			"flg	uf	.1	4097	0\n"
			"flg	of	.1	4098	0\n"
			"flg	dz	.1	4099	0\n"
			"flg	nv	.1	4100	0\n"
			"flg	frm	.3	4101	0\n";

		break;
	}
	return rz_str_dup(p);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	bool is_64_bits = a && a->bits == 64;

	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return is_64_bits ? 4 : 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
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

static void set_stack_effect(RzAnalysisOp *op, cs_insn *insn) {
	op->stackop = RZ_ANALYSIS_STACK_NOP;
	if (!IS_REG_WRITTEN(insn, RISCV_REG_X2)) {
		return;
	}

	// x2 i.e. SP is written, but how ?

	// incremented or decremented ?
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_ADD:
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -MAYBE_IMM(insn);
		return;

	case RZ_ANALYSIS_OP_TYPE_SUB:
		op->stackop = RZ_ANALYSIS_STACK_DEC;
		op->stackptr = MAYBE_IMM(insn);
		return;

	case RZ_ANALYSIS_OP_TYPE_LOAD:
		if (MEM_BASE(insn, RISCV_REG_X2)) {
			op->stackop = RZ_ANALYSIS_STACK_GET;
			op->stackptr = op->refptr;
		}
		return;

	case RZ_ANALYSIS_OP_TYPE_STORE:
		if (MEM_BASE(insn, RISCV_REG_X2)) {
			op->stackop = RZ_ANALYSIS_STACK_SET;
			op->stackptr = op->refptr;
		}
		return;

		// TODO: Add RESET and ALIGN

	default:
		break;
	}
	return;
}

static bool riscv_fini(void *user) {
	RiscvContext *ctx = (RiscvContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_riscv_cs = {
	.name = "riscv",
	.desc = "Capstone RISCV analyzer",
	.license = "BSD",
	.esil = false,
	.arch = "riscv",
	.get_reg_profile = get_reg_profile,
	.archinfo = archinfo,
	.bits = 32 | 64,
	.op = &analyze_op,
	.init = riscv_init,
	.fini = riscv_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_riscv_cs,
	.version = RZ_VERSION
};
#endif
