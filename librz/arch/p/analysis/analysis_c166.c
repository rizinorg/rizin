// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <analysis_private.h>
#include <rz_analysis.h>
#include <rz_util/rz_str_util.h>

#include "librz/arch/isa/c166/c166_disas.h"

static RzTypeCond c166_cc_to_cond(ut8 cc) {
	///< See table 5 in C166 ISM
	switch (H_NIB(cc) * 2) {
	case C166_CC_UC:
		return RZ_TYPE_COND_AL;
	case C166_CC_NET:
		return RZ_TYPE_COND_NE; ///< NE & not end of table
	case C166_CC_EQ:
		return RZ_TYPE_COND_EQ;
	case C166_CC_NE:
		return RZ_TYPE_COND_NE;
	case C166_CC_V:
		return RZ_TYPE_COND_VS;
	case C166_CC_NV:
		return RZ_TYPE_COND_VC;
	case C166_CC_N:
		return RZ_TYPE_COND_MI;
	case C166_CC_NN:
		return RZ_TYPE_COND_PL;
	case C166_CC_NC:
		return RZ_TYPE_COND_HS;
	case C166_CC_C:
		return RZ_TYPE_COND_LO;
	case C166_CC_SGE:
		return RZ_TYPE_COND_GE;
	case C166_CC_SGT:
		return RZ_TYPE_COND_GT;
	case C166_CC_SLE:
		return RZ_TYPE_COND_LE;
	case C166_CC_SLT:
		return RZ_TYPE_COND_LT;
	case C166_CC_UGT:
		return RZ_TYPE_COND_HI;
	case C166_CC_ULE:
		return RZ_TYPE_COND_LS;
	case C166_CC_NUSR0:
	case C166_CC_NUSR1:
	case C166_CC_USR0:
	case C166_CC_USR1:
		return RZ_TYPE_COND_EXCEPTION;
	default:
		rz_warn_if_reached();
		return RZ_TYPE_COND_EXCEPTION; ///< unreachable
	}
}

ut64 get_reg_val(RzAnalysis *analysis, const char *name) {
	RzReg *areg = rz_analysis_get_reg(analysis);
	RzRegItem *reg = rz_reg_get(areg, name, RZ_REG_TYPE_GPR);
	const ut64 value = rz_reg_get_value(areg, reg);
	RZ_LOG_DEBUG("`%s` reg value: 0x%08" PFMT64x "\n", name, value);
	return value;
}

bool set_reg_val(RzAnalysis *analysis, const char *name, const ut64 value) {
	RzReg *areg = rz_analysis_get_reg(analysis);
	RzRegItem *reg = rz_reg_get(areg, name, RZ_REG_TYPE_GPR);

	RZ_LOG_DEBUG("`%s` reg new value: 0x%08" PFMT64x "\n", name, value);
	if (!rz_reg_set_value(areg, reg, value)) {
		RZ_LOG_ERROR("Error setting reg `%s` value `%" PFMT64u "`\n", name, value);
		return false;
	}
	return true;
}

#define GET_A_SGTDIS get_reg_val(analysis, "SGTDIS")
#define GET_A_SCINT  get_reg_val(analysis, "INTSCXT")

#define GET_A_CP  get_reg_val(analysis, "CP")
#define GET_A_CSP get_reg_val(analysis, "CSP")
#define GET_A_IP  get_reg_val(analysis, "IP")
#define GET_A_SP  get_reg_val(analysis, "SP")

#define SET_A_CP(val)  set_reg_val(analysis, "CP", val)
#define SET_A_CSP(val) set_reg_val(analysis, "CSP", val)
#define SET_A_IP(val)  set_reg_val(analysis, "IP", val)
#define SET_A_SP(val)  set_reg_val(analysis, "SP", val)

static void c166_set_mimo_addr_from_reg(RzAnalysisOp *op, ut8 reg) {
	if (reg < 0xF0) {
		op->mmio_address = BASE_SFR_ADDR + (2 * reg);
	}
}

static ut16 target_addressing_mode_caddr(RzAnalysisOp *op, ut16 target) {
	/**
	 * caddr: 	Specifies an absolute 16-bit code address within the current segment.
	 * 			Branches MAY NOT be taken to odd code addresses. Therefore, the least
	 * 	  		significant bit of ’caddr’ is not used.
	 *
	 *	     	Target Address: (IP) = caddr 			   caddr = 0000h...FFFEh
	 *	      	Target Segment: -
	 */

	return (SEG | (target & 0xFFFE));
}

static void c166_set_jump_target_from_caddr(RzAnalysisOp *op, ut16 target) {
	op->disp = op->jump = op->ptr = target_addressing_mode_caddr(op, target);
	FAIL;
}

static void c166_set_jump_target_seg_caddr(RzAnalysisOp *op, ut8 seg, ut16 target) {
	op->ptr = op->jump = (((ut32)seg) << 16) | target;
	op->fail = op->addr + op->size;
	op->eob = true;
}

static RzAnalysisValue *c166_new_gpr_value(const RzAnalysis *analysis, ut8 i, bool byte) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_REG;
	if (byte) {
		val->base = BASE_SFR_ADDR + (L_NIB(i));
		val->reg = rz_reg_get_at(analysis->reg, RZ_REG_TYPE_GPR, 8, val->base);
	} else {
		val->base = BASE_SFR_ADDR + 2 * (L_NIB(i));
		val->reg = rz_reg_get_at(analysis->reg, RZ_REG_TYPE_GPR, 16, val->base);
	}
	return val;
}

static RzAnalysisValue *c166_new_reg_value(const RzAnalysis *analysis, ut8 reg, bool byte) {
	if (reg < 0xF0) {
		RzAnalysisValue *val = rz_analysis_value_new();
		val->type = RZ_ANALYSIS_VAL_REG;
		val->base = BASE_SFR_ADDR + (2 * reg);
		val->reg = rz_reg_get_at(analysis->reg, RZ_REG_TYPE_GPR, 16, val->base);
		return val;
	}
	return c166_new_gpr_value(analysis, reg, byte);
}

static RzAnalysisValue *c166_new_mem_value(const RzAnalysis *analysis, const C166_Inst *instr, ut16 mem) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_MEM;
	RzRegItem *reg;
	if (mem < 0x4000) {
		reg = rz_reg_get(analysis->reg, "DPP0", RZ_REG_TYPE_GPR);
	} else if (mem < 0x8000) {
		reg = rz_reg_get(analysis->reg, "DPP1", RZ_REG_TYPE_GPR);
	} else if (mem < 0xC000) {
		reg = rz_reg_get(analysis->reg, "DPP2", RZ_REG_TYPE_GPR);
	} else {
		reg = rz_reg_get(analysis->reg, "DPP3", RZ_REG_TYPE_GPR);
	}

	switch (instr->ext.mode) {
	case C166_EXT_MODE_NONE:
		val->reg = reg;
		break;
	case C166_EXT_MODE_SEG:
		val->base = ((ut32)instr->ext.value) << 16;
		break;
	case C166_EXT_MODE_PAGE:
		val->reg = reg;
		val->base = ((ut32)instr->ext.value) << 14;
		break;
	}
	val->base += mem & 0x3FFF;
	return val;
}

static RzAnalysisValue *c166_new_imm_value(ut16 data, bool absolute) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_IMM;
	val->imm = data;
	val->absolute = absolute;
	return val;
}

static RzAnalysisValue *c166_new_bitaddr_value(const RzAnalysis *analysis, const C166_Inst *instr, ut8 bitoff) {
	RzAnalysisValue *val = rz_analysis_value_new();
	val->type = RZ_ANALYSIS_VAL_MEM;
	if (bitoff >= 0xF0) {
		val->reg = rz_reg_get(analysis->reg, c166_rw[L_NIB(bitoff)], RZ_REG_TYPE_GPR);
		val->base = rz_reg_get_value(analysis->reg, val->reg);
		return val;
	}
	if (bitoff >= 0x80) {
		val->base = (instr->ext.esfr ? BASE_ESFR_B_ADDR : BASE_SFR_B_ADDR) + (2 * (bitoff & 0x7F));
	} else {
		val->base = BASE_RAM_B_ADDR + 2 * bitoff;
	}
	val->reg = rz_reg_get_at(analysis->reg, RZ_REG_TYPE_GPR, 16, val->base);
	return val;
}

static void c166_op_rn_rm(RzAnalysis *analysis, RzAnalysisOp *op, ut8 nm, ut32 type, bool byte) {
	op->dst = c166_new_gpr_value(analysis, H_NIB(nm), byte);
	op->src[0] = c166_new_gpr_value(analysis, L_NIB(nm), byte);
	op->type = type;
}

static void c166_op_rn_x(RzAnalysis *analysis, RzAnalysisOp *op, ut8 nx, ut32 type, bool byte) {
	op->dst = c166_new_gpr_value(analysis, H_NIB(nx), byte);
	switch ((nx >> 2) & 0b11) {
	case 0b11:
		op->src[0] = c166_new_gpr_value(analysis, nx & 0b11, false);
		op->src[0]->memref = byte ? 1 : 2;
		break;
	case 0b10:
		op->src[0] = c166_new_gpr_value(analysis, nx & 0b11, false);
		op->src[0]->memref = byte ? 1 : 2;
		break;
	default:
		op->src[0] = c166_new_imm_value(nx & 0b111, true);
		break;
	}
	op->type = type;
}

static void c166_op_neg(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	const bool byte = buf[0] == C166_NEGB_Rbn;
	op->type = RZ_ANALYSIS_OP_TYPE_CPL;
	op->dst = c166_new_gpr_value(analysis, H_NIB(buf[1]), byte);
}

static void c166_op_ext(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

static void c166_op_atomic_or_extr(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
}

/**
 * Switches contexts of any register. Switching context is a push and load operation.
 * The contents of the register specified by the first operand op1, are pushed onto the stack.
 * That register is then loaded with the value specified by the second operand, op2.
 *
 * Syntax:
 *	SCXT op1, op2
 * Source Operand(s):
 *	op1, op2 → WORD
 * Destination Operand(s):
 *	op1 → WORD
 * Operation:
 *	(tmp1) ← (op1)
 *	(tmp2) ← (op2)
 *	(SP) ← (SP) - 2
 *	((SP)) ← (tmp1)
 *	(op1) ← (tmp2)
 *
 * Mnemonic:
 *	SCXT reg, #data16 - C6 RR ## ##
 *	SCXT reg, mem - D6 RR MM MM
 */
static void c166_op_scxt(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
	op->src[0] = c166_new_reg_value(analysis, buf[1], false);
	if (buf[0] == C166_SCXT_reg_mem) {
		op->val = SEG || rz_read_at_le16(buf, 2);
	} else {
		op->val = rz_read_at_le16(buf, 2);
	}
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = 2;
}

/**
 * Invokes a trap or interrupt routine based on the specified operand op1. The invoked
 * routine is determined by branching to the specified vector table entry point. This routine
 * has no indication of whether it was called by software or hardware. System state is
 * preserved identically to hardware interrupt entry except that the CPU priority level is not
 * affected. The RETI, Return from Interrupt instruction is used to resume execution after
 * the completion of the trap or interrupt routine. The CSP is pushed if the segmentation is
 * enabled. This is indicated by the SGTDIS bit of the CPUCON1 register.
 *
 * See: Table 5-2 Hardware Trap Summary
 * Syntax:
 *	TRAP op1
 * Source Operand(s):
 *	op1 → 7-bit trap number
 * Destination Operand(s):
 *	none
 * Operation:
 *	(SP) ← (SP) - 2
 *	((SP) ← (PSW)
 *	IF (CPUCON1.SGTDIS = 0) THEN
 *		(SP) ← (SP) - 2
 *		((SP)) ← (CSP)
 *	END IF
 *	(CSP) ← (VSEG)
 *	(SP) ← (SP) - 2
 *	((SP)) ← (IP)
 *	(IP) ← ((op1) * 4) <<CPUCON1.SCINT  (CPUCON1.INTSCXT)
 *
 * Mnemonic:
 *	TRAP #trap7 - 9B t:ttt0
 */
static void c166_op_trap7(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
	const ut8 trap7 = buf[1] >> 1;
	(void)trap7;
	op->fail = op->addr + op->size;
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = 4;
	const ut8 SGTDIS = (ut8)GET_A_SGTDIS;
	if (SGTDIS == 0) {
		op->stackptr += 2;
	}
	SET_A_IP((buf[1] * 4) << GET_A_SCINT);
}

/**
 * If the condition specified by op1 is met, a branch to the absolute address specified by
 * op2 is taken. If the condition is not met, no action is taken, and program execution
 * continues normally with the instruction following the JMPI instruction.
 *
 * Syntax:
 *	JMPI op1, op2
 * Source Operand(s):
 *	op1 → condition code
 *	op2 → 16-bit address offset
 * Destination Operand(s):
 *	none
 * Operation:
 *	IF ((op1) = 1) THEN
 *		(IP) ← (op2)
 *	ELSE
 *		Next Instruction
 *	END IF
 *
 * Mnemonic:
 *	JMPI cc, [Rwn] - 9C cn
 */
static void c166_op_jmpi_cc_orwn(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_RCJMP;
	op->cond = c166_cc_to_cond(buf[1]);
	op->fail = op->addr + op->size;

	const ut16 cp = GET_A_CP;
	RzRegItem *reg = rz_reg_get(analysis->reg, c166_rw[buf[1] & 0xF], RZ_REG_TYPE_GPR);
	op->ireg = reg->name;
	const ut16 v = rz_reg_get_value(analysis->reg, reg);
	const ut8 seg = GET_A_CSP;
	if (buf[1] == 1) {
		op->jump = (((ut32)seg) << 16) | ((cp + 2 * v) - op->size);
		SET_A_IP(op->jump);
	}
}

/**
 * Branches unconditionally to the absolute address specified by op2
 * within the segment specified by op1.
 *
 * Syntax:
 *	JMPS op1, op2
 * Source Operand(s):
 *	op1 → segment number
 *	op2 → 16-bit address offset
 * Destination Operand(s):
 *	none
 * Operation:
 *	IF (CPUCON1.SGTDIS = 0) THEN
 *		(CSP) ← op1
 *	END IF
 *	(IP) ← op2
 *
 * Mnemonic:
 *	JMPS seg, caddr - FA SS MM MM
 */
static void c166_op_jmps_seg_caddr(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_JMP; /* mandatory jump */
	const ut8 seg = buf[1];
	const ut16 caddr = rz_read_at_le16(buf, 2);
	const ut8 SGTDIS = (ut8)GET_A_SGTDIS;
	if (SGTDIS == 0) {
		if (!SET_A_CSP((ut64)seg)) {
			RZ_LOG_WARN("Error setting reg value\n");
		}
	}
	c166_set_jump_target_seg_caddr(op, seg, caddr);
	// SET_IP(caddr); ///< Need implement relative jump by offset
	SET_A_IP((((ut32)seg) << 16) | (caddr - op->size)); ///< (caddr - op->size) for emulation fix
}

/**
 * If the extended condition specified by op1 is met, program execution continues at
 * the location of the instruction pointer, IP, plus the specified displacement, op2.
 * The displacement is a 2s complement number which is sign-extended and counts the
 * relative distance in words. The value of the IP used in the target address
 * calculation is the address of the instruction following the JMPR instruction.
 * If the specified condition is not met, program execution continues normally
 * with the instruction following the JMPR instruction.
 *
 * Syntax:
 *	JMPR op1, op2
 * Source Operand(s):
 *	op1 → condition code
 *	op2 → 8-bit signed displacement
 * Destination Operand(s):
 *	none
 * Operation:
 *	IF ((op1) = 1) THEN
 *		(IP) ← (IP) + 2*sign_extend(op2)
 *	ELSE
 *		Next Instruction
 *	END IF
 *
 * Mnemonic:
 *	JMPR cc, rel - cD rr
 */
static void c166_op_jmpr_cc_rel(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP; /* conditional jump */
	op->cond = c166_cc_to_cond(buf[0]);
	op->jump = op->addr + op->size + (2 * ((st8)buf[1]));
	SET_A_IP(op->jump);
	op->fail = op->addr + op->size;
}

/**
 * If the condition specified by op1 is met, a branch to the absolute address specified by
op2 is taken. If the condition is not met, no action is taken, and program execution
continues normally with the instruction following the JMPI instruction.
 *
 * Syntax:
 *	JMPI op1, op2
 * Source Operand(s):
 *	op1 → condition code
 *	op2 → 16-bit address offset
 * Destination Operand(s):
 *	none
 * Operation:
 *	IF ((op1) = 1) THEN
 *		(IP) ← (op2)
 *	ELSE
 *		Next Instruction
 *	END IF
 *
 * Mnemonic:
 *	JMPI cc, [Rwn] - 9C cn
 */
static void c166_op_jmpa_cc_caddr(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->cond = c166_cc_to_cond(buf[1]);
	if (op->cond == RZ_TYPE_COND_AL) { // Absolute Unconditional
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		FAIL;
	}
	const ut16 offset = rz_read_at_le16(buf, 2);
	const ut8 csp_val = (ut8)GET_A_CSP;
	op->disp = op->jump = op->ptr = (csp_val << 16) | offset;
	FAIL;
}

/**
 * A branch is taken to the absolute location specified by op2 within
 * the segment specified by op1. The previous value of the CSP is placed
 * into the system stack to ensure correct return to the calling segment.
 * The value of the instruction pointer (IP) is also placed into the system stack.
 * Because the IP always points to the instruction following the branch
 * instruction, the value stored on the system stack represents the return
 * address to the calling routine.
 *
 * Syntax:
 *	CALLS op1, op2
 * Source Operand(s):
 *	op1 → segment number
 *	op2 → 16-bit address offset
 * Destination Operand(s):
 *	none
 * Operation:
 *	(SP) ← (SP) - 2
 *	((SP)) ← (CSP)
 *	(SP) ← (SP) - 2
 *	((SP)) ← (IP)
 *	IF (CPUCON1.SGTDIS = 0) THEN
 *		(CSP) ← op1
 *	END IF
 *	(IP) ← op2
 *
 * Mnemonic:
 *	CALLS seg, caddr - DA SS MM MM
 */
static void c166_op_call_seg_caddr(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_CALL;
	const ut8 seg = buf[1];
	const ut16 caddr = rz_read_at_le16(buf, 2);
	c166_set_jump_target_seg_caddr(op, seg, caddr);
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = 4;

	ut8 SP = (ut8)GET_A_SP;
	SET_A_SP((ut64)SP - 2);
	SP = (ut8)GET_A_SP;

	const ut8 SGTDIS = (ut8)GET_A_SGTDIS;
	if (SGTDIS == 0) {
		if (!SET_A_CSP((ut64)seg)) {
			RZ_LOG_WARN("Error setting reg value\n");
		}
	}
	SET_A_IP((ut64)caddr);
	op->eob = true;
}

/**
 * Pushes the word specified by operand op1 and the value of the instruction pointer, IP,
 * onto the system stack, and branches to the absolute memory location specified by the
 * second operand op2. Because IP always points to the instruction following the branch
 * instruction, the value stored on the system stack represents the return address of the
 * calling routine.
 *
 * Syntax:
 *	PCALL op1, op2
 * Source Operand(s):
 *	op1 → WORD
 *	op2 → 16-bit address offset
 * Destination Operand(s):
 *	none
 * Operation:
 *	(tmp) ← (op1)
 *	(SP) ← (SP) - 2
 *	((SP)) ← (tmp)
 *	(SP) ← (SP) - 2
 *	((SP)) ← (IP)
 *	(IP) ← op2
 *
 * Mnemonic:
 *	PCALL reg, caddr - E2 RR MM MM
 */
static void c166_op_pcall_reg_caddr(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	const ut16 caddr = rz_read_at_le16(buf, 2);
	op->stackop = RZ_ANALYSIS_STACK_INC;
	op->stackptr = 4;

	ut8 SP = (ut8)GET_A_SP;
	SET_A_SP((ut64)SP - 2);
	SP = (ut8)GET_A_SP;
	SET_A_IP((ut64)caddr);

	op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
	c166_set_jump_target_from_caddr(op, caddr);
	c166_set_mimo_addr_from_reg(op, buf[1]);
	op->eob = true;
}

/**
 * If the condition specified by op1 is met, a branch to the absolute memory location
 * specified by the second operand op2 is taken. The value of the instruction pointer IP is
 * placed into the system stack. Because the IP always points to the instruction following
 * the branch instruction, the value stored in the system stack represents the return
 * address of the calling routine. A static prediction scheme is used: if the bit ’a’ of the
 * instruction long word is cleared then CALLA is assumed ’taken’ and if this bit is set to 1,
 * CALLA is assumed ’not taken’. CALLA+ and CALLA- instructions are converted into
 * CALLA assumed ’taken’ (prediction bit cleared) and ’not taken’ (prediction bit set)
 * respectively. For regular CALLA instructions, the assembler assumes them ’taken’.
 *
 * Syntax:
 *	CALLA op1, op2
 * Source Operand(s):
 *	op1 → extended condition code
 *	op2 → 16-bit address offset
 * Destination Operand(s):
 *	none
 * Operation:
 *	IF (op1) THEN
 *		(SP) ← (SP) - 2
 *		((SP)) ← (IP)
 *		(IP) ← op2
 *	ELSE
 *		next instruction
 *	END IF
 *
 * Mnemonic:
 *	CALLA xcc, caddr - CA d00a MM MM
 */
static void c166_op_call_cc_caddr(RzAnalysisOp *op, const ut8 *buf) {
	op->cond = c166_cc_to_cond(buf[1]);
	if (op->cond == RZ_TYPE_COND_AL) { // Absolute Unconditional
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_CCALL;
		FAIL;
	}
	if (buf[1]) {
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
	}
	c166_set_jump_target_from_caddr(op, rz_read_at_le16(buf, 2));
	op->eob = true;
}

/**
 * If the condition specified by op1 is met, a branch to the location specified indirectly by
 * the second operand op2 is taken. The value of the instruction pointer IP is placed onto
 * the system stack. Because the IP always points to the instruction following the branch
 * instruction, the value stored in the system stack represents the return address of the
 * calling routine. If the condition is not met, no action is taken and the next instruction
 * is executed normally.
 *
 * Syntax:
 *	CALLI op1, op2
 * Source Operand(s):
 *	op1 → condition code
 *	op2 → 16-bit address offset
 * Destination Operand(s):
 *	none
 * Operation:
 *	IF (op1) THEN
 *		(SP) ← (SP) - 2
 *		((SP)) ← (IP)
 *		(IP) ← op2
 *	ELSE
 *		next instruction
 *	END IF
 *
 * Mnemonic:
 *	CALLI cc, [Rwn] - AB cn
 */
static void c166_op_call_cc_rwn(RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
	op->cond = c166_cc_to_cond(buf[1]);
	op->reg = c166_rw[buf[1] & 0xF];
	op->fail = op->addr + op->size;
	op->eob = true;
}

/**
 * A branch is taken to the location specified by the instruction pointer IP plus the relative
 * displacement op1. The displacement is a two’s complement number which is sign
 * extended and counts the relative distance in words. The value of the instruction pointer
 * (IP) is placed into the system stack. Because the IP always points to the instruction
 * following the branch instruction, the value stored in the system stack represents the
 * return address of the calling routine. The value of the IP used in the target address
 * calculation is the address of the instruction following the CALLR instruction.
 *
 * Syntax:
 *	CALLR op1
 * Source Operand(s):
 *	op1 → 8-bit signed displacement
 * Destination Operand(s):
 *	none
 * Operation:
 *	(SP) ← (SP) - 2
 *	((SP)) ← (IP)
 *	(IP) ← (IP) + 2*sign_extend(op1)
 *
 * Mnemonic:
 *	CALLR rel - BB rr
 */
static void c166_op_call_rel(RzAnalysisOp *op, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_CALL;
	op->jump = op->addr + op->size + (2 * ((st8)buf[1]));
	op->stackop = RZ_ANALYSIS_STACK_GET;
	op->eob = true;
}

/**
 * Returns from a subroutine. The IP is popped from the system stack.
 *
 * Syntax:
 *	RET
 * Source Operand(s):
 *	none
 * Destination Operand(s):
 *	none
 * Operation:
 *	(IP) ← ((SP))
 *	(SP) ← (SP) + 2
 *
 * Mnemonic:
 *	RET - CB 00
 */
static void c166_op_ret(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->eob = true;
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	op->stackop = RZ_ANALYSIS_STACK_GET;
	op->stackptr = 2;
}

/**
 * Returns from an interrupt routine. The IP, CSP, and PSW are popped off the
 * system stack. The CSP is only popped if segmentation is enabled.
 * This is indicated by the SGTDIS bit in the CPUCON1 register.
 *
 * Syntax:
 *	RETI
 *
 * Source Operand(s):
 *	none
 *
 * Destination Operand(s):
 *	none
 *
 * Operation:
 *	(IP) ← ((SP))
 *	(SP) ← (SP) + 2
 *	IF (CPUCON1.SGTDIS = 0) THEN
 *		(CSP) ← ((SP))
 *		(SP) ← (SP) + 2
 *	END IF
 *	(PSW) ← ((SP))
 *	(SP) ← (SP) + 2
 *
 * Mnemonic:
 *	RETI - FB 88
 */
static void c166_op_reti(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->eob = true;
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	op->stackop = RZ_ANALYSIS_STACK_GET;
	op->stackptr = 6;
}

/**
 * Returns from a subroutine. First the IP is popped from the system stack
 * and then the next word is popped from the system stack into the operand
 * specified by op1.
 *
 * Syntax:
 *	RETP op1
 *
 * Source Operand(s):
 *	none
 *
 * Destination Operand(s):
 *	op1 → WORD
 *
 * Operation:
 *	(IP) ← ((SP))
 *	(SP) ← (SP) + 2
 *	(tmp) ← ((SP))
 *	(SP) ← (SP) + 2
 *	(op1) ← (tmp)
 *
 * Mnemonic:
 *	RETP reg - EB RR
 */
static void c166_op_retp(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->eob = true;
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	op->stackop = RZ_ANALYSIS_STACK_GET;
	op->stackptr = 4;
	op->dst = c166_new_reg_value(analysis, buf[1], false);
}

/**
 * Returns from an inter-segment subroutine. The IP and CSP are popped from
 * the system stack.
 *
 * Syntax:
 *	RETS
 *
 * Source Operand(s):
 *	none
 *
 * Destination Operand(s):
 *	none
 *
 * Operation:
 *	(IP) ← ((SP))
 *	(SP) ← (SP) + 2
 *	IF (CPUCON1.SGTDIS = 0) THEN
 *		(CSP) ← ((SP))
 *	END IF
 *	(SP) ← (SP) + 2
 *
 * Mnemonic:
 *	RETS - DB 00
 */
static void c166_op_rets(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	op->eob = true;
	op->type = RZ_ANALYSIS_OP_TYPE_RET;
	op->stackop = RZ_ANALYSIS_STACK_GET;
	op->stackptr = 4;
}

static void c166_op_mov_reg_data(RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	const ut8 reg = buf[1];
	const bool byte = buf[0] == C166_MOVB_reg_data8;
	const ut16 mask = byte ? 0xFF : 0xFFFF;
	const ut16 data = rz_read_at_le16(&buf, 2) & mask;

	op->type = RZ_ANALYSIS_OP_TYPE_MOV;
	op->dst = c166_new_reg_value(analysis, reg, false);
	op->src[0] = c166_new_imm_value(data, true);
	if (op->dst != NULL) {
		op->mmio_address = op->dst->base;
	}
}

static void c166_op_mov_reg_mem(const RzAnalysis *analysis, RzAnalysisOp *op, const C166_Inst *instr, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_MOV;
	const bool byte = buf[0] != C166_MOV_reg_mem;
	const ut16 mask = byte ? 0xFF : 0xFFFF;
	const ut32 addr = rz_read_at_le16(buf, 2) & mask;
	op->dst = c166_new_reg_value(analysis, buf[1], byte);
	op->src[0] = c166_new_mem_value(analysis, instr, addr);
	if (op->dst != NULL) {
		op->mmio_address = op->dst->base;
	}
}

static void c166_op_mov_mem_reg(const RzAnalysis *analysis, RzAnalysisOp *op, const C166_Inst *instr, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_MOV;
	const bool byte = buf[0] != C166_MOV_mem_reg;
	op->src[0] = c166_new_reg_value(analysis, buf[1], byte);
	op->dst = c166_new_mem_value(analysis, instr, rz_read_at_le16(buf, 2));
	if (op->src[0])
		op->mmio_address = op->src[0]->base;
}

static void c166_op_bfld(const RzAnalysis *analysis, RzAnalysisOp *op, const C166_Inst *instr, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_STORE;
	op->dst = c166_new_bitaddr_value(analysis, instr, buf[1]);
	if (op->dst != NULL) {
		op->mmio_address = op->dst->base;
	}
}

static void c166_op_jmp_bitoff(const RzAnalysis *analysis, RzAnalysisOp *op, const RzTypeCond cond, const C166_Inst *instr, const ut8 *buf) {
	op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
	op->cond = cond;
	op->ptr = op->addr + op->size + (2 * ((st8)buf[2]));
	op->jump = op->addr + op->size + (2 * ((st8)buf[2]));
	op->fail = op->addr + op->size;
	op->src[0] = c166_new_bitaddr_value(analysis, instr, buf[1]);
	if (op->src[0]) {
		op->mmio_address = op->src[0]->base;
	}
}

static void c166_op_set_type(RZ_NONNULL C166_Inst *instr, RzAnalysis *analysis, RzAnalysisOp *op, const ut8 *buf) {
	const ut8 operand1 = get_operand(instr, 1);
	switch (instr->id) {
	case C166_ADD_Rwn_Rwm:
	case C166_ADDC_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_ADD, false);
		break;
	case C166_ADDB_Rbn_Rbm:
	case C166_ADDCB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_ADD, true);
		break;
	case C166_ADD_Rwn_x:
	case C166_ADDC_Rwn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_ADD, false);
		break;
	case C166_ADDB_Rbn_x:
	case C166_ADDCB_Rbn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_ADD, true);
		break;
	case C166_ADD_mem_reg:
	case C166_ADD_reg_mem:
	case C166_ADDB_mem_reg:
	case C166_ADDB_reg_mem:
	case C166_ADDC_mem_reg:
	case C166_ADDC_reg_mem:
	case C166_ADDCB_mem_reg:
	case C166_ADDCB_reg_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		c166_set_mimo_addr_from_reg(op, operand1);
		break;
	case C166_ADD_reg_data16:
	case C166_ADDC_reg_data16:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (buf[1] > 0xF0) {
			op->reg = c166_rb[buf[1] & 0xF];
		}
		op->val = rz_read_at_le16(buf, 2);
		c166_set_mimo_addr_from_reg(op, buf[1]);
		break;
	case C166_ADDB_reg_data8:
	case C166_ADDCB_reg_data8:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (operand1 > 0xF0) {
			op->reg = c166_rb[operand1 & 0xF];
		}
		op->val = get_operand(instr, 2);
		c166_set_mimo_addr_from_reg(op, operand1);
		break;

	case C166_SUB_Rwn_Rwm:
	case C166_SUBC_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_SUB, false);
		break;
	case C166_SUBB_Rbn_Rbm:
	case C166_SUBCB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_SUB, true);
		break;
	case C166_SUB_Rwn_x:
	case C166_SUBC_Rwn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_SUB, false);
		break;
	case C166_SUBB_Rbn_x:
	case C166_SUBCB_Rbn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_SUB, true);
		break;
	case C166_SUB_mem_reg:
	case C166_SUB_reg_data16:
	case C166_SUB_reg_mem:
	case C166_SUBC_mem_reg:
	case C166_SUBC_reg_data16:
	case C166_SUBC_reg_mem:
	case C166_SUBB_mem_reg:
	case C166_SUBB_reg_data8:
	case C166_SUBB_reg_mem:
	case C166_SUBCB_mem_reg:
	case C166_SUBCB_reg_data8:
	case C166_SUBCB_reg_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		c166_set_mimo_addr_from_reg(op, operand1);
		break;
	case C166_MUL_Rwn_Rwm:
	case C166_MULU_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_MUL, false);
		break;
	case C166_DIV_Rwn:
	case C166_DIVL_Rwn:
	case C166_DIVLU_Rwn:
	case C166_DIVU_Rwn:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case C166_AND_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_AND, false);
		break;
	case C166_ANDB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_AND, true);
		break;
	case C166_AND_Rwn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_AND, false);
		break;
	case C166_ANDB_Rbn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_AND, true);
		break;
	case C166_AND_mem_reg:
	case C166_AND_reg_data16:
	case C166_AND_reg_mem:
	case C166_ANDB_mem_reg:
	case C166_ANDB_reg_data8:
	case C166_ANDB_reg_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		c166_set_mimo_addr_from_reg(op, operand1);
		break;
	case C166_OR_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_OR, false);
		break;
	case C166_OR_Rwn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_OR, false);
		break;
	case C166_ORB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_OR, true);
		break;
	case C166_ORB_Rbn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_OR, true);
		break;
	case C166_OR_mem_reg:
	case C166_OR_reg_data16:
	case C166_OR_reg_mem:
	case C166_ORB_mem_reg:
	case C166_ORB_reg_data8:
	case C166_ORB_reg_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		c166_set_mimo_addr_from_reg(op, operand1);
		break;
	case C166_XOR_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_XOR, false);
		break;
	case C166_XOR_Rwn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_XOR, false);
		break;
	case C166_XORB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_XOR, true);
		break;
	case C166_XORB_Rbn_x:
		c166_op_rn_x(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_XOR, true);
		break;
	case C166_XOR_mem_reg:
	case C166_XOR_reg_data16:
	case C166_XOR_reg_mem:
	case C166_XORB_mem_reg:
	case C166_XORB_reg_data8:
	case C166_XORB_reg_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		c166_set_mimo_addr_from_reg(op, operand1);
		break;
	case C166_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case C166_BCLR_bitoff0:
	case C166_BCLR_bitoff1:
	case C166_BCLR_bitoff2:
	case C166_BCLR_bitoff3:
	case C166_BCLR_bitoff4:
	case C166_BCLR_bitoff5:
	case C166_BCLR_bitoff6:
	case C166_BCLR_bitoff7:
	case C166_BCLR_bitoff8:
	case C166_BCLR_bitoff9:
	case C166_BCLR_bitoff10:
	case C166_BCLR_bitoff11:
	case C166_BCLR_bitoff12:
	case C166_BCLR_bitoff13:
	case C166_BCLR_bitoff14:
	case C166_BCLR_bitoff15:
	case C166_BSET_bitoff0:
	case C166_BSET_bitoff1:
	case C166_BSET_bitoff2:
	case C166_BSET_bitoff3:
	case C166_BSET_bitoff4:
	case C166_BSET_bitoff5:
	case C166_BSET_bitoff6:
	case C166_BSET_bitoff7:
	case C166_BSET_bitoff8:
	case C166_BSET_bitoff9:
	case C166_BSET_bitoff10:
	case C166_BSET_bitoff11:
	case C166_BSET_bitoff12:
	case C166_BSET_bitoff13:
	case C166_BSET_bitoff14:
	case C166_BSET_bitoff15:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->dst = c166_new_bitaddr_value(analysis, instr, operand1);
		if (op->dst)
			op->mmio_address = op->dst->base;
		break;
	case C166_BFLDH_bitoff_x:
	case C166_BFLDL_bitoff_x:
		c166_op_bfld(analysis, op, instr, buf);
		break;
	case C166_BMOV_bitaddr_bitaddr:
	case C166_BMOVN_bitaddr_bitaddr:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->dst = c166_new_bitaddr_value(analysis, instr, operand1);
		op->src[0] = c166_new_bitaddr_value(analysis, instr, get_operand(instr, 2));
		if (op->dst)
			op->mmio_address = op->dst->base;
		break;
	case C166_BCMP_bitaddr_bitaddr:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case C166_RET:
		c166_op_ret(analysis, op, buf);
		break;
	case C166_RETI:
		c166_op_reti(analysis, op, buf);
		break;
	case C166_RETS:
		c166_op_rets(analysis, op, buf);
		break;
	case C166_RETP_reg:
		c166_op_retp(analysis, op, buf);
		break;
	case C166_POP_reg:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		c166_set_mimo_addr_from_reg(op, operand1);
		break;
	case C166_PUSH_reg:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		c166_set_mimo_addr_from_reg(op, operand1);
		break;
	case C166_SHL_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_SHL, false);
		break;
	case C166_SHL_Rwn_data4:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case C166_ASHR_Rwn_Rwm:
	case C166_SHR_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_SHR, false);
		break;
	case C166_SHR_Rwn_data4:
	case C166_ASHR_Rwn_data4:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case C166_ROL_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_ROL, false);
		break;
	case C166_ROL_Rwn_data4:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case C166_ROR_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_ROR, false);
		break;
	case C166_ROR_Rwn_data4:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case C166_MOV_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_MOV, false);
		break;
	case C166_MOV_Rwn_data4:
	case C166_MOV_Rwn_oRwm:
	case C166_MOV_Rwn_oRwmp:
	case C166_MOV_noRwm_Rwn:
	case C166_MOV_oRwm_Rwn:
	case C166_MOV_oRwn_oRwm:
	case C166_MOV_oRwn_oRwmp:
	case C166_MOV_oRwnp_oRwm:
	case C166_MOVB_Rbn_Rbm:
	case C166_MOVB_Rbn_data4:
	case C166_MOVB_Rbn_oRwm:
	case C166_MOVB_Rbn_oRwmp:
	case C166_MOVB_noRwm_Rbn:
	case C166_MOVB_oRwm_Rbn:
	case C166_MOVB_oRwn_oRwm:
	case C166_MOVB_oRwn_oRwmp:
	case C166_MOVB_oRwnp_oRwm:
	case C166_MOVBS_Rwn_Rbm:
	case C166_MOVBZ_Rwn_Rbm:
	case C166_MOV_Rwn_oRwm_data16:
	case C166_MOV_oRwm_data16_Rwn:
	case C166_MOVB_Rbn_oRwm_data16:
	case C166_MOVB_oRwm_data16_Rbn:
	case C166_MOVBS_reg_mem:
	case C166_MOVBZ_reg_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case C166_MOV_reg_data16:
	case C166_MOVB_reg_data8:
		c166_op_mov_reg_data(analysis, op, buf);
		break;
	case C166_MOV_reg_mem:
	case C166_MOVB_reg_mem:
		c166_op_mov_reg_mem(analysis, op, instr, buf);
		break;
	case C166_MOV_mem_reg:
	case C166_MOVB_mem_reg:
	case C166_MOVBS_mem_reg:
	case C166_MOVBZ_mem_reg:
		c166_op_mov_mem_reg(analysis, op, instr, buf);
		break;
	case C166_MOV_mem_oRwn:
	case C166_MOVB_mem_oRwn:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->dst = c166_new_mem_value(analysis, instr, rz_read_at_le16(buf, 2));
		if (op->dst) {
			op->mmio_address = op->dst->base;
		}
		break;
	case C166_MOV_oRwn_mem:
	case C166_MOVB_oRwn_mem: {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->src[0] = c166_new_mem_value(analysis, instr, rz_read_at_le16(buf, 2));
		if (op->src[0])
			op->mmio_address = op->src[0]->base;
		break;
	}
	case C166_NEG_Rwn:
	case C166_NEGB_Rbn:
		c166_op_neg(analysis, op, buf);
		break;
	case C166_CPL_Rwn:
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		op->reg = c166_rw[(operand1 >> 4) & 0xF];
		break;
	case C166_CPLB_Rbn:
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		op->reg = c166_rb[(operand1 >> 4) & 0xF];
		break;
	case C166_CMP_Rwn_Rwm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_CMP, false);
		break;
	case C166_CMP_Rwn_x:
	case C166_CMPD1_Rwn_data4:
	case C166_CMPD2_Rwn_data4:
	case C166_CMPI1_Rwn_data4:
	case C166_CMPI2_Rwn_data4:
	case C166_CMPD1_Rwn_data16:
	case C166_CMPD2_Rwn_data16:
	case C166_CMPI1_Rwn_data16:
	case C166_CMPI2_Rwn_data16:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->reg = c166_rw[(operand1 >> 4) & 0xF];
		break;
	case C166_CMPB_Rbn_Rbm:
		c166_op_rn_rm(analysis, op, operand1, RZ_ANALYSIS_OP_TYPE_CMP, true);
		break;
	case C166_CMPB_Rbn_x:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->reg = c166_rb[(operand1 >> 4) & 0xF];
		break;
	case C166_CMPD1_Rwn_mem:
	case C166_CMPD2_Rwn_mem:
	case C166_CMPI1_Rwn_mem:
	case C166_CMPI2_Rwn_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->reg = c166_rw[operand1 & 0xF];
		op->mmio_address = rz_read_at_le16(buf, 2);
		break;
	case C166_CMP_reg_data16:
	case C166_CMP_reg_mem:
	case C166_CMPB_reg_data8:
	case C166_CMPB_reg_mem:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		c166_set_mimo_addr_from_reg(op, operand1);
		break;
	case C166_TRAP_trap7:
		c166_op_trap7(analysis, op, buf);
		op->eob = true;
		break;
	case C166_JB_bitaddr_rel:
	case C166_JBC_bitaddr_rel:
		c166_op_jmp_bitoff(analysis, op, RZ_TYPE_COND_EQ, instr, buf);
		op->eob = true;
		break;
	case C166_JNB_bitaddr_rel: ///< Relative Jump if Bit Clear
	case C166_JNBS_bitaddr_rel: ///< Relative Jump if Bit Clear and Set Bit
		c166_op_jmp_bitoff(analysis, op, RZ_TYPE_COND_NE, instr, buf);
		op->eob = true;
		break;
	case C166_JMPI_cc_oRwn: {
		c166_op_jmpi_cc_orwn(analysis, op, buf);
		op->eob = true;
		break;
	}
	case C166_JMPR_cc_C_or_ULT_rel:
	case C166_JMPR_cc_EQ_or_Z_rel:
	case C166_JMPR_cc_N_rel:
	case C166_JMPR_cc_NC_or_NGE_rel:
	case C166_JMPR_cc_NE_or_NZ_rel:
	case C166_JMPR_cc_NET_rel:
	case C166_JMPR_cc_NN_rel:
	case C166_JMPR_cc_NV_rel:
	case C166_JMPR_cc_SGE_rel:
	case C166_JMPR_cc_SGT_rel:
	case C166_JMPR_cc_SLE_rel:
	case C166_JMPR_cc_SLT_rel:
	case C166_JMPR_cc_UC_rel:
	case C166_JMPR_cc_UGT_rel:
	case C166_JMPR_cc_ULE_rel:
	case C166_JMPR_cc_V_rel:
		c166_op_jmpr_cc_rel(analysis, op, buf);
		op->eob = true;
		break;
	case C166_JMPS_seg_caddr: ///< Intersegment transitions (Far Jumps/Calls)
		c166_op_jmps_seg_caddr(analysis, op, buf);
		op->eob = true;
		break;
	case C166_JMPA_cc_caddr: ///< Intra-segment (Absolute) transitions and calls
		c166_op_jmpa_cc_caddr(analysis, op, buf);
		op->eob = true;
		break;
	case C166_CALLA_cc_caddr: ///< Intra-segment (Absolute) transitions and calls
		c166_op_call_cc_caddr(op, buf);
		break;
	case C166_CALLI_cc_Rwn:
		c166_op_call_cc_rwn(op, buf);
		break;
	case C166_CALLR_rel:
		c166_op_call_rel(op, buf);
		break;
	case C166_CALLS_seg_caddr: ///< Intersegment transitions (Far Jumps/Calls)
		c166_op_call_seg_caddr(analysis, op, buf);
		break;
	case C166_PCALL_reg_caddr:
		c166_op_pcall_reg_caddr(analysis, op, buf);
		break;
	case C166_EXTP_or_EXTS_Rwm_irang2:
	case C166_EXTP_or_EXTS_pag10_or_seg8_irang2:
		c166_op_ext(analysis, op, buf);
		break;
	case C166_ATOMIC_or_EXTR_irang2:
		c166_op_atomic_or_extr(analysis, op, buf);
		break;
	case C166_SCXT_reg_mem:
	case C166_SCXT_reg_data16:
		c166_op_scxt(analysis, op, buf);
		op->eob = true;
		break;
	case C166_PRIOR_Rwn_Rwm:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case C166_EINIT:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case C166_SBRK:
	case C166_SRST:
	case C166_SRVWDT:
	case C166_DISWDT:
	case C166_ENWDT:
	case C166_PWRDN:
	case C166_IDLE:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case C166_BXOR_bitaddr_bitaddr:
	case C166_BAND_bitaddr_bitaddr:
	case C166_BOR_bitaddr_bitaddr:
		break;
	case C166_CoXXX_83:
	case C166_CoMOV:
	case C166_CoXXX_93:
	case C166_CoXXX_A3:
	case C166_CoSTORE_C3:
	case C166_CoSTORE_B3:
		break;
	default:
		RZ_LOG_DEBUG("c166_op_set_type 0x%02x\n", instr->id);
		rz_warn_if_reached();
	}
}

static int c166_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	rz_return_val_if_fail(analysis && op && buf && len > 0, 0);

	if (analysis->big_endian) {
		RZ_LOG_FATAL("analysis->big_endian");
		return -1;
	}

	if (analysis->pcalign == 0) {
		analysis->pcalign = 2;
		RZ_LOG_FATAL("analysis->pcalign");
	}

	C166State *state = (C166State *)analysis->plugin_data;
	if (!state) {
		RZ_LOG_FATAL("C166State was NULL.");
	}
	C166_Inst instr = { 0 };
	instr.addr = (ut32)addr;

	op->addr = addr;
	op->id = (int)buf[0];

	if (check_unused_opcode(op->id)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_UNKNOWN;
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->nopcode = 1;
		op->cycles = 1;
		op->size = 2;
		op->eob = true;
		op->mnemonic = rz_str_newf("%s %x", FMT_BYTE, buf[0]);
		return op->size;
	}

	const st32 ret = c166_decode_command(state, &instr, buf, len);
	if (ret <= 0) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->mnemonic = rz_str_dup("invalid");
		op->eob = true;
		op->size = ret;
		return op->size;
	}
	if (RZ_STR_ISEMPTY(instr.instr))
		RZ_LOG_DEBUG("instr.addr: 0x%04x [0x%02x]\n", instr.addr, instr.id);
	rz_warn_if_fail(RZ_STR_ISNOTEMPTY(instr.instr));
	rz_warn_if_fail(ret == 1 || ret == 2 || ret == 4);

	op->size = ret;

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s",
			instr.instr, RZ_STR_ISNOTEMPTY(instr.operands) ? " " : "", instr.operands);
	}

	c166_op_set_type(&instr, analysis, op, buf);
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	IP\n"
		"=SP	SP\n"
		"=A0	r8\n"
		"=A1	r9\n"
		"=A2	r10\n"
		"=A3	r11\n"

		"gpr	IP	.32	0	0\n"

		"gpr	r0	.16	65040	0\n" // FE10 == CP
		"gpr	r1	.16	65042	0\n"
		"gpr	r2	.16	65044	0\n"
		"gpr	r3	.16	65046	0\n"
		"gpr	r4	.16	65048	0\n"
		"gpr	r5	.16	65050	0\n"
		"gpr	r6	.16	65052	0\n"
		"gpr	r7	.16	65054	0\n"
		"gpr	r8	.16	65056	0\n"
		"gpr	r9	.16	65058	0\n"
		"gpr	r10	.16	65060	0\n"
		"gpr	r11	.16	65062	0\n"
		"gpr	r12	.16	65064	0\n"
		"gpr	r13	.16	65066	0\n"
		"gpr	r14	.16	65068	0\n"
		"gpr	r15	.16	65070	0\n"

		// Sub regs
		"gpr	rl0	.8	65040	0\n"
		"gpr	rh0	.8	65041	0\n"
		"gpr	rl1	.8	65042	0\n"
		"gpr	rh1	.8	65043	0\n"
		"gpr	rl2	.8	65044	0\n"
		"gpr	rh2	.8	65045	0\n"
		"gpr	rl3	.8	65046	0\n"
		"gpr	rh3	.8	65047	0\n"
		"gpr	rl4	.8	65048	0\n"
		"gpr	rh4	.8	65049	0\n"
		"gpr	rl5	.8	65050	0\n"
		"gpr	rh5	.8	65051	0\n"
		"gpr	rl6	.8	65052	0\n"
		"gpr	rh6	.8	65053	0\n"
		"gpr	rl7	.8	65054	0\n"
		"gpr	rh7	.8	65055	0\n"

		"seg	DPP0	.10	65024	0\n" ///< FE00; CPU Data Page Pointer 0 Register (10 bits)
		"seg	DPP1	.10	65026	0\n" ///< FE02; CPU Data Page Pointer 1 Register (10 bits)
		"seg	DPP2	.10	65028	0\n" ///< FE04; CPU Data Page Pointer 2 Register (10 bits)
		"seg	DPP3	.10	65030	0\n" ///< FE06; CPU Data Page Pointer 3 Register (10 bits)
		"gpr	CSP	.8	65032	0\n" ///< FE08; CPU Code Segment Pointer Register (8 bits, read only)

		"gpr	r_FE0A	.16	65034	0\n" ///< FE0A; RESERVED
		"gpr	MDH	.16	65036	0\n" ///< FE0C; CPU Multiply Divide Register - High Word
		"gpr	MDL	.16	65038	0\n" ///< FE0E; CPU Multiply Divide Register - Low Word
		"gpr	CP	.16	65040	0\n" ///< FE10; CPU Context Pointer Register
		"gpr	SP	.16	65042	0\n" ///< FE12; CPU System Stack Pointer Register
		"gpr	STKOV	.16	65044	0\n" ///< FE14; CPU Stack Overflow Pointer Register
		"gpr	STKUN	.16	65046	0\n" ///< FE16; CPU Stack Underflow Pointer Register
		"gpr	CPUCON1	.16	65048	0\n" ///< FE18; CPU Core Control Register 1
		"seg	VECSC	.2	65048.5	0\n" ///< CPU Core: Scaling factor of Vector Table
		"flg	WDTCTL	.1	65048.4	0\n" ///< CPU Core: Configuration of Watch Dog Timer
		"flg	SGTDIS	.1	65048.3	0\n" ///< CPU Core: Segmentation Disable/Enable Control
		"flg	INTSCXT	.1	65048.2	0\n" ///< CPU Core: Enable Interruptibility of Switch Context
		"flg	BP	.1	65048.1	0\n" ///< CPU Core: Enable Branch Prediction Unit
		"flg	ZCJ	.1	65048.0	0\n" ///< CPU Core: Enable Zero Cycle Jump function
		"gpr	CPUCON2	.16	65050	0\n" ///< FE1A; CPU Core Control Register 2
		"gpr	r_FE1C	.16	65052	0\n" ///< FE1C; RESERVED
		"gpr	r_FE1E	.16	65054	0\n" ///< FE1E; RESERVED
		"gpr	r_FE20	.16	65056	0\n" ///< FE20; RESERVED
		"gpr	r_FE22	.16	65058	0\n" ///< FE22; RESERVED
		"gpr	r_FE24	.16	65060	0\n" ///< FE24; RESERVED
		"gpr	r_FE26	.16	65062	0\n" ///< FE26; RESERVED
		"gpr	r_FE28	.16	65064	0\n" ///< FE28; RESERVED
		"gpr	r_FE2A	.16	65066	0\n" ///< FE2A; RESERVED
		"gpr	r_FE2C	.16	65068	0\n" ///< FE2C; RESERVED
		"gpr	r_FE2E	.16	65070	0\n" ///< FE2E; RESERVED
		"gpr	r_FE30	.16	65072	0\n" ///< FE30; RESERVED
		"gpr	r_FE32	.16	65074	0\n" ///< FE32; RESERVED
		"gpr	r_FE34	.16	65076	0\n" ///< FE34; RESERVED
		"gpr	r_FE36	.16	65078	0\n" ///< FE36; RESERVED
		"gpr	r_FE38	.16	65080	0\n" ///< FE38; RESERVED
		"gpr	r_FE3A	.16	65082	0\n" ///< FE3A; RESERVED
		"gpr	r_FE3C	.16	65084	0\n" ///< FE3C; RESERVED
		"gpr	r_FE3E	.16	65086	0\n" ///< FE3E; RESERVED
		"gpr	T2	.16	65088	0\n" ///< FE40; GPT1 Timer 2 Register
		"gpr	T3	.16	65090	0\n" ///< FE42; GPT1 Timer 3 Register
		"gpr	T4	.16	65092	0\n" ///< FE44; GPT1 Timer 4 Register
		"gpr	T5	.16	65094	0\n" ///< FE46; GPT2 Timer 5 Register
		"gpr	T6	.16	65096	0\n" ///< FE48; GPT2 Timer 6 Register
		"gpr	CAPREL	.16	65098	0\n" ///< FE4A; GPT2 Capture/Reload Register
		"gpr	r_FE4C	.16	65100	0\n" ///< FE4C; RESERVED
		"gpr	r_FE4E	.16	65102	0\n" ///< FE4E; RESERVED
		"gpr	T0	.16	65104	0\n" ///< FE50; CAPCOM Timer 0 Register
		"gpr	T1	.16	65106	0\n" ///< FE52; CAPCOM Timer 1 Register
		"gpr	T0REL	.16	65108	0\n" ///< FE54; CAPCOM Timer 0 Reload Register
		"gpr	T1REL	.16	65110	0\n" ///< FE56; CAPCOM Timer 1 Reload Register
		"gpr	r_FE58	.16	65112	0\n" ///< FE58; RESERVED
		"gpr	r_FE5A	.16	65114	0\n" ///< FE5A; RESERVED
		"gpr	r_FE5C	.16	65116	0\n" ///< FE5C; RESERVED
		"gpr	r_FE5E	.16	65118	0\n" ///< FE5E; RESERVED
		"gpr	r_FE60	.16	65120	0\n" ///< FE60; RESERVED
		"gpr	r_FE62	.16	65122	0\n" ///< FE62; RESERVED
		"gpr	r_FE64	.16	65124	0\n" ///< FE64; RESERVED
		"gpr	r_FE66	.16	65126	0\n" ///< FE66; RESERVED
		"gpr	r_FE68	.16	65128	0\n" ///< FE68; RESERVED
		"gpr	r_FE6A	.16	65130	0\n" ///< FE6A; RESERVED
		"gpr	r_FE6C	.16	65132	0\n" ///< FE6C; RESERVED
		"gpr	r_FE6E	.16	65134	0\n" ///< FE6E; RESERVED
		"gpr	r_FE70	.16	65136	0\n" ///< FE70; RESERVED
		"gpr	r_FE72	.16	65138	0\n" ///< FE72; RESERVED
		"gpr	r_FE74	.16	65140	0\n" ///< FE74; RESERVED
		"gpr	r_FE76	.16	65142	0\n" ///< FE76; RESERVED
		"gpr	r_FE78	.16	65144	0\n" ///< FE78; RESERVED
		"gpr	r_FE7A	.16	65146	0\n" ///< FE7A; RESERVED
		"gpr	r_FE7C	.16	65148	0\n" ///< FE7C; RESERVED
		"gpr	CC31	.16	65150	0\n" ///< FE7E; CAPCOM 2 Register 31
		"gpr	CC0	.16	65152	0\n" ///< FE80; CAPCOM Register 0
		"gpr	CC1	.16	65154	0\n" ///< FE82; CAPCOM Register 1
		"gpr	CC2	.16	65156	0\n" ///< FE84; CAPCOM Register 2
		"gpr	CC3	.16	65158	0\n" ///< FE86; CAPCOM Register 3
		"gpr	CC4	.16	65160	0\n" ///< FE88; CAPCOM Register 4
		"gpr	CC5	.16	65162	0\n" ///< FE8A; CAPCOM Register 5
		"gpr	CC6	.16	65164	0\n" ///< FE8C; CAPCOM Register 6
		"gpr	CC7	.16	65166	0\n" ///< FE8E; CAPCOM Register 7
		"gpr	CC8	.16	65168	0\n" ///< FE90; CAPCOM Register 8
		"gpr	CC9	.16	65170	0\n" ///< FE92; CAPCOM Register 9
		"gpr	CC10	.16	65172	0\n" ///< FE94; CAPCOM Register 10
		"gpr	CC11	.16	65174	0\n" ///< FE96; CAPCOM Register 11
		"gpr	CC12	.16	65176	0\n" ///< FE98; CAPCOM Register 12
		"gpr	CC13	.16	65178	0\n" ///< FE9A; CAPCOM Register 13
		"gpr	CC14	.16	65180	0\n" ///< FE9C; CAPCOM Register 14
		"gpr	CC15	.16	65182	0\n" ///< FE9E; CAPCOM Register 15
		"gpr	ADDAT	.16	65184	0\n" ///< FEA0; A/D Converter Result Register
		"gpr	r_FEA2	.16	65186	0\n" ///< FEA2; RESERVED
		"gpr	r_FEA4	.16	65188	0\n" ///< FEA4; RESERVED
		"gpr	r_FEA6	.16	65190	0\n" ///< FEA6; RESERVED
		"gpr	r_FEA8	.16	65192	0\n" ///< FEA8; RESERVED
		"gpr	r_FEAA	.16	65194	0\n" ///< FEAA; RESERVED
		"gpr	r_FEAC	.16	65196	0\n" ///< FEAC; RESERVED
		"gpr	WDT	.16	65198	0\n" ///< FEAE; Watchdog Timer Register (read only)
		"gpr	S0TBUF	.16	65200	0\n" ///< FEB0; Serial Channel 0 Transmit Buffer Register
		"gpr	S0RBUF	.16	65202	0\n" ///< FEB2; Serial Channel 0 Receive Buffer Register (read only)
		"gpr	S0BG	.16	65204	0\n" ///< FEB4; Serial Channel 0 Baud Rate Generator Reload Register

		// "gpr			.8	65206	0\n" // FEB6;
		// "gpr			.8	65207	0\n" // FEB7;

		"gpr	S1TBUF	.16	65208	0\n" ///< FEB8; Serial Channel 1 Transmit Buffer Register
		"gpr	S1RBUF	.16	65210	0\n" ///< FEBA; Serial Channel 1 Receive Buffer Register
		"gpr	S1BG	.16	65212	0\n" ///< FEBC; Serial Channel 1 Baud Rate Generator/Reload Register
		"gpr	r_FEBE	.16	65214	0\n" ///< FEBE; RESERVED
		"gpr	PECC0	.16	65216	0\n" ///< FEC0; PEC Channel 0 Control Register
		"gpr	PECC1	.16	65218	0\n" ///< FEC2; PEC Channel 1 Control Register
		"gpr	PECC2	.16	65220	0\n" ///< FEC4; PEC Channel 2 Control Register
		"gpr	PECC3	.16	65222	0\n" ///< FEC6; PEC Channel 3 Control Register
		"gpr	PECC4	.16	65224	0\n" ///< FEC8; PEC Channel 4 Control Register
		"gpr	PECC5	.16	65226	0\n" ///< FECA; PEC Channel 5 Control Register
		"gpr	PECC6	.16	65228	0\n" ///< FECC; PEC Channel 6 Control Register
		"gpr	PECC7	.16	65230	0\n" ///< FECE; PEC Channel 7 Control Register
		"gpr	r_FED0	.16	65232	0\n" ///< FED0; RESERVED
		"gpr	r_FED2	.16	65234	0\n" ///< FED2; RESERVED
		"gpr	r_FED4	.16	65236	0\n" ///< FED4; RESERVED
		"gpr	r_FED6	.16	65238	0\n" ///< FED6; RESERVED
		"gpr	r_FED8	.16	65240	0\n" ///< FED8; RESERVED
		"gpr	r_FEDA	.16	65242	0\n" ///< FEDA; RESERVED
		"gpr	r_FEDC	.16	65244	0\n" ///< FEDC; RESERVED
		"gpr	r_FEDE	.16	65246	0\n" ///< FEDE; RESERVED
		"gpr	r_FEE0	.16	65248	0\n" ///< FEE0; RESERVED
		"gpr	r_FEE2	.16	65250	0\n" ///< FEE2; RESERVED
		"gpr	r_FEE4	.16	65252	0\n" ///< FEE4; RESERVED
		"gpr	r_FEE6	.16	65254	0\n" ///< FEE6; RESERVED
		"gpr	r_FEE8	.16	65256	0\n" ///< FEE8; RESERVED
		"gpr	r_FEEA	.16	65258	0\n" ///< FEEA; RESERVED
		"gpr	r_FEEC	.16	65260	0\n" ///< FEEC; RESERVED
		"gpr	r_FEEE	.16	65262	0\n" ///< FEEE; RESERVED
		"gpr	r_FEF0	.16	65264	0\n" ///< FEF0; RESERVED
		"gpr	r_FEF2	.16	65266	0\n" ///< FEF2; RESERVED
		"gpr	r_FEF4	.16	65268	0\n" ///< FEF4; RESERVED
		"gpr	r_FEF6	.16	65270	0\n" ///< FEF6; RESERVED
		"gpr	r_FEF8	.16	65272	0\n" ///< FEF8; RESERVED
		"gpr	r_FEFA	.16	65274	0\n" ///< FEFA; RESERVED
		"gpr	r_FEFC	.16	65276	0\n" ///< FEFC; RESERVED
		"gpr	r_FEFE	.16	65278	0\n" ///< FEFE; RESERVED
		"gpr	P0	.16	65280	0\n" ///< FF00; Port 0 Register
		"gpr	DP0	.16	65282	0\n" ///< FF02; Port 0 Direction Control Register
		"gpr	P1	.16	65284	0\n" ///< FF04; Port 1 Register
		"gpr	DP1	.16	65286	0\n" ///< FF06; Port 1 Direction Control Register
		"gpr	P4	.16	65288	0\n" ///< FF08; Port 4 Register (7 bits)
		"gpr	DP4	.16	65290	0\n" ///< FF0A; Port 4 Direction Control Register
		"gpr	SYSCON	.16	65292	0\n" ///< FF0C; CPU System Configuration Register
		"gpr	MDC	.16	65294	0\n" ///< FF0E; CPU Multiply/   Divide Control Register
		"gpr	PSW	.16	65296	0\n" ///< FF10; CPU Program Status Word
		"flg	e	.1	65296.4	0\n"
		"flg	z	.1	65296.3	0\n"
		"flg	v	.1	65296.2	0\n"
		"flg	c	.1	65296.1	0\n"
		"flg	n	.1	65296.0	0\n"
		"gpr	r_FF12	.16	65298	0\n" ///< FF12; RESERVED
		"gpr	r_FF14	.16	65300	0\n" ///< FF14; RESERVED
		"gpr	r_FF16	.16	65302	0\n" ///< FF16; RESERVED
		"gpr	r_FF18	.16	65304	0\n" ///< FF18; RESERVED
		"gpr	r_FF1A	.16	65306	0\n" ///< FF1A; RESERVED
		"gpr	ZEROS	.16	65308	0\n" ///< FF1C; Constant Value 0's Register (read only)
		"gpr	ONES	.16	65310	0\n" ///< FF1E; Constant Value 1's Register (read only)
		"gpr	r_FF20	.16	65312	0\n" ///< FF20; RESERVED
		"gpr	r_FF22	.16	65314	0\n" ///< FF22; RESERVED
		"gpr	r_FF24	.16	65316	0\n" ///< FF24; RESERVED
		"gpr	r_FF26	.16	65318	0\n" ///< FF26; RESERVED
		"gpr	r_FF28	.16	65320	0\n" ///< FF28; RESERVED
		"gpr	r_FF2A	.16	65322	0\n" ///< FF2A; RESERVED
		"gpr	r_FF2C	.16	65324	0\n" ///< FF2C; RESERVED
		"gpr	r_FF2E	.16	65326	0\n" ///< FF2E; RESERVED
		"gpr	r_FF30	.16	65328	0\n" ///< FF30; RESERVED
		"gpr	r_FF32	.16	65330	0\n" ///< FF32; RESERVED
		"gpr	r_FF34	.16	65332	0\n" ///< FF34; RESERVED
		"gpr	r_FF36	.16	65334	0\n" ///< FF36; RESERVED
		"gpr	r_FF38	.16	65336	0\n" ///< FF38; RESERVED
		"gpr	r_FF3A	.16	65338	0\n" ///< FF3A; RESERVED
		"gpr	r_FF3C	.16	65340	0\n" ///< FF3C; RESERVED
		"gpr	r_FF3E	.16	65342	0\n" ///< FF3E; RESERVED
		"gpr	T2CON	.16	65344	0\n" ///< FF40; GPT1 Timer 2 Control Register
		"gpr	T3CON	.16	65346	0\n" ///< FF42; GPT1 Timer 3 Control Register
		"gpr	T4CON	.16	65348	0\n" ///< FF44; GPT1 Timer 4 Control Register
		"gpr	T5CON	.16	65350	0\n" ///< FF46; GPT2 Timer 5 Control Register
		"gpr	T6CON	.16	65352	0\n" ///< FF48; GPT2 Timer 6 Control Register
		"gpr	r_FF4A	.16	65354	0\n" ///< FF4A; RESERVED
		"gpr	r_FF4C	.16	65356	0\n" ///< FF4C; RESERVED
		"gpr	r_FF4E	.16	65358	0\n" ///< FF4E; RESERVED
		"gpr	T01CON	.16	65360	0\n" ///< FF50; CAPCOM Timer 0 and Timer 1 Ctrl. Reg.
		"gpr	CCM0	.16	65362	0\n" ///< FF52; CAPCOM Mode Control Register 0
		"gpr	CCM1	.16	65364	0\n" ///< FF54; CAPCOM Mode Control Register 1
		"gpr	CCM2	.16	65366	0\n" ///< FF56; CAPCOM Mode Control Register 2
		"gpr	CCM3	.16	65368	0\n" ///< FF58; CAPCOM Mode Control Register 3
		"gpr	r_FF5A	.16	65370	0\n" ///< FF5A; RESERVED
		"gpr	r_FF5C	.16	65372	0\n" ///< FF5C; RESERVED
		"gpr	r_FF5E	.16	65374	0\n" ///< FF5E; RESERVED

		"gpr	T2IC	.16	65376	0\n" ///< FF60; GPT1 Timer 2 Interrupt Control Register
		"gpr	T3IC	.16	65378	0\n" ///< FF62; GPT1 Timer 3 Interrupt Control Register
		"gpr	T4IC	.16	65380	0\n" ///< FF64; GPT1 Timer 4 Interrupt Control Register
		"gpr	T5IC	.16	65382	0\n" ///< FF66; GPT2 Timer 5 Interrupt Control Register
		"gpr	T6IC	.16	65384	0\n" ///< FF68; GPT2 Timer 6 Interrupt Control Register
		"gpr	CRIC	.16	65386	0\n" ///< FF6A; GPT2 CAPREL Interrupt Control Register
		"gpr	S0TIC	.16	65388	0\n" ///< FF6C; Serial Channel 0 Transmit Interrupt Control Register
		"gpr	S0RIC	.16	65390	0\n" ///< FF6E; Serial Channel 0 Receive Interrupt Control Register
		"gpr	S0EIC	.16	65392	0\n" ///< FF70; Serial Channel 0 Error Interrupt Ctrl. Reg.
		"gpr	S1TIC	.16	65394	0\n" ///< FF72; Serial Channel 1 Transmit Interrupt Control
		"gpr	S1RIC	.16	65396	0\n" ///< FF74; Serial Channel 1 Receive Interrupt Control
		"gpr	S1EIC	.16	65398	0\n" ///< FF76; Serial Channel 1 Error Interrupt control
		"gpr	CC0IC	.16	65400	0\n" ///< FF78; CAPCOM Register 0 Interrupt Ctrl. Reg.
		"gpr	CC1IC	.16	65402	0\n" ///< FF7A; CAPCOM Register 1 Interrupt Ctrl. Reg.
		"gpr	CC2IC	.16	65404	0\n" ///< FF7C; CAPCOM Register 2 Interrupt Ctrl. Reg.
		"gpr	CC3IC	.16	65406	0\n" ///< FF7E; CAPCOM Register 3 Interrupt Ctrl. Reg.
		"gpr	CC4IC	.16	65408	0\n" ///< FF80; CAPCOM Register 4 Interrupt Ctrl. Reg.
		"gpr	CC5IC	.16	65410	0\n" ///< FF82; CAPCOM Register 5 Interrupt Ctrl. Reg.
		"gpr	CC6IC	.16	65412	0\n" ///< FF84; CAPCOM Register 6Interrupt Ctrl. Reg.
		"gpr	CC7IC	.16	65414	0\n" ///< FF86; CAPCOM Register 7 Interrupt Ctrl. Reg.
		"gpr	CC8IC	.16	65416	0\n" ///< FF88; CAPCOM Register 8 Interrupt Ctrl. Reg.
		"gpr	CC9IC	.16	65418	0\n" ///< FF8A; CAPCOM Register 9 Interrupt Ctrl. Reg.
		"gpr	CC10IC	.16	65420	0\n" ///< FF8C; CAPCOM Register 10 Interrupt Ctrl. Reg.
		"gpr	CC11IC	.16	65422	0\n" ///< FF8E; CAPCOM Register 11 Interrupt Ctrl. Reg.
		"gpr	CC12IC	.16	65424	0\n" ///< FF90; CAPCOM Register 12 Interrupt Ctrl. Reg.
		"gpr	CC13IC	.16	65426	0\n" ///< FF92; CAPCOM Register 13 Interrupt Ctrl. Reg.
		"gpr	CC14IC	.16	65428	0\n" ///< FF94; CAPCOM Register 14 Interrupt Ctrl. Reg.
		"gpr	CC15IC	.16	65430	0\n" ///< FF96; CAPCOM Register 15 Interrupt Ctrl. Reg.
		"gpr	ADCIC	.16	65432	0\n" ///< FF98; A/D Converter End of Conversion Interrupt Control Register
		"gpr	ADEIC	.16	65434	0\n" ///< FF9A; A/D Converter Overrun Error Interrupt Control Register
		"gpr	T0IC	.16	65436	0\n" ///< FF9C; CAPCOM Timer 0 Interrupt Ctrl. Reg.
		"gpr	T1IC	.16	65438	0\n" ///< FF9E; CAPCOM Timer 1 Interrupt Ctrl. Reg.
		"gpr	ADCON	.16	65440	0\n" ///< FFA0; A/D Converter Control Register
		"gpr	P5	.16	65442	0\n" ///< FFA2; Port 5 Register (read only)
		"gpr	r_FFA4	.16	65444	0\n" ///< FFA4; RESERVED
		"gpr	r_FFA6	.16	65446	0\n" ///< FFA6; RESERVED
		"gpr	r_FFA8	.16	65448	0\n" ///< FFA8; RESERVED
		"gpr	r_FFAA	.16	65450	0\n" ///< FFAA; RESERVED
		"gpr	TFR	.16	65452	0\n" ///< FFAC; Trap Flag Register
		"gpr	WDTCON	.16	65454	0\n" ///< FFAE; Watchdog Timer Control Register
		"gpr	S0CON	.16	65456	0\n" ///< FFB0; Serial Channel 0 Control Register
		"gpr	r_FFB2	.16	65458	0\n" ///< FFB2; RESERVED
		"gpr	r_FFB4	.16	65460	0\n" ///< FFB4; RESERVED
		"gpr	r_FFB6	.16	65462	0\n" ///< FFB6; RESERVED
		"gpr	S1CON	.16	65464	0\n" ///< FFB8; Serial Channel 1 Control Register
		"gpr	r_FFBA	.16	65466	0\n" ///< FFBA; RESERVED
		"gpr	r_FFBC	.16	65468	0\n" ///< FFBC; RESERVED
		"gpr	r_FFBE	.16	65470	0\n" ///< FFBE; RESERVED
		"gpr	P2	.16	65472	0\n" ///< FFC0; Port 2 Register
		"gpr	DP2	.16	65474	0\n" ///< FFC2; Port 2 Direction Control Register
		"gpr	P3	.16	65476	0\n" ///< FFC4; Port 3 Register
		"gpr	DP3	.16	65478	0\n" ///< FFC6; Port 3 Direction Control Register

		"gpr	r_FFC8	.16	65480	0\n" ///< FFC8; RESERVED
		"gpr	r_FFCA	.16	65482	0\n" ///< FFCA; RESERVED
		"gpr	r_FFCC	.16	65484	0\n" ///< FFCC; RESERVED
		"gpr	r_FFCE	.16	65486	0\n" ///< FFCE; RESERVED
		"gpr	r_FFD0	.16	65488	0\n" ///< FFD0; RESERVED
		"gpr	r_FFD2	.16	65490	0\n" ///< FFD2; RESERVED
		"gpr	r_FFD4	.16	65492	0\n" ///< FFD4; RESERVED
		"gpr	r_FFD6	.16	65494	0\n" ///< FFD6; RESERVED
		"gpr	r_FFD8	.16	65496	0\n" ///< FFD8; RESERVED
		"gpr	MRW	.16	65498	0\n" ///< FFDA; MAC Repeat Word
		"gpr	MCW	.16	65500	0\n" ///< FFDC; MAC Control Word
		"gpr	MSW	.16	65502	0"; ///< FFDE; MAC Status Word
	return strdup(p);
}

static st32 archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_c166 = {
	.name = "c166",
	.desc = "Siemens/Infineon C166 microcontroller analysis",
	.license = "LGPL3",
	.arch = "c166",
	.bits = 16,
	.op = &c166_op,
	.archinfo = &archinfo,
	.get_reg_profile = &get_reg_profile,
	.init = &c16x_init,
	.fini = &c16x_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_c166,
	.version = RZ_VERSION
};
#endif
