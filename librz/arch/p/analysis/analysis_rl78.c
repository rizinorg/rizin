// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include "rl78/rl78_instr.h"
#include "rl78/rl78.h"

static int rl78_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask);
static void populate_jump_fields(const RL78Instr *instr, size_t instr_size, ut64 addr, RzAnalysisOp *op);
static char *get_reg_profile(RzAnalysis *analysis);

static int rl78_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_ILL;

	RL78Instr instr = { 0 };
	size_t bytes_read = 0;
	if (!rl78_dis(&instr, &bytes_read, buf, len)) {
		op->size = bytes_read;
		return bytes_read;
	} else {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	}

	op->size = bytes_read;
	op->addr = addr;
	switch (instr.operation) {
	case RL78_OPERATION_ADD:
	case RL78_OPERATION_ADDC:
	case RL78_OPERATION_ADDW:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case RL78_OPERATION_AND:
	case RL78_OPERATION_AND1:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case RL78_OPERATION_BC:
	case RL78_OPERATION_BF:
	case RL78_OPERATION_BH:
	case RL78_OPERATION_BNC:
	case RL78_OPERATION_BNH:
	case RL78_OPERATION_BNZ:
	case RL78_OPERATION_BT:
	case RL78_OPERATION_BTCLR:
	case RL78_OPERATION_BZ:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		populate_jump_fields(&instr, bytes_read, addr, op);
		break;
	case RL78_OPERATION_BR:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		populate_jump_fields(&instr, bytes_read, addr, op);
		break;
	// conditional skip instructions
	case RL78_OPERATION_SKC:
	case RL78_OPERATION_SKH:
	case RL78_OPERATION_SKNC:
	case RL78_OPERATION_SKNH:
	case RL78_OPERATION_SKNZ:
	case RL78_OPERATION_SKZ:
		// TODO set op->jump to instruction after next (i.e. skip)
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case RL78_OPERATION_BRK:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		break;
	case RL78_OPERATION_CALL:
	case RL78_OPERATION_CALLT:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		populate_jump_fields(&instr, bytes_read, addr, op);
		break;
	case RL78_OPERATION_CLRB:
	case RL78_OPERATION_CLRW:
	case RL78_OPERATION_CLR1:
		// TODO (byte/word/bitclear)
		break;
	case RL78_OPERATION_CMP:
	case RL78_OPERATION_CMPS:
	case RL78_OPERATION_CMPW:
	case RL78_OPERATION_CMP0:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case RL78_OPERATION_DEC:
	case RL78_OPERATION_DECW:
	case RL78_OPERATION_SUB:
	case RL78_OPERATION_SUBC:
	case RL78_OPERATION_SUBW:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case RL78_OPERATION_EI:
	case RL78_OPERATION_DI:
		// TODO (interrupt enable/disable)
		break;
	case RL78_OPERATION_DIVHU:
	case RL78_OPERATION_DIVWU:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case RL78_OPERATION_HALT:
		// TODO (halt)
		break;
	case RL78_OPERATION_INC:
	case RL78_OPERATION_INCW:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case RL78_OPERATION_MULH:
	case RL78_OPERATION_MULHU:
	case RL78_OPERATION_MULU:
		// multiply-and-accumulate
	case RL78_OPERATION_MACH:
	case RL78_OPERATION_MACHU:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case RL78_OPERATION_MOV:
	case RL78_OPERATION_MOVS:
	case RL78_OPERATION_MOVW:
	case RL78_OPERATION_MOV1:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case RL78_OPERATION_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case RL78_OPERATION_NOT1:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case RL78_OPERATION_ONEB:
	case RL78_OPERATION_ONEW:
		// TODO (byte/word set to 1)
		break;
	case RL78_OPERATION_OR:
	case RL78_OPERATION_OR1:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case RL78_OPERATION_POP:
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		break;
	case RL78_OPERATION_PUSH:
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		break;
	case RL78_OPERATION_RET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case RL78_OPERATION_RETB:
	case RL78_OPERATION_RETI:
		// TODO (return from software/hardware vectored interrupt)
		break;
	case RL78_OPERATION_ROL:
	case RL78_OPERATION_ROLC:
	case RL78_OPERATION_ROLWC:
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		break;
	case RL78_OPERATION_ROR:
	case RL78_OPERATION_RORC:
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		break;
	case RL78_OPERATION_SAR:
	case RL78_OPERATION_SARW:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case RL78_OPERATION_SEL:
	case RL78_OPERATION_SET1:
	case RL78_OPERATION_SHL:
	case RL78_OPERATION_SHLW:
	case RL78_OPERATION_SHR:
	case RL78_OPERATION_SHRW:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case RL78_OPERATION_STOP:
		// TODO (stop mode set)
		break;
	case RL78_OPERATION_XCH:
	case RL78_OPERATION_XCHW:
		op->type = RZ_ANALYSIS_OP_TYPE_XCHG;
		break;
	case RL78_OPERATION_XOR:
	case RL78_OPERATION_XOR1:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	return op->size;
}

static void populate_jump_fields(const RL78Instr *instr, size_t instr_size, ut64 addr, RzAnalysisOp *op) {
	const RL78Operand *target = &instr->op0;
	if (instr->operation == RL78_OPERATION_BT ||
		instr->operation == RL78_OPERATION_BF ||
		instr->operation == RL78_OPERATION_BTCLR) {
		target = &instr->op1;
	}

	switch (target->type) {
	case RL78_OP_TYPE_ABSOLUTE_ADDR_20:
	case RL78_OP_TYPE_ABSOLUTE_ADDR_16:
		op->jump = target->v0;
		break;
	case RL78_OP_TYPE_RELATIVE_ADDR_16:
	case RL78_OP_TYPE_RELATIVE_ADDR_8:
		op->jump = addr + target->v0;
	case RL78_OP_TYPE_SYMBOL:
		// TODO indirect call to symbol (CALL AX)
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	if (op->type == RZ_ANALYSIS_OP_TYPE_CJMP) {
		op->fail = addr + instr_size;
	}
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=ZF	z\n"
		"=CF	cy\n"
		"=SN	%s\n" // x8 on linux or android, x16 for the rest
		// ABI: https://www.renesas.com/eu/en/document/mat/cc-rl-compiler-users-manual
		"=A0	ax\n"
		"=A1	bc\n"
		"=A2	de\n"
		// general-purpose registers
		"gpr	hl	.16	0	0\n"
		"gpr	de	.16	0	0\n"
		"gpr	bc	.16	0	0\n"
		"gpr	ax	.16	0	0\n"
		"gpr	h	.8	0	0\n"
		"gpr	l	.8	0	0\n"
		"gpr	d	.8	0	0\n"
		"gpr	e	.8	0	0\n"
		"gpr	b	.8	0	0\n"
		"gpr	c	.8	0	0\n"
		"gpr	a	.8	0	0\n"
		"gpr	x	.8	0	0\n"

		// flags
		"flg	psw	.8	0	0       ie_z_rbs1_ac_rbs0_isp1_isp0_cy\n"
		"flg	ie	.1	0	0	interrupt_enable\n"
		"flg	z	.1	0	0	zero\n"
		"flg	rbs1	.1	0	0	register_bank_select_bit_1\n"
		"flg	ac	.1	0	0	auxiliary_carry\n" // set if carry or borrow at bit 3
		"flg	rbs0	.1	0	0	register_bank_select_bit_0\n"
		"flg	isp1	.1	0	0	in_service_priority_flags_bit_1\n"
		"flg	isp0	.1	0	0	in_service_priority_flags_bit_0\n"
		"flg	cy	.1	0	0	carry\n";

	return rz_str_dup(p);
}

RzAnalysisPlugin rz_analysis_plugin_rl78 = {
	.name = "rl78",
	.desc = "Renesas RL78 analysis plugin",
	.license = "LGPL3",
	.arch = "rl78",
	.bits = 16,
	.op = &rl78_op,
	.get_reg_profile = &get_reg_profile
};
