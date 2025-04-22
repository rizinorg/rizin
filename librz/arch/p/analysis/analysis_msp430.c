// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>

#include <msp430/msp430_disas.h>
#include <msp430/msp430_il.h>

static int msp430_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int ret;
	struct msp430_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	op->size = -1;
	op->nopcode = 1;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->family = RZ_ANALYSIS_OP_FAMILY_CPU;

	ret = op->size = msp430_decode_command(buf, len, &cmd);

	if (ret < 0) {
		return ret;
	}

	op->addr = addr;

	switch (cmd.type) {
	case MSP430_ONEOP:
		switch (cmd.opcode) {
		case MSP430_RRA:
		case MSP430_RRC:
			op->type = RZ_ANALYSIS_OP_TYPE_ROR;
			break;
		case MSP430_PUSH:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		case MSP430_CALL:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->fail = addr + op->size;
			op->jump = rz_read_at_le16(buf, 2);
			break;
		case MSP430_RETI:
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			break;
		}
		break;
	case MSP430_TWOOP:
		switch (cmd.opcode) {
		case MSP430_BIT:
		case MSP430_BIC:
		case MSP430_BIS:
		case MSP430_MOV:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			if ((cmd.instr)[0] == 'b' && (cmd.instr)[1] == 'r') {
				// Emulated branch instruction, moves source operand to PC register.
				op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			}
			break;
		case MSP430_DADD:
		case MSP430_ADDC:
		case MSP430_ADD: op->type = RZ_ANALYSIS_OP_TYPE_ADD; break;
		case MSP430_SUBC:
		case MSP430_SUB: op->type = RZ_ANALYSIS_OP_TYPE_SUB; break;
		case MSP430_CMP: op->type = RZ_ANALYSIS_OP_TYPE_CMP; break;
		case MSP430_XOR: op->type = RZ_ANALYSIS_OP_TYPE_XOR; break;
		case MSP430_AND: op->type = RZ_ANALYSIS_OP_TYPE_AND; break;
		}
		break;
	case MSP430_JUMP:
		if (cmd.jmp_cond == MSP430_JMP) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		}
		op->jump = addr + cmd.jmp_addr;
		op->fail = addr + 2;
		break;
	case MSP430_INV:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		RzILOpEffect *il_op = rz_msp430_lift_instr(analysis, &cmd, addr, op->size);
		op->il_op = il_op;
	}
	return ret;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *prof =
		"=PC pc\n"
		"=SP sp\n"
		"=A0 r4\n"
		"=A1 r5\n"
		"gpr pc  .16  0     0\n"
		"gpr sp  .16  2     0\n"
		"gpr sr  .16  4     0\n"
		"gpr cg  .16  6     0\n"
		"gpr r4  .16  8     0\n"
		"gpr r5  .16  10    0\n"
		"gpr r6  .16  12    0\n"
		"gpr r7  .16  14    0\n"
		"gpr r8  .16  16    0\n"
		"gpr r9  .16  18    0\n"
		"gpr r10 .16  20    0\n"
		"gpr r11 .16  22    0\n"
		"gpr r12 .16  24    0\n"
		"gpr r13 .16  26    0\n"
		"gpr r14 .16  28    0\n"
		"gpr r15 .16  30    0\n";
	return rz_str_dup(prof);
}

RzAnalysisPlugin rz_analysis_plugin_msp430 = {
	.name = "msp430",
	.desc = "TI MSP430 code analysis plugin",
	.license = "LGPL3",
	.arch = "msp430",
	.bits = 16,
	.op = msp430_op,
	.il_config = rz_msp430_il_config,
	.get_reg_profile = get_reg_profile
};
