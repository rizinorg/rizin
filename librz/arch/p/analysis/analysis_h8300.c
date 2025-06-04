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

static void h8300_analysis_jmp(RzAnalysisOp *op, ut64 addr, const ut8 *buf) {
	switch (buf[0]) {
	case H8300_JMP_1:
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		break;
	case H8300_JMP_2:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = rz_read_at_be16(buf, 2);
		break;
	case H8300_JMP_3:
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		op->jump = buf[1];
		break;
	}
}

static void h8300_analysis_jsr(RzAnalysisOp *op, ut64 addr, const ut8 *buf) {
	switch (buf[0]) {
	case H8300_JSR_1:
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		break;
	case H8300_JSR_2:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = rz_read_at_be16(buf, 2);
		op->fail = addr + 4;
		break;
	case H8300_JSR_3:
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		op->jump = buf[1];
		break;
	}
}

static int h8300_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int ret;
	struct h8300_cmd cmd = { 0 };

	if (!op) {
		return 2;
	}

	op->addr = addr;
	ret = op->size = h8300_decode_command(buf, len, &cmd, addr);

	if (ret < 0) {
		return ret;
	}

	switch (cmd.id) {
	case H8300_INSN_MOV_B:
	case H8300_INSN_MOV_W:
	case H8300_INSN_EEPMOV:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case H8300_INSN_CMP_B:
	case H8300_INSN_CMP_W:
	case H8300_INSN_BTST:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case H8300_INSN_AND_B:
	case H8300_INSN_AND_W:
	case H8300_INSN_AND_L:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case H8300_INSN_RTS:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case H8300_INSN_SHAL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case H8300_INSN_SHAR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case H8300_INSN_XOR:
	case H8300_INSN_XORC:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case H8300_INSN_MULXU:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case H8300_INSN_ANDC:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case H8300_INSN_ADD_B:
	case H8300_INSN_ADD_W:
	case H8300_INSN_ADD_L:
	case H8300_INSN_ADDS:
	case H8300_INSN_ADDX:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case H8300_INSN_SUB_B:
	case H8300_INSN_SUB_W:
	case H8300_INSN_SUBS:
	case H8300_INSN_SUBX:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case H8300_INSN_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case H8300_INSN_JSR:
		h8300_analysis_jsr(op, addr, buf);
		break;
	case H8300_INSN_JMP:
		h8300_analysis_jmp(op, addr, buf);
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
		op->jump = addr + 2 + (st8)(buf[1]);
		op->fail = addr + 2;
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s", cmd.instr, RZ_STR_ISEMPTY(cmd.operands) ? "" : " ", cmd.operands);
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
};
