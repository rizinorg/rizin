// SPDX-FileCopyrightText: 2012-2015 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2012-2015 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2012-2015 Bhootravi <ravi2809@gmail.com>
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
	ut8 opcode = buf[0];
	struct h8300_cmd cmd;

	if (!op) {
		return 2;
	}

	op->addr = addr;
	ret = op->size = h8300_decode_command(buf, &cmd);

	if (ret < 0) {
		return ret;
	}
	switch (opcode >> 4) {
	case H8300_MOV_4BIT_2:
	case H8300_MOV_4BIT_3:
	case H8300_MOV_4BIT:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case H8300_CMP_4BIT:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case H8300_XOR_4BIT:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case H8300_AND_4BIT:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case H8300_ADD_4BIT:
	case H8300_ADDX_4BIT:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case H8300_SUBX_4BIT:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	};
	if (op->type != RZ_ANALYSIS_OP_TYPE_UNK) {
		goto step_esil;
	}

	switch (opcode) {
	case H8300_MOV_R82IND16:
	case H8300_MOV_IND162R16:
	case H8300_MOV_R82ABS16:
	case H8300_MOV_ABS162R16:
	case H8300_MOV_R82RDEC16:
	case H8300_MOV_INDINC162R16:
	case H8300_MOV_R82DISPR16:
	case H8300_MOV_DISP162R16:
	case H8300_MOV_IMM162R16:
	case H8300_MOV_1:
	case H8300_MOV_2:
	case H8300_EEPMOV:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case H8300_RTS:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case H8300_CMP_1:
	case H8300_CMP_2:
	case H8300_BTST_R2R8:
	case H8300_BTST:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case H8300_SHL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case H8300_SHR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case H8300_XOR:
	case H8300_XORC:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case H8300_MULXU:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case H8300_ANDC:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case H8300_ADDB_DIRECT:
	case H8300_ADDW_DIRECT:
	case H8300_ADDS:
	case H8300_ADDX:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case H8300_SUB_1:
	case H8300_SUBW:
	case H8300_SUBS:
	case H8300_SUBX:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case H8300_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case H8300_JSR_1:
	case H8300_JSR_2:
	case H8300_JSR_3:
		h8300_analysis_jsr(op, addr, buf);
		break;
	case H8300_JMP_1:
	case H8300_JMP_2:
	case H8300_JMP_3:
		h8300_analysis_jmp(op, addr, buf);
		break;
	case H8300_BRA:
	case H8300_BRN:
	case H8300_BHI:
	case H8300_BLS:
	case H8300_BCC:
	case H8300_BCS:
	case H8300_BNE:
	case H8300_BEQ:
	case H8300_BVC:
	case H8300_BVS:
	case H8300_BPL:
	case H8300_BMI:
	case H8300_BGE:
	case H8300_BLT:
	case H8300_BGT:
	case H8300_BLE:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + 2 + (st8)(buf[1]);
		op->fail = addr + 2;
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	};

step_esil:
	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		h8300_analyze_op_esil(analysis, op, addr, buf);
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
};
