// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include "h8300_disas.h"

#define OPS_ADD(T, F, X) \
	do { \
		cmd->ops[cmd->operand_count].typ = T; \
		cmd->ops[cmd->operand_count].F = (X); \
		cmd->operand_count++; \
	} while (0)

#define OPS_ADD_EXT2(T, F, F1, F2, X1, X2) \
	do { \
		cmd->ops[cmd->operand_count].typ = T; \
		cmd->ops[cmd->operand_count].F.F1 = (X1); \
		cmd->ops[cmd->operand_count].F.F2 = (X2); \
		cmd->operand_count++; \
	} while (0)

static const char *commands[] = {
	[H8300_INSN_MOV_B] = "mov.b",
	[H8300_INSN_MOV_W] = "mov.w",
	[H8300_INSN_ANDC] = "andc",
	[H8300_INSN_ADD_B] = "add.b",
	[H8300_INSN_ADD_W] = "add.w",
	[H8300_INSN_ADDS] = "adds",
	[H8300_INSN_AND] = "and",
	[H8300_INSN_ADDX] = "addx",
	[H8300_INSN_SUB_B] = "sub.b",
	[H8300_INSN_SUB_W] = "sub.w",
	[H8300_INSN_BNOT] = "bnot",
	[H8300_INSN_BSET] = "bset",
	[H8300_INSN_BCLR] = "bclr",
	[H8300_INSN_BTST] = "btst",
	[H8300_INSN_BSR] = "bsr",
	[H8300_INSN_NOP] = "nop",
	[H8300_INSN_DAA] = "daa",
	[H8300_INSN_DAS] = "das",
	[H8300_INSN_DEC] = "dec",
	[H8300_INSN_INC] = "inc",
	[H8300_INSN_NEG] = "neg",
	[H8300_INSN_NOT] = "not",
	[H8300_INSN_OR] = "or",
	[H8300_INSN_DIVXU] = "divxu",
	[H8300_INSN_MULXU] = "mulxu",
	[H8300_INSN_EEPMOV] = "eepmov",
	[H8300_INSN_JMP] = "jmp",
	[H8300_INSN_JSR] = "jsr",
	[H8300_INSN_ORC] = "orc",
	[H8300_INSN_ROTL] = "rotl",
	[H8300_INSN_ROTR] = "rotr",
	[H8300_INSN_ROTXL] = "rotxl",
	[H8300_INSN_ROTXR] = "rotxr",
	[H8300_INSN_RTE] = "rte",
	[H8300_INSN_RTS] = "rts",
	[H8300_INSN_SHAL] = "shal",
	[H8300_INSN_SHAR] = "shar",
	[H8300_INSN_SHLL] = "shll",
	[H8300_INSN_SHLR] = "shlr",
	[H8300_INSN_SLEEP] = "sleep",
	[H8300_INSN_STC] = "stc",
	[H8300_INSN_SUBS] = "subs",
	[H8300_INSN_SUBX] = "subx",
	[H8300_INSN_XOR] = "xor",
	[H8300_INSN_XORC] = "xorc",
	[H8300_INSN_LDC] = "ldc",

	[H8300_INSN_BRA] = "bra",
	[H8300_INSN_BRN] = "brn",
	[H8300_INSN_BHI] = "bhi",
	[H8300_INSN_BLS] = "bls",
	[H8300_INSN_BCC] = "bcc",
	[H8300_INSN_BCS] = "bcs",
	[H8300_INSN_BNE] = "bne",
	[H8300_INSN_BEQ] = "beq",
	[H8300_INSN_BVC] = "bvc",
	[H8300_INSN_BVS] = "bvs",
	[H8300_INSN_BPL] = "bpl",
	[H8300_INSN_BMI] = "bmi",
	[H8300_INSN_BGE] = "bge",
	[H8300_INSN_BLT] = "blt",
	[H8300_INSN_BGT] = "bgt",
	[H8300_INSN_BLE] = "ble",
	[H8300_INSN_BST] = "bst",
	[H8300_INSN_BIST] = "bist",
	[H8300_INSN_BOR] = "bor",
	[H8300_INSN_BIOR] = "bior",
	[H8300_INSN_BXOR] = "bxor",
	[H8300_INSN_BIXOR] = "bixor",
	[H8300_INSN_BAND] = "band",
	[H8300_INSN_BIAND] = "biand",
	[H8300_INSN_BLD] = "bld",
	[H8300_INSN_BILD] = "bild",
	[H8300_INSN_CMP_B] = "cmp.b",
	[H8300_INSN_CMP_W] = "cmp.w",
	[H8300_INSN_POP] = "pop",
	[H8300_INSN_PUSH] = "push",
};

static int decode_opcode(const ut8 *bytes, struct h8300_cmd *cmd) {
	if (cmd->id >= RZ_ARRAY_SIZE(commands)) {
		return -1;
	}

	strncpy(cmd->instr, commands[cmd->id], H8300_INSTR_MAXLEN - 1);
	cmd->instr[H8300_INSTR_MAXLEN - 1] = '\0';

	return 0;
}

static int decode_eepmov(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}
	cmd->operands[0] = '\0';

	switch (bytes[0]) {
	case H8300_RTS:
	case H8300_RTE:
		ret = 2;
		break;
	}

	return ret;
}

static int decode_i8ccr(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_IMM;
	OPS_ADD(H8300_OP_IMM, imm, bytes[1]);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"#0x%x:8,ccr", bytes[1]);
	return ret;
}

static int decode_ccrr8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8;
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"ccr,r%u%c", bytes[1] & 0x7,
		bytes[1] & 0x8 ? 'l' : 'h');
	return ret;
}

static int decode_r8ccr(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8;
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"r%u%c,ccr", bytes[1] & 0x7,
		bytes[1] & 0x8 ? 'l' : 'h');

	return ret;
}

static int decode_r16r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R16R16;
	OPS_ADD(H8300_OP_R16, reg, bytes[1] >> 4);
	OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u,r%u",
		bytes[1] >> 4,
		bytes[1] & 0x7);

	return ret;
}

static int decode_sr16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	unsigned reg, val;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	reg = bytes[1] & 0x7;
	val = bytes[1] & 0x80 ? 2 : 1;

	cmd->fmt = H8300_INSN_FORMAT_IMMR16;
	OPS_ADD(H8300_OP_IMM, imm, val);
	OPS_ADD(H8300_OP_R16, reg, reg);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "#%u,r%u", val, reg);

	return ret;
}

#define SIGN_EXT(value, bits) \
	((int)(((unsigned int)(value) << (32 - (bits))) >> (32 - (bits))))

static int decode_pc_rel(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	st8 disp = SIGN_EXT(bytes[1], 8);

	cmd->fmt = H8300_INSN_FORMAT_PCREL8;
	OPS_ADD(H8300_OP_PCREL8, disp, disp);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, ".%s0x%02x",
		disp < 0 ? "-" : "", disp & 0x7f);

	return ret;
}

/* [opcode ] [ 0000 | 0 rd] [      imm    ] */
static int decode_imm16r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	ut16 imm;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	imm = rz_read_at_be16(bytes, 2);

	cmd->fmt = H8300_INSN_FORMAT_IMMR16;
	OPS_ADD(H8300_OP_IMM, imm, imm);
	OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "#0x%x:16,r%u",
		imm, bytes[1] & 0x7);

	return ret;
}

/* [ opcode ] [ 0 rs | 0 rd ] [         disp    ] */
static int decode_rd16r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	st16 disp = (st16)rz_read_at_be16(bytes, 2);

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R16RD16;
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"r%u,@(%+d,r%u)",
			bytes[1] & 0x7, disp,
			(bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RD16R16;
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"@(%+d,r%u),r%u", disp,
			(bytes[1] >> 4) & 0x7, bytes[1] & 0x7);
	}

	return ret;
}

static int decode_r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R16;
	OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"r%u", bytes[1] & 0x7);

	return ret;
}

/* [ opcode ] [ 0 r2 | 0 rd ] @rs+,@rd */
static int decode_incdecr16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R16RDEC;
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
		OPS_ADD(H8300_OP_RDEC, reg, (bytes[1] >> 4) & 0x7);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u,@-r%u",
			bytes[1] & 0x7, (bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RINCR16;
		OPS_ADD(H8300_OP_RINC, reg, (bytes[1] >> 4) & 0x7);
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN, "@r%u+,r%u",
			(bytes[1] >> 4) & 0x7, bytes[1] & 0x7);
	}

	return ret;
}

/* [ opcode ] [ 0 rs | 0 rd ] */
static int decode_ri16r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R16RI16;
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
		OPS_ADD(H8300_OP_RI16, reg, (bytes[1] >> 4) & 0x7);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u,@r%u",
			bytes[1] & 0x7,
			(bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RI16R16;
		OPS_ADD(H8300_OP_RI16, reg, (bytes[1] >> 4) & 0x7);
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN, "@r%u,r%u",
			(bytes[1] >> 4) & 0x7,
			bytes[1] & 0x7);
	}

	return ret;
}

/* [ opcode ] [0 | IMM | rd ] */
static int decode_i3r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_IMMR8;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[1] >> 4) & 0x7);
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "#0x%x:3,r%u%c",
		(bytes[1] >> 4) & 0x7, bytes[1] & 0x7,
		bytes[1] & 0x8 ? 'l' : 'h');

	return ret;
}

/* [opcode] [0 | rd | 0000] [opcode] [0|IMM|0000] */
static int decode_i3ri16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_IMMRI16;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[3] >> 4) & 0x7);
	OPS_ADD(H8300_OP_RI16, reg, bytes[1] >> 4);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "#0x%x:3,@r%u",
		(bytes[3] >> 4) & 0x7, bytes[1] >> 4);

	return ret;
}

/* [opcode] [   abs   ] [opcode] [0|IMM | 0000] */
static int decode_i3abs8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_IMMABS;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[3] >> 4) & 0x7);
	OPS_ADD(H8300_OP_ABS, imm, 0xff00 | bytes[1]);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "#0x%x:3,@0x%x:8",
		(bytes[3] >> 4) & 0x7, bytes[1]);

	return ret;
}

/* [opcode] [ rn  |  rd ] */
static int decode_r8r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8R8;
	OPS_ADD(H8300_OP_R8, reg, bytes[1] >> 4);
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u%c,r%u%c",
		(bytes[1] >> 4) & 0x7, bytes[1] & 0x80 ? 'l' : 'h',
		bytes[1] & 0x7, bytes[1] & 0x8 ? 'l' : 'h');

	return ret;
}

/* [opcode] [0| rd | 0000] [opcode] [ rn | 0 ] */
static int decode_r8ri16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8RI16;
	OPS_ADD(H8300_OP_R8, reg, bytes[3] >> 4);
	OPS_ADD(H8300_OP_RI16, reg, bytes[1] >> 4);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u%c,@r%u",
		(bytes[3] >> 4) & 0x7,
		bytes[3] & 0x80 ? 'l' : 'h',
		bytes[1] >> 4);

	return ret;
}

/* [opcode] [ abs ] [opcode] [ rn | 0000 ] */
static int decode_r8abs8_4(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8ABS;
	OPS_ADD(H8300_OP_R8, reg, bytes[3] >> 4);
	OPS_ADD(H8300_OP_ABS, imm, 0xff00 | bytes[1]);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u%c,@0x%x:8",
		(bytes[3] >> 4) & 0x7,
		bytes[3] & 0x80 ? 'l' : 'h',
		bytes[1]);

	return ret;
}

/* [ opcode ] [ 0000 |  rd ] */
static int decode_r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8;
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u%c",
		(bytes[1]) & 0x7,
		bytes[1] & 0x8 ? 'l' : 'h');

	return ret;
}

/* [ opcode ] [ rs | 0 rd] */
static int decode_r8r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8R16;
	OPS_ADD(H8300_OP_R8, reg, bytes[1] >> 4);
	OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u%c,r%u",
		(bytes[1] >> 4) & 0x7,
		bytes[1] & 0x80 ? 'l' : 'h',
		bytes[1] & 0x7);

	return ret;
}

/* [opcode] [0000 0000] [       abs    ] */
int decode_abs16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	ut16 abs;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	abs = rz_read_at_be16(bytes, 2);

	cmd->fmt = H8300_INSN_FORMAT_ABS;
	OPS_ADD(H8300_OP_ABS, imm, abs);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "@0x%x:16", abs);

	return ret;
}

/* [opcode] [  abs    ] */
int decode_mi8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_MI8;
	OPS_ADD(H8300_OP_MI8, imm, bytes[1]);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"@@0x%x:8", bytes[1]);

	return ret;
}

/* [opcode] [0 rn 0000] */
static int decode_ri16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_RI16;
	OPS_ADD(H8300_OP_RI16, reg, (bytes[1] >> 4) & 0x7);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"@r%u", (bytes[1] >> 4) & 0x7);

	return ret;
}

/* [ opcode ] [ 0000 | 0 rd ] [     abs    ] */
static int decode_abs16r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	ut16 abs;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	abs = rz_read_at_be16(bytes, 2);
	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R16ABS;
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
		OPS_ADD(H8300_OP_ABS, imm, abs);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"r%u,@0x%x:16", bytes[1] & 0x7, abs);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_ABSR16;
		OPS_ADD(H8300_OP_ABS, imm, abs);
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN, "@0x%x:16,r%u",
			abs, bytes[1] & 0x7);
	}

	return ret;
}

/* [ opcode ] [ 1 rd | rs ] */
static int decode_r8ri16_type2(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8RI16;
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
		OPS_ADD(H8300_OP_RI16, reg, (bytes[1] >> 4) & 0x7);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u%c,@r%u",
			bytes[1] & 0x7, bytes[1] & 0x8 ? 'l' : 'h',
			(bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RI16R8;
		OPS_ADD(H8300_OP_RI16, reg, (bytes[1] >> 4) & 0x7);
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN, "@r%u,r%u%c",
			(bytes[1] >> 4) & 0x7,
			bytes[1] & 0x7, bytes[1] & 0x8 ? 'l' : 'h');
	}

	return ret;
}

/* [ opcode ] [ 1 rd |  rs ] [       disp     ] */
static int decode_r8rd16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	st16 disp = (st16)rz_read_at_be16(bytes, 2);
	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8RD16;
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"r%u%c,@(%+d,r%u)",
			bytes[1] & 0x7, bytes[1] & 0x8 ? 'l' : 'h',
			disp, (bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RD16R8;
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"@(%+d,r%u),r%u%c",
			disp, (bytes[1] >> 4) & 0x7,
			bytes[1] & 0x7, bytes[1] & 0x8 ? 'l' : 'h');
	}
	return ret;
}

/* [ opcode ] [1 rd rs ] */
static int decode_incdecr8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8RDEC;
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
		OPS_ADD(H8300_OP_RDEC, reg, (bytes[1] >> 4) & 0x7);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"r%u%c,@-r%u",
			bytes[1] & 0x7, bytes[1] & 0x8 ? 'l' : 'h',
			(bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RINCR8;
		OPS_ADD(H8300_OP_RINC, reg, (bytes[1] >> 4) & 0x7);
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"@r%u+,r%u%c",
			(bytes[1] >> 4) & 0x7,
			bytes[1] & 0x7, bytes[1] & 0x8 ? 'l' : 'h');
	}

	return ret;
}

/* [opcode ] [ 8 | rs ] [    abs    ] */
static int decode_r8abs16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	ut16 abs;

	if (bytes[0] == 0x6A && bytes[1] >> 4 == 4) {
		strncpy(cmd->instr, "movfpe", H8300_INSTR_MAXLEN);
	} else if (bytes[0] == 0x6A && bytes[1] >> 4 == 0xC) {
		strncpy(cmd->instr, "movtpe", H8300_INSTR_MAXLEN);
	} else if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	abs = rz_read_at_be16(bytes, 2);

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8ABS;
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
		OPS_ADD(H8300_OP_ABS, imm, abs);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u%c,@0x%x:16",
			bytes[1] & 0x7, bytes[1] & 0x8 ? 'l' : 'h', abs);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_ABSR8;
		OPS_ADD(H8300_OP_ABS, imm, abs);
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN, "@0x%x:16,r%u%c",
			abs, bytes[1] & 0x7,
			bytes[1] & 0x8 ? 'l' : 'h');
	}

	return ret;
}

static int decode_nop(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->operands[0] = '\0';

	return ret;
}

static int decode_abs8r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_ABSR8;
	OPS_ADD(H8300_OP_ABS, imm, 0xff00 | bytes[1]);
	OPS_ADD(H8300_OP_R8, reg, bytes[0] & 0xf);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"@0x%x:8,r%u%c",
		bytes[1], bytes[0] & 0x7,
		bytes[0] & 0x8 ? 'l' : 'h');

	return ret;
}

static int decode_r8abs8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8ABS;
	OPS_ADD(H8300_OP_R8, reg, bytes[0] & 0xf);
	OPS_ADD(H8300_OP_ABS, imm, 0xff00 | bytes[1]);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"r%u%c,@0x%x:8",
		bytes[0] & 0x7, bytes[0] & 0x8 ? 'l' : 'h',
		bytes[1]);
	return ret;
}

static int decode_i8r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_IMMR8;
	OPS_ADD(H8300_OP_IMM, imm, bytes[1]);
	OPS_ADD(H8300_OP_R8, reg, bytes[0] & 0xf);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "#0x%x:8,r%u%c",
		bytes[1], bytes[0] & 0x7, bytes[0] & 0x8 ? 'l' : 'h');

	return ret;
}

int h8300_decode_command(const ut8 *instr, ut64 len, struct h8300_cmd *cmd, ut64 pc) {
	cmd->pc = pc;
	int ret = 0;

	if (len < 2) {
		return 0;
	}

#define CASE_F_F(F, X, I) \
	case (X): \
		cmd->id = H8300_INSN_##I; \
		cmd->size = F(instr, cmd); \
		return cmd->size;
#define CASE_F_R8(X, I) CASE_F_F(decode_r8, X, I)

	if (len >= 4) {
		ut32 x = ((ut32)instr[0] << 24) | (instr[1] << 16) | (instr[2] << 8) | instr[3];
		switch (x & ~0x00700070) {
			CASE_F_F(decode_i3ri16, 0x7d007000, BSET);
			CASE_F_F(decode_i3ri16, 0x7d007200, BCLR);
			CASE_F_F(decode_i3ri16, 0x7d006700, BST);
			CASE_F_F(decode_i3ri16, 0x7d006780, BIST);
			CASE_F_F(decode_i3ri16, 0x7d007100, BNOT);

			CASE_F_F(decode_i3ri16, 0x7c007600, BAND);
			CASE_F_F(decode_i3ri16, 0x7c007680, BIAND);
			CASE_F_F(decode_i3ri16, 0x7c007780, BILD);
			CASE_F_F(decode_i3ri16, 0x7c007480, BIOR);
			CASE_F_F(decode_i3ri16, 0x7c007580, BIXOR);
			CASE_F_F(decode_i3ri16, 0x7c007700, BLD);
			CASE_F_F(decode_i3ri16, 0x7c007400, BOR);
			CASE_F_F(decode_i3ri16, 0x7c007300, BTST);
			CASE_F_F(decode_i3ri16, 0x7c007500, BXOR);
		default:
			break;
		}
		switch (x & ~0x00ff0070) {
			CASE_F_F(decode_i3abs8, 0x7f007000, BSET);
			CASE_F_F(decode_i3abs8, 0x7f007200, BCLR);
			CASE_F_F(decode_i3abs8, 0x7f006700, BST);
			CASE_F_F(decode_i3abs8, 0x7f006780, BIST);
			CASE_F_F(decode_i3abs8, 0x7f007100, BNOT);

			CASE_F_F(decode_i3abs8, 0x7e007600, BAND);
			CASE_F_F(decode_i3abs8, 0x7e007680, BIAND);
			CASE_F_F(decode_i3abs8, 0x7e007780, BILD);
			CASE_F_F(decode_i3abs8, 0x7e007480, BIOR);
			CASE_F_F(decode_i3abs8, 0x7e007580, BIXOR);
			CASE_F_F(decode_i3abs8, 0x7e007700, BLD);
			CASE_F_F(decode_i3abs8, 0x7e007400, BOR);
			CASE_F_F(decode_i3abs8, 0x7e007300, BTST);
			CASE_F_F(decode_i3abs8, 0x7e007500, BXOR);
		default:
			break;
		}
		switch (x & ~0x007000f0) {
			CASE_F_F(decode_r8ri16, 0x7d006000, BSET);
			CASE_F_F(decode_r8ri16, 0x7d006200, BCLR);
			CASE_F_F(decode_r8ri16, 0x7d006100, BNOT);

			CASE_F_F(decode_r8ri16, 0x7c006300, BTST);
		default:
			break;
		}
		switch (x & ~0x00ff00f0) {
			CASE_F_F(decode_r8abs8_4, 0x7f006000, BSET);
			CASE_F_F(decode_r8abs8_4, 0x7f006200, BCLR);
			CASE_F_F(decode_r8abs8_4, 0x7f006100, BNOT);

			CASE_F_F(decode_r8abs8_4, 0x7e006300, BTST);
		default:
			break;
		}
	}

	switch (instr[0] >> 4) {
		CASE_F_F(decode_abs8r8, 0x2, MOV_B);
		CASE_F_F(decode_r8abs8, 0x3, MOV_B);

		CASE_F_F(decode_i8r8, 0xf, MOV_B);
		CASE_F_F(decode_i8r8, H8300_AND_4BIT, AND);
		CASE_F_F(decode_i8r8, H8300_ADDX_4BIT, ADDX);
		CASE_F_F(decode_i8r8, H8300_ADD_4BIT_8, ADD_B);
		CASE_F_F(decode_i8r8, H8300_CMP_4BIT, CMP_B);
		CASE_F_F(decode_i8r8, H8300_OR_4BIT, OR);
		CASE_F_F(decode_i8r8, H8300_SUBX_4BIT, SUBX);
		CASE_F_F(decode_i8r8, H8300_XOR_4BIT, XOR);
	default: break;
	}

	switch (((ut16)instr[0] << 4) | (instr[1] >> 4)) {
		CASE_F_R8(0x0f0, DAA);
		CASE_F_R8(0x1f0, DAS);
		CASE_F_R8(0x1a0, DEC);
		CASE_F_R8(0x0a0, INC);
		CASE_F_R8(0x178, NEG);
		CASE_F_R8(0x170, NOT);
		CASE_F_R8(0x128, ROTL);
		CASE_F_R8(0x138, ROTR);
		CASE_F_R8(0x120, ROTXL);
		CASE_F_R8(0x130, ROTXR);
		CASE_F_R8(0x108, SHAL);
		CASE_F_R8(0x100, SHLL);
		CASE_F_R8(0x118, SHAR);
		CASE_F_R8(0x110, SHLR);
	default:
		break;
	}

	switch (((ut16)instr[0] << 8) | (instr[1] & 0xf8)) {
		CASE_F_F(decode_r16, 0x6d70, POP);
		CASE_F_F(decode_r16, 0x6df0, PUSH);
	default:
		break;
	}

	switch (((ut16)instr[0] << 8 | instr[1]) & 0xff80) {
		CASE_F_F(decode_i3r8, 0x7600, BAND);
		CASE_F_F(decode_i3r8, 0x7680, BIAND)
		CASE_F_F(decode_i3r8, 0x7200, BCLR)
		CASE_F_F(decode_i3r8, 0x7700, BLD);
		CASE_F_F(decode_i3r8, 0x7780, BILD);
		CASE_F_F(decode_i3r8, 0x7480, BIOR);
		CASE_F_F(decode_i3r8, 0x6700, BST);
		CASE_F_F(decode_i3r8, 0x6780, BIST);
		CASE_F_F(decode_i3r8, 0x7500, BXOR);
		CASE_F_F(decode_i3r8, 0x7580, BIXOR);
		CASE_F_F(decode_i3r8, 0x7100, BNOT);
		CASE_F_F(decode_i3r8, 0x7400, BOR);
		CASE_F_F(decode_i3r8, 0x7000, BSET);
		CASE_F_F(decode_i3r8, 0x7300, BTST);
	default: break;
	}

	switch (instr[0]) {
	case H8300_ANDC:
		cmd->id = H8300_INSN_ANDC;
		ret = decode_i8ccr(instr, cmd);
		break;
	case H8300_SUBS:
		cmd->id = H8300_INSN_SUBS;
		ret = decode_sr16(instr, cmd);
		break;
	case H8300_ADD_W:
		cmd->id = H8300_INSN_ADD_W;
		ret = decode_r16r16(instr, cmd);
		break;
	case H8300_CMP_W:
		cmd->id = H8300_INSN_CMP_W;
		ret = decode_r16r16(instr, cmd);
		break;
	case H8300_ADDS:
		cmd->id = H8300_INSN_ADDS;
		ret = decode_sr16(instr, cmd);
		break;
	case H8300_AND:
		cmd->id = H8300_INSN_AND;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_ADD_B:
		cmd->id = H8300_INSN_ADD_B;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_BCLR_R2R8:
		cmd->id = H8300_INSN_BCLR;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_SUB_1:
		cmd->id = H8300_INSN_SUB_B;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_SUBX:
		cmd->id = H8300_INSN_SUBX;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_ADDX:
		cmd->id = H8300_INSN_ADDX;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_XOR:
		cmd->id = H8300_INSN_XOR;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_BNOT_1:
		cmd->id = H8300_INSN_BNOT;
		ret = decode_r8r8(instr, cmd);
		break;
	case 0x60:
		cmd->id = H8300_INSN_BSET;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_CMP_B:
		cmd->id = H8300_INSN_CMP_B;
		ret = decode_r8r8(instr, cmd);
		break;
	case 0x0c:
		cmd->id = H8300_INSN_MOV_B;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_BTST_R2R8:
		cmd->id = H8300_INSN_BTST;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_BSR:
		cmd->id = H8300_INSN_BSR;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_NOP:
		cmd->id = H8300_INSN_NOP;
		ret = decode_nop(instr, cmd);
		break;
	case H8300_DIVXU:
		cmd->id = H8300_INSN_DIVXU;
		ret = decode_r8r16(instr, cmd);
		break;
	case H8300_MULXU:
		cmd->id = H8300_INSN_MULXU;
		ret = decode_r8r16(instr, cmd);
		break;
	case H8300_EEPMOV:
		cmd->id = H8300_INSN_EEPMOV;
		ret = decode_eepmov(instr, cmd);
		break;
	case H8300_RTS:
		cmd->id = H8300_INSN_RTS;
		ret = decode_eepmov(instr, cmd);
		break;
	case H8300_RTE:
		cmd->id = H8300_INSN_RTE;
		ret = decode_eepmov(instr, cmd);
		break;
	case H8300_SLEEP:
		cmd->id = H8300_INSN_SLEEP;
		ret = decode_eepmov(instr, cmd);
		break;
	case 0x59:
		cmd->id = H8300_INSN_JMP;
		ret = decode_ri16(instr, cmd);
		break;
	case 0x5a:
		cmd->id = H8300_INSN_JMP;
		ret = decode_abs16(instr, cmd);
		break;
	case 0x5b:
		cmd->id = H8300_INSN_JMP;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_JSR_1:
		cmd->id = H8300_INSN_JSR;
		ret = decode_ri16(instr, cmd);
		break;
	case H8300_JSR_2:
		cmd->id = H8300_INSN_JSR;
		ret = decode_abs16(instr, cmd);
		break;
	case H8300_JSR_3:
		cmd->id = H8300_INSN_JSR;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BRA:
		cmd->id = H8300_INSN_BRA;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BRN:
		cmd->id = H8300_INSN_BRN;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BHI:
		cmd->id = H8300_INSN_BHI;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BLS:
		cmd->id = H8300_INSN_BLS;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BCC:
		cmd->id = H8300_INSN_BCC;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BCS:
		cmd->id = H8300_INSN_BCS;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BNE:
		cmd->id = H8300_INSN_BNE;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BEQ:
		cmd->id = H8300_INSN_BEQ;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BVC:
		cmd->id = H8300_INSN_BVC;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BVS:
		cmd->id = H8300_INSN_BVS;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BPL:
		cmd->id = H8300_INSN_BPL;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BMI:
		cmd->id = H8300_INSN_BMI;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BGE:
		cmd->id = H8300_INSN_BGE;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BLT:
		cmd->id = H8300_INSN_BLT;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BGT:
		cmd->id = H8300_INSN_BGT;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_BLE:
		cmd->id = H8300_INSN_BLE;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_ORC:
		cmd->id = H8300_INSN_ORC;
		ret = decode_i8ccr(instr, cmd);
		break;
	case H8300_LDC:
		cmd->id = H8300_INSN_LDC;
		ret = decode_r8ccr(instr, cmd);
		break;
	case H8300_LDC_2:
		cmd->id = H8300_INSN_LDC;
		ret = decode_i8ccr(instr, cmd);
		break;
	case H8300_STC:
		cmd->id = H8300_INSN_STC;
		ret = decode_ccrr8(instr, cmd);
		break;
	case H8300_XORC:
		cmd->id = H8300_INSN_XORC;
		ret = decode_i8ccr(instr, cmd);
		break;
	case H8300_OR:
		cmd->id = H8300_INSN_OR;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_SUB_W:
		cmd->id = H8300_INSN_SUB_W;
		ret = decode_r16r16(instr, cmd);
		break;
	case 0x0d:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_r16r16(instr, cmd);
		break;
	case 0x79:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_imm16r16(instr, cmd);
		break;
	case 0x68:
		cmd->id = H8300_INSN_MOV_B;
		ret = decode_r8ri16_type2(instr, cmd);
		break;
	case 0x69:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_ri16r16(instr, cmd);
		break;
	case 0x6a:
		cmd->id = H8300_INSN_MOV_B;
		ret = decode_r8abs16(instr, cmd);
		break;
	case 0x6b:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_abs16r16(instr, cmd);
		break;
	case 0x6c:
		cmd->id = H8300_INSN_MOV_B;
		ret = decode_incdecr8(instr, cmd);
		break;
	case 0x6d:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_incdecr16(instr, cmd);
		break;
	case 0x6e:
		cmd->id = H8300_INSN_MOV_B;
		ret = decode_r8rd16(instr, cmd);
		break;
	case 0x6f:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_rd16r16(instr, cmd);
		break;

	default: break;
	}

	cmd->size = ret;
	return ret;
}
