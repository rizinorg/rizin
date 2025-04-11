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

static const char *commands_4bit[] = {
	[H8300_MOV_4BIT_2] = "mov.b",
	[H8300_MOV_4BIT_3] = "mov.b",
	[H8300_ADD_4BIT] = "add.b",
	[H8300_ADDX_4BIT] = "addx",
	[H8300_CMP_4BIT] = "cmp.b",
	[H8300_SUBX_4BIT] = "subx",
	[H8300_OR_4BIT] = "or",
	[H8300_XOR_4BIT] = "xor",
	[H8300_AND_4BIT] = "and",
	[H8300_MOV_4BIT] = "mov.b"
};

static const char *commands[] = {
	[H8300_ANDC] = "andc",
	[H8300_ADDB_DIRECT] = "add.b",
	[H8300_ADDW_DIRECT] = "add.w",
	[H8300_ADDS] = "adds",
	[H8300_AND] = "and",
	[H8300_ADDX] = "addx",
	[H8300_SUBW] = "sub.w",
	[H8300_BILD_IMM2R8] = "bld",
	[H8300_BNOT_1] = "bnot",
	[H8300_BNOT_2] = "bnot",
	[H8300_BSET_1] = "bset",
	[H8300_BSET_2] = "bset",
	[H8300_BCLR_R2R8] = "bclr",
	[H8300_BCLR_IMM2R8] = "bclr",
	[H8300_BCLR_R2IND16] = "bclr",
	[H8300_BCLR_R2ABS8] = "bclr",
	[H8300_BOR_BIOR] = "bior",

	[H8300_BAND_BIAND] = "biand",
	[H8300_BIAND_IMM2IND16] = "biand",
	[H8300_BIAND_IMM2ABS8] = "biand",
	[H8300_BST_BIST] = "bist",
	[H8300_BTST] = "btst",
	[H8300_BTST_R2R8] = "btst",
	[H8300_BXOR] = "bixor",

	[H8300_BSR] = "bsr",
	[H8300_NOP] = "nop",
	[H8300_DAA] = "daa",
	[H8300_DAS] = "das",
	[H8300_DEC] = "dec",
	[H8300_INC] = "inc",
	[H8300_NOT_NEG] = "neg",
	[H8300_OR] = "or",
	[H8300_DIVXU] = "divxu",
	[H8300_MULXU] = "mulxu",
	[H8300_EEPMOV] = "eepmov",
	[H8300_JMP_1] = "jmp",
	[H8300_JMP_2] = "jmp",
	[H8300_JMP_3] = "jmp",
	[H8300_JSR_1] = "jsr",
	[H8300_JSR_2] = "jsr",
	[H8300_JSR_3] = "jsr",
	[H8300_ORC] = "orc",
	[H8300_ROTL] = "rotl",
	[H8300_ROTR] = "rotr",
	[H8300_RTE] = "rte",
	[H8300_RTS] = "rts",
	[H8300_SHL] = "shal",
	[H8300_SHR] = "shar",
	[H8300_SLEEP] = "sleep",
	[H8300_STC] = "stc",
	[H8300_SUB_1] = "sub.b",
	[H8300_SUBS] = "subs",
	[H8300_SUBX] = "subx",
	[H8300_XOR] = "xor",
	[H8300_XORC] = "xorc",

	[H8300_LDC] = "ldc",
	[H8300_LDC_2] = "ldc",

	[H8300_MOV_1] = "mov.b",
	[H8300_MOV_2] = "mov.w",
	[H8300_MOV_IMM162R16] = "mov.w",
	[H8300_MOV_DISP162R16] = "mov.w",
	[H8300_MOV_INDINC162R16] = "mov.w",
	[H8300_MOV_ABS162R16] = "mov.w",
	[H8300_MOV_IND162R16] = "mov.w",

	[H8300_MOV_R82IND16] = "mov.b",
	[H8300_MOV_R82DISPR16] = "mov.b",
	[H8300_MOV_R82RDEC16] = "mov.b",
	[H8300_MOV_R82ABS16] = "mov.b",

	[H8300_BRA] = "bra",
	[H8300_BRN] = "brn",
	[H8300_BHI] = "bhi",
	[H8300_BLS] = "bls",
	[H8300_BCC] = "bcc",
	[H8300_BCS] = "bcs",
	[H8300_BNE] = "bne",
	[H8300_BEQ] = "beq",
	[H8300_BVC] = "bvc",
	[H8300_BVS] = "bvs",
	[H8300_BPL] = "bpl",
	[H8300_BMI] = "bmi",
	[H8300_BGE] = "bge",
	[H8300_BLT] = "blt",
	[H8300_BGT] = "bgt",
	[H8300_BLE] = "ble",

	[H8300_CMP_1] = "cmp.b",
	[H8300_CMP_2] = "cmp.w",
};

static const char *commands_9bit[] = {
	[H8300_BST] = "bst",
	[H8300_BIST] = "bist",
	[H8300_BOR] = "bor",
	[H8300_BIOR] = "bior",
	[H8300_BXOR] = "bxor",
	[H8300_BIXOR] = "bixor",
	[H8300_BAND] = "band",
	[H8300_BIAND] = "biand",
	[H8300_BLD] = "bld",
	[H8300_BILD] = "bild",
};

static int decode_opcode_4bit(const ut8 *bytes, struct h8300_cmd *cmd) {
	ut8 opcode = bytes[0] >> 4;

	if (opcode >= sizeof(commands_4bit) / sizeof(void *) || !commands_4bit[opcode]) {
		return -1;
	}

	strncpy(cmd->instr, commands_4bit[opcode], H8300_INSTR_MAXLEN - 1);
	cmd->instr[H8300_INSTR_MAXLEN - 1] = '\0';

	return 0;
}

static int decode_opcode(const ut8 *bytes, struct h8300_cmd *cmd) {
	ut16 ext_opcode;

	ext_opcode = (rz_read_be16(bytes)) >> 7;

	switch (ext_opcode) {
	case H8300_BOR:
	case H8300_BIOR:
	case H8300_BXOR:
	case H8300_BIXOR:
	case H8300_BAND:
	case H8300_BIAND:
	case H8300_BLD:
	case H8300_BILD:
	case H8300_BST:
	case H8300_BIST:
		if (ext_opcode >= sizeof(commands_9bit) / sizeof(void *) ||
			!commands_9bit[ext_opcode]) {
			break;
		}
		strncpy(cmd->instr, commands_9bit[ext_opcode], H8300_INSTR_MAXLEN - 1);
		cmd->instr[H8300_INSTR_MAXLEN - 1] = '\0';
		return 0;
	}

	switch (bytes[0]) {
	case H8300_BIAND_IMM2IND16:
	case H8300_BIAND_IMM2ABS8:
	case H8300_BCLR_R2IND16:
	case H8300_BCLR_R2ABS8:
		switch (bytes[2]) {
		case 0x74:
			strncpy(cmd->instr, bytes[3] & 0x80 ? "bior" : "bor",
				H8300_INSTR_MAXLEN - 1);
			return 0;
		case 0x76:
			strncpy(cmd->instr, bytes[3] & 0x80 ? "biand" : "band",
				H8300_INSTR_MAXLEN - 1);
			return 0;
		case 0x77:
			strncpy(cmd->instr, bytes[3] & 0x80 ? "bild" : "bld",
				H8300_INSTR_MAXLEN - 1);
			return 0;
		case 0x67:
			strncpy(cmd->instr, bytes[3] & 0x80 ? "bist" : "bst",
				H8300_INSTR_MAXLEN - 1);
			return 0;
		case 0x75:
			strncpy(cmd->instr, bytes[3] & 0x80 ? "bixor" : "bxor",
				H8300_INSTR_MAXLEN - 1);
			return 0;
		case 0x60:
		case 0x70:
			strncpy(cmd->instr, "bset", H8300_INSTR_MAXLEN - 1);
			return 0;
		case 0x61:
		case 0x71:
			strncpy(cmd->instr, "bnot", H8300_INSTR_MAXLEN - 1);
			return 0;
		}
		break;
	}

	if (bytes[0] >= sizeof(commands) / sizeof(void *) || !commands[bytes[0]]) {
		return -1;
	}

	strncpy(cmd->instr, commands[bytes[0]], H8300_INSTR_MAXLEN - 1);
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

static int decode_pc_rel(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_PCREL8;
	OPS_ADD(H8300_OP_PCREL8, disp, (st8)bytes[1]);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, ".%d",
		(st8)bytes[1]);

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
	ut16 disp;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	disp = rz_read_at_be16(bytes, 2);

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R16RD16;
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"r%u,@(0x%x:16,r%u)",
			bytes[1] & 0x7, disp,
			(bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RD16R16;
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"@(0x%x:16,r%u),r%u", disp,
			(bytes[1] >> 4) & 0x7, bytes[1] & 0x7);
	}

	return ret;
}

static int decode_pop(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	ut8 tmp = bytes[1] >> 4;

	strncpy(cmd->instr, tmp == 0x7 ? "pop" : "push",
		H8300_INSTR_MAXLEN - 1);
	cmd->instr[H8300_INSTR_MAXLEN - 1] = '\0';

	cmd->fmt = H8300_INSN_FORMAT_R16;
	OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"r%u", bytes[1] & 0x7);

	return ret;
}

/* [ opcode ] [ 0 r2 | 0 rd ] @rs+,@rd */
static int decode_incdecr16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	ut8 tmp = bytes[1] >> 4;

	if (bytes[0] == 0x6D && (tmp == 7 || tmp == 0xF)) {
		return decode_pop(bytes, cmd);
	}

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

	cmd->fmt = H8300_INSN_FORMAT_IMMR8;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[3] >> 4) & 0x7);
	OPS_ADD(H8300_OP_RI16, reg, bytes[1] >> 4);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "#0x%x:3,@r%u",
		(bytes[3] >> 4) & 0x7, bytes[1] >> 4);

	return ret;
}

/* [opcode] [   abs   ] [opcode] [0|IMM | 0000] */
static int decode_i3a8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_IMMR8;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[3] >> 4) & 0x7);
	OPS_ADD(H8300_OP_ABS, imm, bytes[1]);

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
static int decode_r8a8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8ABS;
	OPS_ADD(H8300_OP_R8, reg, bytes[3] >> 4);
	OPS_ADD(H8300_OP_ABS, imm, bytes[1]);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "r%u%c,@0x%x:8",
		(bytes[3] >> 4) & 0x7,
		bytes[3] & 0x80 ? 'l' : 'h',
		bytes[1]);

	return ret;
}

/* [ opcode ] [ 0000 |  rd ] */
static int decode_daa(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (bytes[0] == 0x17 && bytes[1] >> 4 == 0) {
		strncpy(cmd->instr, "not", H8300_INSTR_MAXLEN - 1);
		cmd->instr[H8300_INSTR_MAXLEN - 1] = '\0';
	} else if (bytes[0] == 0x12 && bytes[1] >> 4 == 0) {
		strncpy(cmd->instr, "rotxl", H8300_INSTR_MAXLEN - 1);
		cmd->instr[H8300_INSTR_MAXLEN - 1] = '\0';
	} else if (bytes[0] == 0x13 && bytes[1] >> 4 == 0) {
		strncpy(cmd->instr, "rotxr", H8300_INSTR_MAXLEN - 1);
		cmd->instr[H8300_INSTR_MAXLEN - 1] = '\0';
	} else if (bytes[0] == 0x10 && bytes[1] >> 4 == 0) {
		strncpy(cmd->instr, "shll", H8300_INSTR_MAXLEN - 1);
	} else if (bytes[0] == 0x11 && bytes[1] >> 4 == 0) {
		strncpy(cmd->instr, "shlr", H8300_INSTR_MAXLEN - 1);
	} else if (decode_opcode(bytes, cmd)) {
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
	ut16 disp;

	if (decode_opcode(bytes, cmd)) {
		return -1;
	}

	disp = rz_read_at_be16(bytes, 2);
	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8RD16;
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"r%u%c,@(0x%x:16,r%u)",
			bytes[1] & 0x7, bytes[1] & 0x8 ? 'l' : 'h',
			disp, (bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RD16R8;
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);

		snprintf(cmd->operands, H8300_INSTR_MAXLEN,
			"@(0x%x:16,r%u),r%u%c",
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
		cmd->fmt = H8300_INSN_FORMAT_R8ABS;
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

static int decode_a8r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode_4bit(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_ABSR8;
	OPS_ADD(H8300_OP_ABS, imm, bytes[1]);
	OPS_ADD(H8300_OP_R8, reg, bytes[0] & 0xf);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"@0x%x:8,r%u%c",
		bytes[1], bytes[0] & 0x7,
		bytes[0] & 0x8 ? 'l' : 'h');

	return ret;
}

static int decode_r8i8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode_4bit(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_R8IMM;
	OPS_ADD(H8300_OP_R8, reg, bytes[0] & 0xf);
	OPS_ADD(H8300_OP_IMM, imm, bytes[1]);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN,
		"r%u%c,@0x%x:8",
		bytes[0] & 0x7, bytes[0] & 0x8 ? 'l' : 'h',
		bytes[1]);
	return ret;
}

static int decode_i8r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (decode_opcode_4bit(bytes, cmd)) {
		return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_IMMR8;
	OPS_ADD(H8300_OP_IMM, imm, bytes[1]);
	OPS_ADD(H8300_OP_R8, reg, bytes[0] & 0xf);

	snprintf(cmd->operands, H8300_INSTR_MAXLEN, "#0x%x:8,r%u%c",
		bytes[1], bytes[0] & 0x7, bytes[0] & 0x8 ? 'l' : 'h');

	return ret;
}

int h8300_decode_command(const ut8 *instr, struct h8300_cmd *cmd) {
	int ret = 0;

	switch (instr[0] >> 4) {
	case H8300_MOV_4BIT_3:
		cmd->id = H8300_INSN_MOV;
		ret = decode_r8i8(instr, cmd);
		break;
	case H8300_MOV_4BIT_2:
		cmd->id = H8300_INSN_MOV;
		ret = decode_a8r8(instr, cmd);
		break;
	case H8300_AND_4BIT:
		cmd->id = H8300_INSN_AND;
		ret = decode_i8r8(instr, cmd);
		break;
	case H8300_ADDX_4BIT:
		cmd->id = H8300_INSN_ADDX;
		ret = decode_i8r8(instr, cmd);
		break;
	case H8300_ADD_4BIT:
		cmd->id = H8300_INSN_ADD;
		ret = decode_i8r8(instr, cmd);
		break;
	case H8300_CMP_4BIT:
		cmd->id = H8300_INSN_CMP;
		ret = decode_i8r8(instr, cmd);
		break;
	case H8300_MOV_4BIT:
		cmd->id = H8300_INSN_MOV;
		ret = decode_i8r8(instr, cmd);
		break;
	case H8300_OR_4BIT:
		cmd->id = H8300_INSN_OR;
		ret = decode_i8r8(instr, cmd);
		break;
	case H8300_SUBX_4BIT:
		cmd->id = H8300_INSN_SUBX;
		ret = decode_i8r8(instr, cmd);
		break;
	case H8300_XOR_4BIT:
		cmd->id = H8300_INSN_XOR;
		ret = decode_i8r8(instr, cmd);
		break;
	}

	if (ret) {
		return ret;
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
	case H8300_ADDW_DIRECT:
		cmd->id = H8300_INSN_ADDW;
		ret = decode_r16r16(instr, cmd);
		break;
	case H8300_CMP_2:
		cmd->id = H8300_INSN_CMP;
		ret = decode_r16r16(instr, cmd);
		break;
	case H8300_ADDS:
		cmd->id = H8300_INSN_ADDS;
		ret = decode_sr16(instr, cmd);
		break;
	case H8300_BAND_BIAND:
		cmd->id = H8300_INSN_BAND_BIAND;
		ret = decode_i3r8(instr, cmd);
		break;
	case H8300_BCLR_IMM2R8:
		cmd->id = H8300_INSN_BCLR;
		ret = decode_i3r8(instr, cmd);
		break;
	case H8300_BST_BIST:
		cmd->id = H8300_INSN_BST_BIST;
		ret = decode_i3r8(instr, cmd);
		break;
	case H8300_BTST:
		cmd->id = H8300_INSN_BTST;
		ret = decode_i3r8(instr, cmd);
		break;
	case H8300_BILD_IMM2R8:
		cmd->id = H8300_INSN_BILD;
		ret = decode_i3r8(instr, cmd);
		break;
	case H8300_BOR_BIOR:
		cmd->id = H8300_INSN_BOR_BIOR;
		ret = decode_i3r8(instr, cmd);
		break;
	case H8300_BXOR_BIXOR:
		cmd->id = H8300_INSN_BXOR;
		ret = decode_i3r8(instr, cmd);
		break;
	case H8300_BNOT_2:
		cmd->id = H8300_INSN_BNOT;
		ret = decode_i3r8(instr, cmd);
		break;
	case H8300_BSET_2:
		cmd->id = H8300_INSN_BSET;
		ret = decode_i3r8(instr, cmd);
		break;
	/// r2r8 format
	case H8300_AND:
		cmd->id = H8300_INSN_AND;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_ADDB_DIRECT:
		cmd->id = H8300_INSN_ADDB;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_BCLR_R2R8:
		cmd->id = H8300_INSN_BCLR;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_SUB_1:
		cmd->id = H8300_INSN_SUB;
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
	case H8300_BSET_1:
		cmd->id = H8300_INSN_BSET;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_CMP_1:
		cmd->id = H8300_INSN_CMP;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_MOV_1:
		cmd->id = H8300_INSN_MOV;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_BTST_R2R8:
		cmd->id = H8300_INSN_BTST;
		ret = decode_r8r8(instr, cmd);
		break;
	case H8300_BCLR_R2IND16:
		cmd->id = H8300_INSN_BCLR;
		switch (instr[2]) {
		case 0x60:
		case 0x61:
		case 0x62:
			ret = decode_r8ri16(instr, cmd);
			break;
		case 0x70:
		case 0x71:
		case 0x72:
		case 0x67:
		case 0x75:
			ret = decode_i3ri16(instr, cmd);
			break;
		default:
			ret = -1;
		}
		break;
	case H8300_BCLR_R2ABS8:
		cmd->id = H8300_INSN_BCLR;
		switch (instr[2]) {
		case 0x60:
		case 0x61:
		case 0x62:
			ret = decode_r8a8(instr, cmd);
			break;
		case 0x67:
		case 0x70:
		case 0x71:
		case 0x72:
			ret = decode_i3a8(instr, cmd);
			break;
		default:
			ret = -1;
		}
		break;
	case H8300_BIAND_IMM2IND16:
		cmd->id = H8300_INSN_BIAND;
		ret = decode_i3ri16(instr, cmd);
		break;
	case H8300_BIAND_IMM2ABS8:
		cmd->id = H8300_INSN_BIAND;
		ret = decode_i3a8(instr, cmd);
		break;
	case H8300_BSR:
		cmd->id = H8300_INSN_BSR;
		ret = decode_pc_rel(instr, cmd);
		break;
	case H8300_NOP:
		cmd->id = H8300_INSN_NOP;
		ret = decode_nop(instr, cmd);
		break;
	/// DAA format
	case H8300_DAA:
		cmd->id = H8300_INSN_DAA;
		ret = decode_daa(instr, cmd);
		break;
	case H8300_DAS:
		cmd->id = H8300_INSN_DAS;
		ret = decode_daa(instr, cmd);
		break;
	case H8300_DEC:
		cmd->id = H8300_INSN_DEC;
		ret = decode_daa(instr, cmd);
		break;
	case H8300_INC:
		cmd->id = H8300_INSN_INC;
		ret = decode_daa(instr, cmd);
		break;
	case H8300_NOT_NEG:
		cmd->id = H8300_INSN_NOT_NEG;
		ret = decode_daa(instr, cmd);
		break;
	case H8300_ROTL:
		cmd->id = H8300_INSN_ROTL;
		ret = decode_daa(instr, cmd);
		break;
	case H8300_ROTR:
		cmd->id = H8300_INSN_ROTR;
		ret = decode_daa(instr, cmd);
		break;
	case H8300_SHL:
		cmd->id = H8300_INSN_SHL;
		ret = decode_daa(instr, cmd);
		break;
	case H8300_SHR:
		cmd->id = H8300_INSN_SHR;
		ret = decode_daa(instr, cmd);
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
	case H8300_JMP_1:
		cmd->id = H8300_INSN_JMP;
		ret = decode_ri16(instr, cmd);
		break;
	case H8300_JSR_1:
		cmd->id = H8300_INSN_JSR;
		ret = decode_ri16(instr, cmd);
		break;
	case H8300_JMP_2:
		cmd->id = H8300_INSN_JMP;
		ret = decode_abs16(instr, cmd);
		break;
	case H8300_JSR_2:
		cmd->id = H8300_INSN_JSR;
		ret = decode_abs16(instr, cmd);
		break;
	/// jmp_abs8 format
	case H8300_JMP_3:
		cmd->id = H8300_INSN_JMP;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_JSR_3:
		cmd->id = H8300_INSN_JSR;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BRA:
		cmd->id = H8300_INSN_BRA;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BRN:
		cmd->id = H8300_INSN_BRN;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BHI:
		cmd->id = H8300_INSN_BHI;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BLS:
		cmd->id = H8300_INSN_BLS;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BCC:
		cmd->id = H8300_INSN_BCC;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BCS:
		cmd->id = H8300_INSN_BCS;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BNE:
		cmd->id = H8300_INSN_BNE;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BEQ:
		cmd->id = H8300_INSN_BEQ;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BVC:
		cmd->id = H8300_INSN_BVC;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BVS:
		cmd->id = H8300_INSN_BVS;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BPL:
		cmd->id = H8300_INSN_BPL;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BMI:
		cmd->id = H8300_INSN_BMI;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BGE:
		cmd->id = H8300_INSN_BGE;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BLT:
		cmd->id = H8300_INSN_BLT;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BGT:
		cmd->id = H8300_INSN_BGT;
		ret = decode_mi8(instr, cmd);
		break;
	case H8300_BLE:
		cmd->id = H8300_INSN_BLE;
		ret = decode_mi8(instr, cmd);
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
	case H8300_MOV_2:
		cmd->id = H8300_INSN_MOV;
		ret = decode_r16r16(instr, cmd);
		break;
	case H8300_SUBW:
		cmd->id = H8300_INSN_SUBW;
		ret = decode_r16r16(instr, cmd);
		break;
	case H8300_MOV_IMM162R16:
		cmd->id = H8300_INSN_MOV;
		ret = decode_imm16r16(instr, cmd);
		break;
	case H8300_MOV_IND162R16:
		cmd->id = H8300_INSN_MOV;
		ret = decode_ri16r16(instr, cmd);
		break;
	case H8300_MOV_DISP162R16:
		cmd->id = H8300_INSN_MOV;
		ret = decode_rd16r16(instr, cmd);
		break;
	case H8300_MOV_INDINC162R16:
		cmd->id = H8300_INSN_MOV;
		ret = decode_incdecr16(instr, cmd);
		break;
	case H8300_MOV_ABS162R16:
		cmd->id = H8300_INSN_MOV;
		ret = decode_abs16r16(instr, cmd);
		break;
	case H8300_MOV_R82IND16:
		cmd->id = H8300_INSN_MOV;
		ret = decode_r8ri16_type2(instr, cmd);
		break;
	case H8300_MOV_R82DISPR16:
		cmd->id = H8300_INSN_MOV;
		ret = decode_r8rd16(instr, cmd);
		break;
	case H8300_MOV_R82RDEC16:
		cmd->id = H8300_INSN_MOV;
		ret = decode_incdecr8(instr, cmd);
		break;
	case H8300_MOV_R82ABS16:
		cmd->id = H8300_INSN_MOV;
		ret = decode_r8abs16(instr, cmd);
		break;
	default:
		return -1;
	}
	return ret;
}
