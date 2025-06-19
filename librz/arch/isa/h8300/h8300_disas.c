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
	[H8300_INSN_MOV_L] = "mov.l",
	[H8300_INSN_MOVTPE] = "movtpe",
	[H8300_INSN_MOVFPE] = "movfpe",
	[H8300_INSN_ANDC] = "andc",
	[H8300_INSN_ADD_B] = "add.b",
	[H8300_INSN_ADD_W] = "add.w",
	[H8300_INSN_ADD_L] = "add.l",
	[H8300_INSN_ADDS] = "adds",
	[H8300_INSN_AND_B] = "and.b",
	[H8300_INSN_AND_W] = "and.w",
	[H8300_INSN_AND_L] = "and.l",
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
	[H8300_INSN_DEC_B] = "dec.b",
	[H8300_INSN_DEC_W] = "dec.w",
	[H8300_INSN_DEC_L] = "dec.l",
	[H8300_INSN_INC_B] = "inc.b",
	[H8300_INSN_INC_W] = "inc.w",
	[H8300_INSN_INC_L] = "inc.l",
	[H8300_INSN_NEG] = "neg",
	[H8300_INSN_NOT] = "not",
	[H8300_INSN_OR] = "or",
	[H8300_INSN_DIVXU_B] = "divxu.b",
	[H8300_INSN_DIVXU_W] = "divxu.w",
	[H8300_INSN_DIVXS_B] = "divxs.b",
	[H8300_INSN_DIVXS_W] = "divxs.w",
	[H8300_INSN_MULXU] = "mulxu",
	[H8300_INSN_EEPMOV_B] = "eepmov.b",
	[H8300_INSN_EEPMOV_W] = "eepmov.w",
	[H8300_INSN_EXTS_W] = "exts.w",
	[H8300_INSN_EXTS_L] = "exts.l",
	[H8300_INSN_EXTU_W] = "extu.w",
	[H8300_INSN_EXTU_L] = "extu.l",
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
	[H8300_INSN_LDC_B] = "ldc.b",
	[H8300_INSN_LDC_W] = "ldc.w",

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
	[H8300_INSN_CMP_L] = "cmp.l",
	[H8300_INSN_POP] = "pop",
	[H8300_INSN_PUSH] = "push",
};

static const char *register8_names[] = {
	"r0h",
	"r1h",
	"r2h",
	"r3h",
	"r4h",
	"r5h",
	"r6h",
	"r7h",
	"r0l",
	"r1l",
	"r2l",
	"r3l",
	"r4l",
	"r5l",
	"r6l",
	"r7l",
};

static const char *register16_names[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"e0",
	"e1",
	"e2",
	"e3",
	"e4",
	"e5",
	"e6",
	"e7",
};

static const char *register32_names[] = {
	"er0",
	"er1",
	"er2",
	"er3",
	"er4",
	"er5",
	"er6",
	"er7",
};

const char *h8300_get_opcode_name(H8300InsnId id) {
	if (id >= RZ_ARRAY_SIZE(commands)) {
		return NULL;
	}
	return commands[id];
}

const char *h8300_get_register8_name(ut8 id) {
	if (id >= RZ_ARRAY_SIZE(register8_names)) {
		return NULL;
	}
	return register8_names[id];
}

const char *h8300_get_register16_name(ut8 id) {
	if (id >= RZ_ARRAY_SIZE(register16_names)) {
		return NULL;
	}
	return register16_names[id];
}

const char *h8300_get_register32_name(ut8 id) {
	if (id >= RZ_ARRAY_SIZE(register32_names)) {
		return NULL;
	}
	return register32_names[id];
}

static void decode_operands(struct h8300_cmd *cmd) {
	for (int i = 0; i < cmd->operand_count; ++i) {
		H8300Operand *op = cmd->ops + i;
		switch (op->typ) {
		case H8300_OP_NONE: break;
		case H8300_OP_R8:
			rz_str_cat(cmd->operands, register8_names[op->reg]);
			break;
		case H8300_OP_R16:
			rz_str_cat(cmd->operands, register16_names[op->reg]);
			break;
		case H8300_OP_R32:
			rz_str_cat(cmd->operands, register32_names[op->reg]);
			break;
		case H8300_OP_CCR:
			rz_str_cat(cmd->operands, "ccr");
			break;
		case H8300_OP_IMM:
			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				"#%#x", op->imm);
			break;
		case H8300_OP_ABS:
			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				"@%#x", op->imm);
			break;
		case H8300_OP_PCREL:
			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				".%+d", op->disp);
			break;
		case H8300_OP_MI8:
			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				"@@%x:8", op->imm);
			break;
		case H8300_OP_RD32:
		case H8300_OP_RD16:
			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				"@(%+d,%s)", op->rd.disp, register32_names[op->rd.reg]);
			break;

		case H8300_OP_RI16:
			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				"@%s", register16_names[op->reg]);
			break;
		case H8300_OP_RI32:
			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				"@%s", register32_names[op->reg]);
			break;
		case H8300_OP_RINC:
			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				"@%s+", register16_names[op->reg]);
			break;
		case H8300_OP_RDEC:

			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				"@-%s", register32_names[op->reg]);
			break;
		case H8300_OP_RIINC32:
			snprintf(cmd->operands + strlen(cmd->operands), RZ_ARRAY_SIZE(cmd->operands),
				"@%s+", register32_names[op->reg]);
			break;
		}
		if (cmd->operand_count > 1 && i < cmd->operand_count - 1) {
			rz_str_cat(cmd->operands, ",");
		}
	}
}

static int decode_opcode(struct h8300_cmd *cmd) {
	const char *opcode_name = h8300_get_opcode_name(cmd->id);
	if (!opcode_name) {
		return -1;
	}

	strncpy(cmd->instr, opcode_name, H8300_INSTR_MAXLEN - 1);
	cmd->instr[H8300_INSTR_MAXLEN - 1] = '\0';
	return 0;
}

static int decode_none(const ut8 *bytes, struct h8300_cmd *cmd, ut8 sz) {
	return sz;
}

static int decode_i8ccr(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_IMM;
	OPS_ADD(H8300_OP_IMM, imm, bytes[1]);
	OPS_ADD(H8300_OP_CCR, imm, 0);
	return ret;
}

static int decode_ccrr8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_R8;
	OPS_ADD(H8300_OP_CCR, imm, 0);
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
	return ret;
}

static int decode_r8ccr(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_R8;
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
	OPS_ADD(H8300_OP_CCR, imm, 0);
	return ret;
}

static int decode_r16r16_2(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_R16R16;
	OPS_ADD(H8300_OP_R16, reg, bytes[1] >> 4);
	OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0xf);

	return ret;
}

static int decode_r16r32_2(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_R16R32;
	OPS_ADD(H8300_OP_R16, reg, bytes[1] >> 4);
	OPS_ADD(H8300_OP_R32, reg, bytes[1] & 0xf);
	return ret;
}

static int decode_r16r16_4(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	cmd->fmt = H8300_INSN_FORMAT_R16R16;
	OPS_ADD(H8300_OP_R16, reg, bytes[3] >> 4);
	OPS_ADD(H8300_OP_R16, reg, bytes[3] & 0xf);
	return ret;
}

static int decode_r16r32_4(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	cmd->fmt = H8300_INSN_FORMAT_R16R32;
	OPS_ADD(H8300_OP_R16, reg, bytes[3] >> 4);
	OPS_ADD(H8300_OP_R32, reg, bytes[3] & 0xf);
	return ret;
}

static int decode_sr16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	unsigned reg, val;
	reg = bytes[1] & 0x7;
	switch ((bytes[1] >> 4)) {
	case 0x0: val = 1; break;
	case 0x8: val = 2; break;
	case 0x9: val = 4; break;
	default: return -1;
	}

	cmd->fmt = H8300_INSN_FORMAT_IMMR16;
	OPS_ADD(H8300_OP_IMM, imm, val);
	OPS_ADD(H8300_OP_R16, reg, reg);
	return ret;
}

static int decode_xr16(const ut8 *bytes, struct h8300_cmd *cmd, ut16 x) {
	int ret = 2;
	unsigned reg;
	reg = bytes[1] & 0x7;

	cmd->fmt = H8300_INSN_FORMAT_IMMR16;
	OPS_ADD(H8300_OP_IMM, imm, x);
	OPS_ADD(H8300_OP_R16, reg, reg);
	return ret;
}

#define SIGN_EXT(value, bits) \
	((int)((unsigned int)(value) << (32 - (bits))) >> (32 - (bits)))

static int decode_pc_rel(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	st16 disp = SIGN_EXT(bytes[1], 8);

	cmd->fmt = H8300_INSN_FORMAT_PCREL8;
	OPS_ADD(H8300_OP_PCREL, disp, disp);
	return ret;
}

static int decode_pc_rel16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	st16 disp = SIGN_EXT(rz_read_at_be16(bytes, 2), 16);

	cmd->fmt = H8300_INSN_FORMAT_PCREL8;
	OPS_ADD(H8300_OP_PCREL, disp, disp);
	return ret;
}

/* [opcode ] [ 0000 | 0 rd] [      imm    ] */
static int decode_imm16r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	ut16 imm;
	imm = rz_read_at_be16(bytes, 2);

	cmd->fmt = H8300_INSN_FORMAT_IMMR16;
	OPS_ADD(H8300_OP_IMM, imm, imm);
	OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
	return ret;
}

/* [ opcode ] [ 0 rs | 0 rd ] [         disp    ] */
static int decode_rd16r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	st16 disp = (st16)rz_read_at_be16(bytes, 2);

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R16RD16;
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RD16R16;
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
	}

	return ret;
}

static int decode_r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_R16;
	OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
	return ret;
}

static int decode_r32(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	ut8 r = bytes[3] >> 4;
	cmd->fmt = H8300_INSN_FORMAT_R32;
	OPS_ADD(H8300_OP_R32, reg, r);

	return ret;
}

static int decode_riinc32(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	ut8 r = bytes[3] >> 4;
	cmd->fmt = H8300_INSN_FORMAT_RIINC32;
	OPS_ADD(H8300_OP_RIINC32, reg, r);
	return ret;
}

/* [ opcode ] [ 0 r2 | 0 rd ] @rs+,@rd */
static int decode_incdecr16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R16RDEC;
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
		OPS_ADD(H8300_OP_RDEC, reg, (bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RINCR16;
		OPS_ADD(H8300_OP_RINC, reg, (bytes[1] >> 4) & 0x7);
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
	}

	return ret;
}

/* [ opcode ] [ 0 rs | 0 rd ] */
static int decode_ri32r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R16RI32;
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
		OPS_ADD(H8300_OP_RI32, reg, (bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RI32R16;
		OPS_ADD(H8300_OP_RI32, reg, (bytes[1] >> 4) & 0x7);
		OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
	}

	return ret;
}

/* [ opcode ] [0 | IMM | rd ] */
static int decode_i3r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_IMMR8;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[1] >> 4) & 0x7);
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
	return ret;
}

/* [opcode] [0 | rd | 0000] [opcode] [0|IMM|0000] */
static int decode_i3ri32(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_IMMRI32;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[3] >> 4) & 0x7);
	OPS_ADD(H8300_OP_RI32, reg, bytes[1] >> 4);
	return ret;
}

/* [opcode] [   abs   ] [opcode] [0|IMM | 0000] */
static int decode_i3abs8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_IMMABS;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[3] >> 4) & 0x7);
	OPS_ADD(H8300_OP_ABS, imm, 0xff00 | bytes[1]);
	return ret;
}

/* [opcode] [ rn  |  rd ] */
static int decode_r8r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_R8R8;
	OPS_ADD(H8300_OP_R8, reg, bytes[1] >> 4);
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
	return ret;
}

/* [opcode] [0| rd | 0000] [opcode] [ rn | 0 ] */
static int decode_r8ri32_4(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_R8RI32;
	OPS_ADD(H8300_OP_R8, reg, bytes[3] >> 4);
	OPS_ADD(H8300_OP_RI32, reg, bytes[1] >> 4);
	return ret;
}

/* [opcode] [ abs ] [opcode] [ rn | 0000 ] */
static int decode_r8abs8_4(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_R8ABS;
	OPS_ADD(H8300_OP_R8, reg, bytes[3] >> 4);
	OPS_ADD(H8300_OP_ABS, imm, 0xff00 | bytes[1]);
	return ret;
}

/* [ opcode ] [ 0000 |  rd ] */
static int decode_r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_R8;
	OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
	return ret;
}

/* [ opcode ] [ rs | 0 rd] */
static int decode_r8r16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_R8R16;
	OPS_ADD(H8300_OP_R8, reg, bytes[1] >> 4);
	OPS_ADD(H8300_OP_R16, reg, bytes[1] & 0x7);
	return ret;
}

/* [opcode] [0000 0000] [       abs    ] */
int decode_abs16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	ut16 abs;
	abs = rz_read_at_be16(bytes, 2);

	cmd->fmt = H8300_INSN_FORMAT_ABS;
	OPS_ADD(H8300_OP_ABS, imm, abs);
	return ret;
}

/* [opcode] [  abs    ] */
int decode_mi8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_MI8;
	OPS_ADD(H8300_OP_MI8, imm, bytes[1]);
	return ret;
}

/* [opcode] [0 rn 0000] */
static int decode_ri32(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_RI32;
	OPS_ADD(H8300_OP_RI32, reg, (bytes[1] >> 4) & 0x7);
	return ret;
}

/* [ opcode ] [ 0000 | 0 rd ] [     abs    ] */
static int decode_abs16r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	ut16 abs = rz_read_at_be16(bytes, 2);
	ut8 r = bytes[1] & 0xf;
	cmd->fmt = H8300_INSN_FORMAT_ABSR16;
	OPS_ADD(H8300_OP_ABS, imm, abs);
	OPS_ADD(H8300_OP_R16, reg, r);

	return ret;
}

/* [ opcode ] [ 1 rd | rs ] */
static int decode_r8ri32_2(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8RI32;
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
		OPS_ADD(H8300_OP_RI32, reg, (bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RI32R8;
		OPS_ADD(H8300_OP_RI32, reg, (bytes[1] >> 4) & 0x7);
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
	}

	return ret;
}

/* [ opcode ] [ 1 rd |  rs ] [       disp     ] */
static int decode_r8rd16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	st16 disp = (st16)rz_read_at_be16(bytes, 2);
	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8RD16;
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RD16R8;
		OPS_ADD_EXT2(H8300_OP_RD16, rd, reg, disp,
			(bytes[1] >> 4) & 0x7, disp);
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
	}
	return ret;
}

static int decode_rd32_6(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 6;

	st16 d = (st16)rz_read_at_be16(bytes, 4);
	ut8 r = bytes[3] >> 4;
	cmd->fmt = H8300_INSN_FORMAT_RD32;
	OPS_ADD_EXT2(H8300_OP_RD32, rd, reg, disp, r, d);
	return ret;
}

static int decode_rd3224_10(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 10;
	st32 d = (st32)SIGN_EXT(rz_read_at_be24(bytes, 7), 24);
	ut8 r = bytes[3] >> 4;
	cmd->fmt = H8300_INSN_FORMAT_RD32;
	OPS_ADD_EXT2(H8300_OP_RD32, rd, reg, disp, r, d);
	return ret;
}

static int decode_rd32r32_6(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 6;

	st16 d = (st16)rz_read_at_be16(bytes, 4);
	ut8 rs = (bytes[3] >> 4) & 0x7;
	ut8 rd = bytes[3] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_RD32R32;
	OPS_ADD_EXT2(H8300_OP_RD32, rd, reg, disp, rs, d);
	OPS_ADD(H8300_OP_R32, reg, rd);
	return ret;
}

static int decode_r32rd32_6(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 6;

	st16 d = (st16)rz_read_at_be16(bytes, 4);
	ut8 rs = (bytes[3] >> 4) & 0x7;
	ut8 rd = bytes[3] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_R32RD32;
	OPS_ADD(H8300_OP_R32, reg, rd);
	OPS_ADD_EXT2(H8300_OP_RD32, rd, reg, disp, rs, d);
	return ret;
}

static int decode_rd3224r32_10(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 10;

	st32 d = (st32)SIGN_EXT(rz_read_at_be24(bytes, 7), 24);
	ut8 rs = (bytes[3] >> 4) & 0x7;
	ut8 rd = bytes[5] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_RD32R32;
	OPS_ADD_EXT2(H8300_OP_RD32, rd, reg, disp, rs, d);
	OPS_ADD(H8300_OP_R32, reg, rd);
	return ret;
}

static int decode_r32rd3224_10(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 10;

	st32 d = (st32)SIGN_EXT(rz_read_at_be24(bytes, 7), 24);
	ut8 rs = (bytes[3] >> 4) & 0x7;
	ut8 rd = bytes[5] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_R32RD32;
	OPS_ADD(H8300_OP_R32, reg, rd);
	OPS_ADD_EXT2(H8300_OP_RD32, rd, reg, disp, rs, d);
	return ret;
}

static int decode_rd3224r8_8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 8;

	st32 d = (st32)SIGN_EXT(rz_read_at_be24(bytes, 5), 24);
	ut8 rs = (bytes[1] >> 4) & 0x7;
	ut8 rd = bytes[4] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_RD32R8;
	OPS_ADD_EXT2(H8300_OP_RD32, rd, reg, disp, rs, d);
	OPS_ADD(H8300_OP_R8, reg, rd);
	return ret;
}

static int decode_r8rd3224_8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 8;

	st32 d = (st32)SIGN_EXT(rz_read_at_be24(bytes, 5), 24);
	ut8 rs = (bytes[1] >> 4) & 0x7;
	ut8 rd = bytes[4] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_R8RD32;
	OPS_ADD(H8300_OP_R8, reg, rd);
	OPS_ADD_EXT2(H8300_OP_RD32, rd, reg, disp, rs, d);
	return ret;
}

/* [ opcode ] [1 rd rs ] */
static int decode_incdecr8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8RDEC;
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
		OPS_ADD(H8300_OP_RDEC, reg, (bytes[1] >> 4) & 0x7);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RINCR8;
		OPS_ADD(H8300_OP_RINC, reg, (bytes[1] >> 4) & 0x7);
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
	}
	return ret;
}

/* [opcode ] [ 8 | rs ] [    abs    ] */
static int decode_r8abs16(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;
	ut16 abs;
	abs = rz_read_at_be16(bytes, 2);

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8ABS;
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
		OPS_ADD(H8300_OP_ABS, imm, abs);
	} else {
		cmd->fmt = H8300_INSN_FORMAT_ABSR8;
		OPS_ADD(H8300_OP_ABS, imm, abs);
		OPS_ADD(H8300_OP_R8, reg, bytes[1] & 0xf);
	}

	return ret;
}

static int decode_nop(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;
	return ret;
}

static int decode_abs8r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_ABSR8;
	OPS_ADD(H8300_OP_ABS, imm, 0xff00 | bytes[1]);
	OPS_ADD(H8300_OP_R8, reg, bytes[0] & 0xf);

	return ret;
}

static int decode_r8abs8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_R8ABS;
	OPS_ADD(H8300_OP_R8, reg, bytes[0] & 0xf);
	OPS_ADD(H8300_OP_ABS, imm, 0xff00 | bytes[1]);

	return ret;
}

static ut32 read_abs16(const ut8 *bytes, ut32 off) {
	ut16 x = rz_read_at_be16(bytes, 4);
	st32 sx32 = SIGN_EXT(x, 16);
	return sx32 & 0xffffff;
}

static int decode_abs16_6(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 6;

	ut32 abs_addr = read_abs16(bytes, 4);
	cmd->fmt = H8300_INSN_FORMAT_ABS;
	OPS_ADD(H8300_OP_ABS, imm, abs_addr);

	return ret;
}

static int decode_abs16r32_6(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 6;

	ut32 abs_addr = read_abs16(bytes, 4);
	ut8 r = bytes[3] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_ABSR32;
	OPS_ADD(H8300_OP_ABS, imm, abs_addr);
	OPS_ADD(H8300_OP_R32, reg, r);

	return ret;
}

static int decode_r32abs16_6(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 6;

	ut32 abs_addr = read_abs16(bytes, 4);
	ut8 r = bytes[3] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_R32ABS;
	OPS_ADD(H8300_OP_R32, reg, r);
	OPS_ADD(H8300_OP_ABS, imm, abs_addr);

	return ret;
}

static int decode_abs24_8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 8;
	ut32 abs_addr = rz_read_at_be24(bytes, 5);
	cmd->fmt = H8300_INSN_FORMAT_ABS;
	OPS_ADD(H8300_OP_ABS, imm, abs_addr);

	return ret;
}

static int decode_abs24r8_6(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 6;

	ut32 abs_addr = rz_read_at_be24(bytes, 3);
	ut8 r = bytes[1] & 0xf;
	cmd->fmt = H8300_INSN_FORMAT_ABSR8;
	OPS_ADD(H8300_OP_ABS, imm, abs_addr);
	OPS_ADD(H8300_OP_R8, reg, r);

	return ret;
}

static int decode_r8abs24_6(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 6;

	ut32 abs_addr = rz_read_at_be24(bytes, 3);
	ut8 r = bytes[1] & 0xf;
	cmd->fmt = H8300_INSN_FORMAT_R8ABS;
	OPS_ADD(H8300_OP_R8, reg, r);
	OPS_ADD(H8300_OP_ABS, imm, abs_addr);

	return ret;
}

static int decode_abs24r32_8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 8;

	ut32 abs_addr = rz_read_at_be24(bytes, 5);
	ut8 r = bytes[3] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_ABSR32;
	OPS_ADD(H8300_OP_ABS, imm, abs_addr);
	OPS_ADD(H8300_OP_R32, reg, r);

	return ret;
}

static int decode_r32abs24_8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 8;

	ut32 abs_addr = rz_read_at_be24(bytes, 5);
	ut8 r = bytes[3] & 0x7;
	cmd->fmt = H8300_INSN_FORMAT_R32ABS;
	OPS_ADD(H8300_OP_R32, reg, r);
	OPS_ADD(H8300_OP_ABS, imm, abs_addr);

	return ret;
}

static int decode_i8r8(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_IMMR8;
	OPS_ADD(H8300_OP_IMM, imm, bytes[1]);
	OPS_ADD(H8300_OP_R8, reg, bytes[0] & 0xf);
	return ret;
}

static int decode_i32r32(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 6;

	ut32 immval = rz_read_at_be32(bytes, 2);
	ut8 regval = bytes[1] & 0x7;

	cmd->fmt = H8300_INSN_FORMAT_IMMR32;
	OPS_ADD(H8300_OP_IMM, imm, immval);
	OPS_ADD(H8300_OP_R32, reg, regval);

	return ret;
}

static int decode_r32r32_2(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 2;

	ut8 regsval = (bytes[1] >> 4) & 0x7;
	ut8 regdval = bytes[1] & 0x7;

	cmd->fmt = H8300_INSN_FORMAT_R32R32;
	OPS_ADD(H8300_OP_R32, reg, regsval);
	OPS_ADD(H8300_OP_R32, reg, regdval);

	return ret;
}

static int decode_ri32r32_4(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	ut8 regsval = (bytes[3] >> 4) & 0x7;
	ut8 regdval = bytes[3] & 0x7;

	cmd->fmt = H8300_INSN_FORMAT_RI32R32;
	OPS_ADD(H8300_OP_RI32, reg, regsval);
	OPS_ADD(H8300_OP_R32, reg, regdval);

	return ret;
}

static int decode_r32ri32_4(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	ut8 regsval = (bytes[3] >> 4) & 0x7;
	ut8 regdval = bytes[3] & 0x7;

	cmd->fmt = H8300_INSN_FORMAT_R32RI32;
	OPS_ADD(H8300_OP_R32, reg, regdval);
	OPS_ADD(H8300_OP_RI32, reg, regsval);

	return ret;
}

static int decode_riinc32r32_4(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	ut8 regsval = (bytes[3] >> 4) & 0x7;
	ut8 regdval = bytes[3] & 0x7;

	cmd->fmt = H8300_INSN_FORMAT_RIINC32R32;
	OPS_ADD(H8300_OP_RIINC32, reg, regsval);
	OPS_ADD(H8300_OP_R32, reg, regdval);

	return ret;
}

static int decode_r32riinc32_4(const ut8 *bytes, struct h8300_cmd *cmd) {
	int ret = 4;

	ut8 regsval = (bytes[3] >> 4) & 0x7;
	ut8 regdval = bytes[3] & 0x7;

	cmd->fmt = H8300_INSN_FORMAT_R32RIINC32;
	OPS_ADD(H8300_OP_R32, reg, regdval);
	OPS_ADD(H8300_OP_RIINC32, reg, regsval);

	return ret;
}

#define CASE_F_F_IMPL(F, I) \
	cmd->id = H8300_INSN_##I; \
	cmd->size = F(instr, cmd); \
	return cmd->size;
#define CASE_F_F(F, X, I) \
	case (X): \
		CASE_F_F_IMPL(F, I)
#define CASE_F_R8(X, I) CASE_F_F(decode_r8, X, I)
#define CASE_F_F_VA(F, X, I, ...) \
	case (X): \
		cmd->id = H8300_INSN_##I; \
		cmd->size = F(instr, cmd, __VA_ARGS__); \
		return cmd->size;
#define CASE_F_F_CCR(F, X, I) \
	case (X): \
		cmd->id = H8300_INSN_##I; \
		cmd->size = F(instr, cmd); \
		OPS_ADD(H8300_OP_CCR, imm, 0); \
		return cmd->size;

static int h8300_decode_10(const ut8 *instr, struct h8300_cmd *cmd) {
	ut64 x7 = rz_read_be64(instr) >> 8;
	switch (x7 & 0xffffff8fffffff) {
		CASE_F_F_CCR(decode_rd3224_10, 0x014078006b2000, LDC_W);
	default: break;
	}
	switch (x7 & 0xffffff8ffff8ff) {
		CASE_F_F(decode_rd3224r32_10, 0x010078006b2000, MOV_L);
		CASE_F_F(decode_r32rd3224_10, 0x010078806ba000, MOV_L);
	default: break;
	}
	return -1;
}
static int h8300_decode_8(const ut8 *instr, struct h8300_cmd *cmd) {
	ut64 x5 = rz_read_be64(instr) >> 24;
	switch (x5) {
		CASE_F_F_CCR(decode_abs24_8, 0x01406b2000, LDC_W);
	default: break;
	}
	switch (x5 & 0xff8ffff0ff) {
		CASE_F_F(decode_rd3224r8_8, 0x78006a2000, MOV_B);
		CASE_F_F(decode_r8rd3224_8, 0x78006aa000, MOV_B);
	default: break;
	}
	switch (x5 & 0xfffffff8ff) {
		CASE_F_F(decode_abs24r32_8, 0x01006b2000, MOV_L);
		CASE_F_F(decode_r32abs24_8, 0x01006ba000, MOV_L);
	default: break;
	}
	return -1;
}

static int h8300_decode_6(const ut8 *instr, struct h8300_cmd *cmd) {
	ut32 x2 = rz_read_be16(instr);
	switch (x2 & 0xfff8) {
		CASE_F_F(decode_i32r32, 0x7a10, ADD_L);
		CASE_F_F(decode_i32r32, 0x7a60, AND_L);
		CASE_F_F(decode_i32r32, 0x7a20, CMP_L);
		CASE_F_F(decode_i32r32, 0x7a00, MOV_L);
	default: break;
	}

	ut32 x4 = rz_read_be32(instr);
	switch (x4 & 0xffffff8f) {
		CASE_F_F_CCR(decode_rd32_6, 0x01406f00, LDC_W);
	default: break;
	}
	switch (x4 & 0xfffffff8) {
		CASE_F_F(decode_abs16r32_6, 0x01006b00, MOV_L);
		CASE_F_F(decode_r32abs16_6, 0x01006b80, MOV_L);
	default: break;
	}
	switch (x4 & 0xffffff88) {
		CASE_F_F(decode_rd32r32_6, 0x01006f00, MOV_L);
		CASE_F_F(decode_r32rd32_6, 0x01006f80, MOV_L);
	default: break;
	}
	switch (x4 & 0xfff0ff00) {
		CASE_F_F(decode_abs24r8_6, 0x6a200000, MOV_B);
		CASE_F_F(decode_r8abs24_6, 0x6aa00000, MOV_B);
	default: break;
	}
	switch (x4) {
		CASE_F_F_CCR(decode_abs16_6, 0x01406b00, LDC_W);
	default: break;
	}
	return -1;
}

static int h8300_decode_4(const ut8 *instr, struct h8300_cmd *cmd) {
	ut32 x2 = rz_read_be16(instr);
	ut32 x4 = rz_read_be32(instr);

	switch (x2 & 0xfff0) {
		CASE_F_F(decode_imm16r16, 0x7960, AND_W);
		CASE_F_F(decode_imm16r16, 0x7910, ADD_W);
		CASE_F_F(decode_imm16r16, 0x7920, CMP_W);

		CASE_F_F(decode_abs16r8, 0x6a00, MOV_B);
		CASE_F_F(decode_r8abs16, 0x6a80, MOV_B);
		CASE_F_F(decode_r8abs16, 0x6a40, MOVFPE);
		CASE_F_F(decode_r8abs16, 0x6ac0, MOVTPE);
	default:
		break;
	}
	switch (x2) {
		CASE_F_F(decode_pc_rel16, 0x5800, BRA);
		CASE_F_F(decode_pc_rel16, 0x5810, BRN);
		CASE_F_F(decode_pc_rel16, 0x5820, BHI);
		CASE_F_F(decode_pc_rel16, 0x5830, BLS);
		CASE_F_F(decode_pc_rel16, 0x5840, BCC);
		CASE_F_F(decode_pc_rel16, 0x5850, BCS);
		CASE_F_F(decode_pc_rel16, 0x5860, BNE);
		CASE_F_F(decode_pc_rel16, 0x5870, BEQ);
		CASE_F_F(decode_pc_rel16, 0x5880, BVC);
		CASE_F_F(decode_pc_rel16, 0x5890, BVS);
		CASE_F_F(decode_pc_rel16, 0x58a0, BPL);
		CASE_F_F(decode_pc_rel16, 0x58b0, BMI);
		CASE_F_F(decode_pc_rel16, 0x58c0, BGE);
		CASE_F_F(decode_pc_rel16, 0x58d0, BLT);
		CASE_F_F(decode_pc_rel16, 0x58e0, BGT);
		CASE_F_F(decode_pc_rel16, 0x58f0, BLE);
	default: break;
	}

	switch (x4) {
		CASE_F_F_VA(decode_none, 0x7b5c598f, EEPMOV_B, 4);
		CASE_F_F_VA(decode_none, 0x7bd4598f, EEPMOV_W, 4);
	default:
		break;
	}

	switch (x4 & ~0x00700070) {
		CASE_F_F(decode_i3ri32, 0x7d007000, BSET);
		CASE_F_F(decode_i3ri32, 0x7d007200, BCLR);
		CASE_F_F(decode_i3ri32, 0x7d006700, BST);
		CASE_F_F(decode_i3ri32, 0x7d006780, BIST);
		CASE_F_F(decode_i3ri32, 0x7d007100, BNOT);

		CASE_F_F(decode_i3ri32, 0x7c007600, BAND);
		CASE_F_F(decode_i3ri32, 0x7c007680, BIAND);
		CASE_F_F(decode_i3ri32, 0x7c007780, BILD);
		CASE_F_F(decode_i3ri32, 0x7c007480, BIOR);
		CASE_F_F(decode_i3ri32, 0x7c007580, BIXOR);
		CASE_F_F(decode_i3ri32, 0x7c007700, BLD);
		CASE_F_F(decode_i3ri32, 0x7c007400, BOR);
		CASE_F_F(decode_i3ri32, 0x7c007300, BTST);
		CASE_F_F(decode_i3ri32, 0x7c007500, BXOR);
	default:
		break;
	}
	switch (x4 & ~0x00ff0070) {
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
	switch (x4 & ~0x007000f0) {
		CASE_F_F(decode_r8ri32_4, 0x7d006000, BSET);
		CASE_F_F(decode_r8ri32_4, 0x7d006200, BCLR);
		CASE_F_F(decode_r8ri32_4, 0x7d006100, BNOT);

		CASE_F_F(decode_r8ri32_4, 0x7c006300, BTST);
	default:
		break;
	}
	switch (x4 & ~0x00ff00f0) {
		CASE_F_F(decode_r8abs8_4, 0x7f006000, BSET);
		CASE_F_F(decode_r8abs8_4, 0x7f006200, BCLR);
		CASE_F_F(decode_r8abs8_4, 0x7f006100, BNOT);

		CASE_F_F(decode_r8abs8_4, 0x7e006300, BTST);
	default:
		break;
	}

	switch (x4 & 0xffffff00) {
		CASE_F_F(decode_r16r16_4, 0x01d05100, DIVXS_B);
	default:
		break;
	}
	switch (x4 & 0xffffff08) {
		CASE_F_F(decode_r16r32_4, 0x01d05300, DIVXS_W);
	default:
		break;
	}
	switch (x4 & 0xffffff88) {
		CASE_F_F(decode_imm16r16, 0x01f06600, AND_L);

		CASE_F_F(decode_ri32r32_4, 0x01006900, MOV_L);
		CASE_F_F(decode_riinc32r32_4, 0x01006d00, MOV_L);
		CASE_F_F(decode_r32ri32_4, 0x01006980, MOV_L);
		CASE_F_F(decode_r32riinc32_4, 0x01006d80, MOV_L);
	default:
		break;
	}
	switch (x4 & 0xffffff8f) {
		CASE_F_F_CCR(decode_r32, 0x01406900, LDC_W);
		CASE_F_F_CCR(decode_riinc32, 0x01406d00, LDC_W);
	default:
		break;
	}
	return -1;
}

static int h8300_decode_2(const ut8 *instr, struct h8300_cmd *cmd) {
	ut32 x2 = rz_read_be16(instr);

	switch (instr[0] >> 4) {
		CASE_F_F(decode_abs8r8, 0x2, MOV_B);
		CASE_F_F(decode_r8abs8, 0x3, MOV_B);

		CASE_F_F(decode_i8r8, 0xf, MOV_B);
		CASE_F_F(decode_i8r8, 0xe, AND_B);
		CASE_F_F(decode_i8r8, 0x9, ADDX);
		CASE_F_F(decode_i8r8, 0x8, ADD_B);
		CASE_F_F(decode_i8r8, 0xa, CMP_B);
		CASE_F_F(decode_i8r8, H8300_OR_4BIT, OR);
		CASE_F_F(decode_i8r8, H8300_SUBX_4BIT, SUBX);
		CASE_F_F(decode_i8r8, H8300_XOR_4BIT, XOR);
	default: break;
	}

	switch (x2) {
		CASE_F_F_VA(decode_none, 0x5670, RTE, 2);
		CASE_F_F_VA(decode_none, 0x5470, RTS, 2);
		CASE_F_F_VA(decode_none, 0x0180, SLEEP, 2);
	default:
		break;
	}

	switch (x2 & 0xfff0) {
		CASE_F_R8(0x0f00, DAA);
		CASE_F_R8(0x1f00, DAS);
		CASE_F_R8(0x1a00, DEC_B);
		CASE_F_R8(0x0a00, INC_B);
		CASE_F_R8(0x1780, NEG);
		CASE_F_R8(0x1700, NOT);
		CASE_F_R8(0x1280, ROTL);
		CASE_F_R8(0x1380, ROTR);
		CASE_F_R8(0x1200, ROTXL);
		CASE_F_R8(0x1300, ROTXR);
		CASE_F_R8(0x1080, SHAL);
		CASE_F_R8(0x1000, SHLL);
		CASE_F_R8(0x1180, SHAR);
		CASE_F_R8(0x1100, SHLR);

		CASE_F_R8(0x17d0, EXTS_W);
		CASE_F_R8(0x17f0, EXTS_L);
		CASE_F_R8(0x1750, EXTU_W);
		CASE_F_R8(0x1770, EXTU_L);

		CASE_F_F_VA(decode_xr16, 0x1b50, DEC_W, 1);
		CASE_F_F_VA(decode_xr16, 0x1bd0, DEC_W, 2);
		CASE_F_F_VA(decode_xr16, 0x0b50, INC_W, 1);
		CASE_F_F_VA(decode_xr16, 0x0bd0, INC_W, 2);
	default:
		break;
	}

	switch (x2 & 0xfff8) {
		CASE_F_F(decode_r16, 0x6d70, POP);
		CASE_F_F(decode_r16, 0x6df0, PUSH);

		CASE_F_F(decode_imm16r16, 0x7900, MOV_W);
		CASE_F_F(decode_abs16r8, 0x6b00, MOV_W);

		CASE_F_F_VA(decode_xr16, 0x1b70, DEC_L, 1);
		CASE_F_F_VA(decode_xr16, 0x1bf0, DEC_L, 2);
		CASE_F_F_VA(decode_xr16, 0x0b70, INC_L, 1);
		CASE_F_F_VA(decode_xr16, 0x0bf0, INC_L, 2);

	case 0x0b00:
	case 0x0b80:
	case 0x0b90:
		CASE_F_F_IMPL(decode_sr16, ADDS);
	case 0x1b00:
	case 0x1b80:
	case 0x1b90:
		CASE_F_F_IMPL(decode_sr16, SUBS);

	default:
		break;
	}

	switch (x2 & 0xff88) {
		CASE_F_F(decode_r32r32_2, 0x0a80, ADD_L);
		CASE_F_F(decode_r32r32_2, 0x1f80, CMP_L);
		CASE_F_F(decode_r32r32_2, 0x0f80, MOV_L);
	default:
		break;
	}

	switch (x2 & 0xff80) {
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

	switch (x2 & 0xff08) {
		CASE_F_F(decode_r16r32_2, 0x5300, DIVXU_W);
	default: break;
	}

	int ret = 0;
	switch (instr[0]) {
		CASE_F_F(decode_r8r8, 0x08, ADD_B);
		CASE_F_F(decode_r16r16_2, 0x09, ADD_W);

	case H8300_ANDC:
		cmd->id = H8300_INSN_ANDC;
		ret = decode_i8ccr(instr, cmd);
		break;
	case 0x1d:
		cmd->id = H8300_INSN_CMP_W;
		ret = decode_r16r16_2(instr, cmd);
		break;
	case 0x16:
		cmd->id = H8300_INSN_AND_B;
		ret = decode_r8r8(instr, cmd);
		break;
		CASE_F_F(decode_r8r8, 0x66, AND_W);
	case 0x62:
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
	case 0x0e:
		cmd->id = H8300_INSN_ADDX;
		ret = decode_r8r8(instr, cmd);
		break;
	case 0x15:
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
	case 0x1c:
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
		CASE_F_F(decode_r8r16, 0x51, DIVXU_B);

	case H8300_MULXU:
		cmd->id = H8300_INSN_MULXU;
		ret = decode_r8r16(instr, cmd);
		break;
	case 0x59:
		cmd->id = H8300_INSN_JMP;
		ret = decode_ri32(instr, cmd);
		break;
	case 0x5a:
		cmd->id = H8300_INSN_JMP;
		ret = decode_abs16(instr, cmd);
		break;
	case 0x5b:
		cmd->id = H8300_INSN_JMP;
		ret = decode_mi8(instr, cmd);
		break;
	case 0x5d:
		cmd->id = H8300_INSN_JSR;
		ret = decode_ri32(instr, cmd);
		break;
	case 0x5e:
		cmd->id = H8300_INSN_JSR;
		ret = decode_abs16(instr, cmd);
		break;
	case 0x5f:
		cmd->id = H8300_INSN_JSR;
		ret = decode_mi8(instr, cmd);
		break;

		CASE_F_F(decode_pc_rel, 0x40, BRA);
		CASE_F_F(decode_pc_rel, 0x41, BRN);
		CASE_F_F(decode_pc_rel, 0x42, BHI);
		CASE_F_F(decode_pc_rel, 0x43, BLS);
		CASE_F_F(decode_pc_rel, 0x44, BCC);
		CASE_F_F(decode_pc_rel, 0x45, BCS);
		CASE_F_F(decode_pc_rel, 0x46, BNE);
		CASE_F_F(decode_pc_rel, 0x47, BEQ);
		CASE_F_F(decode_pc_rel, 0x48, BVC);
		CASE_F_F(decode_pc_rel, 0x49, BVS);
		CASE_F_F(decode_pc_rel, 0x4a, BPL);
		CASE_F_F(decode_pc_rel, 0x4b, BMI);
		CASE_F_F(decode_pc_rel, 0x4c, BGE);
		CASE_F_F(decode_pc_rel, 0x4d, BLT);
		CASE_F_F(decode_pc_rel, 0x4e, BGT);
		CASE_F_F(decode_pc_rel, 0x4f, BLE);

	case H8300_ORC:
		cmd->id = H8300_INSN_ORC;
		ret = decode_i8ccr(instr, cmd);
		break;
	case 0x03:
		cmd->id = H8300_INSN_LDC_B;
		ret = decode_r8ccr(instr, cmd);
		break;
	case 0x07:
		cmd->id = H8300_INSN_LDC_B;
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
		ret = decode_r16r16_2(instr, cmd);
		break;
	case 0x0d:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_r16r16_2(instr, cmd);
		break;
	case 0x68:
		cmd->id = H8300_INSN_MOV_B;
		ret = decode_r8ri32_2(instr, cmd);
		break;
	case 0x69:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_ri32r16(instr, cmd);
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
	return ret;
}

int h8300_decode_command(const ut8 *instr, ut64 len, struct h8300_cmd *cmd, ut64 pc) {
	cmd->pc = pc;
	int ret = 0;
#define FAST_PATH(N) \
	if (len >= N) { \
		ret = h8300_decode_##N(instr, cmd); \
		if (ret > 0) { \
			goto beach; \
		} \
	}

	FAST_PATH(10);
	FAST_PATH(8);
	FAST_PATH(6);
	FAST_PATH(4);
	FAST_PATH(2);

beach:
	if (cmd->id != H8300_INSN_INVALID) {
		if (decode_opcode(cmd) == -1) {
			return -1;
		}
		decode_operands(cmd);
	}
	cmd->size = ret;
	return ret;
}
