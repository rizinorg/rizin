// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_util/rz_bits.h>
#include "h8300_disas.h"

#define INS_OP(I) (cmd->ops[(I)])

#define OPS_ADD(T, F, X) \
	do { \
		cmd->ops[cmd->ops_count].typ = T; \
		cmd->ops[cmd->ops_count].F = (X); \
		cmd->ops_count++; \
	} while (0)

#define OPS_ADD_EXT2(T, F, F1, F2, X1, X2) \
	do { \
		cmd->ops[cmd->ops_count].typ = T; \
		cmd->ops[cmd->ops_count].F.F1 = (X1); \
		cmd->ops[cmd->ops_count].F.F2 = (X2); \
		cmd->ops_count++; \
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
	[H8300_INSN_SUB_L] = "sub.l",
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
	[H8300_INSN_NEG_B] = "neg.b",
	[H8300_INSN_NEG_W] = "neg.w",
	[H8300_INSN_NEG_L] = "neg.l",
	[H8300_INSN_NOT_B] = "not.b",
	[H8300_INSN_NOT_W] = "not.w",
	[H8300_INSN_NOT_L] = "not.l",
	[H8300_INSN_OR_B] = "or.b",
	[H8300_INSN_OR_W] = "or.w",
	[H8300_INSN_OR_L] = "or.l",
	[H8300_INSN_DIVXU_B] = "divxu.b",
	[H8300_INSN_DIVXU_W] = "divxu.w",
	[H8300_INSN_DIVXS_B] = "divxs.b",
	[H8300_INSN_DIVXS_W] = "divxs.w",
	[H8300_INSN_MULXU_B] = "mulxu.b",
	[H8300_INSN_MULXU_W] = "mulxu.w",
	[H8300_INSN_MULXS_B] = "mulxs.b",
	[H8300_INSN_MULXS_W] = "mulxs.w",
	[H8300_INSN_EEPMOV_B] = "eepmov.b",
	[H8300_INSN_EEPMOV_W] = "eepmov.w",
	[H8300_INSN_EXTS_W] = "exts.w",
	[H8300_INSN_EXTS_L] = "exts.l",
	[H8300_INSN_EXTU_W] = "extu.w",
	[H8300_INSN_EXTU_L] = "extu.l",
	[H8300_INSN_JMP] = "jmp",
	[H8300_INSN_JSR] = "jsr",
	[H8300_INSN_ORC] = "orc",
	[H8300_INSN_ROTL_B] = "rotl.b",
	[H8300_INSN_ROTR_B] = "rotr.b",
	[H8300_INSN_ROTXL_B] = "rotxl.b",
	[H8300_INSN_ROTXR_B] = "rotxr.b",
	[H8300_INSN_ROTL_W] = "rotl.w",
	[H8300_INSN_ROTR_W] = "rotr.w",
	[H8300_INSN_ROTXL_W] = "rotxl.w",
	[H8300_INSN_ROTXR_W] = "rotxr.w",
	[H8300_INSN_ROTL_L] = "rotl.l",
	[H8300_INSN_ROTR_L] = "rotr.l",
	[H8300_INSN_ROTXL_L] = "rotxl.l",
	[H8300_INSN_ROTXR_L] = "rotxr.l",
	[H8300_INSN_RTE] = "rte",
	[H8300_INSN_RTS] = "rts",
	[H8300_INSN_SHAL_B] = "shal.b",
	[H8300_INSN_SHAR_B] = "shar.b",
	[H8300_INSN_SHLL_B] = "shll.b",
	[H8300_INSN_SHLR_B] = "shlr.b",
	[H8300_INSN_SHAL_W] = "shal.w",
	[H8300_INSN_SHAR_W] = "shar.w",
	[H8300_INSN_SHLL_W] = "shll.w",
	[H8300_INSN_SHLR_W] = "shlr.w",
	[H8300_INSN_SHAL_L] = "shal.l",
	[H8300_INSN_SHAR_L] = "shar.l",
	[H8300_INSN_SHLL_L] = "shll.l",
	[H8300_INSN_SHLR_L] = "shlr.l",
	[H8300_INSN_SLEEP] = "sleep",
	[H8300_INSN_STC_B] = "stc.b",
	[H8300_INSN_STC_W] = "stc.w",
	[H8300_INSN_SUBS] = "subs",
	[H8300_INSN_SUBX] = "subx",
	[H8300_INSN_XOR_B] = "xor.b",
	[H8300_INSN_XOR_W] = "xor.w",
	[H8300_INSN_XOR_L] = "xor.l",
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
	[H8300_INSN_POP_W] = "pop.w",
	[H8300_INSN_POP_L] = "pop.l",
	[H8300_INSN_PUSH_W] = "push.w",
	[H8300_INSN_PUSH_L] = "push.l",
	[H8300_INSN_TRAPA] = "trapa",
};

static const char *register_names[] = {
	"reg_invalid",
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

const char *h8300_get_register_name(H8300Register id) {
	if (id >= RZ_ARRAY_SIZE(register_names)) {
		return NULL;
	}
	return register_names[id];
}

static ut32 read_abs8(const ut8 *bytes, ut32 off) {
	ut8 x = rz_read_at_be8(bytes, off);
	return (ut32)x | 0xffff00;
}

static ut32 read_abs16(const ut8 *bytes, ut32 off) {
	ut16 x = rz_read_at_be16(bytes, off);
	st32 sx32 = rz_bits_sign_ext32(x, 16);
	return sx32 & 0xffffff;
}

static ut32 read_abs24(const ut8 *bytes, ut32 off) {
	return rz_read_at_be24(bytes, off);
}

#define read_abs(T, BS)  read_abs##T(BS, (ret - T / 8))
#define read_disp(T, BS) (rz_bits_sign_ext32(rz_read_at_be##T(BS, (ret - T / 8)), T))

#define BHIGH(B) (((B) >> 4) & 0xf)
#define BLOW(B)  ((B) & 0xf)

static ut8 r8_low(ut8 x) {
	return BLOW(x) + H8300_REG8_BEGIN;
}

static ut8 r8_high(ut8 x) {
	return BHIGH(x) + H8300_REG8_BEGIN;
}

#define r16_low(x)  (BLOW(x) + H8300_REG16_BEGIN)
#define r16_high(x) (BHIGH(x) + H8300_REG16_BEGIN)

static ut8 r32_low(ut8 x) {
	return (x & 0x7) + H8300_REG32_BEGIN;
}

static ut8 r32_high(ut8 x) {
	return (BHIGH(x) & 0x7) + H8300_REG32_BEGIN;
}

#define IMPL_APPEND_OPERAND(name, F, T) \
	static void append_##name(H8300Instruction *cmd, ut8 reg) { \
		if (cmd->cpu_type == CPU_H8300H) { \
			INS_OP(cmd->ops_count).width = H8300Operand_32; \
			OPS_ADD(T, F, r32_low(reg)); \
		} else { \
			INS_OP(cmd->ops_count).width = H8300Operand_16; \
			OPS_ADD(T, F, r16_low(reg)); \
		} \
	}

IMPL_APPEND_OPERAND(ri, reg, H8300_OP_RI);
IMPL_APPEND_OPERAND(rpostinc, reg, H8300_OP_RPOSTINC);
IMPL_APPEND_OPERAND(rpredec, reg, H8300_OP_RPREDEC);

static void append_rd(H8300Instruction *cmd, ut8 reg, st32 disp) {
	if (cmd->cpu_type == CPU_H8300H) {
		INS_OP(cmd->ops_count).width = H8300Operand_32;
		OPS_ADD_EXT2(H8300_OP_RD, rd, reg, disp, r32_low(reg), disp);
	} else {
		INS_OP(cmd->ops_count).width = H8300Operand_16;
		OPS_ADD_EXT2(H8300_OP_RD, rd, reg, disp, r16_low(reg), disp);
	}
}

static void decode_operands(H8300Instruction *cmd, H8300InstructionStr *opstr) {
	for (int i = 0; i < cmd->ops_count; ++i) {
		H8300Operand *op = cmd->ops + i;
#define OPSTR opstr->ops_str
		switch (op->typ) {
		case H8300_OP_NONE: break;
		case H8300_OP_R8:
		case H8300_OP_R16:
		case H8300_OP_R32:
			rz_str_cat(OPSTR, register_names[op->reg]);
			break;
		case H8300_OP_CCR:
			rz_str_cat(OPSTR, "ccr");
			break;
#define STR_APPENDF(S, F, ...) snprintf(S + strlen(S), RZ_ARRAY_SIZE(S) - strlen(S), F, __VA_ARGS__)
		case H8300_OP_IMM:
			STR_APPENDF(OPSTR, "#%#x", op->imm);
			break;
		case H8300_OP_ABS:
			STR_APPENDF(OPSTR, "@%#x", op->imm);
			break;
		case H8300_OP_PCREL:
			STR_APPENDF(OPSTR, ".%+d", op->disp);
			break;
		case H8300_OP_MI8:
			STR_APPENDF(OPSTR, "@@%x:8", op->imm);
			break;
		case H8300_OP_RD:
			STR_APPENDF(OPSTR, "@(%+d,%s)", op->rd.disp, register_names[op->rd.reg]);
			break;
		case H8300_OP_RI:
			STR_APPENDF(OPSTR, "@%s", register_names[op->reg]);
			break;
		case H8300_OP_RPOSTINC:
			STR_APPENDF(OPSTR, "@%s+", register_names[op->reg]);
			break;
		case H8300_OP_RPREDEC:
			STR_APPENDF(OPSTR, "@-%s", register_names[op->reg]);
			break;
		}
		if (cmd->ops_count > 1 && i < cmd->ops_count - 1) {
			rz_str_cat(OPSTR, ",");
		}
	}
}

static int decode_opcode(const H8300Instruction *cmd, H8300InstructionStr *opstr) {
	const char *opcode_name = h8300_get_opcode_name(cmd->id);
	if (!opcode_name) {
		return -1;
	}

	strncpy(opstr->instr, opcode_name, H8300_INSTR_MAXLEN - 1);
	opstr->instr[H8300_INSTR_MAXLEN - 1] = '\0';
	return 0;
}

static int decode_none(const ut8 *bytes, H8300Instruction *cmd, ut8 sz) {
	return sz;
}

static int decode_i8ccr(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_IMM;
	OPS_ADD(H8300_OP_IMM, imm, bytes[1]);
	OPS_ADD(H8300_OP_CCR, imm, 0);
	return ret;
}

static int decode_ccrr8(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_R8;
	OPS_ADD(H8300_OP_CCR, imm, 0);
	OPS_ADD(H8300_OP_R8, reg, r8_low(bytes[1]));
	return ret;
}

static int decode_r8ccr(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_R8;
	OPS_ADD(H8300_OP_R8, reg, r8_low(bytes[1]));
	OPS_ADD(H8300_OP_CCR, imm, 0);
	return ret;
}

#define RR_IMPL(B, BRS, BRD, OFBRS, OFBRD) \
	static int decode_r##BRS##r##BRD##_##B(const ut8 *bytes, H8300Instruction *cmd) { \
		int ret = B; \
		cmd->fmt = H8300_INSN_FORMAT_R##BRS##R##BRD; \
		OPS_ADD(H8300_OP_R##BRS, reg, r##BRS##_high(bytes[OFBRS])); \
		OPS_ADD(H8300_OP_R##BRD, reg, r##BRD##_low(bytes[OFBRS])); \
		return ret; \
	}

RR_IMPL(2, 16, 16, 1, 1)
RR_IMPL(2, 16, 32, 1, 1)
RR_IMPL(4, 8, 16, 3, 3)
RR_IMPL(4, 16, 32, 3, 3)

static int decode_sr16_32(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	unsigned val;
	switch ((bytes[1] >> 4)) {
	case 0x0: val = 1; break;
	case 0x8: val = 2; break;
	case 0x9: val = 4; break;
	default: return -1;
	}

	OPS_ADD(H8300_OP_IMM, imm, val);
	if (cmd->cpu_type == CPU_H8300H) {
		cmd->fmt = H8300_INSN_FORMAT_IMMR32;
		OPS_ADD(H8300_OP_R32, reg, r32_low(bytes[1]));
	} else {
		cmd->fmt = H8300_INSN_FORMAT_IMMR16;
		OPS_ADD(H8300_OP_R16, reg, r16_low(bytes[1]));
	}
	return ret;
}

static int decode_xr16(const ut8 *bytes, H8300Instruction *cmd, ut16 x) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_IMMR16;
	OPS_ADD(H8300_OP_IMM, imm, x);
	OPS_ADD(H8300_OP_R16, reg, r16_low(bytes[1]));
	return ret;
}

static int decode_xr32(const ut8 *bytes, H8300Instruction *cmd, ut16 x) {
	int ret = 2;
	unsigned reg = r32_low(bytes[1]);

	cmd->fmt = H8300_INSN_FORMAT_IMMR32;
	OPS_ADD(H8300_OP_IMM, imm, x);
	OPS_ADD(H8300_OP_R32, reg, reg);
	return ret;
}

static int decode_pc_rel(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	st32 disp = rz_bits_sign_ext32(bytes[1], 8);

	cmd->fmt = H8300_INSN_FORMAT_PCREL8;
	OPS_ADD(H8300_OP_PCREL, disp, disp);
	return ret;
}

static int decode_pc_rel16(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	st32 disp = rz_bits_sign_ext32(rz_read_at_be16(bytes, 2), 16);

	cmd->fmt = H8300_INSN_FORMAT_PCREL8;
	OPS_ADD(H8300_OP_PCREL, disp, disp);
	return ret;
}

/* [opcode ] [ 0000 | 0 rd] [      imm    ] */
static int decode_i16r16_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	ut16 imm = rz_read_at_be16(bytes, 2);

	cmd->fmt = H8300_INSN_FORMAT_IMMR16;
	OPS_ADD(H8300_OP_IMM, imm, imm);
	OPS_ADD(H8300_OP_R16, reg, r16_low(bytes[1]));
	return ret;
}

static int decode_i2_2(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_IMM;
	ut8 i2 = (bytes[1] >> 4) & 0x3;
	OPS_ADD(H8300_OP_IMM, imm, i2);
	return ret;
}

static int decode_r16_2(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_R16;
	OPS_ADD(H8300_OP_R16, reg, r16_low(bytes[1]));
	return ret;
}

static int decode_r32_2(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_R32;
	OPS_ADD(H8300_OP_R32, reg, r32_low(bytes[1]));
	return ret;
}

static int decode_r32_4l(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_R32;
	OPS_ADD(H8300_OP_R32, reg, r32_low(bytes[3]));
	return ret;
}

static int decode_rinc_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_RPOSTINC;
	append_rpostinc(cmd, BHIGH(bytes[3]));
	return ret;
}

static int decode_rdec_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_RPREDEC;
	append_rpredec(cmd, BHIGH(bytes[3]));
	return ret;
}

/* [ opcode ] [ 0 r2 | 0 rd ] @rs+,@rd */
static int decode_incdecr16(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;

	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R16RDEC;
		OPS_ADD(H8300_OP_R16, reg, r16_low(bytes[1]));
		append_rpredec(cmd, BHIGH(bytes[1]));
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RINCR16;
		append_rpostinc(cmd, BHIGH(bytes[1]));
		OPS_ADD(H8300_OP_R16, reg, r16_low(bytes[1]));
	}

	return ret;
}

/* [ opcode ] [0 | IMM | rd ] */
static int decode_i3r8(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_IMMR8;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[1] >> 4) & 0x7);
	OPS_ADD(H8300_OP_R8, reg, r8_low(bytes[1]));
	return ret;
}

/* [opcode] [0 | rd | 0000] [opcode] [0|IMM|0000] */
static int decode_i3ri_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_IMMRI;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[3] >> 4) & 0x7);

	append_ri(cmd, (bytes[1] >> 4));
	return ret;
}

/* [opcode] [   abs   ] [opcode] [0|IMM | 0000] */
static int decode_i3abs8_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_IMMABS;
	OPS_ADD(H8300_OP_IMM, imm, (bytes[3] >> 4) & 0x7);
	OPS_ADD(H8300_OP_ABS, imm, read_abs8(bytes, 1));
	return ret;
}

/* [opcode] [ rn  |  rd ] */
static int decode_r8r8_2(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_R8R8;
	OPS_ADD(H8300_OP_R8, reg, r8_high(bytes[1]));
	OPS_ADD(H8300_OP_R8, reg, r8_low(bytes[1]));
	return ret;
}

/* [opcode] [ abs ] [opcode] [ rn | 0000 ] */
static int decode_r8abs8_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_R8ABS;
	OPS_ADD(H8300_OP_R8, reg, r8_high(bytes[3]));
	OPS_ADD(H8300_OP_ABS, imm, read_abs8(bytes, 1));
	return ret;
}

/* [ opcode ] [ 0000 |  rd ] */
static int decode_r8_2(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_R8;
	OPS_ADD(H8300_OP_R8, reg, r8_low(bytes[1]));
	return ret;
}

/* [ opcode ] [ rs | 0 rd] */
static int decode_r8r16(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_R8R16;
	OPS_ADD(H8300_OP_R8, reg, r8_high(bytes[1]));
	OPS_ADD(H8300_OP_R16, reg, r16_low(bytes[1]));
	return ret;
}

/* [opcode] [  abs    ] */
static int decode_mi8(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_MI8;
	OPS_ADD(H8300_OP_MI8, imm, bytes[1]);
	return ret;
}

#define ABS_IMPL(B, BABS) \
	static int decode_abs##BABS##_##B(const ut8 *bytes, H8300Instruction *cmd) { \
		int ret = B; \
		ut32 abs_addr = read_abs(BABS, bytes); \
		cmd->fmt = H8300_INSN_FORMAT_ABS; \
		OPS_ADD(H8300_OP_ABS, imm, abs_addr); \
		return ret; \
	}

ABS_IMPL(4, 16);
ABS_IMPL(6, 16);
ABS_IMPL(8, 24);

#define ABSR_IMPL(B, BABS, BR, OFR) \
	static int decode_abs##BABS##r##BR##_##B(const ut8 *bytes, H8300Instruction *cmd) { \
		int ret = B; \
		ut32 abs = read_abs(BABS, bytes); \
		ut8 r = r##BR##_low(bytes[OFR]); \
		cmd->fmt = H8300_INSN_FORMAT_ABSR##BR; \
		OPS_ADD(H8300_OP_ABS, imm, abs); \
		OPS_ADD(H8300_OP_R##BR, reg, r); \
		return ret; \
	}
#define RABS_IMPL(B, BABS, BR, OFR) \
	static int decode_r##BR##abs##BABS##_##B(const ut8 *bytes, H8300Instruction *cmd) { \
		int ret = B; \
		ut32 abs = read_abs(BABS, bytes); \
		ut8 r = r##BR##_low(bytes[OFR]); \
		cmd->fmt = H8300_INSN_FORMAT_R##BR##ABS; \
		OPS_ADD(H8300_OP_R##BR, reg, r); \
		OPS_ADD(H8300_OP_ABS, imm, abs); \
		return ret; \
	}

ABSR_IMPL(2, 8, 8, 0);
RABS_IMPL(2, 8, 8, 0);

ABSR_IMPL(4, 16, 8, 1);
RABS_IMPL(4, 16, 8, 1);
ABSR_IMPL(4, 16, 16, 1);
RABS_IMPL(4, 16, 16, 1);

ABSR_IMPL(6, 24, 8, 1);
RABS_IMPL(6, 24, 8, 1);
ABSR_IMPL(6, 24, 16, 1);
RABS_IMPL(6, 24, 16, 1);

ABSR_IMPL(6, 16, 32, 3);
RABS_IMPL(6, 16, 32, 3);

ABSR_IMPL(8, 24, 32, 3);
RABS_IMPL(8, 24, 32, 3);

/* [opcode] [0 rn 0000] */
static int decode_ri_2(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	cmd->fmt = H8300_INSN_FORMAT_RI;
	append_ri(cmd, BHIGH(bytes[1]));
	return ret;
}

static int decode_ri_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_RI;
	append_ri(cmd, BHIGH(bytes[3]));
	return ret;
}

#define RIR_IMPL(B, BR, OFRI, OFR) \
	static int decode_rir##BR##_##B(const ut8 *bytes, H8300Instruction *cmd) { \
		int ret = B; \
		if (bytes[OFRI] & 0x80) { \
			cmd->fmt = H8300_INSN_FORMAT_R##BR##RI; \
			OPS_ADD(H8300_OP_R##BR, reg, r##BR##_low(bytes[OFR])); \
			append_ri(cmd, BHIGH(bytes[OFRI])); \
		} else { \
			cmd->fmt = H8300_INSN_FORMAT_RIR##BR; \
			append_ri(cmd, BHIGH(bytes[OFRI])); \
			OPS_ADD(H8300_OP_R##BR, reg, r##BR##_low(bytes[OFR])); \
		} \
		return ret; \
	}

RIR_IMPL(2, 16, 1, 1);
RIR_IMPL(2, 8, 1, 1);
RIR_IMPL(4, 32, 3, 3);

static int decode_r8ri_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_R8RI;
	OPS_ADD(H8300_OP_R8, reg, r8_high(bytes[3]));
	append_ri(cmd, BHIGH(bytes[1]));
	return ret;
}

static int decode_rd3216_6(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 6;
	cmd->fmt = H8300_INSN_FORMAT_RD;
	append_rd(cmd, BHIGH(bytes[3]), read_disp(16, bytes));
	return ret;
}

static int decode_rd3224_10(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 10;
	cmd->fmt = H8300_INSN_FORMAT_RD;
	append_rd(cmd, BHIGH(bytes[3]), read_disp(24, bytes));
	return ret;
}

#define RDR_IMPL(B, Br, Bd, OFRD, OFR) \
	static int decode_rd32##Bd##r##Br##_##B(const ut8 *bytes, H8300Instruction *cmd) { \
		int ret = B; \
		st32 d = read_disp(Bd, bytes); \
		ut8 rrd = BHIGH(bytes[OFRD]); \
		ut8 r = r##Br##_low(bytes[OFR]); \
		if (bytes[OFRD] & 0x80) { \
			cmd->fmt = H8300_INSN_FORMAT_R##Br##RD; \
			OPS_ADD(H8300_OP_R##Br, reg, r); \
			append_rd(cmd, rrd, d); \
		} else { \
			cmd->fmt = H8300_INSN_FORMAT_RDR##Br; \
			append_rd(cmd, rrd, d); \
			OPS_ADD(H8300_OP_R##Br, reg, r); \
		} \
		return ret; \
	}

#define RDR_IMPL1(B, Br, Bd, OFRD, OFR) \
	static int decode_rd32##Bd##r##Br##_##B(const ut8 *bytes, H8300Instruction *cmd) { \
		int ret = B; \
		st32 d = read_disp(Bd, bytes); \
		ut8 rrd = BHIGH(bytes[OFRD]); \
		ut8 r = r##Br##_low(bytes[OFR]); \
		cmd->fmt = H8300_INSN_FORMAT_RDR##Br; \
		append_rd(cmd, rrd, d); \
		OPS_ADD(H8300_OP_R##Br, reg, r); \
		return ret; \
	}
#define RRD_IMPL1(B, Br, Bd, OFRD, OFR) \
	static int decode_r##Br##rd32##Bd##_##B(const ut8 *bytes, H8300Instruction *cmd) { \
		int ret = B; \
		st32 d = read_disp(Bd, bytes); \
		ut8 rrd = BHIGH(bytes[OFRD]); \
		ut8 r = r##Br##_low(bytes[OFR]); \
		cmd->fmt = H8300_INSN_FORMAT_R##Br##RD; \
		OPS_ADD(H8300_OP_R##Br, reg, r); \
		append_rd(cmd, rrd, d); \
		return ret; \
	}

RDR_IMPL(4, 8, 16, 1, 1);
RDR_IMPL(4, 16, 16, 1, 1);

RDR_IMPL(6, 32, 16, 3, 3);

RDR_IMPL1(8, 8, 24, 1, 3);
RRD_IMPL1(8, 8, 24, 1, 3);
RDR_IMPL1(8, 16, 24, 1, 3);
RRD_IMPL1(8, 16, 24, 1, 3);

RDR_IMPL1(10, 32, 24, 3, 5);
RRD_IMPL1(10, 32, 24, 3, 5);

static int decode_nop(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	return ret;
}

static int decode_i8r8(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;

	cmd->fmt = H8300_INSN_FORMAT_IMMR8;
	OPS_ADD(H8300_OP_IMM, imm, bytes[1]);
	OPS_ADD(H8300_OP_R8, reg, r8_low(bytes[0]));
	return ret;
}

static int decode_i32r32_6(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 6;

	ut32 immval = rz_read_at_be32(bytes, 2);
	ut8 regval = r32_low(bytes[1]);

	cmd->fmt = H8300_INSN_FORMAT_IMMR32;
	OPS_ADD(H8300_OP_IMM, imm, immval);
	OPS_ADD(H8300_OP_R32, reg, regval);

	return ret;
}

static int decode_r32r32_2(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;

	ut8 regsval = r32_high(bytes[1]);
	ut8 regdval = r32_low(bytes[1]);

	cmd->fmt = H8300_INSN_FORMAT_R32R32;
	OPS_ADD(H8300_OP_R32, reg, regsval);
	OPS_ADD(H8300_OP_R32, reg, regdval);

	return ret;
}

static int decode_r32r32_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;

	ut8 regsval = r32_high(bytes[3]);
	ut8 regdval = r32_low(bytes[3]);

	cmd->fmt = H8300_INSN_FORMAT_R32R32;
	OPS_ADD(H8300_OP_R32, reg, regsval);
	OPS_ADD(H8300_OP_R32, reg, regdval);

	return ret;
}

static int decode_incdecr8(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 2;
	if (bytes[1] & 0x80) {
		cmd->fmt = H8300_INSN_FORMAT_R8RDEC;
		OPS_ADD(H8300_OP_R8, reg, r8_low(bytes[1]));
		append_rpredec(cmd, BHIGH(bytes[1]));
	} else {
		cmd->fmt = H8300_INSN_FORMAT_RINCR8;
		append_rpostinc(cmd, BHIGH(bytes[1]));
		OPS_ADD(H8300_OP_R8, reg, r8_low(bytes[1]));
	}
	return ret;
}

static int decode_rincr32_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_RINCR32;
	append_rpostinc(cmd, BHIGH(bytes[3]));
	OPS_ADD(H8300_OP_R32, reg, r32_low(bytes[3]));
	return ret;
}

static int decode_r32rdec_4(const ut8 *bytes, H8300Instruction *cmd) {
	int ret = 4;
	cmd->fmt = H8300_INSN_FORMAT_R32RDEC;
	OPS_ADD(H8300_OP_R32, reg, r32_low(bytes[3]));
	append_rpredec(cmd, BHIGH(bytes[3]));
	return ret;
}

#define CASE_F_F_IMPL_BODY(F, I) \
	cmd->id = H8300_INSN_##I; \
	cmd->size = F(instr, cmd);
#define CASE_F_F_IMPL(F, I) \
	cmd->id = H8300_INSN_##I; \
	cmd->size = F(instr, cmd); \
	return cmd->size;

#define CASE_F_F(F, X, I) \
	case (X): \
		CASE_F_F_IMPL(F, I);
#define CASE_F_R8(X, I) CASE_F_F(decode_r8_2, X, I)
#define CASE_F_F_VA(F, X, I, ...) \
	case (X): \
		cmd->id = H8300_INSN_##I; \
		cmd->size = F(instr, cmd, __VA_ARGS__); \
		return cmd->size;
#define CASE_F_F_CCR(F, X, I) \
	case (X): \
		CASE_F_F_IMPL_BODY(F, I) \
		OPS_ADD(H8300_OP_CCR, imm, 0); \
		return cmd->size;
#define CASE_F_CCR_F(F, X, I) \
	case (X): \
		OPS_ADD(H8300_OP_CCR, imm, 0); \
		CASE_F_F_IMPL_BODY(F, I) \
		return cmd->size;
#define CASE_DEFAULT_BREAK \
	default: break;

static int h8300_decode_10(const ut8 *instr, H8300Instruction *cmd) {
	ut64 x7 = rz_read_be64(instr) >> 8;
	if (cmd->cpu_type == CPU_H8300H) {
		switch (x7 & 0xffffff8ffff8ff) {
			CASE_F_F(decode_rd3224r32_10, 0x010078006b2000, MOV_L);
			CASE_F_F(decode_r32rd3224_10, 0x010078806ba000, MOV_L);
			CASE_DEFAULT_BREAK;
		}
	}

	switch (x7 & 0xffffff8fffffff) {
		CASE_F_F_CCR(decode_rd3224_10, 0x014078006b2000, LDC_W);
		CASE_F_CCR_F(decode_rd3224_10, 0x014078006ba000, STC_W);
	default: break;
	}

	return -1;
}
static int h8300_decode_8(const ut8 *instr, H8300Instruction *cmd) {
	ut64 x5 = rz_read_be64(instr) >> 24;
	if (cmd->cpu_type == CPU_H8300H) {
		switch (x5 & 0xfffffff8ff) {
			CASE_F_F(decode_abs24r32_8, 0x01006b2000, MOV_L);
			CASE_F_F(decode_r32abs24_8, 0x01006ba000, MOV_L);
			CASE_DEFAULT_BREAK;
		}
	}

	switch (x5) {
		CASE_F_F_CCR(decode_abs24_8, 0x01406b2000, LDC_W);
		CASE_F_CCR_F(decode_abs24_8, 0x01406ba000, STC_W);
	default: break;
	}
	switch (x5 & 0xff8ffff0ff) {
		CASE_F_F(decode_rd3224r8_8, 0x78006a2000, MOV_B);
		CASE_F_F(decode_r8rd3224_8, 0x78006aa000, MOV_B);
		CASE_F_F(decode_rd3224r16_8, 0x78006b2000, MOV_W);
		CASE_F_F(decode_r16rd3224_8, 0x78006ba000, MOV_W);
	default: break;
	}
	return -1;
}

static int h8300_decode_6(const ut8 *instr, H8300Instruction *cmd) {
	ut32 x2 = rz_read_be16(instr);
	ut32 x4 = rz_read_be32(instr);
	if (cmd->cpu_type == CPU_H8300H) {
		switch (x2 & 0xfff8) {
			CASE_F_F(decode_i32r32_6, 0x7a10, ADD_L);
			CASE_F_F(decode_i32r32_6, 0x7a30, SUB_L);
			CASE_F_F(decode_i32r32_6, 0x7a60, AND_L);
			CASE_F_F(decode_i32r32_6, 0x7a20, CMP_L);
			CASE_F_F(decode_i32r32_6, 0x7a00, MOV_L);
			CASE_F_F(decode_i32r32_6, 0x7a40, OR_L);
			CASE_F_F(decode_i32r32_6, 0x7a50, XOR_L);
			CASE_DEFAULT_BREAK;
		}
		switch (x4 & 0xfffffff8) {
			CASE_F_F(decode_abs16r32_6, 0x01006b00, MOV_L);
			CASE_F_F(decode_r32abs16_6, 0x01006b80, MOV_L);
			CASE_DEFAULT_BREAK;
		}
		switch (x4 & 0xffffff08) {
			CASE_F_F(decode_rd3216r32_6, 0x01006f00, MOV_L);
			CASE_DEFAULT_BREAK;
		}
	}

	switch (x4 & 0xffffff8f) {
		CASE_F_F_CCR(decode_rd3216_6, 0x01406f00, LDC_W);
		CASE_F_CCR_F(decode_rd3216_6, 0x01406f80, STC_W);
	default: break;
	}
	switch (x4 & 0xfff0ff00) {
		CASE_F_F(decode_abs24r8_6, 0x6a200000, MOV_B);
		CASE_F_F(decode_r8abs24_6, 0x6aa00000, MOV_B);
		CASE_F_F(decode_abs24r16_6, 0x6b200000, MOV_W);
		CASE_F_F(decode_r16abs24_6, 0x6ba00000, MOV_W);
	default: break;
	}
	switch (x4) {
		CASE_F_F_CCR(decode_abs16_6, 0x01406b00, LDC_W);
		CASE_F_CCR_F(decode_abs16_6, 0x01406b80, STC_W);
	default: break;
	}
	return -1;
}

static int h8300_decode_4(const ut8 *instr, H8300Instruction *cmd) {
	ut32 x2 = rz_read_be16(instr);
	ut32 x4 = rz_read_be32(instr);

	if (cmd->cpu_type == CPU_H8300H) {
		switch (x4 & 0xfffffff8) {
			CASE_F_F(decode_r32_4l, 0x01006d70, POP_L);
			CASE_F_F(decode_r32_4l, 0x01006df0, PUSH_L);
			CASE_DEFAULT_BREAK;
		}
		switch (x4 & 0xffffff88) {
			CASE_F_F(decode_r32r32_4, 0x01f06600, AND_L);

			CASE_F_F(decode_rir32_4, 0x01006900, MOV_L);
			CASE_F_F(decode_rir32_4, 0x01006980, MOV_L);
			CASE_F_F(decode_rincr32_4, 0x01006d00, MOV_L);
			CASE_F_F(decode_r32rdec_4, 0x01006d80, MOV_L);

			CASE_F_F(decode_r32r32_4, 0x01f06400, OR_L);
			CASE_F_F(decode_r32r32_4, 0x01f06500, XOR_L);
			CASE_DEFAULT_BREAK;
		}
	}

	if (cmd->cpu_type != CPU_H8300L) {
		switch (x2 & 0xfff0) {
			CASE_F_F(decode_abs16r8_4, 0x6a40, MOVFPE);
			CASE_F_F(decode_r8abs16_4, 0x6ac0, MOVTPE);
			CASE_DEFAULT_BREAK;
		}
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

	switch (x2 & 0xff00) {
		CASE_F_F(decode_rd3216r16_4, 0x6f00, MOV_W);
	default:
		break;
	}

	switch (x2 & 0xfff0) {
		CASE_F_F(decode_i16r16_4, 0x7960, AND_W);
		CASE_F_F(decode_i16r16_4, 0x7910, ADD_W);
		CASE_F_F(decode_i16r16_4, 0x7930, SUB_W);
		CASE_F_F(decode_i16r16_4, 0x7920, CMP_W);
		CASE_F_F(decode_i16r16_4, 0x7940, OR_W);
		CASE_F_F(decode_i16r16_4, 0x7950, XOR_W);

		CASE_F_F(decode_abs16r8_4, 0x6a00, MOV_B);
		CASE_F_F(decode_r8abs16_4, 0x6a80, MOV_B);
		CASE_F_F(decode_i16r16_4, 0x7900, MOV_W);
		CASE_F_F(decode_abs16r16_4, 0x6b00, MOV_W);
		CASE_F_F(decode_r16abs16_4, 0x6b80, MOV_W);
	default:
		break;
	}

	switch (x4) {
		CASE_F_F_VA(decode_none, 0x7b5c598f, EEPMOV_B, 4);
		CASE_F_F_VA(decode_none, 0x7bd4598f, EEPMOV_W, 4);
	default:
		break;
	}

	switch (x4 & ~0x00700070) {
		CASE_F_F(decode_i3ri_4, 0x7d007000, BSET);
		CASE_F_F(decode_i3ri_4, 0x7d007200, BCLR);
		CASE_F_F(decode_i3ri_4, 0x7d006700, BST);
		CASE_F_F(decode_i3ri_4, 0x7d006780, BIST);
		CASE_F_F(decode_i3ri_4, 0x7d007100, BNOT);

		CASE_F_F(decode_i3ri_4, 0x7c007600, BAND);
		CASE_F_F(decode_i3ri_4, 0x7c007680, BIAND);
		CASE_F_F(decode_i3ri_4, 0x7c007780, BILD);
		CASE_F_F(decode_i3ri_4, 0x7c007480, BIOR);
		CASE_F_F(decode_i3ri_4, 0x7c007580, BIXOR);
		CASE_F_F(decode_i3ri_4, 0x7c007700, BLD);
		CASE_F_F(decode_i3ri_4, 0x7c007400, BOR);
		CASE_F_F(decode_i3ri_4, 0x7c007300, BTST);
		CASE_F_F(decode_i3ri_4, 0x7c007500, BXOR);
	default:
		break;
	}
	switch (x4 & ~0x00ff0070) {
		CASE_F_F(decode_i3abs8_4, 0x7f007000, BSET);
		CASE_F_F(decode_i3abs8_4, 0x7f007200, BCLR);
		CASE_F_F(decode_i3abs8_4, 0x7f006700, BST);
		CASE_F_F(decode_i3abs8_4, 0x7f006780, BIST);
		CASE_F_F(decode_i3abs8_4, 0x7f007100, BNOT);

		CASE_F_F(decode_i3abs8_4, 0x7e007600, BAND);
		CASE_F_F(decode_i3abs8_4, 0x7e007680, BIAND);
		CASE_F_F(decode_i3abs8_4, 0x7e007780, BILD);
		CASE_F_F(decode_i3abs8_4, 0x7e007480, BIOR);
		CASE_F_F(decode_i3abs8_4, 0x7e007580, BIXOR);
		CASE_F_F(decode_i3abs8_4, 0x7e007700, BLD);
		CASE_F_F(decode_i3abs8_4, 0x7e007400, BOR);
		CASE_F_F(decode_i3abs8_4, 0x7e007300, BTST);
		CASE_F_F(decode_i3abs8_4, 0x7e007500, BXOR);
	default:
		break;
	}
	switch (x4 & ~0x007000f0) {
		CASE_F_F(decode_r8ri_4, 0x7d006000, BSET);
		CASE_F_F(decode_r8ri_4, 0x7d006200, BCLR);
		CASE_F_F(decode_r8ri_4, 0x7d006100, BNOT);

		CASE_F_F(decode_r8ri_4, 0x7c006300, BTST);
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
	switch (x4 & 0xffffff8f) {
		CASE_F_F_CCR(decode_ri_4, 0x01406900, LDC_W);
		CASE_F_F_CCR(decode_rinc_4, 0x01406d00, LDC_W);

		CASE_F_CCR_F(decode_ri_4, 0x01406980, STC_W);
		CASE_F_CCR_F(decode_rdec_4, 0x01406d80, STC_W);
	default:
		break;
	}
	switch (x4 & 0xffffff00) {
		CASE_F_F(decode_r8r16_4, 0x01d05100, DIVXS_B);
		CASE_F_F(decode_r8r16_4, 0x01c05000, MULXS_B);
	default:
		break;
	}
	switch (x4 & 0xffffff08) {
		CASE_F_F(decode_r16r32_4, 0x01d05300, DIVXS_W);
		CASE_F_F(decode_r16r32_4, 0x01c05200, MULXS_W);
	default:
		break;
	}
	return -1;
}

static int h8300_decode_2(const ut8 *instr, H8300Instruction *cmd) {
	ut32 x2 = rz_read_be16(instr);

	if (cmd->cpu_type == CPU_H8300H) {
		switch (x2 & 0xff88) {
			CASE_F_F(decode_r32r32_2, 0x0a80, ADD_L);
			CASE_F_F(decode_r32r32_2, 0x1a80, SUB_L);
			CASE_F_F(decode_r32r32_2, 0x1f80, CMP_L);
			CASE_F_F(decode_r32r32_2, 0x0f80, MOV_L);
			CASE_DEFAULT_BREAK;
		}
		switch (x2 & 0xfff0) {
			CASE_F_F(decode_r32_2, 0x17b0, NEG_L);
			CASE_F_F(decode_r32_2, 0x1730, NOT_L);

			CASE_F_F(decode_r32_2, 0x12b0, ROTL_L);
			CASE_F_F(decode_r32_2, 0x13b0, ROTR_L);
			CASE_F_F(decode_r32_2, 0x1230, ROTXL_L);
			CASE_F_F(decode_r32_2, 0x1330, ROTXR_L);
			CASE_F_F(decode_r32_2, 0x10b0, SHAL_L);
			CASE_F_F(decode_r32_2, 0x1030, SHLL_L);
			CASE_F_F(decode_r32_2, 0x11b0, SHAR_L);
			CASE_F_F(decode_r32_2, 0x1130, SHLR_L);

			CASE_F_F(decode_r32_2, 0x17f0, EXTS_L);
			CASE_F_F(decode_r32_2, 0x1770, EXTU_L);
			CASE_DEFAULT_BREAK;
		}
		switch (x2 & 0xfff8) {
			CASE_F_F_VA(decode_xr32, 0x1b70, DEC_L, 1);
			CASE_F_F_VA(decode_xr32, 0x1bf0, DEC_L, 2);
			CASE_F_F_VA(decode_xr32, 0x0b70, INC_L, 1);
			CASE_F_F_VA(decode_xr32, 0x0bf0, INC_L, 2);
			CASE_DEFAULT_BREAK;
		}
	}

	switch (x2 & 0xffcf) {
		CASE_F_F(decode_i2_2, 0x5700, TRAPA);
	default: break;
	}

	switch (instr[0] >> 4) {
		CASE_F_F(decode_abs8r8_2, 0x2, MOV_B);
		CASE_F_F(decode_r8abs8_2, 0x3, MOV_B);

		CASE_F_F(decode_i8r8, 0xf, MOV_B);
		CASE_F_F(decode_i8r8, 0xe, AND_B);
		CASE_F_F(decode_i8r8, 0x9, ADDX);
		CASE_F_F(decode_i8r8, 0x8, ADD_B);
		CASE_F_F(decode_i8r8, 0xa, CMP_B);
		CASE_F_F(decode_i8r8, 0xc, OR_B);
		CASE_F_F(decode_i8r8, 0xb, SUBX);
		CASE_F_F(decode_i8r8, 0xd, XOR_B);
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
		CASE_F_R8(0x1780, NEG_B);
		CASE_F_F(decode_r16_2, 0x1790, NEG_W);
		CASE_F_R8(0x1700, NOT_B);
		CASE_F_F(decode_r16_2, 0x1710, NOT_W);

		CASE_F_R8(0x1280, ROTL_B);
		CASE_F_R8(0x1380, ROTR_B);
		CASE_F_R8(0x1200, ROTXL_B);
		CASE_F_R8(0x1300, ROTXR_B);
		CASE_F_R8(0x1080, SHAL_B);
		CASE_F_R8(0x1000, SHLL_B);
		CASE_F_R8(0x1180, SHAR_B);
		CASE_F_R8(0x1100, SHLR_B);

		CASE_F_F(decode_r16_2, 0x1290, ROTL_W);
		CASE_F_F(decode_r16_2, 0x1390, ROTR_W);
		CASE_F_F(decode_r16_2, 0x1210, ROTXL_W);
		CASE_F_F(decode_r16_2, 0x1310, ROTXR_W);
		CASE_F_F(decode_r16_2, 0x1090, SHAL_W);
		CASE_F_F(decode_r16_2, 0x1010, SHLL_W);
		CASE_F_F(decode_r16_2, 0x1190, SHAR_W);
		CASE_F_F(decode_r16_2, 0x1110, SHLR_W);

		CASE_F_F(decode_r16_2, 0x17d0, EXTS_W);
		CASE_F_F(decode_r16_2, 0x1750, EXTU_W);

		CASE_F_F_VA(decode_xr16, 0x1b50, DEC_W, 1);
		CASE_F_F_VA(decode_xr16, 0x1bd0, DEC_W, 2);
		CASE_F_F_VA(decode_xr16, 0x0b50, INC_W, 1);
		CASE_F_F_VA(decode_xr16, 0x0bd0, INC_W, 2);
	default:
		break;
	}

	switch (x2 & 0xfff8) {
		CASE_F_F(decode_r16_2, 0x6d70, POP_W);
		CASE_F_F(decode_r16_2, 0x6df0, PUSH_W);

		CASE_F_F(decode_i16r16_4, 0x7900, MOV_W);
		CASE_F_F(decode_abs16r8_4, 0x6b00, MOV_W);

	case 0x0b00:
	case 0x0b80:
	case 0x0b90:
		CASE_F_F_IMPL(decode_sr16_32, ADDS);

	case 0x1b00:
	case 0x1b80:
	case 0x1b90:
		CASE_F_F_IMPL(decode_sr16_32, SUBS);

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
		CASE_F_F(decode_r8r8_2, 0x08, ADD_B);
		CASE_F_F(decode_r16r16_2, 0x09, ADD_W);
		CASE_F_F(decode_r16r32_2, 0x52, MULXU_W);

		CASE_F_F(decode_r8r8_2, 0x18, SUB_B);
		CASE_F_F(decode_r16r16_2, 0x19, SUB_W);

		CASE_F_F(decode_r8r8_2, 0x14, OR_B);
		CASE_F_F(decode_r16r16_2, 0x64, OR_W);

		CASE_F_F(decode_r8r8_2, 0x1e, SUBX);

		CASE_F_F(decode_r8r8_2, 0x15, XOR_B);
		CASE_F_F(decode_r16r16_2, 0x65, XOR_W);

	case H8300_ANDC:
		cmd->id = H8300_INSN_ANDC;
		ret = decode_i8ccr(instr, cmd);
		break;
	case 0x1d:
		cmd->id = H8300_INSN_CMP_W;
		ret = decode_r16r16_2(instr, cmd);
		break;

		CASE_F_F(decode_r8r8_2, 0x16, AND_B);
		CASE_F_F(decode_r16r16_2, 0x66, AND_W);
	case 0x62:
		cmd->id = H8300_INSN_BCLR;
		ret = decode_r8r8_2(instr, cmd);
		break;
	case 0x0e:
		cmd->id = H8300_INSN_ADDX;
		ret = decode_r8r8_2(instr, cmd);
		break;
	case H8300_BNOT_1:
		cmd->id = H8300_INSN_BNOT;
		ret = decode_r8r8_2(instr, cmd);
		break;
	case 0x60:
		cmd->id = H8300_INSN_BSET;
		ret = decode_r8r8_2(instr, cmd);
		break;
	case 0x1c:
		cmd->id = H8300_INSN_CMP_B;
		ret = decode_r8r8_2(instr, cmd);
		break;
	case 0x0c:
		cmd->id = H8300_INSN_MOV_B;
		ret = decode_r8r8_2(instr, cmd);
		break;
	case H8300_BTST_R2R8:
		cmd->id = H8300_INSN_BTST;
		ret = decode_r8r8_2(instr, cmd);
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

	case H8300_MULXU_B:
		cmd->id = H8300_INSN_MULXU_B;
		ret = decode_r8r16(instr, cmd);
		break;
	case 0x59:
		cmd->id = H8300_INSN_JMP;
		ret = decode_ri_2(instr, cmd);
		break;
	case 0x5a:
		cmd->id = H8300_INSN_JMP;
		ret = decode_abs16_4(instr, cmd);
		break;
	case 0x5b:
		cmd->id = H8300_INSN_JMP;
		ret = decode_mi8(instr, cmd);
		break;
	case 0x5d:
		cmd->id = H8300_INSN_JSR;
		ret = decode_ri_2(instr, cmd);
		break;
	case 0x5e:
		cmd->id = H8300_INSN_JSR;
		ret = decode_abs16_4(instr, cmd);
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
	case H8300_STC_B:
		cmd->id = H8300_INSN_STC_B;
		ret = decode_ccrr8(instr, cmd);
		break;
	case H8300_XORC:
		cmd->id = H8300_INSN_XORC;
		ret = decode_i8ccr(instr, cmd);
		break;
	case 0x0d:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_r16r16_2(instr, cmd);
		break;
	case 0x68:
		cmd->id = H8300_INSN_MOV_B;
		ret = decode_rir8_2(instr, cmd);
		break;
	case 0x69:
		cmd->id = H8300_INSN_MOV_W;
		ret = decode_rir16_2(instr, cmd);
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
		ret = decode_rd3216r8_4(instr, cmd);
		break;

	default: break;
	}
	return ret;
}

H8300CpuType h8300_cpu_type(const char *cpu) {
	if (RZ_STR_EQ(cpu, "h8300") || RZ_STR_EQ(cpu, "H8300")) {
		return CPU_H8300;
	}
	if (RZ_STR_EQ(cpu, "h8300l") || RZ_STR_EQ(cpu, "H8300L")) {
		return CPU_H8300L;
	}
	if (RZ_STR_EQ(cpu, "h8300h") || RZ_STR_EQ(cpu, "H8300H")) {
		return CPU_H8300H;
	}
	return CPU_H8300;
}

int h8300_decode_command(const ut8 *instr, ut64 len, H8300Instruction *cmd, ut64 pc, const char *cpu) {
	cmd->pc = pc;
	int ret = 0;
#define FAST_PATH(N) \
	if (len >= N) { \
		ret = h8300_decode_##N(instr, cmd); \
		if (ret > 0) { \
			goto beach; \
		} \
	}

	cmd->cpu_type = h8300_cpu_type(cpu);

	FAST_PATH(10);
	FAST_PATH(8);
	FAST_PATH(6);
	FAST_PATH(4);
	FAST_PATH(2);

beach:
	cmd->size = ret;
	return ret;
}

bool h8300_make_opstr(H8300Instruction *cmd, H8300InstructionStr *ins_str) {
	if (cmd->id != H8300_INSN_INVALID) {
		if (decode_opcode(cmd, ins_str) == -1) {
			return false;
		}
		decode_operands(cmd, ins_str);
	}
	return true;
}
