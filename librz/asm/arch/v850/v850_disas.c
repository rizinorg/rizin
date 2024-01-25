// SPDX-FileCopyrightText: 2014-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>

#include "v850_disas.h"

#define R1 GR_get(get_reg1(inst))
#define R2 GR_get(get_reg2(inst))
#define R3 GR_get(get_reg3(inst))

static const char *instrs[] = {
	[V850_MOV] = "mov",
	[V850_NOT] = "not",
	[V850_DIVH] = "divh",
	[V850_JMP] = "jmp",
	[V850_SATSUBR] = "satsubr",
	[V850_SATSUB] = "stasub",
	[V850_SATADD] = "satadd",
	[V850_MULH] = "mulh",
	[V850_OR] = "or",
	[V850_XOR] = "xor",
	[V850_AND] = "and",
	[V850_TST] = "tst",
	[V850_SUBR] = "subr",
	[V850_SUB] = "sub",
	[V850_ADD] = "add",
	[V850_CMP] = "cmp",
	[V850_MOV_IMM5] = "mov",
	[V850_SATADD_IMM5] = "satadd",
	[V850_ADD_IMM5] = "add",
	[V850_CMP_IMM5] = "cmp",
	[V850_SHR_IMM5] = "shr",
	[V850_SAR_IMM5] = "sar",
	[V850_SHL_IMM5] = "shl",
	[V850_MULH_IMM5] = "mulh",
	[V850_SLDB] = "sldb",
	[V850_SSTB] = "sstb",
	[V850_SLDH] = "sldh",
	[V850_SSTH] = "ssth",
	[V850_SLDW] = "sldw",
	[V850_SSTW] = "sstw",
	[V850_BCOND] = "bcond",
	[V850_ADDI] = "addi",
	[V850_MOVEA] = "movea",
	[V850_MOVHI] = "movhi",
	[V850_SATSUBI] = "satsubi",
	[V850_ORI] = "ori",
	[V850_XORI] = "xori",
	[V850_ANDI] = "andi",
	[V850_MULHI] = "mulhi",
	[V850_LDB] = "ld.b",
	[V850_LDH] = "ld.h",
	[V850_LDW] = "ld.w",
	[V850_STB] = "st.b",
	[V850_STH] = "st.h",
	[V850_STW] = "st.w",

	[V850_LDBU] = "ld.bu",
	[V850_LDHU] = "ld.hu",
	[V850_LDDW] = "ld.dw",
	[V850_SLDBU] = "sld.bu",
	[V850_SLDHU] = "sld.hu",
	[V850_STDW] = "st.dw",
	[V850_MULU] = "mulu",
	[V850_MAC] = "mac",
	[V850_MACU] = "macu",
	[V850_ADF] = "adf",
	[V850_SBF] = "sbf",
	[V850_BINS] = "bins",
	[V850_BSH] = "bsh",
	[V850_BSW] = "bsw",
	[V850_CMOV] = "cmov",
	[V850_HSH] = "hsh",
	[V850_HSW] = "hsw",
	[V850_ROTL] = "rotl",
	[V850_SAR] = "sar",
	[V850_SASF] = "sasf",
	[V850_SETF] = "setf",
	[V850_SHL] = "shl",
	[V850_SHR] = "shr",
	[V850_SXB] = "sxb",
	[V850_SXH] = "sxh",
	[V850_ZXB] = "zxb",
	[V850_ZXH] = "zxh",
	[V850_SCH0L] = "sch0l",
	[V850_SCH0R] = "sch0r",
	[V850_SCH1L] = "sch1l",
	[V850_SCH1R] = "sch1r",
	[V850_DIVHU] = "divhu",
	[V850_DIVU] = "divu",
	[V850_DIVQ] = "divq",
	[V850_DIVQU] = "divqu",
	[V850_DIV] = "div",
	[V850_MUL] = "mul",

	[V850_LOOP] = "loop",
	[V850_SET1] = "set1",
	[V850_NOT1] = "not1",
	[V850_CLR1] = "clr1",
	[V850_TST1] = "tst1",
	[V850_JARL] = "jarl",
	[V850_JR] = "jr",
	[V850_CALLT] = "callt",
	[V850_CAXI] = "caxi",
	[V850_CLL] = "cll",
	[V850_CTRET] = "ctret",
	[V850_DI] = "di",
	[V850_DISPOSE] = "dispose",
	[V850_EI] = "ei",
	[V850_EIRET] = "eiret",
	[V850_FERET] = "feret",
	[V850_FETRAP] = "fetrap",
	[V850_HALT] = "halt",
	[V850_LDSR] = "ldsr",
	[V850_LDLW] = "ldlw",
	[V850_NOP] = "nop",
	[V850_POPSP] = "popsp",
	[V850_PREPARE] = "prepare",
	[V850_PUSHSP] = "pushsp",
	[V850_RIE] = "rie",
	[V850_SNOOZE] = "snooze",
	[V850_STSR] = "stsr",
	[V850_STCW] = "stcw",
	[V850_SWITCH] = "switch",
	[V850_SYNCE] = "synce",
	[V850_SYNCI] = "synci",
	[V850_SYNCM] = "syncm",
	[V850_SYNCP] = "syncp",
	[V850_SYSCALL] = "syscall",
	[V850_TRAP] = "trap",

	[V850_CACHE] = "cache",
	[V850_PREF] = "pref",
};

static const char *conds[] = {
	[V850_COND_BV] = "bv",
	[V850_COND_BL] = "bl",
	[V850_COND_BE] = "be",
	[V850_COND_BNH] = "bnh",
	[V850_COND_BN] = "bn",
	[V850_COND_BR] = "br",
	[V850_COND_BLT] = "blt",
	[V850_COND_BLE] = "ble",
	[V850_COND_BNV] = "bnv",
	[V850_COND_BNL] = "bnl",
	[V850_COND_BNE] = "bne",
	[V850_COND_BH] = "bh",
	[V850_COND_BP] = "bp",
	[V850_COND_BSA] = "bsa",
	[V850_COND_BGE] = "bge",
	[V850_COND_BGT] = "bgt",
};

#define INSTR(...)    snprintf(inst->instr, V850_INSTR_MAXLEN - 1, __VA_ARGS__);
#define PRINT_INSTR   INSTR("%s", instrs[inst->id])
#define OPERANDS(...) snprintf(inst->operands, V850_INSTR_MAXLEN - 1, __VA_ARGS__);

static bool decode_formatI(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 5, 10);
	inst->reg2 = get_reg2(inst);
	inst->reg1 = get_reg1(inst);
	if (inst->w1 == 0) {
		inst->id = V850_NOP;
		PRINT_INSTR;
		return true;
	} else {
		switch (inst->opcode) {
		case V850_ADD:
		case V850_AND:
		case V850_CMP:
		case V850_DIVH:
		case V850_FETRAP:
		case V850_JMP:
		case V850_MOV:
		case V850_MULH:
		case V850_NOP:
		case V850_NOT:
		case V850_OR:
		case V850_RIE:
		case V850_SATADD:
		case V850_SATSUB:
		case V850_SATSUBR:
		case V850_SUB:
		case V850_SUBR:
		case V850_SWITCH:
		case V850_SXB:
		case V850_SXH:
		case V850_SYNCE:
		case V850_SYNCI:
		case V850_SYNCM:
		case V850_SYNCP:
		case V850_TST:
		case V850_XOR:
		case V850_ZXB:
		case V850_ZXH: inst->id = inst->opcode; break;
		default: return false;
		}
	}

	PRINT_INSTR;
	switch (inst->id) {
	case V850_JMP:
		OPERANDS("[%s]", R1);
		break;
	default: {
		OPERANDS("%s, %s", R1, R2);
		break;
	}
	}
	return true;
}

static bool decode_formatII(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 5, 10);
	inst->reg2 = get_reg2(inst);
	st32 imm = get_reg1(inst);
	switch (inst->opcode) {
	case V850_ADD_IMM5:
	case V850_CMP_IMM5:
	case V850_MOV_IMM5:
	case V850_MULH_IMM5:
	case V850_SATADD_IMM5:
		inst->imm = sext32(imm, 5);
		inst->id = inst->opcode;
		break;
	case V850_SAR_IMM5:
	case V850_SHL_IMM5:
	case V850_SHR_IMM5:
		inst->id = inst->opcode;
		inst->imm = imm;
		break;
	default:
		// CALLT
		if ((inst->w1 >> 6) == 0x8) {
			inst->id = V850_CALLT;
			inst->imm = inst->w1 & 0x3f;
			break;
		}
		return false;
	}

	PRINT_INSTR;
	OPERANDS("%d, %s", inst->imm, R2);
	return true;
}

static bool decode_formatIII(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 7, 10);
	inst->disp = sext32(get_disp9(inst), 9);
	inst->cond = get_cond(inst);
	switch (inst->opcode) {
	case 0xb: inst->id = V850_BCOND; break;
	default: return false;
	}

	const char *cond_s = conds[inst->cond];
	if (!cond_s) {
		return false;
	}

	INSTR("%s", cond_s);
	OPERANDS("0x%06llx", (st64)(inst->addr + inst->disp));
	return true;
}

static bool decode_formatIV_1(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 7, 10);
	inst->disp = inst->w2 & 0x7f;
	inst->reg2 = get_reg2(inst);
	switch (inst->opcode) {
	case 0x6: inst->id = V850_SLDB; break;
	case 0x8:
		inst->id = V850_SLDH;
		inst->disp <<= 1;
		break;
	case 0x7: inst->id = V850_SSTB; break;
	case 0x9:
		inst->id = V850_SSTH;
		inst->disp <<= 1;
		break;
	default:
		if (inst->opcode != 0xa) {
			return false;
		}
		if (inst->w1 & 1) {
			inst->id = V850_SSTW;
		} else {
			inst->id = V850_SLDW;
		}
		inst->disp = (inst->disp & ~1) << 1;
		break;
	}

	PRINT_INSTR;
	OPERANDS("%d[ep] %s", inst->disp, R2);
	return true;
}

static bool decode_formatIV_2(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 4, 10);
	inst->disp = inst->w2 & 0xf;
	inst->reg2 = get_reg2(inst);
	switch (inst->opcode) {
	case 0x6: inst->id = V850_SLDBU; break;
	case 0x7:
		inst->id = V850_SLDHU;
		inst->disp <<= 1;
		break;
	default: return false;
	}

	PRINT_INSTR;
	OPERANDS("%d[ep] %s", inst->disp, R2);
	return true;
}

static bool decode_formatV(V850_Inst *inst) {
	if (inst->w2 & 1) {
		return false;
	}
	inst->opcode = get_opcode(inst, 6, 10);
	inst->reg2 = get_reg2(inst);
	inst->disp = get_disp22(inst);
	switch (inst->opcode) {
	case 0x1e:
		if (inst->reg2 == 0) {
			inst->id = V850_JR;
		} else {
			inst->id = V850_JARL;
		}
		inst->disp = sext32(inst->disp, 22);
		break;
	default: return false;
	}

	PRINT_INSTR;
	OPERANDS("0x%06llx, %s", inst->addr + inst->disp, R2);
	return true;
}

static bool decode_formatVI(V850_Inst *inst, RzBuffer *b) {
	inst->opcode = get_opcode(inst, 5, 10);
	inst->reg1 = get_reg1(inst);
	inst->reg2 = get_reg2(inst);
	inst->imm = get_imm16(inst);
	if (inst->reg2 == 0) {
		switch (inst->opcode) {
		case 0x17:
			if (inst->reg1) {
				inst->id = V850_JARL;
			} else {
				inst->id = V850_JR;
			}
			break;
		case 0x37: inst->id = V850_JMP; break;
		case 0x31: inst->id = V850_MOV; break;
		default:
			return false;
		}
		ut16 imm_ = 0;
		if (!rz_buf_read_le16_at(b, 4, &imm_)) {
			return false;
		}
		inst->imm |= (st32)(imm_) << 16;
		inst->byte_size = 6;
	} else {
		switch (inst->opcode) {
		case V850_ADDI:
		case V850_MOVEA:
		case V850_SATSUBI:
			inst->id = inst->opcode;
			inst->imm = sext32(inst->imm, 16);
			break;
		case V850_ANDI:
		case V850_MULHI:
		case V850_MOVHI:
		case V850_ORI:
		case V850_XORI:
			inst->id = inst->opcode;
			break;
		default: return false;
		}
	}

	PRINT_INSTR;
	switch (inst->id) {
	case V850_MOV:
		OPERANDS("0x%x, %s", inst->imm, R1);
		break;
	case V850_ANDI:
	case V850_ADDI:
	case V850_MOVHI:
	case V850_MULHI:
	case V850_ORI:
	case V850_SATSUBI:
	case V850_XORI:
		OPERANDS("%d, %s, %s", inst->imm, R1, R2);
		break;
	default:
		OPERANDS("0x%x, %s, %s", inst->imm, R1, R2);
		break;
	}
	return true;
}

static bool decode_formatVII(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 5, 10);
	inst->sub_opcode = inst->w2 & 1;
	inst->reg1 = get_reg1(inst);
	inst->reg2 = get_reg2(inst);
	inst->disp = get_imm16(inst);
	switch (inst->opcode) {
	case 0x38: inst->id = V850_LDB; break;
	case 0x3a: inst->id = V850_STB; break;
	case 0x3b:
		if (!(inst->sub_opcode)) {
			inst->id = V850_STH;
		} else {
			inst->id = V850_STW;
		}
		inst->disp &= ~1;
		break;
	case 0x3d: /// GUESS!
		if (inst->sub_opcode && inst->reg2) {
			inst->id = V850_LDBU;
			break;
		}
		return false;
	case 0x3e: {
		if (inst->sub_opcode) {
			inst->id = V850_LDBU;
			break;
		}
		return false;
	}
	case 0x39: {
		if (!(inst->sub_opcode)) {
			inst->id = V850_LDH;
		} else {
			inst->id = V850_LDW;
		}
		inst->disp &= ~1;
		break;
	}
	case 0x37:
		if (inst->reg2 == 0 && inst->sub_opcode) {
			inst->id = V850_LOOP;
			inst->disp &= ~1;
			break;
		}
		return false;
	case 0x3f: {
		if (inst->reg2 == 0 && inst->sub_opcode) {
			inst->id = V850_BCOND;
			inst->cond = get_cond(inst);
			inst->disp = sext32(((inst->disp >> 1) | (((inst->w1 >> 4) & 1) << 15)) << 1, 17);
			INSTR("%s", conds[inst->cond]);
			OPERANDS("0x%06llx", inst->addr + inst->disp);
			return true;
		}
		if (inst->sub_opcode) {
			inst->id = V850_LDHU;
			break;
		}

		inst->reg3 = get_reg3(inst);
		if (inst->reg2 == 0 && extract(inst->w2, 0, 11) == 0x378) {
			inst->id = V850_LDLW;
			break;
		}
		if (inst->reg2 == 0 && extract(inst->w2, 0, 11) == 0x37a) {
			inst->id = V850_STCW;
			break;
		}
		if (extract(inst->w2, 0, 11) == 0xc4) {
			inst->id = V850_ROTL;
			break;
		}
		return false;
	}
	default: return false;
	}

	PRINT_INSTR;
	switch (inst->id) {
	case V850_LDB:
	case V850_LDBU:
	case V850_LDH:
	case V850_LDHU:
	case V850_LDW:
		inst->disp = sext32(inst->disp, 16);
		OPERANDS("%d[%s], %s", inst->disp, R1, R2);
		break;
	case V850_STB:
	case V850_STH:
	case V850_STW:
		OPERANDS("%s, %d[%s]", R2, inst->disp, R1);
		break;
	case V850_BCOND:
		break;
	case V850_LDLW:
		OPERANDS("[%s], %s", R1, GR_get(inst->reg3));
		break;
	case V850_STCW:
		OPERANDS("%s, [%s]", GR_get(inst->reg3), R2);
		break;
	case V850_LOOP:
		OPERANDS("%s, %d", R1, inst->disp);
		break;
	case V850_ROTL:
		OPERANDS("%d, %s, %s", inst->disp, R2, GR_get(inst->reg3));
		break;
	default: break;
	}

	return true;
}

static bool decode_formatVIII(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 5, 10);
	inst->sub_opcode = inst->w1 >> 14;
	switch (inst->opcode | (inst->sub_opcode << 6)) {
	case 0x38 | (0x2 << 6): inst->id = V850_CLR1; break;
	case 0x3e | (0x1 << 6): inst->id = V850_NOT1; break;
	case 0x3e | (0x0 << 6): inst->id = V850_SET1; break;
	case 0x3e | (0x3 << 6): inst->id = V850_TST1; break;
	default: return false;
	}

	inst->reg1 = get_reg1(inst);
	inst->bit = (inst->w1 >> 11) & 0x7;
	inst->disp = get_imm16(inst);
	PRINT_INSTR;
	OPERANDS("%d, %d[%s]", inst->bit, inst->disp, R1);
	return true;
}

static bool decode_formatIX(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 5, 10);
	if (inst->w2 & 1) {
		return false;
	}

	inst->reg1 = get_reg1(inst);
	inst->reg2 = get_reg2(inst);
	inst->sub_opcode = get_imm16(inst) & ~1;
	ut8 selID = -1;

	if (inst->opcode == 0x3f) {
		switch (inst->w2) {
		case 0b0000000011100100: inst->id = V850_CLR1; break;
		case 0b0000000011100010: inst->id = V850_NOT1; break;
		case 0b0000000011100110: inst->id = V850_TST1; break;
		case 0b0000000011100000: inst->id = V850_SET1; break;
		case 0b0000000010100000: inst->id = V850_SAR; break;
		case 0b0000000011000000: inst->id = V850_SHL; break;
		case 0b0000000010000000: inst->id = V850_SHR; break;
		default:
			if (extract(inst->sub_opcode, 0, 11) == 0x020) {
				inst->id = V850_LDSR;
			} else if (extract(inst->sub_opcode, 0, 11) == 0x040) {
				inst->id = V850_STSR;
			} else if (extract(inst->sub_opcode, 0, 11) == 0x364 && inst->reg1 == 0) {
				inst->id = V850_SCH0L;
			} else if (extract(inst->sub_opcode, 0, 11) == 0x360 && inst->reg1 == 0) {
				inst->id = V850_SCH0R;
			} else if (extract(inst->sub_opcode, 0, 11) == 0x366 && inst->reg1 == 0) {
				inst->id = V850_SCH1L;
			} else if (extract(inst->sub_opcode, 0, 11) == 0x362 && inst->reg1 == 0) {
				inst->id = V850_SCH1R;
			} else if (extract(inst->sub_opcode, 4, 7) == 0x09 ||
				extract(inst->sub_opcode, 4, 7) == 0x0b ||
				extract(inst->sub_opcode, 4, 7) == 0x0d) {
				inst->id = V850_BINS;
			} else {
				return false;
			}
			selID = inst->sub_opcode >> 11;
			break;
		}
	} else if (inst->opcode == 0x3e) {
		switch (inst->w2) {
		case 0b0000001000000000: inst->id = V850_SASF; break;
		case 0b0000000000000000: inst->id = V850_SETF; break;
		default: return false;
		}
	} else {
		return false;
	}

	PRINT_INSTR;
	switch (inst->id) {
	case V850_STSR:
		OPERANDS("%s, %s, %d", SR_get(inst->reg1, selID), R2, get_reg3(inst));
		break;
	case V850_LDSR:
		OPERANDS("%s, %s, %d", R1, SR_get(inst->reg2, selID), get_reg3(inst));
		break;
	case V850_SHL: OPERANDS("%s, %s", R1, R2); break;
	default: break;
	}
	return true;
}

static bool decode_formatX(V850_Inst *inst) {
	if (inst->w2 & 1) {
		return false;
	}

	inst->opcode = get_opcode(inst, 5, 10);
	inst->sub_opcode = (get_imm16(inst) & ~1) | (get_reg2(inst) << 21) | (get_reg1(inst) << 16);

	ut32 dword = inst->w1 | (inst->w2 << 16);
	if (dword == 0xf160ffff) {
		inst->id = V850_CLL;
	} else if (dword == 0b00000001010001000000011111100000) {
		inst->id = V850_CTRET;
	} else if (dword == 0b00000001011000000000011111100000) {
		inst->id = V850_DI;
	} else if (dword == 0b00000001011000001000011111100000) {
		inst->id = V850_EI;
	} else if (dword == 0b00000001010010000000011111100000) {
		inst->id = V850_EIRET;
	} else if (dword == 0b00000001010010100000011111100000) {
		inst->id = V850_FERET;
	} else if (dword == 0b00000001001000000000011111100000) {
		inst->id = V850_HALT;
	} else if (dword == 0b00000001001000000000111111100000) {
		inst->id = V850_SNOOZE;
	} else if (inst->w2 == 0 && extract(inst->w1, 4, 7) == 0x7f) {
		inst->id = V850_RIE;
		INSTR("%s", instrs[inst->id]);
		OPERANDS("%d %d", extract(inst->w1, 0, 4), extract(inst->w1, 11, 5));
		return true;
	} else if ((inst->w2 & 0xc7ff) == 0x0160 && (inst->w1 >> 5) == 0b11010111111) {
		inst->id = V850_SYSCALL;
		INSTR("%s", instrs[inst->id]);
		OPERANDS("0x%02x", (inst->w1 & 0x1f) | (extract(inst->w2, 11, 3) << 5));
		return true;
	} else if (inst->w2 == 0b0000000100000000 && (inst->w1 >> 5) == 0b00000111111) {
		inst->id = V850_TRAP;
		INSTR("%s", instrs[inst->id]);
		OPERANDS("%d", inst->w1 & 0x1f);
		return true;
	} else if (extract(inst->w2, 0, 11) == 0b00101100000 && (extract(inst->w1, 5, 6) | extract(inst->w1, 13, 3) << 6) == 0x1ff) {
		inst->id = V850_CACHE;
		inst->reg1 = get_reg1(inst);
		ut16 cacheop = extract(inst->w2, 11, 5) | extract(inst->w1, 11, 2);

		INSTR("%s", instrs[inst->id]);
		OPERANDS("0x%02x [%s]", cacheop, GR_get(inst->reg1));
		return true;
	} else if (extract(inst->w2, 0, 11) == 0b00101100000 && extract(inst->w1, 5, 11) == 0b11011111111) {
		inst->id = V850_PREF;
		inst->reg1 = get_reg1(inst);
		ut16 prefop = extract(inst->w2, 11, 5);

		INSTR("%s", instrs[inst->id]);
		OPERANDS("0x%02x [%s]", prefop, GR_get(inst->reg1));
		return true;
	} else {
		return false;
	}

	PRINT_INSTR;
	return true;
}

static bool decode_formatXI(V850_Inst *inst) {
	if (inst->w2 & 1) {
		return false;
	}

	inst->opcode = get_opcode(inst, 5, 10);
	inst->reg1 = get_reg1(inst);
	inst->reg2 = get_reg2(inst);
	inst->reg3 = get_reg3(inst);
	inst->sub_opcode = extract(inst->w2, 1, 10);

	if (inst->opcode != 0x3f) {
		return false;
	}
	switch (inst->sub_opcode) {
	case 0b0001110111: inst->id = V850_CAXI; break;
	case 0b0101100000: inst->id = V850_DIV; break;
	case 0b0101000000: inst->id = V850_DIVH; break;
	case 0b0101000001: inst->id = V850_DIVHU; break;
	case 0b0101111110: inst->id = V850_DIVQ; break;
	case 0b0101111111: inst->id = V850_DIVQU; break;
	case 0b0101100001: inst->id = V850_DIVU; break;
	case 0b0100010000: inst->id = V850_MUL; break;
	case 0b0100010001: inst->id = V850_MULU; break;
	case 0b0001010001: inst->id = V850_SAR; break;
	case 0b0111011101: inst->id = V850_SATADD; break;
	case 0b0111001101: inst->id = V850_SATSUB; break;
	case 0b0001100001: inst->id = V850_SHL; break;
	case 0b0001000001: inst->id = V850_SHR; break;
	default:
		switch (inst->sub_opcode) {
		case 0b0010110000:
			switch (inst->reg2) {
			case 0x18: inst->id = V850_JARL; break;
			case 0x0c: inst->id = V850_POPSP; break;
			case 0x08: inst->id = V850_PUSHSP; break;
			default: break;
			}
			break;
		default: {
			ut16 sub_opcode_shifted = inst->sub_opcode >> 4;
			switch (sub_opcode_shifted) {
			case 0b011101: inst->id = V850_ADF; break;
			case 0b011100: inst->id = V850_SBF; break;
			case 0b011001: inst->id = V850_CMOV; break;
			default: {
				ut16 ext_res = extract(inst->w2, 5, 7);
				switch (ext_res) {
				case 0b0011110: inst->id = V850_MAC; break;
				case 0b0011111: inst->id = V850_MACU; break;
				default: return false;
				}
			}
			}
		}
		}
		break;
	}

	PRINT_INSTR;

	ut8 cccc = extract(inst->w2, 1, 4);
	ut8 rh = inst->reg1;
	ut8 rt = inst->reg3;

	switch (inst->id) {
	case V850_MACU:
	case V850_MAC: OPERANDS("[%s], %s, %s, %s", R1, R2, R3, GR_get(cccc)); break;
	case V850_CMOV:
	case V850_SBF:
	case V850_ADF: OPERANDS("%d, %s, %s, %s", cccc, R1, R2, R3); break;
	case V850_JARL: OPERANDS("[%s], %s", R1, R3); break;
	case V850_PUSHSP:
	case V850_POPSP: OPERANDS("%d-%d", rh, rt); break;
	default: OPERANDS("[%s], %s, %s", R1, R2, R3); break;
	}
	return true;
}

static bool decode_formatXII(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 5, 10);
	inst->reg2 = get_reg2(inst);
	inst->reg3 = get_reg3(inst);
	inst->sub_opcode = extract(inst->w2, 1, 10) | (get_reg1(inst) << 10);

	if (inst->opcode != 0x3f) {
		return false;
	}
	switch (inst->sub_opcode) {
	case 0b0110100001: inst->id = V850_BSH; break;
	case 0b0110100000: inst->id = V850_BSW; break;
	case 0b0110100011: inst->id = V850_HSH; break;
	case 0b0110100010: inst->id = V850_HSW; break;
	default:
		if ((inst->sub_opcode >> 4 & 0x3f) == 0b011000) {
			inst->id = V850_CMOV;
		} else if ((inst->sub_opcode & 0x3e1) == 0b0100100000) {
			inst->id = V850_MUL;
		} else if ((inst->sub_opcode & 0x3e1) == 0b0100100001) {
			inst->id = V850_MULU;
		} else {
			return false;
		}
		break;
	}

	PRINT_INSTR;
	OPERANDS("%s, %s", R2, R3);
	return true;
}

static const ut8 list12_map[] = {
	/*[0]  = */ 30,
	/*[21] = */ 31,
	/*[22] = */ 29,
	/*[23] = */ 28,
	/*[24] = */ 23,
	/*[25] = */ 22,
	/*[26] = */ 21,
	/*[27] = */ 20,
	/*[28] = */ 27,
	/*[29] = */ 26,
	/*[30] = */ 25,
	/*[31] = */ 24,
};

static int ut8_cmp(const void *a, const void *b) {
	return ((ut8 *)a)[0] - ((ut8 *)b)[0];
}

static char *fmt_list(ut32 lst) {
	ut8 set[12] = { 0 };
	for (ut32 i = 0; i < 12; i++) {
		set[i] = (lst & (1 << i)) ? list12_map[i] : UT8_MAX;
	}
	qsort(set, 12, sizeof(ut8), ut8_cmp);
	RzStrBuf sb = { 0 };
	rz_strbuf_initf(&sb, "{");
	ut8 begin = set[0];
	ut8 end = set[0];
	bool sep = false;
	for (ut32 i = 1; i < 12; i++) {
		ut8 x = set[i];
		if (x == UT8_MAX) {
			if (i == 1 && begin < RZ_ARRAY_SIZE(GR)) {
				rz_strbuf_append(&sb, GR_get(begin));
			}
			break;
		}
		if (x - end == 1) {
			end = x;
			continue;
		}
		if (sep) {
			rz_strbuf_append(&sb, ", ");
		}
		if (begin != end) {
			rz_strbuf_appendf(&sb, "%s - %s", GR_get(begin), GR_get(end));
		} else {
			rz_strbuf_appendf(&sb, "%s", GR_get(begin));
		}
		sep = true;

		rz_strbuf_appendf(&sb, ", %s", GR_get(x));
		sep = true;
		begin = end = x;
	}
	rz_strbuf_append(&sb, "}");
	return rz_strbuf_drain_nofree(&sb);
}

static bool decode_formatXIII(V850_Inst *inst, RzBuffer *b) {
	inst->opcode = get_opcode(inst, 6, 10);
	inst->sub_opcode = get_reg2(inst);
	inst->imm = inst->w1 & 0x3f >> 1;
	inst->list = get_list(inst);
	inst->reg2 = inst->w2 & 0x1f;

	if (inst->sub_opcode != 0) {
		return false;
	}

	char *list_str = fmt_list(inst->list);
	if (!list_str) {
		rz_warn_if_reached();
		return false;
	}
	switch (inst->opcode) {
	case 0b11001: {
		inst->id = V850_DISPOSE;
		ut8 RRRRR = inst->w2 & 0x1f;
		PRINT_INSTR;
		if (RRRRR > 0) {
			OPERANDS("%d, %s, %s", inst->imm, list_str, GR_get(RRRRR));
		} else {
			OPERANDS("%d, %s", inst->imm, list_str);
		}
		break;
	}

	case 0b11110:
		if (inst->reg2 == 1) {
			inst->id = V850_PREPARE;
			OPERANDS("%s, %d", list_str, inst->imm);
		} else if ((inst->reg2 & 0x7) == 0x3) {
			inst->id = V850_PREPARE;
			ut8 ff = inst->reg2 >> 3;
			switch (ff) {
			case 0b00: OPERANDS("%s, %d, sp", list_str, inst->imm); break;
			case 0b01: {
				ut16 imm = 0;
				if (!rz_buf_read_le16(b, &imm)) {
					return false;
				}
				OPERANDS("%s, %d, %d", list_str, inst->imm, sext32(imm, 16));
				break;
			}
			case 0b10: {
				ut16 imm = 0;
				if (!rz_buf_read_le16(b, &imm)) {
					return false;
				}
				OPERANDS("%s, %d, %d", list_str, inst->imm, (ut32)(imm) << 16);
				break;
			}
			case 0b11: {
				ut32 imm = 0;
				if (!rz_buf_read_le32(b, &imm)) {
					return false;
				}
				OPERANDS("%s, %d, %d", list_str, inst->imm, imm);
				break;
			}
			default: break;
			}

		} else {
			return false;
		}
		PRINT_INSTR;
		break;
	default:
		return false;
	}

	free(list_str);
	return true;
}

static bool decode_formatXIV(V850_Inst *inst) {
	inst->opcode = get_opcode(inst, 5, 10);
	inst->reg1 = get_reg1(inst);
	inst->reg3 = get_reg3(inst);
	inst->disp = ((inst->w2 >> 4) & 0x7f) | (inst->w3 << 7);
	inst->sub_opcode = (inst->w2 & 0xf) | ((inst->w1 >> 11) << 4);

	ut16 sub_opcode2 = (inst->w2 & 0x1f) | ((inst->w1 >> 11) << 5);
	switch (inst->opcode | inst->sub_opcode << 6) {
	case 0b111100 | (0b0101 << 6): inst->id = V850_LDB; break;
	case 0b111101 | (0b0101 << 6): inst->id = V850_LDBU; break;
	case 0b111100 | (0b1101 << 6): inst->id = V850_STB; break;
	default:
		switch (inst->opcode | sub_opcode2) {
		case 0b111101 | (0b01001 << 6): inst->id = V850_LDDW; break;
		case 0b111100 | (0b00111 << 6): inst->id = V850_LDH; break;
		case 0b111101 | (0b00111 << 6): inst->id = V850_LDHU; break;
		case 0b111100 | (0b01001 << 6): inst->id = V850_LDW; break;
		case 0b111101 | (0b01111 << 6): inst->id = V850_STDW; break;
		case 0b111101 | (0b01101 << 6): inst->id = V850_STH; break;
		case 0b111100 | (0b01111 << 6): inst->id = V850_STW; break;
		default: return false;
		}
	}

	PRINT_INSTR;
	OPERANDS("%d[%s], %s", inst->imm, R1, R3);
	return true;
}

int v850_decode_command(const ut8 *bytes, int len, V850_Inst *inst) {
	if (len < 2) {
		return -1;
	}
	RzBuffer *b = rz_buf_new_with_bytes(bytes, len);
	if (!b) {
		return -1;
	}

	if (!rz_buf_read_le16(b, &inst->w1)) {
		goto err;
	}
	inst->byte_size = 2;
	if (decode_formatI(inst) ||
		decode_formatII(inst) ||
		decode_formatIII(inst) ||
		decode_formatIV_1(inst) ||
		decode_formatIV_2(inst)) {
		goto ok;
	}

	if (!rz_buf_read_le16(b, &inst->w2)) {
		goto err;
	}
	inst->byte_size = 4;
	if (decode_formatV(inst) ||
		decode_formatVI(inst, b) ||
		decode_formatVII(inst) ||
		decode_formatVIII(inst) ||
		decode_formatIX(inst) ||
		decode_formatX(inst) ||
		decode_formatXI(inst) ||
		decode_formatXII(inst) ||
		decode_formatXIII(inst, b)) {
		goto ok;
	}

	if (!rz_buf_read_le16(b, &inst->w3)) {
		goto err;
	}
	inst->byte_size = 6;
	if (decode_formatXIV(inst)) {
		goto ok;
	}

ok:
	rz_buf_free(b);
	return inst->byte_size;
err:
	inst->byte_size = -1;
	rz_buf_free(b);
	return -1;
}
