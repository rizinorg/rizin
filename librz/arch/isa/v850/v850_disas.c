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
	[V850_LDLW] = "ldl.w",
	[V850_NOP] = "nop",
	[V850_POPSP] = "popsp",
	[V850_PREPARE] = "prepare",
	[V850_PUSHSP] = "pushsp",
	[V850_RIE] = "rie",
	[V850_SNOOZE] = "snooze",
	[V850_STSR] = "stsr",
	[V850_STCW] = "stc.w",
	[V850_SWITCH] = "switch",
	[V850_SYNCE] = "synce",
	[V850_SYNCI] = "synci",
	[V850_SYNCM] = "syncm",
	[V850_SYNCP] = "syncp",
	[V850_SYSCALL] = "syscall",
	[V850_TRAP] = "trap",

	[V850_CACHE] = "cache",
	[V850_PREF] = "pref",

	[V850_ABSF_D] = "absf.d",
	[V850_ABSF_S] = "absf.s",
	[V850_ADDF_D] = "addf.d",
	[V850_ADDF_S] = "addf.s",
	[V850_CEILF_DL] = "ceilf.dl",
	[V850_CEILF_DUL] = "ceilf.dul",
	[V850_CEILF_DUW] = "ceilf.duw",
	[V850_CEILF_DW] = "ceilf.dw",
	[V850_CEILF_SL] = "ceilf.sl",
	[V850_CEILF_SUL] = "ceilf.sul",
	[V850_CEILF_SUW] = "ceilf.suw",
	[V850_CEILF_SW] = "ceilf.sw",
	[V850_CMOVF_D] = "cmovf.d",
	[V850_CMOVF_S] = "cmovf.s",
	[V850_CMPF_D] = "cmpf.d",
	[V850_CMPF_S] = "cmpf.s",
	[V850_CVTF_DL] = "cvtf.dl",
	[V850_CVTF_DS] = "cvtf.ds",
	[V850_CVTF_DUL] = "cvtf.dul",
	[V850_CVTF_DUW] = "cvtf.duw",
	[V850_CVTF_DW] = "cvtf.dw",
	[V850_CVTF_LD] = "cvtf.ld",
	[V850_CVTF_LS] = "cvtf.ls",
	[V850_CVTF_SD] = "cvtf.sd",
	[V850_CVTF_SL] = "cvtf.sl",
	[V850_CVTF_SUL] = "cvtf.sul",
	[V850_CVTF_SUW] = "cvtf.suw",
	[V850_CVTF_SW] = "cvtf.sw",
	[V850_CVTF_ULD] = "cvtf.uld",
	[V850_CVTF_ULS] = "cvtf.uls",
	[V850_CVTF_UWD] = "cvtf.uwd",
	[V850_CVTF_UWS] = "cvtf.uws",
	[V850_CVTF_WD] = "cvtf.wd",
	[V850_CVTF_WS] = "cvtf.ws",
	[V850_DIVF_D] = "divf.d",
	[V850_DIVF_S] = "divf.s",
	[V850_FLOORF_DL] = "floorf.dl",
	[V850_FLOORF_DUL] = "floorf.dul",
	[V850_FLOORF_DUW] = "floorf.duw",
	[V850_FLOORF_DW] = "floorf.dw",
	[V850_FLOORF_SL] = "floorf.sl",
	[V850_FLOORF_SUL] = "floorf.sul",
	[V850_FLOORF_SUW] = "floorf.suw",
	[V850_FLOORF_SW] = "floorf.sw",
	[V850_MADDF_S] = "maddf.s",
	[V850_MAXF_D] = "maxf.d",
	[V850_MAXF_S] = "maxf.s",
	[V850_MINF_D] = "minf.d",
	[V850_MINF_S] = "minf.s",
	[V850_MSUBF_S] = "msubf.s",
	[V850_MULF_D] = "mulf.d",
	[V850_MULF_S] = "mulf.s",
	[V850_NEGF_D] = "negf.d",
	[V850_NEGF_S] = "negf.s",
	[V850_NMADDF_S] = "nmaddf.s",
	[V850_NMSUBF_S] = "nmsubf.s",
	[V850_RECIPF_D] = "recipf.d",
	[V850_RECIPF_S] = "recipf.s",
	[V850_RSQRTF_D] = "rsqrtf.d",
	[V850_RSQRTF_S] = "rsqrtf.s",
	[V850_SQRTF_D] = "sqrtf.d",
	[V850_SQRTF_S] = "sqrtf.s",
	[V850_SUBF_D] = "subf.d",
	[V850_SUBF_S] = "subf.s",
	[V850_TRFSR] = "trfsr",
	[V850_TRNCF_DL] = "trncf.dl",
	[V850_TRNCF_DUL] = "trncf.dul",
	[V850_TRNCF_DUW] = "trncf.duw",
	[V850_TRNCF_DW] = "trncf.dw",
	[V850_TRNCF_SL] = "trncf.sl",
	[V850_TRNCF_SUL] = "trncf.sul",
	[V850_TRNCF_SUW] = "trncf.suw",
	[V850_TRNCF_SW] = "trncf.sw",
};

static const char *conds[] = {
	[V850_COND_BV] = "v",
	[V850_COND_BL] = "l",
	[V850_COND_BE] = "e",
	[V850_COND_BNH] = "nh",
	[V850_COND_BN] = "n",
	[V850_COND_BR] = "r",
	[V850_COND_BLT] = "lt",
	[V850_COND_BLE] = "le",
	[V850_COND_BNV] = "nv",
	[V850_COND_BNL] = "nl",
	[V850_COND_BNE] = "ne",
	[V850_COND_BH] = "h",
	[V850_COND_BP] = "p",
	[V850_COND_BSA] = "sa",
	[V850_COND_BGE] = "ge",
	[V850_COND_BGT] = "gt",
};

#define INSTR(...)    snprintf(inst->instr, V850_INSTR_MAXLEN - 1, __VA_ARGS__);
#define OPERANDS(...) snprintf(inst->operands, V850_OPERANDS_MAXLEN - 1, __VA_ARGS__);
#define PRINT_INSTR   INSTR("%s", instrs[inst->id])
#define ALSO(x, y) \
	{ \
		if ((x)) { \
			inst->id = y; \
			goto ok; \
		}; \
		break; \
	}

static bool decode_formatI(V850_Inst *inst) {
	if (V850_word(inst, 1) == 0) {
		inst->id = V850_NOP;
		goto ok;
	}
	ut8 opcode = get_opcode(inst, 5, 10);
	ut8 r1 = get_reg1(inst);
	ut8 r2 = get_reg2(inst);

	switch (opcode) {
	case V850_DIVH: ALSO(r1 && r2, opcode);
	case V850_MOV:
	case V850_SATADD:
	case V850_SATSUB:
	case V850_SATSUBR:
	case V850_MULH: ALSO(r2, opcode);
	case V850_ADD:
	case V850_AND:
	case V850_CMP:
	case V850_NOT:
	case V850_OR:
	case V850_SUB:
	case V850_SUBR:
	case V850_TST:
	case V850_XOR: inst->id = opcode; goto ok;
	default: break;
	}

	ut16 w1 = V850_word(inst, 1);
	if (w1 == 0b0000000001000000) {
		inst->id = V850_RIE;
		goto ok;
	} else if (w1 == 0b0000000000011101) {
		inst->id = V850_SYNCE;
		goto ok;
	} else if (w1 == 0b0000000000011100) {
		inst->id = V850_SYNCI;
		goto ok;
	} else if (w1 == 0b0000000000011110) {
		inst->id = V850_SYNCM;
		goto ok;
	} else if (w1 == 0b0000000000011111) {
		inst->id = V850_SYNCP;
		goto ok;
	} else if ((w1 & ~(0xf << 11)) == 0b0000000001000000) {
		inst->id = V850_FETRAP;
		goto ok;
	} else if (r2 == 0) {
		switch (opcode) {
		case V850_JMP: inst->id = V850_JMP; goto ok;
		case 0b000010: inst->id = V850_SWITCH; goto ok;
		case 0b000101: inst->id = V850_SXB; goto ok;
		case 0b000111: inst->id = V850_SXH; goto ok;
		case 0b000100: inst->id = V850_ZXB; goto ok;
		case 0b000110: inst->id = V850_ZXH; goto ok;
		default: break;
		}
	}
	return false;

ok:
	switch (inst->id) {
	case V850_RIE:
	case V850_SYNCP:
	case V850_SYNCI:
	case V850_SYNCE:
	case V850_SYNCM:
		break;
	case V850_JMP:
		OPERANDS("[%s]", R1);
		break;
	case V850_SWITCH:
	case V850_SXB:
	case V850_SXH:
	case V850_ZXB:
	case V850_ZXH:
		OPERANDS("%s", R1);
		break;
	case V850_FETRAP:
		OPERANDS("0x%x", i_vec4(inst));
		break;
	case V850_NOP:
		break;
	default: {
		OPERANDS("%s, %s", R1, R2);
		break;
	}
	}
	PRINT_INSTR;
	inst->format = I_reg_reg;
	return true;
}

static bool decode_formatII(V850_Inst *inst) {
	ut8 opcode = get_opcode(inst, 5, 10);
	if (get_reg2(inst) != 0) {
		switch (opcode) {
		case 0x10:
			inst->id = V850_MOV;
			inst->imm = sext32(get_reg1(inst), 5);
			break;
		case 0x11:
			inst->id = V850_SATADD;
			inst->imm = sext32(get_reg1(inst), 5);
			break;
		case 0x12:
			inst->id = V850_ADD;
			inst->imm = sext32(get_reg1(inst), 5);
			break;
		case 0x13:
			inst->id = V850_CMP;
			inst->imm = sext32(get_reg1(inst), 5);
			break;
		case 0x14:
			inst->id = V850_SHR;
			inst->imm = get_reg1(inst);
			break;
		case 0x15:
			inst->id = V850_SAR;
			inst->imm = get_reg1(inst);
			break;
		case 0x16:
			inst->id = V850_SHL;
			inst->imm = get_reg1(inst);
			break;
		case 0x17:
			inst->id = V850_MULH;
			inst->imm = sext32(get_reg1(inst), 5);
			break;
		default:
			return false;
		}
	} else {
		// CALLT
		if (inst->d >> 6 == 0x8) {
			inst->id = V850_CALLT;
			inst->imm = (inst->d & 0x3f) << 1;
		} else {
			return false;
		}
	}

	PRINT_INSTR;
	if (inst->id == V850_CALLT) {
		OPERANDS("%u", inst->imm);
	} else {
		OPERANDS("%d, %s", inst->imm, R2);
	}
	inst->format = II_imm_reg;
	return true;
}

static bool decode_formatIII(V850_Inst *inst) {
	ut8 opcode = get_opcode(inst, 7, 10);
	if (opcode != 0xb) {
		return false;
	}

	inst->id = V850_BCOND;
	inst->disp = sext32(get_disp9(inst), 9);
	ut8 cond = get_cond(inst);
	const char *cond_s = conds[cond];
	if (!cond_s) {
		rz_warn_if_reached();
		return false;
	}

	INSTR("b%s", cond_s);
	OPERANDS("0x%llx", (st64)(inst->addr) + (st32)inst->disp);
	inst->format = III_conditional_branch;
	return true;
}

static bool decode_formatIV_1(V850_Inst *inst) {
	ut8 opcode = get_opcode(inst, 7, 10);
	inst->disp = V850_word(inst, 2) & 0x7f;
	switch (opcode) {
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
		if (opcode != 0xa) {
			return false;
		}
		if (V850_word(inst, 1) & 1) {
			inst->id = V850_SSTW;
		} else {
			inst->id = V850_SLDW;
		}
		inst->disp = (inst->disp & ~1) << 1;
		break;
	}

	PRINT_INSTR;
	OPERANDS("%d[ep] %s", inst->disp, R2);
	inst->format = IV_load_store16;
	return true;
}

static bool decode_formatIV_2(V850_Inst *inst) {
	ut8 opcode = get_opcode(inst, 4, 10);
	inst->disp = V850_word(inst, 2) & 0xf;
	switch (opcode) {
	case 0x6: inst->id = V850_SLDBU; break;
	case 0x7:
		inst->id = V850_SLDHU;
		inst->disp <<= 1;
		break;
	default: return false;
	}

	PRINT_INSTR;
	OPERANDS("%d[ep] %s", inst->disp, R2);
	inst->format = IV_load_store16;
	return true;
}

static bool decode_formatV(V850_Inst *inst) {
	if (V850_word(inst, 2) & 1) {
		return false;
	}
	ut8 opcode = get_opcode(inst, 6, 10);
	if (opcode != 0x1e) {
		return false;
	}

	ut32 disp22 = get_disp22(inst);
	inst->sdisp = sext32(disp22, 22);
	ut64 target = inst->addr + inst->sdisp;

	ut8 reg2 = get_reg2(inst);
	if (reg2 == 0) {
		inst->id = V850_JR;
		OPERANDS("0x%llx", target);
	} else {
		inst->id = V850_JARL;
		OPERANDS("0x%llx, %s", target, R2);
	}

	PRINT_INSTR;
	inst->format = V_jump;
	return true;
}

static bool decode_formatVI(V850_Inst *inst, RzBuffer *b) {
	ut8 opcode = get_opcode(inst, 5, 10);
	ut8 reg1 = get_reg1(inst);
	ut8 reg2 = get_reg2(inst);
	inst->imm = get_imm16(inst);
	if (reg2 == 0) {
		switch (opcode) {
		case 0x17:
			if (reg1) {
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
		ut16 tmp;
		if (!rz_buf_read_le16_at(b, 4, &tmp)) {
			return false;
		}
		inst->byte_size += 2;
		inst->d |= ((ut64)(tmp) << 32);
		inst->imm |= (ut32)(V850_word(inst, 3)) << 16;
	} else {
		switch (opcode) {
		case V850_ADDI:
		case V850_MOVEA:
		case V850_SATSUBI:
			inst->id = opcode;
			inst->imm = sext32(inst->imm, 16);
			break;
		case V850_ANDI:
		case V850_MULHI:
		case V850_MOVHI:
		case V850_ORI:
		case V850_XORI:
			inst->id = opcode;
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
	inst->format = VI_3operand;
	return true;
}

static bool decode_formatVII(V850_Inst *inst) {
	ut8 opcode = get_opcode(inst, 5, 10);
	ut8 sub1 = V850_word(inst, 2) & 1;
	ut16 sub2 = extract(V850_word(inst, 2), 0, 11);
	ut8 reg2 = get_reg2(inst);
	inst->disp = get_imm16(inst);
	switch (opcode) {
	case 0x38:
		inst->id = V850_LDB;
		break;
	case 0x3a:
		inst->id = V850_STB;
		break;
	case 0x3b:
		if (!(sub1)) {
			inst->id = V850_STH;
		} else {
			inst->id = V850_STW;
		}
		inst->disp &= ~1;
		break;
	case 0x3c:
	case 0x3d:
		if (sub1 && reg2) {
			inst->id = V850_LDBU;
			inst->disp = inst->disp | (opcode & 1);
			break;
		}
		return false;
	case 0x39: {
		if (!(sub1)) {
			inst->id = V850_LDH;
		} else {
			inst->id = V850_LDW;
		}
		inst->disp &= ~1;
		break;
	}
	case 0x37:
		if (reg2 == 0 && sub1) {
			inst->id = V850_LOOP;
			inst->disp &= ~1;
			break;
		}
		return false;
	case 0x3f: {
		if (reg2 == 0 && sub1) {
			inst->id = V850_BCOND;
			ut8 cond = get_cond(inst);
			inst->disp = sext32(((inst->disp >> 1) | (((V850_word(inst, 1) >> 4) & 1) << 15)) << 1, 17);
			INSTR("b%s", conds[cond]);
			OPERANDS("0x%llx", (st64)inst->addr + (st32)inst->disp);
			goto ok;
		}
		if (sub1) {
			inst->id = V850_LDHU;
			break;
		}

		if (reg2 == 0 && sub2 == 0x378) {
			inst->id = V850_LDLW;
			break;
		}
		if (reg2 == 0 && sub2 == 0x37a) {
			inst->id = V850_STCW;
			break;
		}
		if (reg2 != 0 && (sub2 == 0xc4 || sub2 == 0xc6)) {
			inst->id = V850_ROTL;
			inst->imm = get_reg1(inst);
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
		OPERANDS("%d[%s], %s", (st32)inst->disp, R1, R2);
		break;
	case V850_STB:
	case V850_STH:
	case V850_STW:
		OPERANDS("%s, %d[%s]", R2, inst->disp, R1);
		break;
	case V850_BCOND:
		break;
	case V850_LDLW:
		OPERANDS("[%s], %s", R1, R3);
		break;
	case V850_STCW:
		OPERANDS("%s, [%s]", R3, R1);
		break;
	case V850_LOOP:
		OPERANDS("%s, %d", R1, inst->disp);
		break;
	case V850_ROTL:
		if (sub2 == 0xc4) {
			OPERANDS("%d, %s, %s", inst->imm, R2, R3);
		} else if (sub2 == 0xc6) {
			OPERANDS("%s, %s, %s", R1, R2, R3);
		} else {
			rz_warn_if_reached();
		}
		break;
	default: break;
	}

ok:
	inst->format = VII_load_store32;
	return true;
}

static bool decode_formatVIII(V850_Inst *inst) {
	ut8 opcode = get_opcode(inst, 5, 10);
	ut8 sub_opcode = V850_word(inst, 1) >> 14;
	switch (opcode | (sub_opcode << 6)) {
	case 0x38 | (0x2 << 6): inst->id = V850_CLR1; break;
	case 0x3e | (0x1 << 6): inst->id = V850_NOT1; break;
	case 0x3e | (0x0 << 6): inst->id = V850_SET1; break;
	case 0x3e | (0x3 << 6): inst->id = V850_TST1; break;
	default: return false;
	}

	ut8 bit = (V850_word(inst, 1) >> 11) & 0x7;
	inst->disp = get_imm16(inst);
	PRINT_INSTR;
	OPERANDS("%d, %d[%s]", bit, inst->disp, R1);
	inst->format = VIII_bit;
	return true;
}

static bool decode_formatIX(V850_Inst *inst) {
	if (V850_word(inst, 2) & 1) {
		return false;
	}

	ut8 reg1 = get_reg1(inst);
	if (extract(inst->d, 4, 6) == 0x3e && V850_word(inst, 2) == 0b0000001000000000) {
		inst->id = V850_SASF;
	} else if (extract(inst->d, 4, 6) == 0x3e && V850_word(inst, 2) == 0b0000000000000000) {
		inst->id = V850_SETF;
	} else {
		ut8 opcode = get_opcode(inst, 5, 10);
		ut16 sub_opcode = get_imm16(inst) & ~1;
		if (reg1 == 0) {
			if (extract(sub_opcode, 0, 11) == 0x364) {
				inst->id = V850_SCH0L;
			} else if (extract(sub_opcode, 0, 11) == 0x360) {
				inst->id = V850_SCH0R;
			} else if (extract(sub_opcode, 0, 11) == 0x366) {
				inst->id = V850_SCH1L;
			} else if (extract(sub_opcode, 0, 11) == 0x362) {
				inst->id = V850_SCH1R;
			} else {
				return false;
			}
		} else {
			if (opcode == 0x3f) {
				switch (V850_word(inst, 2)) {
				case 0b0000000011100100: inst->id = V850_CLR1; break;
				case 0b0000000011100010: inst->id = V850_NOT1; break;
				case 0b0000000011100110: inst->id = V850_TST1; break;
				case 0b0000000011100000: inst->id = V850_SET1; break;
				case 0b0000000010100000: inst->id = V850_SAR; break;
				case 0b0000000011000000: inst->id = V850_SHL; break;
				case 0b0000000010000000: inst->id = V850_SHR; break;
				default:
					if (extract(sub_opcode, 0, 11) == 0x020) {
						inst->id = V850_LDSR;
					} else if (extract(sub_opcode, 0, 11) == 0x040) {
						inst->id = V850_STSR;
					} else if (extract(sub_opcode, 4, 7) == 0x09 ||
						extract(sub_opcode, 4, 7) == 0x0b ||
						extract(sub_opcode, 4, 7) == 0x0d) {
						inst->id = V850_BINS;
					} else {
						return false;
					}
					break;
				}
			} else {
				return false;
			}
		}
	}

	PRINT_INSTR;
	ut8 reg2 = get_reg2(inst);
	switch (inst->id) {
	case V850_STSR:
		OPERANDS("%s, %s, %d", SR_get(reg1, get_selID(inst)), R2, get_reg3(inst));
		break;
	case V850_LDSR:
		OPERANDS("%s, %s, %d", R1, SR_get(reg2, get_selID(inst)), get_reg3(inst));
		break;
	case V850_SHR:
	case V850_SAR:
	case V850_SHL: OPERANDS("%s, %s", R1, R2); break;
	case V850_CLR1:
	case V850_NOT1:
	case V850_TST1:
	case V850_SET1: OPERANDS("%s, [%s]", R2, R1); break;
	case V850_SASF:
	case V850_SETF: OPERANDS("%s, %s", conds[get_cond(inst)], R2); break;
	case V850_BINS: OPERANDS("%s, %d, %d, %s", R1, bins_pos(inst), bins_width(inst), R2); break;
	case V850_SCH0L:
	case V850_SCH0R:
	case V850_SCH1L:
	case V850_SCH1R: OPERANDS("%s, %s", R2, R3); break;
	default: break;
	}
	inst->format = IX_extended1;
	return true;
}

static bool decode_formatX(V850_Inst *inst) {
	if (V850_word(inst, 2) & 1) {
		return false;
	}

	ut32 dword = V850_word(inst, 1) | ((ut32)(V850_word(inst, 2)) << 16);
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
	} else if (V850_word(inst, 2) == 0 && extract(V850_word(inst, 1), 4, 7) == 0x7f) {
		inst->id = V850_RIE;
		OPERANDS("%d %d", extract(V850_word(inst, 1), 11, 5), extract(V850_word(inst, 1), 0, 4));
		goto ok;
	} else if ((V850_word(inst, 2) & 0xc7ff) == 0x0160 && (V850_word(inst, 1) >> 5) == 0b11010111111) {
		inst->id = V850_SYSCALL;
		OPERANDS("0x%02x", x_vector8(inst));
		goto ok;
	} else if (V850_word(inst, 2) == 0b0000000100000000 && (V850_word(inst, 1) >> 5) == 0b00000111111) {
		inst->id = V850_TRAP;
		OPERANDS("%d", V850_word(inst, 1) & 0x1f);
		goto ok;
	} else if (extract(V850_word(inst, 2), 0, 11) == 0b00101100000 && (extract(V850_word(inst, 1), 5, 6) | extract(V850_word(inst, 1), 13, 3) << 6) == 0x1ff) {
		inst->id = V850_CACHE;
		ut16 cacheop = extract(V850_word(inst, 2), 11, 5) | extract(V850_word(inst, 1), 11, 2);
		OPERANDS("0x%02x [%s]", cacheop, R1);
		goto ok;
	} else if (extract(V850_word(inst, 2), 0, 11) == 0b00101100000 && extract(V850_word(inst, 1), 5, 11) == 0b11011111111) {
		inst->id = V850_PREF;
		ut16 prefop = extract(V850_word(inst, 2), 11, 5);
		OPERANDS("0x%02x [%s]", prefop, R1);
		goto ok;
	} else {
		return false;
	}

ok:
	PRINT_INSTR;
	inst->format = X_extended2;
	return true;
}

static bool decode_formatXI(V850_Inst *inst) {
	if (V850_word(inst, 2) & 1) {
		return false;
	}

	ut8 opcode = get_opcode(inst, 5, 10);
	ut8 reg2 = get_reg2(inst);
	ut16 sub_opcode = extract(V850_word(inst, 2), 1, 10);

	if (opcode != 0x3f) {
		return false;
	}
	switch (sub_opcode) {
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
	case 0b1000101100: inst->id = V850_ABSF_D; break;
	default:
		if (sub_opcode == 0b0010110000) {
			switch (reg2) {
			case 0x18: inst->id = V850_JARL; break;
			case 0x0c: inst->id = V850_POPSP; break;
			case 0x08: inst->id = V850_PUSHSP; break;
			default: break;
			}
		} else {
			ut16 sub_opcode_shifted = sub_opcode >> 4;
			switch (sub_opcode_shifted) {
			case 0b011101: inst->id = V850_ADF; break;
			case 0b011100: inst->id = V850_SBF; break;
			case 0b011001: inst->id = V850_CMOV; break;
			default: {
				ut16 ext_res = extract(V850_word(inst, 2), 5, 7);
				switch (ext_res) {
				case 0b0011110: inst->id = V850_MAC; break;
				case 0b0011111: inst->id = V850_MACU; break;
				default: return false;
				}
			}
			}
		}
		break;
	}

	PRINT_INSTR;

	ut8 cccc = extract(V850_word(inst, 2), 1, 4);

	switch (inst->id) {
	case V850_MACU:
	case V850_MAC: OPERANDS("[%s], %s, %s, %s", R1, R2, R3, GR_get(xi_reg4(inst))); break;
	case V850_CMOV:
	case V850_SBF:
	case V850_ADF: OPERANDS("%s, %s, %s, %s", conds[cccc], R1, R2, R3); break;
	case V850_JARL: OPERANDS("[%s], %s", R1, R3); break;
	case V850_PUSHSP:
	case V850_POPSP: OPERANDS("%d-%d", xi_rh(inst), xi_rt(inst)); break;
	case V850_ABSF_D: OPERANDS("%s, %s", R2, R3); break;
	default: OPERANDS("[%s], %s, %s", R1, R2, R3); break;
	}
	inst->format = XI_extended3;
	return true;
}

static bool decode_formatXII(V850_Inst *inst) {
	ut8 opcode = get_opcode(inst, 5, 10);
	ut16 sub_opcode = extract(V850_word(inst, 2), 1, 10) | (get_reg1(inst) << 10);
	if (opcode != 0x3f) {
		return false;
	}
	switch (sub_opcode) {
	case 0b0110100001: inst->id = V850_BSH; break;
	case 0b0110100000: inst->id = V850_BSW; break;
	case 0b0110100011: inst->id = V850_HSH; break;
	case 0b0110100010: inst->id = V850_HSW; break;
	default:
		if ((sub_opcode >> 4 & 0x3f) == 0b011000) {
			inst->id = V850_CMOV;
		} else if ((sub_opcode & 0x3e1) == 0b0100100000) {
			inst->id = V850_MUL;
		} else if ((sub_opcode & 0x3e1) == 0b0100100001) {
			inst->id = V850_MULU;
		} else {
			return false;
		}
		break;
	}

	PRINT_INSTR;
	if (inst->id == V850_CMOV) {
		OPERANDS("%s, %d, %s, %s", conds[xi_cond(inst)], xii_imm5(inst), R2, R3);
	} else {
		OPERANDS("%s, %s", R2, R3);
	}
	inst->format = XII_extended4;
	return true;
}

typedef struct {
	ut8 l;
	ut8 r;
} Range;

static void list12_to_range(const ut8 lst[], unsigned n, Range xs[], unsigned *pnxs) {
	Range *r = xs;
	for (int i = 0; i < n; ++i) {
		ut8 x = lst[i];
		if (r->l == 0) {
			r->l = r->r = x;
			continue;
		}
		if (x - r->r == 1) {
			r->r = x;
			continue;
		}
		r++;
		r->l = r->r = x;
	}
	if (pnxs) {
		*pnxs = r - xs + 1;
	}
}

static char *fmt_list(ut32 lst) {
	ut8 set[12] = { 0 };
	unsigned n = 0;
	xiii_sorted_list(lst, set, &n, false);
	Range xs[12] = { 0 };
	unsigned nxs = 0;
	list12_to_range(set, n, xs, &nxs);

	RzStrBuf sb = { 0 };
	rz_strbuf_initf(&sb, "{");
	bool sep = false;
	for (int i = 0; i < nxs; ++i) {
		Range *r = xs + i;
		if (!(r && r->l && r->r)) {
			break;
		}
		if (sep) {
			rz_strbuf_append(&sb, ", ");
		}
		if (r->l == r->r) {
			rz_strbuf_appendf(&sb, "%s", GR_get(r->l));
		} else {
			rz_strbuf_appendf(&sb, "%s - %s", GR_get(r->l), GR_get(r->r));
		}
		sep = true;
	}
	rz_strbuf_append(&sb, "}");
	return rz_strbuf_drain_nofree(&sb);
}

static bool decode_formatXIII(V850_Inst *inst, RzBuffer *b) {
	ut16 opcode = get_opcode(inst, 6, 15);
	ut16 list12 = xiii_list(inst);
	char *list_str = fmt_list(list12);
	if (!list_str) {
		rz_warn_if_reached();
		return false;
	}
	ut8 sub_opcode = xiii_sub_r1(inst);
	switch (opcode) {
	case 0b11001: {
		inst->id = V850_DISPOSE;
		PRINT_INSTR;
		if (sub_opcode > 0) {
			OPERANDS("%d, %s, %s", xiii_imm5(inst), list_str, GR_get(sub_opcode));
		} else {
			OPERANDS("%d, %s", xiii_imm5(inst), list_str);
		}
		break;
	}
	case 0b11110:
		if (sub_opcode == 1) {
			inst->id = V850_PREPARE;
			OPERANDS("%s, %d", list_str, xiii_imm5(inst));
		} else if ((sub_opcode & 0x7) == 0x3) {
			inst->id = V850_PREPARE;
			switch (xiii_ff(inst)) {
			case 0b00: OPERANDS("%s, %d, sp", list_str, xiii_imm5(inst)); goto ok;
			case 0b01: {
				ut16 tmp;
				if (!rz_buf_read_le16(b, &tmp)) {
					return false;
				}
				inst->byte_size += 2;
				inst->d |= (ut64)(tmp) << 32;
				inst->imm = sext32(V850_word(inst, 3), 16);
				break;
			}
			case 0b10: {
				ut16 tmp;
				if (!rz_buf_read_le16(b, &tmp)) {
					return false;
				}
				inst->byte_size += 2;
				inst->d |= tmp < 32;
				inst->imm = (V850_word(inst, 3)) << 16;
				break;
			}
			case 0b11: {
				ut32 tmp = 0;
				if (!rz_buf_read_le32(b, &tmp)) {
					return false;
				}
				inst->imm = tmp;
				inst->d |= (ut64)(tmp) << 32;
				break;
			}
			default: break;
			}
			OPERANDS("%s, %d, %d", list_str, xiii_imm5(inst), inst->imm);
		} else {
			goto err;
		}
		PRINT_INSTR;
		break;
	default:
		goto err;
	}

ok:
	free(list_str);
	inst->format = XIII_stack;
	return true;
err:
	free(list_str);
	return false;
}

static bool decode_formatXIV(V850_Inst *inst) {
	ut8 opcode = get_opcode(inst, 5, 10);
	ut8 sub_opcode = (V850_word(inst, 2) & 0xf) | ((V850_word(inst, 1) >> 11) << 4);
	ut16 sub_opcode2 = (V850_word(inst, 2) & 0x1f) | ((V850_word(inst, 1) >> 11) << 5);
	switch (opcode | (sub_opcode << 6)) {
	case 0b111100 | (0b0101 << 6): inst->id = V850_LDB; break;
	case 0b111101 | (0b0101 << 6): inst->id = V850_LDBU; break;
	case 0b111100 | (0b1101 << 6): inst->id = V850_STB; break;
	default:
		switch (opcode | (sub_opcode2 << 6)) {
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

	inst->disp = ((V850_word(inst, 2) >> 4) & 0x7f) | (V850_word(inst, 3) << 7);
	inst->disp = sext32(inst->disp, 23);
	PRINT_INSTR;
	switch (inst->id) {
	case V850_LDB:
	case V850_LDBU:
	case V850_LDH:
	case V850_LDHU:
	case V850_LDW:
	case V850_LDDW:
		OPERANDS("%d[%s], %s", (st32)inst->disp, R1, R3);
		break;
	case V850_STB:
	case V850_STH:
	case V850_STW:
	case V850_STDW:
		OPERANDS("%s, %d[%s]", R3, (st32)inst->disp, R1);
	default: break;
	}
	inst->format = XIV_load_store48;
	return true;
}

#define slice(x, l, r) extract(x, l, r - l + 1)
#define OP(l, r)       slice(inst->d, l, r)

static ut8 get_reg4(V850_Inst *i) {
	return slice(i->d, 17, 20);
}

#define R4 GR_get(get_reg4(inst))

static bool v850_decode_formatUnk_float(V850_Inst *inst) {
	// absf.d
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x0) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x18)) {
		inst->id = V850_ABSF_D;
		INSTR("absf.d");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// absf.s
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x0) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x8)) {
		inst->id = V850_ABSF_S;
		INSTR("absf.s");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// addf.d
	if ((OP(05, 10) == 0x3f) && (OP(21, 26) == 0x23 && OP(16, 20) == 0x10)) {
		inst->id = V850_ADDF_D;
		INSTR("addf.d");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// addf.s
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && get_reg1(inst)) && (get_reg3(inst) && OP(21, 26) == 0x23 && OP(16, 20) == 0x0)) {
		inst->id = V850_ADDF_S;
		INSTR("addf.s");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// ceilf.dl
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x2) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x14)) {
		inst->id = V850_CEILF_DL;
		INSTR("ceilf.dl");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// ceilf.dul
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x12) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x14)) {
		inst->id = V850_CEILF_DUL;
		INSTR("ceilf.dul");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// ceilf.duw
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x12) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x10)) {
		inst->id = V850_CEILF_DUW;
		INSTR("ceilf.duw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// ceilf.dw
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x2) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x10)) {
		inst->id = V850_CEILF_DW;
		INSTR("ceilf.dw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// ceilf.sl
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x2) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x4)) {
		inst->id = V850_CEILF_SL;
		INSTR("ceilf.sl");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// ceilf.sul
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x12) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x4)) {
		inst->id = V850_CEILF_SUL;
		INSTR("ceilf.sul");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// ceilf.suw
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x12) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x0)) {
		inst->id = V850_CEILF_SUW;
		INSTR("ceilf.suw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// ceilf.sw
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x2) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x0)) {
		inst->id = V850_CEILF_SW;
		INSTR("ceilf.sw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cmovf.d
	if ((OP(05, 10) == 0x3f) && (OP(21, 26) == 0x20 && OP(20, 20) == 0x1 && OP(16, 16) == 0x0)) {
		inst->id = V850_CMOVF_D;
		INSTR("cmovf.d");
		OPERANDS("%d, %s, %s, %s", slice(inst->d, 17, 19), R2, R1, R3);
		return true;
	}
	// cmovf.s
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && get_reg1(inst)) && (get_reg3(inst) && OP(21, 26) == 0x20 && OP(20, 20) == 0x0 && OP(16, 16) == 0x0)) {
		inst->id = V850_CMOVF_S;
		INSTR("cmovf.s");
		OPERANDS("%d, %s, %s, %s", slice(inst->d, 17, 19), R2, R1, R3);
		return true;
	}
	// cmpf.d
	if ((OP(05, 10) == 0x3f) && (OP(31, 31) == 0x0 && OP(21, 26) == 0x21 && OP(20, 20) == 0x1 && OP(16, 16) == 0x0)) {
		inst->id = V850_CMPF_D;
		INSTR("cmpf.d");
		OPERANDS("%s, %s, %s, %d", conds[slice(inst->d, 27, 30)], R2, R1, slice(inst->d, 17, 19));
		return true;
	}
	// cmpf.s
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && get_reg1(inst)) && (OP(31, 31) == 0x0 && OP(21, 26) == 0x21 && OP(20, 20) == 0x0 && OP(16, 16) == 0x0)) {
		inst->id = V850_CMPF_S;
		INSTR("cmpf.s");
		OPERANDS("%s, %s, %s, %d", conds[slice(inst->d, 27, 30)], R2, R1, slice(inst->d, 17, 19));
		return true;
	}
	// cvtf.dl
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x4) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x14)) {
		inst->id = V850_CVTF_DL;
		INSTR("cvtf.dl");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.ds
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x3) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x12)) {
		inst->id = V850_CVTF_DS;
		INSTR("cvtf.ds");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.dul
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x14) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x14)) {
		inst->id = V850_CVTF_DUL;
		INSTR("cvtf.dul");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.duw
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x14) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x10)) {
		inst->id = V850_CVTF_DUW;
		INSTR("cvtf.duw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.dw
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x4) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x10)) {
		inst->id = V850_CVTF_DW;
		INSTR("cvtf.dw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.ld
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x12)) {
		inst->id = V850_CVTF_LD;
		INSTR("cvtf.ld");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.ls
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x2)) {
		inst->id = V850_CVTF_LS;
		INSTR("cvtf.ls");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.sd
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x2) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x12)) {
		inst->id = V850_CVTF_SD;
		INSTR("cvtf.sd");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.sl
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x4) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x4)) {
		inst->id = V850_CVTF_SL;
		INSTR("cvtf.sl");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.sul
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x14) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x4)) {
		inst->id = V850_CVTF_SUL;
		INSTR("cvtf.sul");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.suw
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x14) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x0)) {
		inst->id = V850_CVTF_SUW;
		INSTR("cvtf.suw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.sw
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x4) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x0)) {
		inst->id = V850_CVTF_SW;
		INSTR("cvtf.sw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.uld
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x11) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x12)) {
		inst->id = V850_CVTF_ULD;
		INSTR("cvtf.uld");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.uls
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x11) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x2)) {
		inst->id = V850_CVTF_ULS;
		INSTR("cvtf.uls");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.uwd
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x10) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x12)) {
		inst->id = V850_CVTF_UWD;
		INSTR("cvtf.uwd");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.uws
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x10) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x2)) {
		inst->id = V850_CVTF_UWS;
		INSTR("cvtf.uws");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.wd
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x0) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x12)) {
		inst->id = V850_CVTF_WD;
		INSTR("cvtf.wd");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// cvtf.ws
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x0) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x2)) {
		inst->id = V850_CVTF_WS;
		INSTR("cvtf.ws");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// divf.d
	if ((OP(05, 10) == 0x3f) && (OP(21, 26) == 0x23 && OP(16, 20) == 0x1e)) {
		inst->id = V850_DIVF_D;
		INSTR("divf.d");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// divf.s
	if ((get_reg1(inst) && OP(05, 10) == 0x3f && get_reg2(inst)) && (get_reg3(inst) && OP(21, 26) == 0x23 && OP(16, 20) == 0xe)) {
		inst->id = V850_DIVF_S;
		INSTR("divf.s");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// floorf.dl
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x3) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x14)) {
		inst->id = V850_FLOORF_DL;
		INSTR("floorf.dl");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// floorf.dul
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x13) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x14)) {
		inst->id = V850_FLOORF_DUL;
		INSTR("floorf.dul");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// floorf.duw
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x13) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x10)) {
		inst->id = V850_FLOORF_DUW;
		INSTR("floorf.duw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// floorf.dw
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x3) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x10)) {
		inst->id = V850_FLOORF_DW;
		INSTR("floorf.dw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// floorf.sl
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x3) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x4)) {
		inst->id = V850_FLOORF_SL;
		INSTR("floorf.sl");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// floorf.sul
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x13) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x4)) {
		inst->id = V850_FLOORF_SUL;
		INSTR("floorf.sul");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// floorf.suw
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x13) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x0)) {
		inst->id = V850_FLOORF_SUW;
		INSTR("floorf.suw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// floorf.sw
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x3) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x0)) {
		inst->id = V850_FLOORF_SW;
		INSTR("floorf.sw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// maddf.s
	if ((get_reg1(inst) && OP(05, 10) == 0x3f && get_reg2(inst)) && (get_reg3(inst) && OP(24, 26) == 0x5 && OP(21, 22) == 0x0 && OP(16, 16) == 0x0 && get_reg4(inst))) {
		inst->id = V850_MADDF_S;
		INSTR("maddf.s");
		OPERANDS("%s, %s, %s, %s", R1, R2, R3, R4);
		return true;
	}
	// maxf.d
	if ((OP(05, 10) == 0x3f) && (OP(21, 26) == 0x23 && OP(16, 20) == 0x18)) {
		inst->id = V850_MAXF_D;
		INSTR("maxf.d");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// maxf.s
	if ((get_reg1(inst) && OP(05, 10) == 0x3f && get_reg2(inst)) && (get_reg3(inst) && OP(21, 26) == 0x23 && OP(16, 20) == 0x8)) {
		inst->id = V850_MAXF_S;
		INSTR("maxf.s");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// minf.d
	if ((OP(05, 10) == 0x3f) && (OP(21, 26) == 0x23 && OP(16, 20) == 0x1a)) {
		inst->id = V850_MINF_D;
		INSTR("minf.d");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// minf.s
	if ((get_reg1(inst) && OP(05, 10) == 0x3f && get_reg2(inst)) && (get_reg3(inst) && OP(21, 26) == 0x23 && OP(16, 20) == 0xa)) {
		inst->id = V850_MINF_S;
		INSTR("minf.s");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// msubf.s
	if ((get_reg1(inst) && OP(05, 10) == 0x3f && get_reg2(inst)) && (get_reg3(inst) && OP(24, 26) == 0x5 && OP(21, 22) == 0x1 && OP(16, 16) == 0x0 && get_reg4(inst))) {
		inst->id = V850_MSUBF_S;
		INSTR("msubf.s");
		OPERANDS("%s, %s, %s, %s", R1, R2, R3, R4);
		return true;
	}
	// mulf.d
	if ((OP(05, 10) == 0x3f) && (OP(21, 26) == 0x23 && OP(16, 20) == 0x14)) {
		inst->id = V850_MULF_D;
		INSTR("mulf.d");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// mulf.s
	if ((get_reg1(inst) && OP(05, 10) == 0x3f && get_reg2(inst)) && (get_reg3(inst) && OP(21, 26) == 0x23 && OP(16, 20) == 0x4)) {
		inst->id = V850_MULF_S;
		INSTR("mulf.s");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// negf.d
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x18)) {
		inst->id = V850_NEGF_D;
		INSTR("negf.d");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// negf.s
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x8)) {
		inst->id = V850_NEGF_S;
		INSTR("negf.s");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// nmaddf.s
	if ((get_reg1(inst) && OP(05, 10) == 0x3f && get_reg2(inst)) && (get_reg3(inst) && OP(24, 26) == 0x5 && OP(21, 22) == 0x2 && OP(16, 16) == 0x0 && get_reg4(inst))) {
		inst->id = V850_NMADDF_S;
		INSTR("nmaddf.s");
		OPERANDS("%s, %s, %s, %s", R1, R2, R3, R4);
		return true;
	}
	// nmsubf.s
	if ((get_reg1(inst) && OP(05, 10) == 0x3f && get_reg2(inst)) && (get_reg3(inst) && OP(24, 26) == 0x5 && OP(21, 22) == 0x3 && OP(16, 16) == 0x0 && get_reg4(inst))) {
		inst->id = V850_NMSUBF_S;
		INSTR("nmsubf.s");
		OPERANDS("%s, %s, %s, %s", R1, R2, R3, R4);
		return true;
	}
	// recipf.d
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x1e)) {
		inst->id = V850_RECIPF_D;
		INSTR("recipf.d");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// recipf.s
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0xe)) {
		inst->id = V850_RECIPF_S;
		INSTR("recipf.s");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// rsqrtf.d
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x2) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x1e)) {
		inst->id = V850_RSQRTF_D;
		INSTR("rsqrtf.d");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// rsqrtf.s
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x2) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0xe)) {
		inst->id = V850_RSQRTF_S;
		INSTR("rsqrtf.s");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// sqrtf.d
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x0) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x1e)) {
		inst->id = V850_SQRTF_D;
		INSTR("sqrtf.d");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// sqrtf.s
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x0) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0xe)) {
		inst->id = V850_SQRTF_S;
		INSTR("sqrtf.s");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// subf.d
	if ((OP(05, 10) == 0x3f) && (OP(21, 26) == 0x23 && OP(16, 20) == 0x12)) {
		inst->id = V850_SUBF_D;
		INSTR("subf.d");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// subf.s
	if ((get_reg1(inst) && OP(05, 10) == 0x3f && get_reg2(inst)) && (get_reg3(inst) && OP(21, 26) == 0x23 && OP(16, 20) == 0x2)) {
		inst->id = V850_SUBF_S;
		INSTR("subf.s");
		OPERANDS("%s, %s, %s", R1, R2, R3);
		return true;
	}
	// trfsr
	if ((OP(11, 15) == 0x0 && OP(05, 10) == 0x3f && OP(00, 04) == 0x0) && (OP(27, 31) == 0x0 && OP(21, 26) == 0x20 && OP(20, 20) == 0x0 && OP(16, 16) == 0x0)) {
		inst->id = V850_TRFSR;
		INSTR("trfsr");
		OPERANDS("%d", slice(inst->d, 17, 19));
		return true;
	}
	// trncf.dl
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x14)) {
		inst->id = V850_TRNCF_DL;
		INSTR("trncf.dl");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// trncf.dul
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x11) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x14)) {
		inst->id = V850_TRNCF_DUL;
		INSTR("trncf.dul");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// trncf.duw
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x11) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x10)) {
		inst->id = V850_TRNCF_DUW;
		INSTR("trncf.duw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// trncf.dw
	if ((OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x10)) {
		inst->id = V850_TRNCF_DW;
		INSTR("trncf.dw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// trncf.sl
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x4)) {
		inst->id = V850_TRNCF_SL;
		INSTR("trncf.sl");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// trncf.sul
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x11) && (OP(21, 26) == 0x22 && OP(16, 20) == 0x4)) {
		inst->id = V850_TRNCF_SUL;
		INSTR("trncf.sul");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// trncf.suw
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x11) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x0)) {
		inst->id = V850_TRNCF_SUW;
		INSTR("trncf.suw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	// trncf.sw
	if ((get_reg2(inst) && OP(05, 10) == 0x3f && OP(00, 04) == 0x1) && (get_reg3(inst) && OP(21, 26) == 0x22 && OP(16, 20) == 0x0)) {
		inst->id = V850_TRNCF_SW;
		INSTR("trncf.sw");
		OPERANDS("%s, %s", R2, R3);
		return true;
	}
	return false;
}

int v850_decode_command(const ut8 *bytes, int len, V850_Inst *inst) {
	if (len < 2) {
		return -1;
	}
	RzBuffer *b = rz_buf_new_with_pointers(bytes, len, false);
	if (!b) {
		return -1;
	}

	for (int i = 0; i < RZ_MIN(8, len) / 2; ++i) {
		ut16 tmp;
		if (!rz_buf_read_le16(b, &tmp)) {
			goto err;
		}
		inst->d |= (ut64)(tmp) << (i * 16);
	}

	inst->byte_size = 2;
	if (decode_formatI(inst) ||
		decode_formatII(inst) ||
		decode_formatIII(inst) ||
		decode_formatIV_1(inst) ||
		decode_formatIV_2(inst)) {
		goto ok;
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
		decode_formatXIII(inst, b) ||
		v850_decode_formatUnk_float(inst)) {
		goto ok;
	}

	inst->byte_size = 6;
	if (decode_formatXIV(inst)) {
		goto ok;
	}
	goto err;

ok:
	rz_buf_free(b);
	return inst->byte_size;
err:
	inst->byte_size = -1;
	rz_buf_free(b);
	return -1;
}
