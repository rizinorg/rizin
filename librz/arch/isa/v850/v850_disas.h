// SPDX-FileCopyrightText: 2014-2018 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_V850_DISASM_H
#define RZ_V850_DISASM_H

#define V850_INSTR_MAXLEN    16
#define V850_OPERANDS_MAXLEN 32

typedef enum {
	V850_MOV = 0x0,
	V850_NOT = 0x1,
	V850_DIVH = 0x2,
	V850_JMP = 0x3,
	V850_SATSUBR = 0x4,
	V850_SATSUB = 0x5,
	V850_SATADD = 0x6,
	V850_MULH = 0x7,
	V850_OR = 0x8,
	V850_XOR = 0x9,
	V850_AND = 0xA,
	V850_TST = 0xB,
	V850_SUBR = 0xC,
	V850_SUB = 0xD,
	V850_ADD = 0xE,
	V850_CMP = 0xF,
	V850_SLDB,
	V850_SSTB = 0x1C,
	V850_SLDH = 0x20,
	V850_SSTH = 0x24,
	V850_SLDW = 0x28,
	V850_SSTW = 0x29,
	V850_BCOND,
	V850_ADDI = 0x30,
	V850_MOVEA = 0x31,
	V850_MOVHI = 0x32,
	V850_SATSUBI = 0x33,
	V850_ORI = 0x34,
	V850_XORI = 0x35,
	V850_ANDI = 0x36,
	V850_MULHI = 0x37,
	V850_LDB = 0x38,
	V850_LDH,
	V850_LDW,
	V850_LDBU,
	V850_LDHU,
	V850_LDDW,
	V850_SLDBU,
	V850_SLDHU,

	V850_STB,
	V850_STH,
	V850_STW,
	V850_STDW,

	V850_MULU,
	V850_MAC,
	V850_MACU,
	V850_ADF,
	V850_SBF,

	V850_BINS,
	V850_BSH,
	V850_BSW,
	V850_CMOV,
	V850_HSH,
	V850_HSW,
	V850_ROTL,
	V850_SAR,
	V850_SASF,
	V850_SETF,
	V850_SHL,
	V850_SHR,
	V850_SXB,
	V850_SXH,
	V850_ZXB,
	V850_ZXH,

	V850_SCH0L,
	V850_SCH0R,
	V850_SCH1L,
	V850_SCH1R,

	V850_DIVHU,
	V850_DIVU,
	V850_DIVQ,
	V850_DIVQU,

	V850_LOOP,

	V850_SET1,
	V850_NOT1,
	V850_CLR1,
	V850_TST1,

	V850_JARL,
	V850_JR,
	V850_DIV,
	V850_MUL,

	V850_CALLT,
	V850_CAXI,
	V850_CLL,
	V850_CTRET,
	V850_DI,
	V850_DISPOSE,
	V850_EI,
	V850_EIRET,
	V850_FERET,
	V850_FETRAP,
	V850_HALT,
	V850_LDSR,
	V850_LDLW,
	V850_NOP,
	V850_POPSP,
	V850_PREPARE,
	V850_PUSHSP,
	V850_RIE,
	V850_SNOOZE,
	V850_STSR,
	V850_STCW,
	V850_SWITCH,
	V850_SYNCE,
	V850_SYNCI,
	V850_SYNCM,
	V850_SYNCP,
	V850_SYSCALL,
	V850_TRAP,

	V850_CACHE,
	V850_PREF,

	V850_ABSF_D,
	V850_ABSF_S,

	V850_ADDF_D,
	V850_ADDF_S,

	V850_CEILF_DL,
	V850_CEILF_DUL,
	V850_CEILF_DUW,
	V850_CEILF_DW,
	V850_CEILF_SL,
	V850_CEILF_SUL,
	V850_CEILF_SUW,
	V850_CEILF_SW,

	V850_CMOVF_D,
	V850_CMOVF_S,

	V850_CMPF_D,
	V850_CMPF_S,

	V850_CVTF_DL,
	V850_CVTF_DS,
	V850_CVTF_DUL,
	V850_CVTF_DUW,
	V850_CVTF_DW,
	V850_CVTF_LD,
	V850_CVTF_LS,
	V850_CVTF_SD,
	V850_CVTF_SL,
	V850_CVTF_SUL,
	V850_CVTF_SUW,
	V850_CVTF_SW,
	V850_CVTF_ULD,
	V850_CVTF_ULS,
	V850_CVTF_UWD,
	V850_CVTF_UWS,
	V850_CVTF_WD,
	V850_CVTF_WS,

	V850_DIVF_D,
	V850_DIVF_S,

	V850_FLOORF_DL,
	V850_FLOORF_DUL,
	V850_FLOORF_DUW,
	V850_FLOORF_DW,
	V850_FLOORF_SL,
	V850_FLOORF_SUL,
	V850_FLOORF_SUW,
	V850_FLOORF_SW,

	V850_MADDF_S,

	V850_MAXF_D,
	V850_MAXF_S,

	V850_MINF_D,
	V850_MINF_S,

	V850_MSUBF_S,

	V850_MULF_D,
	V850_MULF_S,

	V850_NEGF_D,
	V850_NEGF_S,

	V850_NMADDF_S,
	V850_NMSUBF_S,

	V850_RECIPF_D,
	V850_RECIPF_S,

	V850_RSQRTF_D,
	V850_RSQRTF_S,

	V850_SQRTF_D,
	V850_SQRTF_S,

	V850_SUBF_D,
	V850_SUBF_S,

	V850_TRFSR,

	V850_TRNCF_DL,
	V850_TRNCF_DUL,
	V850_TRNCF_DUW,
	V850_TRNCF_DW,
	V850_TRNCF_SL,
	V850_TRNCF_SUL,
	V850_TRNCF_SUW,
	V850_TRNCF_SW,
} V850_InstID;

enum v850_conds {
	V850_COND_BV = 0x0, // Overflow
	V850_COND_BL = 0x1, // Carry/Lower
	V850_COND_BE = 0x2, // Zero/equal
	V850_COND_BNH = 0x3, // Not higher
	V850_COND_BN = 0x4, // Negative
	V850_COND_BR = 0x5, // Always
	V850_COND_BLT = 0x6, // Less than signed
	V850_COND_BLE = 0x7, // Less than or equal signed
	V850_COND_BNV = 0x8, // No overflow
	V850_COND_BNL = 0x9, // No carry / not lower
	V850_COND_BNE = 0xA, // Not zero / not equal
	V850_COND_BH = 0xB, // Higher/Greater than
	V850_COND_BP = 0xC, // Positive / not sign
	V850_COND_BSA = 0xD, // Saturated
	V850_COND_BGE = 0xE, // Greater than or equal signed
	V850_COND_BGT = 0xF, // Greater than signed
};

enum v850_regs {
	V850_ZERO = 0x0,
	V850_R1 = 0x1,
	V850_R2 = 0x2,
	V850_SP = 0x3,
	V850_GP = 0x4,
	V850_TP = 0x5,
	V850_R6 = 0x6,
	V850_R7 = 0x7,
	V850_R8 = 0x8,
	V850_R9 = 0x9,
	V850_R10 = 0xA,
	V850_R11 = 0xB,
	V850_R12 = 0xC,
	V850_R13 = 0xD,
	V850_R14 = 0xE,
	V850_R15 = 0xF,
	V850_R16 = 0x10,
	V850_R17 = 0x11,
	V850_R18 = 0x12,
	V850_R19 = 0x13,
	V850_R20 = 0x14,
	V850_R21 = 0x15,
	V850_R22 = 0x16,
	V850_R23 = 0x17,
	V850_R24 = 0x18,
	V850_R25 = 0x19,
	V850_R26 = 0x1A,
	V850_R27 = 0x1B,
	V850_R28 = 0x1C,
	V850_R29 = 0x1D,
	V850_EP = 0x1E,
	V850_LP = 0x1F,
};

static const char *GR[] = {
	"r0",
	"r1",
	"r2",
	"sp",
	"gp",
	"tp",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	"r16",
	"r17",
	"r18",
	"r19",
	"r20",
	"r21",
	"r22",
	"r23",
	"r24",
	"r25",
	"r26",
	"r27",
	"r28",
	"r29",
	"ep", // EP
	"lp", // LP
	/*PC*/
};

static inline const char *GR_get(ut8 i) {
	if (i >= RZ_ARRAY_SIZE(GR)) {
		rz_warn_if_reached();
		return NULL;
	}
	return GR[i];
}

/*
 * \see Section 3.3-3.5  https://www.renesas.com/us/en/document/mas/rh850g3kh-users-manual-software
 * */
static inline const char *SR_get(ut8 regID, ut8 selID) {
	if (selID == 0) {
		switch (regID) {
		case 0: return "EIPC";
		case 1: return "EIPSW";
		case 2: return "FEPC";
		case 3: return "FEPSW";
		case 4: return "ECR";
		case 5: return "PSW";
		case 6: return "FPSR";
		case 7: return "FPEPC";
		case 8: return "FPST";
		case 9: return "FPCC";
		case 10: return "FPCFG";
		case 11: return "FPEC";
		case 13: return "EIIC";
		case 14: return "FEIC";
		case 16: return "CTPC";
		case 17: return "CTPSW";
		case 20: return "CTBP";
		case 28: return "EIWR";
		case 29: return "FEWR";
		case 31: return "BSEL";
		default: break;
		}
	} else if (selID == 1) {
		switch (regID) {
		case 0: return "MCFG0";
		case 2: return "RBASE";
		case 3: return "EBASE";
		case 4: return "INTBP";
		case 5: return "MCTL";
		case 6: return "PID";
		case 7: return "FPIPR";
		case 11: return "SCCFG";
		case 12: return "SCBP";
		default: break;
		}
	} else if (selID == 2) {
		switch (regID) {
		case 0: return "HTCFG0";
		case 6: return "MEA";
		case 7: return "ASID";
		case 8: return "MEI";
		case 10: return "ISPR";
		case 11: return "PMR";
		case 12: return "ICSR";
		case 13: return "INTCFG";
		default: break;
		}
	} else if (selID == 5) {
		switch (regID) {
		case 0: return "MPM";
		case 1: return "MPRC";
		case 4: return "MPBRGN";
		case 5: return "MPTRGN";
		case 8: return "MCA";
		case 9: return "MCS";
		case 10: return "MCC";
		case 11: return "MCR";
		default: break;
		}
	} else if (selID == 6) {
		switch (regID) {
		case 0: return "MPLA0";
		case 1: return "MPUA0";
		case 2: return "MPAT0";
		case 4: return "MPLA1";
		case 5: return "MPUT1";
		case 6: return "MPAT1";
		case 8: return "MPLA2";
		case 9: return "MPUA2";
		case 10: return "MPAT2";
		case 12: return "MPLA3";
		case 13: return "MPUA3";
		case 14: return "MPAT3";
		case 16: return "MPLA4";
		case 17: return "MPUA4";
		case 18: return "MPAT4";
		case 20: return "MPLA5";
		case 21: return "MPUA5";
		case 22: return "MPAT5";
		case 24: return "MPLA6";
		case 25: return "MPUA6";
		case 26: return "MPAT6";
		case 28: return "MPLA7";
		case 29: return "MPUA7";
		case 30: return "MPAT7";
		default: break;
		}
	} else if (selID == 7) {
		switch (regID) {
		case 0: return "MPLA8";
		case 1: return "MPUA8";
		case 2: return "MPAT8";
		case 4: return "MPLA9";
		case 5: return "MPUT9";
		case 6: return "MPAT9";
		case 8: return "MPLA10";
		case 9: return "MPUA10";
		case 10: return "MPAT10";
		case 12: return "MPLA11";
		case 13: return "MPUA11";
		case 14: return "MPAT11";
		case 16: return "MPLA12";
		case 17: return "MPUA12";
		case 18: return "MPAT12";
		case 20: return "MPLA13";
		case 21: return "MPUA13";
		case 22: return "MPAT13";
		case 24: return "MPLA14";
		case 25: return "MPUA14";
		case 26: return "MPAT14";
		case 28: return "MPLA15";
		case 29: return "MPUA15";
		case 30: return "MPAT15";
		default: break;
		}
	}
	return NULL;
}

enum v850_sysregs {
	V850_SREG_EIPC = 0x0,
	V850_SREG_EIPCW = 0x1,
	V850_SREG_FEPC = 0x2,
	V850_SREG_FEPSW = 0x3,
	V850_SREG_ECR = 0x4,
	V850_SREG_PSW = 0x5,
	V850_SREG_CTPC = 0x10,
	V850_SREG_CTPSW = 0x11,
	V850_SREG_DBPC = 0x12,
	V850_SREG_DBPSW = 0x13,
	V850_SREG_CTBP = 0x14,
	V850_SREG_DIR = 0x15,
};

enum v850_flags {
	V850_FLAG_CY = 1,
	V850_FLAG_OV,
	V850_FLAG_S,
	V850_FLAG_Z,
};

typedef enum {
	I_reg_reg,
	II_imm_reg,
	III_conditional_branch,
	IV_load_store16,
	V_jump,
	VI_3operand,
	VII_load_store32,
	VIII_bit,
	IX_extended1,
	X_extended2,
	XI_extended3,
	XII_extended4,
	XIII_stack,
	XIV_load_store48,
} V850_Inst_Format;

typedef struct {
	ut64 d;
	ut32 imm;
	union {
		ut32 disp;
		st32 sdisp;
	};
	V850_Inst_Format format;
	V850_InstID id;
	ut64 addr;
	ut8 byte_size : 4;
	unsigned type;
	char instr[V850_INSTR_MAXLEN];
	char operands[V850_OPERANDS_MAXLEN];
} V850_Inst;

static inline ut32 extract(ut64 x, ut8 i, ut8 n) {
	return (x >> i) & ((1 << n) - 1);
}

static inline ut16 V850_word(const V850_Inst *i, unsigned index) {
	rz_warn_if_fail(index >= 1 && index <= 4);
	return extract(i->d, (index - 1) * 16, 16);
}

static inline ut16 get_opcode(const V850_Inst *i, unsigned l, unsigned r) {
	return extract(i->d, l, (r - l + 1));
}

static inline ut8 get_reg1(const V850_Inst *i) {
	return V850_word(i, 1) & 0x1F;
}

static inline ut8 get_reg2(const V850_Inst *i) {
	return V850_word(i, 1) >> 11;
}

static inline ut8 get_reg3(const V850_Inst *i) {
	return V850_word(i, 2) >> 11;
}

static inline ut8 xi_reg3(const V850_Inst *i) {
	return ((i->d >> 12) & 0xf) << 1;
}

static inline ut8 xi_reg4(const V850_Inst *i) {
	return ((i->d >> 17) & 0xf) << 1;
}

static inline ut16 get_imm16(const V850_Inst *i) {
	return V850_word(i, 2);
}

static inline ut16 get_disp9(const V850_Inst *i) {
	return (((V850_word(i, 1) >> 4) & 0x7) | ((V850_word(i, 1) >> 11) << 3)) << 1;
}

static inline ut16 get_cond(const V850_Inst *i) {
	return i->d & 0xf;
}

static inline ut16 xi_cond(const V850_Inst *i) {
	return (i->d >> 17) & 0xf;
}

static inline ut32 get_disp22(const V850_Inst *i) {
	return (((i->d >> 16) & 0xffff) | ((i->d & 0x3f) << 16)) & ~1;
}

/**
 * Lists of registers
 * \see xiii_sorted_list
 * \see DISPOSE and PREPARE instruction in section 7.2.2 https://www.renesas.com/us/en/document/mas/rh850g3kh-users-manual-software
 */
static const ut8 V850_list12_map[] = {
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

static inline ut8 i_vec4(const V850_Inst *i) {
	return (i->d >> 11) & 0xf;
}

static inline ut8 viii_bit(const V850_Inst *i) {
	return (V850_word(i, 1) >> 11) & 0x7;
}

static inline ut16 xiii_list(const V850_Inst *i) {
	return ((V850_word(i, 2) >> 5) << 1) | (V850_word(i, 1) & 1);
}

static inline int xiii_ut8_litter(const void *a, const void *b) {
	return ((ut8 *)a)[0] - ((ut8 *)b)[0];
}

static inline int xiii_ut8_greater(const void *a, const void *b) {
	return ((ut8 *)b)[0] - ((ut8 *)a)[0];
}

static inline void xiii_sorted_list(ut32 lst, ut8 set[12], unsigned *pn, bool descending) {
	unsigned n = 0;
	for (ut32 i = 0; i < 12; i++) {
		if (lst & (1 << i)) {
			set[n++] = V850_list12_map[i];
		}
	}
	if (pn) {
		*pn = n;
	}
	qsort(set, n, sizeof(ut8), descending ? xiii_ut8_greater : xiii_ut8_litter);
}

static inline ut8 xiii_ff(const V850_Inst *i) {
	return (V850_word(i, 2) >> 3) & 0b11;
}

static inline ut8 xiii_sub_r1(const V850_Inst *i) {
	return (i->d >> 16) & 0x1f;
}

static inline ut8 xii_imm5(const V850_Inst *i) {
	return i->d & 0x1f;
}
static inline ut8 xiii_imm5(const V850_Inst *i) {
	return (V850_word(i, 1) >> 1) & 0x1f;
}

static inline ut8 get_selID(const V850_Inst *i) {
	return extract(i->d, 27, 5);
}

static inline ut8 bins_msb(const V850_Inst *i) {
	return extract(i->d, 28, 4);
}

static inline ut8 bins_lsb(const V850_Inst *i) {
	return extract(i->d, 17, 3) | (extract(i->d, 27, 1) << 3);
}

static inline ut8 bins_pos(const V850_Inst *i) {
	return bins_lsb(i);
}

static inline ut8 bins_width(const V850_Inst *i) {
	return bins_msb(i) - bins_pos(i) + 1;
}

static inline ut8 xi_rh(const V850_Inst *i) {
	return i->d & 0x1f;
}

static inline ut8 xi_rt(const V850_Inst *i) {
	return (i->d >> (16 + 11)) & 0x1f;
}

static inline ut8 x_vector8(const V850_Inst *i) {
	return (i->d & 0x1f) | (((i->d >> (16 + 11)) & 0x7) << 5);
}

#define STSR_regID (get_reg1(ctx->x))
#define LDSR_regID (get_reg2(ctx->x))

static inline int32_t sext32(uint32_t X, unsigned B) {
	rz_warn_if_fail(B > 0 && B <= 32);
	return (int32_t)(X << (32 - B)) >> (32 - B);
}

int v850_decode_command(const ut8 *bytes, int len, V850_Inst *inst);
#endif /* RZ_V850_DISASM_H */
