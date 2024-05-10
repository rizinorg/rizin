// SPDX-FileCopyrightText: 2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PIC16_H
#define PIC16_H

#include <rz_asm.h>
#include <rz_types.h>

static inline bool is_pic16(const char *x) {
	return RZ_STR_EQ(x, "midrange") || RZ_STR_EQ(x, "pic16");
}

static inline bool is_pic14_or_pic16(const char *x) {
	return RZ_STR_EQ(x, "baseline") ||
		RZ_STR_EQ(x, "pic14") ||
		is_pic16(x);
}

typedef enum {
	PIC16_OP_ARGS_NONE = 0,
	PIC16_OP_ARGS_2F,
	PIC16_OP_ARGS_7F,
	PIC16_OP_ARGS_1D_7F,
	PIC16_OP_ARGS_1N_6K,
	PIC16_OP_ARGS_3B_7F,
	PIC16_OP_ARGS_4K,
	PIC16_OP_ARGS_8K,
	PIC16_OP_ARGS_9K,
	PIC16_OP_ARGS_11K,
	PIC16_OP_ARGS_1N_2M
} Pic16OpArgs;

#define PIC16_OP_ARGS_2F_MASK_F    0x3
#define PIC16_OP_ARGS_7F_MASK_F    0x7f
#define PIC16_OP_ARGS_1D_7F_MASK_D (1 << 7)
#define PIC16_OP_ARGS_1D_7F_MASK_F 0x7f
#define PIC16_OP_ARGS_1N_6K_MASK_N (1 << 6)
#define PIC16_OP_ARGS_1N_6K_MASK_K 0x3f
#define PIC16_OP_ARGS_3B_7F_MASK_B (0x7 << 7)
#define PIC16_OP_ARGS_3B_7F_MASK_F 0x7f
#define PIC16_OP_ARGS_4K_MASK_K    0xf
#define PIC16_OP_ARGS_8K_MASK_K    0xff
#define PIC16_OP_ARGS_9K_MASK_K    0x1ff
#define PIC16_OP_ARGS_11K_MASK_K   0x7ff
#define PIC16_OP_ARGS_1N_2M_MASK_N (1 << 2)
#define PIC16_OP_ARGS_1N_2M_MASK_M 0x3

typedef struct _pic16_op {
	const char *mnemonic;
	Pic16OpArgs args;
} Pic16OpAsmInfo;

typedef enum {
	PIC16_OPCODE_NOP = 0,
	PIC16_OPCODE_RETURN,
	PIC16_OPCODE_RETFIE,
	PIC16_OPCODE_OPTION,
	PIC16_OPCODE_SLEEP,
	PIC16_OPCODE_CLRWDT,
	PIC16_OPCODE_CLRF,
	PIC16_OPCODE_CLRW,
	PIC16_OPCODE_TRIS,
	PIC16_OPCODE_MOVWF,
	PIC16_OPCODE_SUBWF,
	PIC16_OPCODE_DECF,
	PIC16_OPCODE_IORWF,
	PIC16_OPCODE_ANDWF,
	PIC16_OPCODE_XORWF,
	PIC16_OPCODE_ADDWF,
	PIC16_OPCODE_MOVF,
	PIC16_OPCODE_COMF,
	PIC16_OPCODE_INCF,
	PIC16_OPCODE_DECFSZ,
	PIC16_OPCODE_RRF,
	PIC16_OPCODE_RLF,
	PIC16_OPCODE_SWAPF,
	PIC16_OPCODE_INCFSZ,
	PIC16_OPCODE_BCF,
	PIC16_OPCODE_BSF,
	PIC16_OPCODE_BTFSC,
	PIC16_OPCODE_BTFSS,
	PIC16_OPCODE_CALL,
	PIC16_OPCODE_GOTO,
	PIC16_OPCODE_MOVLW,
	PIC16_OPCODE_RETLW,
	PIC16_OPCODE_IORLW,
	PIC16_OPCODE_ANDLW,
	PIC16_OPCODE_XORLW,
	PIC16_OPCODE_SUBLW,
	PIC16_OPCODE_ADDLW,
	PIC16_OPCODE_RESET,
	PIC16_OPCODE_CALLW,
	PIC16_OPCODE_BRW,
	PIC16_OPCODE_MOVIW_1,
	PIC16_OPCODE_MOVWI_1,
	PIC16_OPCODE_MOVLB,
	PIC16_OPCODE_LSLF,
	PIC16_OPCODE_LSRF,
	PIC16_OPCODE_ASRF,
	PIC16_OPCODE_SUBWFB,
	PIC16_OPCODE_ADDWFC,
	PIC16_OPCODE_ADDFSR,
	PIC16_OPCODE_MOVLP,
	PIC16_OPCODE_BRA,
	PIC16_OPCODE_MOVIW_2,
	PIC16_OPCODE_MOVWI_2,
	PIC16_OPCODE_INVALID
} Pic16Opcode;

typedef struct _pic16_op_args_val {
	ut16 f;
	ut16 k;
	ut8 d;
	ut8 m;
	ut8 n;
	ut8 b;
} Pic16OpArgsVal;

typedef struct {
	const char *mnemonic;
	char operands[32];
	Pic16OpArgs args_tag;
	Pic16OpArgsVal args;
	ut32 addr;
	Pic16Opcode opcode;
	ut32 size;
	ut16 instr;
} Pic16Op;

const char *pic16_regname_with_bank(ut32 reg, ut8 bank);
Pic16Opcode pic16_get_opcode(ut16 instr);
const Pic16OpAsmInfo *pic16_get_op_info(Pic16Opcode opcode);
bool pic16_disasm_op(Pic16Op *op, ut64 addr, const ut8 *b, ut64 len);
int pic16_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *b, int l);

int pic16_op(
	RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask);
char *pic16_get_reg_profile(RzAnalysis *a);
RzAnalysisILConfig *pic16_il_config(
	RZ_NONNULL RzAnalysis *analysis);

#endif // PIC16_H
