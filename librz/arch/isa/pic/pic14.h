// SPDX-FileCopyrightText: 2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PIC14_H
#define PIC14_H

#include <rz_types.h>
#include <rz_asm.h>

static inline bool is_pic14(const char *x) {
	return RZ_STR_EQ(x, "baseline") ||
		RZ_STR_EQ(x, "pic14");
}

typedef enum {
	PIC14_OP_ARGS_NONE = 0,
	PIC14_OP_ARGS_2F,
	PIC14_OP_ARGS_3F,
	PIC14_OP_ARGS_3K,
	PIC14_OP_ARGS_1D_5F,
	PIC14_OP_ARGS_5F,
	PIC14_OP_ARGS_3B_5F,
	PIC14_OP_ARGS_8K,
	PIC14_OP_ARGS_9K
} PicBaselineOpArgs;

#define PIC14_OP_ARGS_2F_MASK_F    0x3
#define PIC14_OP_ARGS_3F_MASK_F    0x7
#define PIC14_OP_ARGS_3K_MASK_K    0x7
#define PIC14_OP_ARGS_1D_5F_MASK_D (1 << 5)
#define PIC14_OP_ARGS_1D_5F_MASK_F 0x1f
#define PIC14_OP_ARGS_5F_MASK_F    0x1f
#define PIC14_OP_ARGS_3B_5F_MASK_B (0x7 << 5)
#define PIC14_OP_ARGS_3B_5F_MASK_F 0x1f
#define PIC14_OP_ARGS_8K_MASK_K    0xff
#define PIC14_OP_ARGS_9K_MASK_K    0x1ff

typedef struct _pic14_op {
	const char *mnemonic;
	PicBaselineOpArgs args;
} PicBaselineOpInfo;

typedef enum {
	PIC14_OPCODE_NOP = 0,
	PIC14_OPCODE_OPTION,
	PIC14_OPCODE_SLEEP,
	PIC14_OPCODE_CLRWDT,
	PIC14_OPCODE_TRIS,
	PIC14_OPCODE_MOVLB,
	PIC14_OPCODE_RETURN,
	PIC14_OPCODE_RETFIE,
	PIC14_OPCODE_MOVWF,
	PIC14_OPCODE_CLRF,
	PIC14_OPCODE_CLRW,
	PIC14_OPCODE_SUBWF,
	PIC14_OPCODE_DECF,
	PIC14_OPCODE_IORWF,
	PIC14_OPCODE_ANDWF,
	PIC14_OPCODE_XORWF,
	PIC14_OPCODE_ADDWF,
	PIC14_OPCODE_MOVF,
	PIC14_OPCODE_COMF,
	PIC14_OPCODE_INCF,
	PIC14_OPCODE_DECFSZ,
	PIC14_OPCODE_RRF,
	PIC14_OPCODE_RLF,
	PIC14_OPCODE_SWAPF,
	PIC14_OPCODE_INCFSZ,
	PIC14_OPCODE_BCF,
	PIC14_OPCODE_BSF,
	PIC14_OPCODE_BTFSC,
	PIC14_OPCODE_BTFSS,
	PIC14_OPCODE_RETLW,
	PIC14_OPCODE_CALL,
	PIC14_OPCODE_GOTO,
	PIC14_OPCODE_MOVLW,
	PIC14_OPCODE_IORLW,
	PIC14_OPCODE_ANDLW,
	PIC14_OPCODE_XORLW,
	PIC14_OPCODE_INVALID
} PicBaselineOpcode;

PicBaselineOpcode pic14_get_opcode(ut16 instr);
PicBaselineOpArgs pic14_get_opargs(PicBaselineOpcode opcode);
const PicBaselineOpInfo *pic14_get_op_info(PicBaselineOpcode opcode);
int pic14_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *b, int l);

#endif // PIC14_H
