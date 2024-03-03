// SPDX-FileCopyrightText: 2024 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RX_ARCH_INST_H
#define RX_ARCH_INST_H

#include "rx_opcode_detail.h"

typedef enum rx_operand_kind_enum {
	RX_OPERAND_NULL,
	RX_OPERAND_IMM,
	RX_OPERAND_REG,
	RX_OPERAND_FLAG,
	RX_OPERAND_COND,
} RxOperandKind;

typedef enum {
	RX_FIXOP_NON,
	RX_FIXOP_POST_INC,
	RX_FIXOP_PRE_DEC
} RxOpFixMark;

typedef enum {
	RX_FLAG_C,
	RX_FLAG_Z,
	RX_FLAG_S,
	RX_FLAG_O,
	RX_FLAG_I,
	RX_FLAG_U,
	RX_FLAG_RESERVED
} RxOperandFlag;

typedef enum {
	RX_COND_EQ, // BZ
	RX_COND_NE, // BNZ
	RX_COND_GEU, // BC
	RX_COND_LTU, // BNC
	RX_COND_GTU,
	RX_COND_LEU,
	RX_COND_PZ,
	RX_COND_N,
	RX_COND_GE,
	RX_COND_LT,
	RX_COND_GT,
	RX_COND_LE,
	RX_COND_O,
	RX_COND_NO,
	RX_COND_RA,
	RX_COND_JUMP,
	RX_COND_RESERVED,
} RxOpCondMark;

typedef struct {
	RxOpCondMark cond;
	ut8 pc_dsp_len;
	ut32 pc_dsp_val;
} RxOperandCond;

typedef struct {
	bool as_indirect;
	bool as_base;
	ut8 dsp_width;
	RxOpExtMark memex;
	RxReg ri;
	RxReg reg;
	RxOpFixMark fix_mode;
	ut32 dsp_val;
} RxOperandReg;

typedef struct {
	ut8 imm_width;
	ut32 imm;
} RxOperandImm;

typedef struct rx_operand_t {
	RxOperandKind kind;
	union {
		RxOperandReg reg;
		RxOperandImm imm;
		RxOperandFlag flag;
		RxOperandCond cond;
	} v;
} RxOperand;

typedef struct rx_inst_t {
	RxOpCode op;
	RxOperand v0;
	RxOperand v1;
	RxOperand v2;
	RxOpExtMark sz_mark;
} RxInst;

// TODO make them into function, not static defined here
// TODO: call in init
extern RxOperandFlag rx_cb_map[16];
extern RxReg rx_cr_map[32];

bool rx_try_match_and_parse(RZ_OUT RxInst *inst, RxDesc *desc, st32 RZ_OUT *bytes_read, ut64 bytes);

#endif
