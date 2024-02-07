#ifndef RX_ARCH_INST_H
#define RX_ARCH_INST_H

#include "rx_datasheet.h"

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
	RX_COND_BEQ, // BZ
	RX_COND_BNE, // BNZ
	RX_COND_GEU, // BC
	RX_COND_BLTU, // BNC
	RX_COND_BGTU,
	RX_COND_BLEU,
	RX_COND_BPZ,
	RX_COND_BN,
	RX_COND_BGE,
	RX_COND_BLT,
	RX_COND_BGT,
	RX_COND_BLE,
	RX_COND_BO,
	RX_COND_BNO,
	RX_COND_BRA,
	RX_COND_RESERVED,
	RX_COND_JUMP,
} RxOpCondMark;

typedef struct {
	RxOpCondMark cond;
	ut8 pc_dsp_len;
	ut32 pc_dsp_val;
} RxOperandCond;

typedef struct {
	bool as_indirect;
	ut8 dsp_width;
	RxOpExtMark memex;
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
RxOperandFlag rx_cb_map[16] = {
	RX_FLAG_C,
	RX_FLAG_Z,
	RX_FLAG_S,
	RX_FLAG_O,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_I,
	RX_FLAG_U,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
	RX_FLAG_RESERVED,
};

RxReg rx_cr_map[32] = {
	RX_REG_PSW,
	RX_REG_PC,
	RX_REG_USP,
	RX_REG_FPSW,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_BPSW,
	RX_REG_BPC,
	RX_REG_ISP,
	RX_REG_FINTV,
	RX_REG_INTB,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,

	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
	RX_REG_RESERVED,
};

bool rx_try_match_and_parse(RZ_OUT RxInst *inst, RxDesc *desc, st32 RZ_OUT *bytes_read, ut64 bytes);

#endif
