// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _8051_IL_H_
#define _8051_IL_H_

#include <rz_types.h>
#include <rz_il.h>
#include <rz_analysis.h>

typedef enum {
	I_UNDEFINED = 0,
	I_ACALL, /// Absolute Call
	I_ADD, /// Add Accumulator
	I_ADDC, /// Add Accumulator (With Carry)
	I_AJMP, /// Absolute Jump
	I_ANL, /// Bitwise AND
	I_CJNE, /// Compare and Jump if Not Equal
	I_CLR, /// Clear Register
	I_CPL, /// Complement Register
	I_DA, /// Decimal Adjust
	I_DEC, /// Decrement Register
	I_DIV, /// Divide Accumulator by B
	I_DJNZ, /// Decrement Register and Jump if Not Zero
	I_INC, /// Increment Register
	I_JB, /// Jump if Bit Set
	I_JBC, /// Jump if Bit Set and Clear Bit
	I_JC, /// Jump if Carry Set
	I_JMP, /// Jump to Address
	I_JNB, /// Jump if Bit Not Set
	I_JNC, /// Jump if Carry Not Set
	I_JNZ, /// Jump if Accumulator Not Zero
	I_JZ, /// Jump if Accumulator Zero
	I_LCALL, /// Long Call
	I_LJMP, /// Long Jump
	I_MOV, /// Move Memory
	I_MOVC, /// Move Code Memory
	I_MOVX, /// Move Extended Memory
	I_MUL, /// Multiply Accumulator by B
	I_NOP, /// No Operation
	I_ORL, /// Bitwise OR
	I_POP, /// Pop Value From Stack
	I_PUSH, /// Push Value Onto Stack
	I_RET, /// Return From Subroutine
	I_RETI, /// Return From Interrupt
	I_RL, /// Rotate Accumulator Left
	I_RLC, /// Rotate Accumulator Left Through Carry
	I_RR, /// Rotate Accumulator Right
	I_RRC, /// Rotate Accumulator Right Through Carry
	I_SETB, /// Set Bit
	I_SJMP, /// Short Jump
	I_SUBB, /// Subtract From Accumulator With Borrow
	I_SWAP, /// Swap Accumulator Nibbles
	I_XCH, /// Exchange Bytes
	I_XCHD, /// Exchange Digits
	I_XRL, /// Bitwise Exclusive OR
} I8051OpInst;

/// https://www.win.tue.nl/~aeb/comp/8051/set8051.html

// clang-format off
static const I8051OpInst i8051_inst_tbl[256] = {
         /* 0x00,  0x01,  0x02,   0x03,   0x04,  0x05,  0x06,  0x07,  0x08,  0x09,  0x0a,  0x0b,  0x0c,  0x0d,  0x0e,  0x0f */
 /* 0x00 */ I_NOP, I_AJMP, I_LJMP, I_RR,  I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC, I_INC,
 /* 0x10 */ I_JBC, I_ACALL,I_LCALL,I_RRC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC, I_DEC,
 /* 0x20 */ I_JB,  I_AJMP, I_RET,  I_RL,  I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD, I_ADD,
 /* 0x30 */ I_JNB, I_ACALL,I_RETI, I_RLC, I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,I_ADDC,
 /* 0x40 */ I_JC,  I_AJMP, I_ORL,  I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL, I_ORL,
 /* 0x50 */ I_JNC, I_ACALL,I_ANL,  I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL, I_ANL,
 /* 0x60 */ I_JZ,  I_AJMP, I_XRL,  I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL, I_XRL,
 /* 0x70 */ I_JNZ, I_ACALL,I_ORL,  I_JMP, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
 /* 0x80 */ I_SJMP,I_AJMP, I_ANL,  I_MOVC,I_DIV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
 /* 0x90 */ I_MOV, I_ACALL,I_MOV,  I_MOVC,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,I_SUBB,
 /* 0xa0 */ I_ORL, I_AJMP, I_MOV,  I_INC, I_MUL, 0,     I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
 /* 0xb0 */ I_ANL, I_ACALL,I_CPL,  I_CPL, I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,I_CJNE,
 /* 0xc0 */ I_PUSH,I_AJMP, I_CLR,  I_CLR, I_SWAP,I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH, I_XCH,
 /* 0xd0 */ I_POP, I_ACALL,I_SETB, I_SETB,I_DA,  I_DJNZ,I_XCHD,I_XCHD,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,I_DJNZ,
 /* 0xe0 */ I_MOVX,I_AJMP, I_MOVX, I_MOVX,I_CLR, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
 /* 0xf0 */ I_MOVX,I_ACALL,I_MOVX, I_MOVX,I_CPL, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV, I_MOV,
};
// clang-format on

typedef enum {
	I8051_ADDRESSING_REGISTER = 0,
	I8051_ADDRESSING_DIRECT,
	I8051_ADDRESSING_INDIRECT,
	I8051_ADDRESSING_IMMEDIATE,
	I8051_ADDRESSING_IMMEDIATE16,
	I8051_ADDRESSING_RELATIVE,
	I8051_ADDRESSING_ABSOLUTE,
	I8051_ADDRESSING_LONG,
	I8051_ADDRESSING_INDEXED,
	I8051_ADDRESSING_BIT,
} I8051AddressingMode;

typedef enum {
	I8051_R0 = 0x00,
	I8051_R1 = 0x01,
	I8051_R2 = 0x02,
	I8051_R3 = 0x03,
	I8051_R4 = 0x04,
	I8051_R5 = 0x05,
	I8051_R6 = 0x06,
	I8051_R7 = 0x07,
	I8051_SP = 0x81,
	I8051_DPL = 0x82,
	I8051_DPH = 0x83,
	I8051_PCON = 0x87,
	I8051_TCON = 0x88,
	I8051_TMOD = 0x89,
	I8051_TL0 = 0x8A,
	I8051_TL1 = 0x8B,
	I8051_TH0 = 0x8C,
	I8051_TH1 = 0x8D,
	I8051_PC,
	I8051_PSW = 0xD0,
	I8051_Z = 0xD1,
	I8051_OV = 0xD2,
	I8051_RS0 = 0xD3,
	I8051_RS1 = 0xD4,
	I8051_N = 0xD5,
	I8051_AC = 0xD6,
	I8051_CY = 0xD7,
	I8051_ACC = 0xE0,
	I8051_B = 0xF0,
	I8051_IE = 0xA8,
	I8051_IP = 0xB8,
	I8051_P0 = 0x80,
	I8051_P1 = 0x90,
	I8051_P2 = 0xA0,
	I8051_P3 = 0xB0,
	I8051_SCON = 0x98,
	I8051_SBUF = 0x99,
	I8051_DPTR,
} I8051Register;

enum I8051_PSW_MASKS {
	PSWMASK_P = 0x01,
	PSWMASK_UNUSED = 0x02,
	PSWMASK_OV = 0x04,
	PSWMASK_RS0 = 0x08,
	PSWMASK_RS1 = 0x10,
	PSWMASK_F0 = 0x20,
	PSWMASK_AC = 0x40,
	PSWMASK_C = 0x80
};

typedef struct {
	RzIODesc *desc;
	ut32 addr;
	const char *name;
} i8051_map_entry;

typedef struct {
	const char *name;
	ut32 map_code;
	ut32 map_idata;
	ut32 map_sfr;
	ut32 map_xdata;
	ut32 map_pdata;
} i8051_cpu_model;

typedef struct {
	const i8051_cpu_model *cpu_curr_model;
	i8051_map_entry mem_map[3];
} i8051_plugin_context;

enum i8051_map_entry_type {
	I8051_IDATA = 0,
	I8051_SFR = 1,
	I8051_XDATA = 2,
};

struct i8051_op_t;

typedef struct i8051_op_addressing_t {
	struct i8051_op_t *op;
	I8051AddressingMode mode;
	i8051_plugin_context *ctx;
	union {
		I8051Register reg;
		ut8 addr;
		ut16 addr16;
		struct i8051_op_addressing_t *indirect;
	} d;
} I8051OpAddressing;

typedef struct i8051_op_t {
	ut64 pc;
	ut8 opcode;
	ut8 len;
	I8051OpInst inst;
	ut8 argc;
	I8051OpAddressing **argv;
} I8051Op;

RZ_IPI I8051Op *rz_8051_op_parse(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL const ut8 *buf, int len, ut64 pc);
RZ_IPI RzILOpEffect *rz_8051_il_op(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL const ut8 *buf, int len, ut64 pc);
RZ_IPI RzAnalysisILConfig *rz_8051_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif //_8051_IL_H_
