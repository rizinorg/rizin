// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef H8500_H
#define H8500_H
#include <rz_types.h>

typedef enum {
	BYTE_OPERAND,
	WORD_OPERAND,
} H8500OperandSize;

/**
 * *1 Sz: Operand size
 * Sz = 0: byte operand
 * Sz = 1: word operand
 * *2 rrr (register number field): General register number
 * 000: R0 001: R1 010: R2 011: R3
 * 100: R4 101: R5 110: R6 111: R7
 */
typedef enum {
	AddrINVALID,
	AddrREG,
	AddrRI,
	AddrRIDisp,
	AddrRIPreDec,
	AddrRIPostInc,
	AddrAbs,
	AddrIMM,
	AddrPCRel,
} H8500AddressingMode;

#define ARG_MASK_AddressingMode (0xff)
#define ARG_MODE(A)             (A & ARG_MASK_AddressingMode)
#define ARG_MASK_DATA           (0xff << 8)
#define ARG_PACK_DATA(A)        ((A << 8) & ARG_MASK_DATA)
#define ARG_DATA(A)             ((A & ARG_MASK_DATA) >> 8)
#define ARG_FLAGS(A)            (A & ~(ARG_MASK_DATA))

#define MASK_CONST_OFF 24
#define MASK_INDEX_OFF 59

typedef enum {
	Rrr = 1 << 8,
	Disp8 = 1 << (8 + 1),
	Disp16 = 1 << (8 + 2),
	AA8 = 1 << (8 + 3),
	AA16 = 1 << (8 + 4),
	Data8 = 1 << (8 + 5),
	Data16 = 1 << (8 + 6),
	Placeholder = 1 << (8 + 7),
	Sz = 1 << 16,
	HasOperand = 1 << 17,
	DST = 1 << 18,
	SRC = 1 << 19,
	Crr = 1 << 20,
	cc = 1 << 21,
	Data4 = 1 << 22,
	RegList = 1 << 23, // 24-31 = MASK_CON,
} H8500PatFlags;

#define EA         (1ull << 32)
#define HasINDEX   (1ull << 33)
#define ImpliedR6  (1ull << 34)
#define AA24       (1ull << 35)
#define VEC        (1ull << 36)
#define END        (1ull << 63)
#define MASK_CONST (0xffull << MASK_CONST_OFF)
#define MASK_INDEX (0xfull << MASK_INDEX_OFF)
#define MASK_Rrr   (0x7ull)
#define MASK_Sz    (0x8ull)
#define MASK_cc    (0xfull)
#define MASK_Data4 (0xfull)

typedef ut64 H8500Pat;
typedef ut64 H8500Arg;

typedef struct {
	ut64 flags;
	const char *mnemonic;
	H8500Pat pats[8];
	ut8 ea_width; // 8 or 16
	ut8 size;
} H8500EADescribe;

typedef enum {
	ADD_Q,
	ADDS,
	ADDX,
	AND,
	ANDC,
	Bcc,
	BCLR,
	BNOT,
	BSET,
	BSR,
	BTST,
	CLR,
	CMP,
	DADD,
	DSUB,
	DIVXU,
	EXTS,
	EXTU,
	JMP,
	JSR,
	LDC,
	LDM,
	LINK,
	MOV,
	MOVFPE,
	MOVTPE,
	MULXU,
	NEG,
	NOP,
	NOT,
	OR,
	ORC,
	PJMP,
	PJSR,
	PRTD,
	PRTS,
	ROTL,
	ROTR,
	ROTXL,
	ROTXR,
	RTD,
	RTE,
	RTS,
	SCB_F,
	SCB_NE,
	SCB_EQ,
	SHAL,
	SHAR,
	SHLL,
	SHLR,
	SLEEP,
	STC,
	STM,
	SUB,
	SUBS,
	SUBX,
	SWAP,
	TAS,
	TRAPA,
	TRAP_VS,
	TST,
	UNLK,
	XCH,
	XOR,
	XORC,
} H8500InstructionId;

typedef enum {
	H8500_R0,
	H8500_R1,
	H8500_R2,
	H8500_R3,
	H8500_R4,
	H8500_R5,
	H8500_R6,
	H8500_R7,
#define H8500_FP H8500_R6
#define H8500_SP H8500_R7
} H8500Register;

// EA flags
enum { EA_UNK,
	EA_BanIMM };

typedef struct {
	H8500InstructionId id;
	const char *mnemonic;
	const char *op_mnemonic;
	ut8 size;
	H8500Pat pats[8];
	H8500Arg args[8];
	ut32 ea_flags;
} H8500OpcodeDescribe;

typedef struct {
	ut64 flags;
	union {
		ut32 aa;
		ut32 imm;
		st32 disp;
		ut8 rn;
		struct {
			ut8 rn;
			st32 disp;
		} ri_disp;
	};
} H8500Operand;

typedef struct {
	const H8500OpcodeDescribe *opcode_describe;
	const H8500EADescribe *ea_describe;
	ut8 size;
	ut8 condition_code;
	H8500Operand operands[4];
	ut8 num_operands;
	H8500Operand ea;
	H8500OperandSize operand_size;
} H8500Instruction;

typedef struct {
	char mnemonic[16];
	char ops_str[32];
} H8500InstructionOpstr;

bool h8500_instruction_parse(const ut8 *buf, int len, H8500Instruction *ins);
bool h8500_instruction_get_opstr(H8500Instruction *ins, H8500InstructionOpstr *opstr);
const char *h8500_reg_name(const H8500Operand *op, ut8 reg);

#endif // H8500_H
