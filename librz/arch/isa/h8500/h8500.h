// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef H8500_H
#define H8500_H
#include <stdbool.h>
#include <stdint.h>
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

static const ut64 Rrr = 1 << 8;
static const ut64 Disp8 = 1 << (8 + 1);
static const ut64 Disp16 = 1 << (8 + 2);
static const ut64 AA8 = 1 << (8 + 3);
static const ut64 AA16 = 1 << (8 + 4);
static const ut64 Data8 = 1 << (8 + 5);
static const ut64 Data16 = 1 << (8 + 6);
static const ut64 Placeholder = 1 << (8 + 7);
static const ut64 Sz = 1 << 16;
static const ut64 HasOperand = 1 << 17;
static const ut64 DST = 1 << 18;
static const ut64 SRC = 1 << 19;
static const ut64 Crr = 1 << 20;
static const ut64 cc = 1 << 21;
static const ut64 Data4 = 1 << 22;
static const ut64 RegList = 1 << 23; // 24-31 = MASK_CONS
static const ut64 EA = 1ull << 32; // 59-62 = Operand index
static const ut64 HasINDEX = 1ull << 33;
static const ut64 ImpliedR6 = 1ull << 34;
static const ut64 AA24 = 1ull << 35;
static const ut64 END = 1ull << 63;

static const ut64 MASK_CONST_OFF = 24;
static const ut64 MASK_CONST = 0xff << MASK_CONST_OFF;
static const ut64 MASK_INDEX_OFF = 59;
static const ut64 MASK_INDEX = 0xfull << MASK_INDEX_OFF;
static const ut64 MASK_Rrr = 0b111;
static const ut64 MASK_Sz = 0b1000;
static const ut64 MASK_AddressingMode = 0xff;
static const ut64 MASK_cc = 0xf;
static const ut64 MASK_Data4 = 0xf;

typedef ut64 H8500Pat;

typedef struct {
	ut64 flags;
	uint8_t ea_width; // 8 or 16
	const char *mnemonic;
	H8500Pat pats[8];
	uint8_t size;
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
	PTTS,
} H8500InstructionId;

// EA flags
enum { EA_UNK,
	EA_BanIMM };

typedef struct {
	H8500InstructionId id;
	const char *mnemonic;
	const char *op_mnemonic;
	uint8_t size;
	H8500Pat pats[8];
	H8500Pat args[8];
	ut32 ea_flags;
} H8500OpcodeDescribe;

typedef struct {
	ut64 flags;
	union {
		uint32_t aa;
		uint32_t imm;
		int32_t disp;
		uint8_t rn;
		struct {
			uint8_t rn;
			int32_t disp;
		} ri_disp;
	};
} H8500Operand;

typedef struct {
	const H8500OpcodeDescribe *opcode_describe;
	const H8500EADescribe *ea_describe;
	uint8_t size;
	uint8_t condition_code;
	uint8_t bytes[4];
	H8500Operand operands[4];
	ut8 num_operands;
	H8500Operand ea;
	H8500OperandSize operand_size;
	char mnemonic[16];
	char ops_str[32];
} H8500Instruction;

bool h8500_instruction_parse(const ut8 *buf, ut8 len, H8500Instruction *ins);

#endif // H8500_H
