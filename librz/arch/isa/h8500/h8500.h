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
	AddrRD,
	AddrRI,
	AddrRIDisp,
	AddrRIPreDec,
	AddrRIPostInc,
	AddrAbs,
	AddrIMM,
	AddrPCRel,
	Rrr = 1 << 8,
	Disp8 = 1 << (8 + 1),
	Disp16 = 1 << (8 + 2),
	Addr8 = 1 << (8 + 3),
	Addr16 = 1 << (8 + 4),
	Data8 = 1 << (8 + 5),
	Data16 = 1 << (8 + 6),
	Placeholder = 1 << (8 + 7),
	Sz = 1 << 16,
	HasOperand = 1 << 17,
	DST = 1 << 18,
	SRC = 1 << 19,
	Crr = 1 << 20,
	cc = 1 << 21,
	END = 0b1 << 31,
} H8500OperandFlags;

enum {
	MASK_CONST_OFF = 24,
	MASK_CONST = 0xff << MASK_CONST_OFF,
	MASK_Rrr = 0b111,
	MASK_Sz = 0b1000,
	MASK_AddressingMode = 0xff,
	MASK_cc = 0xf,
};

typedef uint32_t H8500Pat;

typedef struct {
	H8500OperandFlags flags;
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
} H8500InstructionId;

typedef struct {
	H8500InstructionId id;
	const char *mnemonic;
	const char *op_mnemonic;
	uint8_t size;
	H8500Pat pats[8];
	H8500Pat args[8];
} H8500OpcodeDescribe;

typedef struct {
	H8500OperandFlags flags;
	union {
		uint16_t aa;
		uint16_t imm;
		int16_t disp;
		uint8_t rn;
		struct {
			uint8_t rn;
			int16_t disp;
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
