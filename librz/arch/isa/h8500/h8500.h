// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef H8500_H
#define H8500_H
#include <stdbool.h>
#include <stdint.h>
#include <rz_types.h>

typedef enum {
	H8500_RD,
	H8500_RI,
	H8500_RI_DISP,
	H8500_RI_PRE_DEC,
	H8500_RI_POST_INC,
	H8500_ABS_ADDR,
	H8500_IMM,
	H8500_PC_REL,
} H8500AddrssingMode;

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
	Rrr = 1 << 8,
	Disp8 = 2 << 8,
	Disp16 = 3 << 8,
	Addr8 = 4 << 8,
	Addr16 = 5 << 8,
	Data8 = 6 << 8,
	Data16 = 7 << 8,
	Placeholder = 8 << 8,
	Sz = 0b1 << 16,
	END = 0b1 << 31,
} H8500OperandNibbleFlag;

enum {
	MASK_CONST = 0xff,
	MASK_Rrr = 0b111,
	MASK_Sz = 0b1000,
};

typedef uint32_t H8500Pat;

typedef struct {
	H8500AddrssingMode addr_mode;
	uint8_t ea_width; // 8 or 16
	const char *mnemonic;
	H8500Pat pats[8];
	uint8_t size;
} H8500EADescribe;

typedef enum {
	ADD_Q
} H8500InstructionId;

typedef struct {
	H8500InstructionId id;
	const char *mnemonic;
	const char *op_mnemonic;
	uint8_t size;
	H8500Pat pats[4];
	uint8_t args[4];
} H8500OpcodeDescribe;

typedef struct {
	H8500AddrssingMode mode;
	H8500OperandSize operand_size;
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
	char op_str[16];
} H8500Operand;

typedef struct {
	const H8500OpcodeDescribe *opcode_describe;
	const H8500EADescribe *ea_describe;
	uint8_t size;
	uint8_t bytes[4];
	H8500Operand operands[4];
	H8500Operand ea;
	char ops_str[32];
} H8500Instruction;

bool h8500_instruction_parse(const ut8 *buf, ut8 len, H8500Instruction *ins);

#endif // H8500_H
