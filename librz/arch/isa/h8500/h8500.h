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
	H8500_BYTE_OPERAND,
	H8500_WORD_OPERAND,
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
	Addr8 = 3 << 8,
	Addr16 = 3 << 8,
	Data8 = 3 << 8,
	Data16 = 3 << 8,
	Sz = 0b1 << 16,
	MASK_CONST = 0xff,
	END = 0b1 << 31,
} H8500OperandNibbleFlag;

typedef uint32_t H8500Nibble;

typedef struct {
	H8500AddrssingMode addr_mode;
	uint8_t ea_width; // 8 or 16
	const char *mnemonic;
	H8500Nibble nibbles[4];
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
	H8500Nibble nibbles[4];
	uint8_t args[4];
} H8500OpcodeDescribe;

typedef struct {
	const H8500OpcodeDescribe *opcode_describe;
	const H8500EADescribe *ea_describe;
	uint8_t size;
	uint8_t bytes[4];
} H8500Instruction;

bool h8500_instruction_parse(const ut8 *buf, ut8 len, H8500Instruction *ins);

#endif // H8500_H
