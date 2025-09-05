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

typedef enum {
	H8500_W_8 = 8,
	H8500_W_16 = 16,
} H8500OperandWidth; // disp8/disp16, imm8/imm16 or abs8/abs16

typedef enum {
	ADD_Q
} H8500InstructionId;

typedef struct {
	H8500InstructionId id;
} H8500Instruction;

void h8500_instruction_parse(const ut8 *buf, ut8 len, H8500Instruction *ins);

#endif // H8500_H
