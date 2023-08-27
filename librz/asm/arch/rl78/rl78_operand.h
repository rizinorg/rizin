// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RL78_OP_H
#define RL78_OP_H

#include <rz_util.h>
#include <rz_types.h>

typedef enum RL78Label {
	// 8-bit general-purpose registers
	RL78_GPR_X,
	RL78_GPR_A,
	RL78_GPR_C,
	RL78_GPR_B,
	RL78_GPR_E,
	RL78_GPR_D,
	RL78_GPR_L,
	RL78_GPR_H,

	// 16-bit general-purpose registers
	RL78_GPR_AX,
	RL78_GPR_BC,
	RL78_GPR_DE,
	RL78_GPR_HL,

	// special function registers
	RL78_SFR_MEM,
	RL78_SFR_PMC, // processor mode control
	RL78_SFR_ES, // higher part of address for data access
	RL78_SFR_CS, // higher part of address for branching
	RL78_SFR_PSW, // program status word
	RL78_SFR_SPH,
	RL78_SFR_SPL,

	// control registers
	RL78_CR_PC, // program counter
	RL78_CR_PSW, // program status word
	RL78_CR_SP, // stack pointer

	// register banks
	RL78_RB_RB0,
	RL78_RB_RB1,
	RL78_RB_RB2,
	RL78_RB_RB3,

	// program status word bits and flags
	RL78_PSW_CY, // carry
	RL78_PSW_AC, // auxiliary carry
	RL78_PSW_Z, // zero

	_RL78_SYMBOL_COUNT
} RL78Label;

typedef enum RL78OperandType {
	RL78_OP_TYPE_NONE, // used for instructions with less than 2 operands
	RL78_OP_TYPE_IMMEDIATE_8, // #byte
	RL78_OP_TYPE_IMMEDIATE_16, // #word

	// operands of type SFR and SADDR will be parsed into
	// RL78_OP_TYPE_SYMBOL if they point to a labeled address
	RL78_OP_TYPE_SFR, // special function register
	RL78_OP_TYPE_SADDR, // short addressing
	RL78_OP_TYPE_SYMBOL, // A, X, BC
	RL78_OP_TYPE_DECIMAL, // only used for shifts

	RL78_OP_TYPE_ABSOLUTE_ADDR_16, // !...
	RL78_OP_TYPE_ABSOLUTE_ADDR_20, // !!...
	RL78_OP_TYPE_RELATIVE_ADDR_8, // $...
	RL78_OP_TYPE_RELATIVE_ADDR_16, // $!...
	RL78_OP_TYPE_INDIRECT_ADDR, // [HL]
	RL78_OP_TYPE_BASED_ADDR_8, // [HL+byte]
	RL78_OP_TYPE_BASED_ADDR_16, // word[HL]
	RL78_OP_TYPE_BASED_INDEX_ADDR, // [HL+C]

	_RL78_OP_TYPE_COUNT
} RL78OperandType;

typedef enum RL78OperandFlags {
	RL78_OP_FLAG_BA = 1 << 0, // bit addressing (bit index stored in v1)
	RL78_OP_FLAG_ES = 1 << 1 // extension addressing
} RL78OperandFlags;

typedef struct RL78Operand {
	int v0; // contains label enum if applicable or immediate data
	int v1; // contains additional data like the offset for based addressing
	int flags;
	RL78OperandType type;
} RL78Operand;

/**
 * \brief Convert an RL78 operand to a string
 * \param dst A caller-supplied character buffer to print into
 * \param n Size of dst
 * \param operand RL78 operand to be printed
 * \return false If operand->type is out of range or equal to RL78_OP_TYPE_NONE
 */
bool rl78_operand_to_string(RzStrBuf RZ_OUT *dst, const RL78Operand RZ_BORROW *operand);

/**
 * \brief Check whether a symbol is valid, i.e. is in enum bounds
 * \param symbol A symbol
 * \return false If symbol is out of range (i.e. < 0 or >= _RL78_SYMBOL_COUNT)
 */
bool rl78_symbol_valid(int symbol);

#endif
