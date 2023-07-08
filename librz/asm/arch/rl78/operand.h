// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RL78_OPERAND_H
#define RL78_OPERAND_H

#include <stddef.h>
#include <stdbool.h>

#include <rz_types.h>

extern const char *RL78_STRINGS_SYMBOLS[];

enum rl78_symbols : ut8 {
        // 8-bit general-purpose registers
        RL78_GPR_X, RL78_GPR_A, RL78_GPR_C, RL78_GPR_B,
        RL78_GPR_E, RL78_GPR_D, RL78_GPR_L, RL78_GPR_H,

        // 16-bit general-purpose registers
        RL78_GPR_AX, RL78_GPR_BC, RL78_GPR_DE, RL78_GPR_HL,

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

        _RL78_SYMBOL_COUNT
};

enum rl78_operand_type : ut8 {
        RL78_OPERAND_TYPE_NONE, // used for instructions with less than 2 operands
        RL78_OPERAND_TYPE_IMMEDIATE_8, // #byte
        RL78_OPERAND_TYPE_IMMEDIATE_16, // #word
        RL78_OPERAND_TYPE_SYMBOL, // A, X, BC
        RL78_OPERAND_TYPE_ABSOLUTE_ADDR_16, // !...
        RL78_OPERAND_TYPE_ABSOLUTE_ADDR_20, // !!...
        RL78_OPERAND_TYPE_RELATIVE_ADDR_8, // $...
        RL78_OPERAND_TYPE_RELATIVE_ADDR_16, // $!...
        RL78_OPERAND_TYPE_INDIRECT_ADDR, // [HL]
        RL78_OPERAND_TYPE_BASED_ADDR, // [HL+byte]
        RL78_OPERAND_TYPE_BASED_INDEX_ADDR, // [HL+C]

        _RL78_OPERAND_TYPE_COUNT
};

struct rl78_operand {
        ut16 v0; // contains label enum if applicable or immediate data
        ut16 v1; // contains additional data like the offset for based addressing
        bool extension_addressing; // whether ES is used as 4 bit address extension
        enum rl78_operand_type type;
};

/**
 * \brief Convert an RL78 operand to a string
 * \param dst A caller-supplied character buffer to print into
 * \param n Size of dst
 * \param operand RL78 operand to be printed
 * \return false if operand->type is out of range or equal to RL78_OPERAND_TYPE_NONE
 */
bool rl78_operand_to_string(char *dst, size_t n,
                            const struct rl78_operand *operand);

#endif
