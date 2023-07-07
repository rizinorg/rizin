// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RL78_INSTR_H
#define RL78_INSTR_H

#include "operand.h"

extern const char *RL78_STRINGS_OPERATIONS[];

enum rl78_operation {
        RL78_OPERATION_ADD,
        RL78_OPERATION_ADDC,
        RL78_OPERATION_ADDW,
        RL78_OPERATION_AND,
        RL78_OPERATION_AND1,
        RL78_OPERATION_BC,
        RL78_OPERATION_BF,
        RL78_OPERATION_BH,
        RL78_OPERATION_BNC,
        RL78_OPERATION_BNH,
        RL78_OPERATION_BNZ,
        RL78_OPERATION_BR,
        RL78_OPERATION_BRK,
        RL78_OPERATION_BT,
        RL78_OPERATION_BTCLR,
        RL78_OPERATION_BZ,
        RL78_OPERATION_CALL,
        RL78_OPERATION_CALLT,
        RL78_OPERATION_CLRB,
        RL78_OPERATION_CLRW,
        RL78_OPERATION_CLR1,
        RL78_OPERATION_CMP,
        RL78_OPERATION_CMPS,
        RL78_OPERATION_CMPW,
        RL78_OPERATION_CMP0,
        RL78_OPERATION_DEC,
        RL78_OPERATION_DECW,
        RL78_OPERATION_DI,
        RL78_OPERATION_DIVHU,
        RL78_OPERATION_DIVWU,
        RL78_OPERATION_EI,
        RL78_OPERATION_HALT,
        RL78_OPERATION_INC,
        RL78_OPERATION_INCW,
        RL78_OPERATION_MACH,
        RL78_OPERATION_MACHU,
        RL78_OPERATION_MOV,
        RL78_OPERATION_MOVS,
        RL78_OPERATION_MOVW,
        RL78_OPERATION_MOV1,
        RL78_OPERATION_MULH,
        RL78_OPERATION_MULHU,
        RL78_OPERATION_MULU,
        RL78_OPERATION_NOP,
        RL78_OPERATION_NOT1,
        RL78_OPERATION_ONEB,
        RL78_OPERATION_ONEW,
        RL78_OPERATION_OR,
        RL78_OPERATION_OR1,
        RL78_OPERATION_POP,
        RL78_OPERATION_PUSH,
        RL78_OPERATION_RET,
        RL78_OPERATION_RETB,
        RL78_OPERATION_RETI,
        RL78_OPERATION_ROL,
        RL78_OPERATION_ROLC,
        RL78_OPERATION_ROLWC,
        RL78_OPERATION_ROR,
        RL78_OPERATION_RORC,
        RL78_OPERATION_SAR,
        RL78_OPERATION_SARW,
        RL78_OPERATION_SEL,
        RL78_OPERATION_SET1,
        RL78_OPERATION_SHL,
        RL78_OPERATION_SHLW,
        RL78_OPERATION_SHR,
        RL78_OPERATION_SHRW,
        RL78_OPERATION_SKC,
        RL78_OPERATION_SKH,
        RL78_OPERATION_SKNC,
        RL78_OPERATION_SKNH,
        RL78_OPERATION_SKNZ,
        RL78_OPERATION_SKZ,

        _RL78_OPERATION_COUNT
};

struct rl78_instr {
        struct rl78_operand dst;
        struct rl78_operand src;

        enum rl78_operation operation;
};

/**
 * \brief Convert an RL78 instruction to a string
 * \param dst A caller-supplied character buffer to print into
 * \param n Size of dst
 * \param operand The RL78 instruction to be printed
 * \return false on failure
 */
bool rl78_instr_to_string(char *dst, size_t n, const struct rl78_instr *instr);

#endif
