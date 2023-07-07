// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "operand.h"

#include <rz_core.h>

#include <stdio.h>

const char *RL78_STRINGS_SYMBOLS[] = {
        [RL78_GPR_X]    = "x",
        [RL78_GPR_A]    = "a",
        [RL78_GPR_C]    = "c",
        [RL78_GPR_B]    = "b",
        [RL78_GPR_E]    = "e",
        [RL78_GPR_D]    = "d",
        [RL78_GPR_L]    = "l",
        [RL78_GPR_H]    = "h",
        [RL78_GPR_AX]   = "ax",
        [RL78_GPR_BC]   = "bc",
        [RL78_GPR_DE]   = "de",
        [RL78_GPR_HL]   = "hl",
        [RL78_SFR_MEM]  = "mem",
        [RL78_SFR_PMC]  = "pmc",
        [RL78_SFR_ES]   = "es",
        [RL78_SFR_CS]   = "cs",
        [RL78_SFR_PSW]  = "psw",
        [RL78_SFR_SPH]  = "sph",
        [RL78_SFR_SPL]  = "spl",
        [RL78_CR_PC]    = "pc",
        [RL78_CR_PSW]   = "psw",
        [RL78_CR_SP]    = "sp"
};

static bool symbol_invalid(int symbol)
{
        return symbol < 0 || symbol >= _RL78_SYMBOL_COUNT;
}

bool rl78_operand_to_string(char *dst, size_t n,
                            const struct rl78_operand *operand)
{
        if (operand->type <= RL78_OPERAND_TYPE_NONE ||
            operand->type >= _RL78_OPERAND_TYPE_COUNT) {
                return false;
        }

        switch (operand->type) {
                case RL78_OPERAND_TYPE_IMMEDIATE:
                        snprintf(dst, n, "#0x%" PFMT32x, operand->v0);
                        break;
                case RL78_OPERAND_TYPE_SYMBOL:
                        if (symbol_invalid(operand->v0)) {
                                return false;
                        }

                        snprintf(dst, n, "%s", RL78_STRINGS_SYMBOLS[operand->v0]);
                        break;
                case RL78_OPERAND_TYPE_ABSOLUTE_ADDR_16:
                        snprintf(dst, n, "!0x%" PFMT32x, operand->v0);
                        break;
                case RL78_OPERAND_TYPE_ABSOLUTE_ADDR_20:
                        snprintf(dst, n, "!!0x%" PFMT32x, operand->v0);
                        break;
                case RL78_OPERAND_TYPE_RELATIVE_ADDR_8:
                        snprintf(dst, n, "$0x%" PFMT32x, operand->v0);
                        break;
                case RL78_OPERAND_TYPE_RELATIVE_ADDR_16:
                        snprintf(dst, n, "$!0x%" PFMT32x, operand->v0);
                        break;
                case RL78_OPERAND_TYPE_INDIRECT_ADDR:
                        if (symbol_invalid(operand->v0)) {
                                return false;
                        }

                        if (operand->extension_addressing) {
                                snprintf(dst, n, "ES:[%s]", RL78_STRINGS_SYMBOLS[operand->v0]);
                        }
                        else {
                                snprintf(dst, n, "[%s]", RL78_STRINGS_SYMBOLS[operand->v0]);
                        }
                        break;
                case RL78_OPERAND_TYPE_BASED_ADDR:
                        if (symbol_invalid(operand->v0)) {
                                return false;
                        }

                        if (operand->extension_addressing) {
                                snprintf(dst, n, "ES:[%s+0x%" PFMT32x "]",
                                         RL78_STRINGS_SYMBOLS[operand->v0], operand->v1);
                        }
                        else {
                                snprintf(dst, n, "[%s+0x%" PFMT32x "]",
                                         RL78_STRINGS_SYMBOLS[operand->v0], operand->v1);
                        }
                        break;
                case RL78_OPERAND_TYPE_BASED_INDEX_ADDR:
                        if (symbol_invalid(operand->v0) || symbol_invalid(operand->v1)) {
                                return false;
                        }

                        if (operand->extension_addressing) {
                                snprintf(dst, n, "ES:[%s+%s]",
                                         RL78_STRINGS_SYMBOLS[operand->v0],
                                         RL78_STRINGS_SYMBOLS[operand->v1]);
                        }
                        else {
                                snprintf(dst, n, "[%s+%s]",
                                         RL78_STRINGS_SYMBOLS[operand->v0],
                                         RL78_STRINGS_SYMBOLS[operand->v1]);
                        }
                        break;
                default:
                        rz_warn_if_reached();
        }

        return true;
}
