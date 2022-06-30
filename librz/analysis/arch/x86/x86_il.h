// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_ANALYSIS_X86_IL_H
#define RZIL_ANALYSIS_X86_IL_H

#include <rz_lib.h>
#include <rz_analysis.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>

#define BITS_PER_BYTE 8

typedef x86_reg X86Reg;
typedef cs_x86_op X86Op;
typedef x86_op_mem X86Mem;
typedef cs_x86 X86Ins;
typedef x86_insn X86InsMnem;

typedef enum x86_eflags_t {
    X86_EFLAGS_CF = 0,
    X86_EFLAGS_PF = 2,
    X86_EFLAGS_AF = 4,
    X86_EFLAGS_ZF = 6,
    X86_EFLAGS_SF = 7,
    X86_EFLAGS_TF = 8,
    X86_EFLAGS_IF = 9,
    X86_EFLAGS_DF = 10,
    X86_EFLAGS_OF = 11,
    X86_EFLAGS_IOPL = 12,
    X86_EFLAGS_NT = 14,
    X86_EFLAGS_RF = 16,
    X86_EFLAGS_VM = 17,
    X86_EFLAGS_AC = 18,
    X86_EFLAGS_VIF = 19,
    X86_EFLAGS_VIP = 20,
    X86_EFLAGS_ID = 21
} X86EFlags;

#endif /* RZIL_ANALYSIS_X86_IL_H */
