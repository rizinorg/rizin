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

typedef bool X86Bitness;
#define X86_64BIT true
#define X86_32BIT false

#endif /* RZIL_ANALYSIS_X86_IL_H */
