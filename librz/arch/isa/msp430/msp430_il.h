// SPDX-FileCopyrightText: 2024 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MSP430_IL_H
#define MSP430_IL_H

#include <rz_analysis.h>
#include <msp430/msp430_disas.h>

typedef Msp430Cmd Msp430Instruction;

typedef RzILOpEffect *(*MSP430InstructionLifter)(RzAnalysis *analysis, const Msp430Instruction *op, ut64 curr_addr, int instr_size);

RZ_OWN RZ_IPI RzILOpEffect *rz_msp430_lift_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL const Msp430Instruction *op, ut64 current_addr, int size);

RZ_OWN RZ_IPI RzAnalysisILConfig *rz_msp430_il_config(RZ_BORROW RZ_NONNULL RzAnalysis *analysis);

#endif