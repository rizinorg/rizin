// SPDX-FileCopyrightText: 2023 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: LPGL-3.0-only

#ifndef MSP430_IL_H
#define MSP430_IL_H

#include <rz_analysis.h>
#include "msp430_disas.h"

#define WORD_SIZED_READ  1
#define WORD_SIZED_WRITE 2

typedef enum {
    REG,
    INDX,
    SYM,
    ABS,
    IND_REG,
    IND_AUTOINC,
    IMM
} Msp430SourceAddressingMode;

typedef enum {
    REG,
    INDX,
    SYM,
    ABS
} Msp430DestinationAddressingMode;

typedef struct {
    ut8 itype;
    ut8 iopcode;
    ut8 word_sized;

    Msp430SourceAddressingMode src_mode;
    ut32 src;

    Msp430DestinationAddressingMode dst_mode;
    ut32 dst;
} Msp430Instruction;

RZ_IPI RzILOpEffect *rz_msp430_lift_instr(RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op);

RZ_IPI RzAnalysisILConfig *rz_msp430_il_config(RZ_NONNULL RzAnalysis *analysis);


#endif