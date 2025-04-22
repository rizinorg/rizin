// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_V810_H
#define RIZIN_V810_H

#include <rz_analysis.h>
#include "v810_disas.h"

enum {
	C_BGT = 0b1111,
	C_BGE = 0b1110,
	C_BLT = 0b0110,
	C_BLE = 0b0111,

	C_BH = 0b1011,
	C_BNL = 0b1001,
	C_BL = 0b0001,
	C_BNH = 0b0011,

	C_BE = 0b0010,
	C_BNE = 0b1010,

	C_BV = 0b000,
	C_BNV = 0b1000,
	C_BN = 0b0100,
	C_BP = 0b1100,
	C_BC = 0b0001,
	C_BNC = 0b1001,
	C_BZ = 0b0010,
	C_BNZ = 0b1010,
	C_BR = 0b0101,
	C_NOP = 0b1101,
};

typedef struct {
	RzAnalysis *a;
	ut16 w1;
	ut16 w2;
	ut32 pc;
} V810AnalysisContext;

RzAnalysisILConfig *v810_il_config(RzAnalysis *a);
RzAnalysisLiftedILOp v810_il_op(const V810AnalysisContext *a);

#endif // RIZIN_V810_H
