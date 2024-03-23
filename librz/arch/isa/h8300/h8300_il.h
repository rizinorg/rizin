// SPDX-FileCopyrightText: 2024 Ashis Kumar Naik <ashishami2002@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_H8300_IL_H
#define RIZIN_H8300_IL_H

#include <rz_analysis.h>
#include "h8300_disas.h"

RZ_IPI bool rz_h8300_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, H8300Op *aop, H8300Op *next_op);
RZ_IPI RzAnalysisILConfig *rz_h8300_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif // RIZIN_H8300_IL_H
