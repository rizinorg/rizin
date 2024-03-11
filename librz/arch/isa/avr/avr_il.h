// SPDX-FileCopyrightText: 2021-2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_ANALYSIS_AVR_H
#define RZIL_ANALYSIS_AVR_H

#include <rz_analysis.h>
#include "disassembler.h"

RZ_IPI bool rz_avr_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, AVROp *aop, AVROp *next_op);
RZ_IPI RzAnalysisILConfig *rz_avr_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif /* RZIL_ANALYSIS_AVR_H */