// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SH_RZIL_H
#define SH_RZIL_H

#include <rz_analysis.h>
#include "../../../asm/arch/sh/disassembler.h"

RZ_IPI bool rz_sh_il_opcode(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *aop, ut64 pc, RZ_BORROW RZ_NONNULL SHOp *op);
RZ_IPI RzAnalysisILConfig *rz_sh_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif /* SH_RZIL_H */
