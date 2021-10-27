// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_ANALYSIS_AVR_H
#define RZIL_ANALYSIS_AVR_H

#include <rz_analysis.h>
#include "../../../asm/arch/avr/disassembler.h"

RZ_IPI bool avr_rzil_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, AVROp *aop);
RZ_IPI bool avr_rzil_fini(RZ_NONNULL RzAnalysis *analysis);
RZ_IPI bool avr_rzil_init(RZ_NONNULL RzAnalysis *analysis);

#endif /* RZIL_ANALYSIS_AVR_H */