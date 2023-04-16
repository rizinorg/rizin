// SPDX-FileCopyrightText: 2023 Siddharth Mishra <misra.cxx@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PIC_IL_H_
#define PIC_IL_H_

#include "../../../asm/arch/pic/pic_midrange.h"
#include "../../../asm/arch/pic/pic_baseline.h"

// midrange
RZ_IPI RzAnalysisILConfig *rz_pic_midrange_il_vm_config(RZ_NONNULL RzAnalysis *analysis);
RZ_IPI RzILOpEffect *rz_pic_midrange_il_op(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RZ_BORROW RzAnalysisOp *op, ut16 instr);

// baseline
/* RZ_IPI RzAnalysisILConfig *rz_pic_baseline_il_vm_config(RZ_NONNULL RzAnalysis *analysis); */
/* RZ_IPI RzILOpEffect *rz_pic_baseline_il_op(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RZ_BORROW RzAnalysisOp *op, ut16 instr ; */

// TODO: Add support for PIC18F

#endif // PIC_IL_H_
