// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef MIPS_IL_H
#define MIPS_IL_H

#include <rz_analysis.h>
#include <capstone/capstone.h>

RZ_IPI RzILOpEffect *mips_il(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL cs_insn *insn, ut32 pc);
RZ_IPI RzAnalysisILConfig *mips_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif // MIPS_IL_H
