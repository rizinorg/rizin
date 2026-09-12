// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_M68K_IL_H
#define RZ_M68K_IL_H

#include <rz_analysis.h>
#include <rz_il.h>
#include <capstone/capstone.h>

RZ_IPI RzAnalysisILConfig *rz_m68k_cs_il_config(RZ_NONNULL RzAnalysis *analysis);
RZ_IPI RzILOpEffect *rz_m68k_cs_get_il_op(csh handle, cs_mode mode, RZ_NONNULL const cs_insn *insn, ut64 addr);

#endif // RZ_M68K_IL_H
