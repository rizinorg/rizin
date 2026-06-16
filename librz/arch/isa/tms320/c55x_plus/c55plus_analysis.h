// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef ANALYSIS_C55_PLUS_H
#define ANALYSIS_C55_PLUS_H

#include <rz_analysis.h>

int tms320_c55x_plus_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask);

RZ_IPI RzAnalysisILConfig *tms320_c55x_plus_il_config(RZ_NONNULL RzAnalysis *analysis);

#endif /* ANALYSIS_C55_PLUS_H */
