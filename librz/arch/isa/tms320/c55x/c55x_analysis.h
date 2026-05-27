// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-FileCopyrightText: 2014 montekki <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef ANALYSIS_C55X_H
#define ANALYSIS_C55X_H

#include <rz_analysis.h>

int tms320_c55x_op_byte(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len);

#endif /* ANALYSIS_C55X_H */
