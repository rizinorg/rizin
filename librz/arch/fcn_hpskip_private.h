// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FCN_HPSKIP_PRIVATE_H
#define RZ_FCN_HPSKIP_PRIVATE_H

#include <rz_analysis.h>

#define MAX_FLG_NAME_SIZE 64

RZ_IPI bool rz_analysis_regs_exist(RzAnalysisValue *src, RzAnalysisValue *dst);
RZ_IPI int rz_analysis_skip_hp(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op, RzAnalysisBlock *bb, ut64 addr, char *tmp_buf, int oplen, int un_idx, int *idx);

#endif // RZ_FCN_HPSKIP_PRIVATE_H
