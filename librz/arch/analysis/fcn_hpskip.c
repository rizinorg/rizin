// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"
#include "fcn_hpskip_private.h"

RZ_IPI bool rz_analysis_regs_exist(RzAnalysisValue *src, RzAnalysisValue *dst) {
	rz_return_val_if_fail(src && dst, false);
	return src->reg && dst->reg && src->reg->name && dst->reg->name;
}

// 0 if not skipped; 1 if skipped; 2 if skipped before
RZ_IPI int rz_analysis_skip_hp(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op, RzAnalysisBlock *bb, ut64 addr,
	char *tmp_buf, int oplen, int un_idx, int *idx) {
	// this step is required in order to prevent infinite recursion in some cases
	if ((addr + un_idx - oplen) == fcn->addr) {
		// use addr instead of op->addr to mark repeat
		if (!analysis->flb.exist_at(analysis->flb.f, "skip", 4, addr)) {
			snprintf(tmp_buf + 5, MAX_FLG_NAME_SIZE - 6, "%" PFMT64u, addr);
			analysis->flb.set(analysis->flb.f, tmp_buf, addr, oplen);
			fcn->addr += oplen;
			rz_analysis_block_relocate(bb, bb->addr + oplen, bb->size - oplen);
			*idx = un_idx;
			return 1;
		}
		return 2;
	}
	return 0;
}
