// SPDX-FileCopyrightText: 2014 Ilya V. Matveychikov <i.matveychikov@milabs.ru>
// SPDX-FileCopyrightText: 2014 montekki <fedor.sakharov@gmail.com>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_analysis.h>

#include "c55plus_analysis.h"
#include "c55plus_arch.h"
#include "../c55_ir.h"

/**
 * \file c55plus_analysis.c
 *
 * TMS320C55x+ analysis. The instruction is decoded once by the shared
 * decode-IR engine (c55_ir), and the analysis op -- type, branch targets,
 * basic-block fall-through, src/dst/val, stack effects and instruction id --
 * together with the RzIL lift are both derived from that single decoded
 * C55Insn. Anything the engine does not decode is reported as illegal.
 */
int tms320_c55x_plus_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr,
	const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (!op || !buf || len < 1) {
		return 0;
	}

	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_NULL;

	C55Insn ci;
	if (c55_decode(&c55plus_arch_desc, buf, len, &ci)) {
		c55_fill_analysis(&c55plus_arch_desc, &ci, op);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = c55_lift(&c55plus_arch_desc, &ci, op->addr);
		}
		return op->size;
	}

	op->type = RZ_ANALYSIS_OP_TYPE_ILL;
	op->size = 1;
	return op->size;
}
