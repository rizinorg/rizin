// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_54.h"
#include "rz_core.h"
#include "../lua_arch.h"

int lua54_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, const ut8 *data, int len) {
	const LuaInstruction instruction = ctx->instruction;
	const ut64 addr = ctx->addr;
	const LuaOpCode54 opcode = GET_OPCODE54(instruction);

	char comment[128] = { 0 };

	const int a = GETARG_A4(instruction);

	if (opcode > OP_EXTRAARG) {
		op->family = RZ_ANALYSIS_OP_FAMILY_UNKNOWN;
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->nopcode = 1;
		op->cycles = 1;
		op->size = 4;
		op->eob = true;
		ctx->prev_inst = instruction;
		return op->size;
	}

	op->jump = addr + 4;

	if (analysis_op_4_5(analysis, op, ctx, opcode, 4)) {
		return op->size;
	}
	if (opcode == OP_VARARGPREP) {
		/*A       (adjust vararg parameters)                      */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		rz_strf(comment, "prepare varargs, %d fixed args", a);
		rz_meta_set(analysis, RZ_META_TYPE_COMMENT, addr, 4, comment);
	}
	return op->size;
}
