// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_55.h"

int lua55_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, const ut8 *data, int len) {
	const LuaInstruction instruction = ctx->instruction;
	const ut64 addr = ctx->addr;
	const LuaOpCode55 opcode = GET_OPCODE55(instruction);
	op->size = 4;

	char comment[128] = { 0 };

	if (opcode > OP_EXTRAARG) {
		op->family = RZ_ANALYSIS_OP_FAMILY_UNKNOWN;
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->nopcode = 1;
		op->cycles = 1;
		op->eob = true;
		ctx->prev_inst = instruction;
		return op->size;
	}
	const int a = GETARG_A4(instruction);
	const int b = GETARG_B4(instruction);
	const int c = GETARG_C4(instruction);
	const int ax = GETARG_Ax4(instruction);
	op->jump = addr + 4;

	if (analysis_op_4_5(analysis, op, ctx, opcode, 5)) {
		return op->size;
	}

	switch (opcode) {
	case OP_ERRNNIL: /*   A Bx    raise error if R[A] ~= nil (K[Bx - 1] is global name)*/
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case OP_GETVARG: /*   A B C    R[A] := R[B][R[C]], R[B] is vararg parameter    */
		TYPE_DST_SRC_ABC_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a, b, c);
		break;
	case OP_EXTRAARG: /*  Ax	extra (larger) argument for previous opcode	*/
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->val = ax;
		break;
	case OP_VARARGPREP: /*A       (adjust vararg parameters)                      */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		rz_strf(comment, "prepare varargs, %d fixed args", a);
		break;
	default:
		RZ_LOG_DEBUG("OPCODE: %d\n", opcode);
		rz_warn_if_reached();
	}
	if (strlen(comment) > 0) {
		rz_meta_set(analysis, RZ_META_TYPE_COMMENT, addr, 4, comment);
	}

	ctx->prev_inst = instruction;
	return op->size;
}
