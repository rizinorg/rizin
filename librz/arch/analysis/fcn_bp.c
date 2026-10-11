// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

static bool can_affect_bp(RzAnalysis *analysis, RzAnalysisOp *op) {
	RzAnalysisValue *dst = op->dst;
	RzAnalysisValue *src = op->src[0];
	const char *opdreg = (dst && dst->reg) ? dst->reg->name : NULL;
	const char *opsreg = (src && src->reg) ? src->reg->name : NULL;
	const char *bp_name = rz_reg_get_name(analysis->reg, RZ_REG_NAME_BP);
	bool is_bp_dst = opdreg && !dst->memref && !strcmp(opdreg, bp_name);
	bool is_bp_src = opsreg && !src->memref && !strcmp(opsreg, bp_name);
	if (op->type == RZ_ANALYSIS_OP_TYPE_XCHG) {
		return is_bp_src || is_bp_dst;
	}
	return is_bp_dst;
}

/*
 * This function checks whether any operation in a given function may change bp (excluding "mov bp, sp"
 * and "pop bp" at the end).
 */
static void __analysis_fcn_check_bp_use(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	if (!fcn) {
		return;
	}
	RzAnalysisOp op = { 0 };
	RzAnalysisBlock *bb;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc(bb->size);
		if (!buf) {
			continue;
		}
		(void)analysis->iob.read_at(analysis->iob.io, bb->addr, (ut8 *)buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			rz_analysis_op_init(&op);
			rz_analysis_op(analysis, &op, at, buf + idx, bb->size - idx, RZ_ANALYSIS_OP_MASK_VAL);
			if (op.size < 1) {
				op.size = 1;
			}
			switch (op.type) {
			case RZ_ANALYSIS_OP_TYPE_MOV:
			case RZ_ANALYSIS_OP_TYPE_LEA: {
				const char *sp = rz_reg_get_name(analysis->reg, RZ_REG_NAME_SP);
				const char *srcreg = op.src[0] && op.src[0]->reg ? op.src[0]->reg->name : NULL;
				if (can_affect_bp(analysis, &op) && srcreg && sp && strcmp(srcreg, sp)) {
					fcn->bp_frame = false;
					rz_analysis_op_fini(&op);
					free(buf);
					return;
				}
				break;
			}
			case RZ_ANALYSIS_OP_TYPE_ADD:
			case RZ_ANALYSIS_OP_TYPE_AND:
			case RZ_ANALYSIS_OP_TYPE_CMOV:
			case RZ_ANALYSIS_OP_TYPE_NOT:
			case RZ_ANALYSIS_OP_TYPE_OR:
			case RZ_ANALYSIS_OP_TYPE_ROL:
			case RZ_ANALYSIS_OP_TYPE_ROR:
			case RZ_ANALYSIS_OP_TYPE_SAL:
			case RZ_ANALYSIS_OP_TYPE_SAR:
			case RZ_ANALYSIS_OP_TYPE_SHR:
			case RZ_ANALYSIS_OP_TYPE_SUB:
			case RZ_ANALYSIS_OP_TYPE_XOR:
			case RZ_ANALYSIS_OP_TYPE_SHL:
			case RZ_ANALYSIS_OP_TYPE_XCHG:
				if (can_affect_bp(analysis, &op)) {
					fcn->bp_frame = false;
					rz_analysis_op_fini(&op);
					free(buf);
					return;
				}
				break;
			default:
				break;
			}
			idx += op.size;
			at += op.size;
			rz_analysis_op_fini(&op);
		}
		free(buf);
	}
}

/**
 *  \brief This function checks whether any operation in a given function may change BP
 *
 *  Excludes pattern like "mov bp, sp" and "pop sp, bp" for saving stack pointer value
 */
RZ_API void rz_analysis_function_check_bp_use(RzAnalysisFunction *fcn) {
	rz_return_if_fail(fcn);
	__analysis_fcn_check_bp_use(fcn->analysis, fcn);
}
