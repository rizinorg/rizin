// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Helper functions for the new analysis. Some of them not yet temporarily.
 */

#include <rz_analysis.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_io.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>

RZ_API bool rz_inquiry_op_type_is_eob(_RzAnalysisOpType type) {
	switch (type) {
	default:
		false;
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_RCJMP:
	case RZ_ANALYSIS_OP_TYPE_MJMP:
	case RZ_ANALYSIS_OP_TYPE_MCJMP:
	case RZ_ANALYSIS_OP_TYPE_UCJMP:
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_UCALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_CCALL:
	case RZ_ANALYSIS_OP_TYPE_UCCALL:
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_CRET:
	case RZ_ANALYSIS_OP_TYPE_ILL:
	case RZ_ANALYSIS_OP_TYPE_UNK:
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_SWI:
	case RZ_ANALYSIS_OP_TYPE_CSWI:
	case RZ_ANALYSIS_OP_TYPE_LEAVE:
	case RZ_ANALYSIS_OP_TYPE_SWITCH:
		return true;
	}
}

RZ_API RZ_OWN RzILOpEffect *rz_inquiry_gen_il_bb(RZ_NONNULL RzAnalysis *analysis, RZ_BORROW RZ_NONNULL RzIO *io, ut64 addr) {
	rz_return_val_if_fail(analysis && analysis->cur && io, NULL);
	RzILOpEffect *bb = NULL;
	RzAnalysisOp op = { 0 };
	rz_analysis_op_init(&op);
	// Estimate a reasonable number of bytes to read.
	int max_read_size = (analysis->cur->bits / 8) * 16;
	int actual_size = max_read_size;
	ut8 *buf = RZ_NEWS0(ut8, actual_size);
	if (!actual_size || !buf) {
		goto fail;
	}
	bool changes_cf = true;
	do {
		actual_size = rz_io_nread_at(io, addr, buf, max_read_size);
		if (actual_size < 0) {
			RZ_LOG_WARN("inquiry: Failed to read memory for IL basic block generation.\n");
			goto fail;
		}
		if (rz_analysis_op(analysis, &op, addr, buf, actual_size, RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_BASIC) <= 0 || !op.il_op) {
			rz_analysis_op_fini(&op);
			break;
		}
		bb = rz_il_op_new_seq(bb, op.il_op);
		// Take ownership of IL op pointer.
		op.il_op = NULL;
		changes_cf = rz_analysis_op_changes_control_flow(&op);
		rz_analysis_op_fini(&op);
		addr += op.size;
		rz_mem_memzero(buf, max_read_size);
	} while (!changes_cf);

	free(buf);
	return bb;

fail:
	free(buf);
	rz_analysis_op_fini(&op);
	rz_il_op_effect_free(bb);
	return NULL;
}
