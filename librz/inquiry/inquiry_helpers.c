// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Helper functions for the new analysis. Some of them not yet temporarily.
 */

#include <rz_inquiry/rz_interpreter.h>
#include <rz_analysis.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_io.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>

RZ_API RZ_OWN RzInterpreterILBB *rz_inquiry_gen_il_bb(RZ_NONNULL RzAnalysis *analysis, RZ_BORROW RZ_NONNULL RzIO *io, ut64 addr) {
	rz_return_val_if_fail(analysis && analysis->cur && io, NULL);
	RzInterpreterILBB *il_bb = NULL;
	RzAnalysisOp op = { 0 };
	rz_analysis_op_init(&op);
	// Estimate a reasonable number of bytes to read.
	int max_read_size = (analysis->cur->bits / 8) * 16;
	ut8 *buf = RZ_NEWS0(ut8, max_read_size);
	if (!max_read_size || !buf) {
		goto fail;
	}
	il_bb = rz_pvector_new((RzPVectorFree)rz_interpreter_insn_pkt_free);
	if (!il_bb) {
		goto fail;
	}
	bool changes_cf = true;
	do {
		if (!rz_io_read_at_mapped(io, addr, buf, max_read_size)) {
			RZ_LOG_WARN("inquiry: Failed to read memory for IL basic block generation.\n");
			goto fail;
		}
		if (rz_analysis_op(analysis, &op, addr, buf, max_read_size, RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_INSN_PKT) <= 0) {
			RZ_LOG_ERROR("Failed to decode IL op\n");
			goto fail;
		}
		bool lifted = true;
		if (!op.il_op) {
			// Not lifted. Map to NOP
			lifted = false;
			op.il_op = rz_il_op_new_nop();
		}
		RzInterpreterInsnPkt *pkt = RZ_NEW0(RzInterpreterInsnPkt);
		pkt->effect = op.il_op;
		pkt->insn_pkt_size = op.size;
		rz_pvector_push(il_bb, pkt);
		// Take ownership of IL op pointer.
		op.il_op = NULL;
		if (lifted) {
			changes_cf = rz_analysis_op_changes_control_flow(&op);
		}
		rz_analysis_op_fini(&op);
		addr += op.size;
		rz_mem_memzero(buf, max_read_size);
	} while (!changes_cf);

	free(buf);
	return il_bb;

fail:
	free(buf);
	rz_analysis_op_fini(&op);
	rz_pvector_free(il_bb);
	return NULL;
}
