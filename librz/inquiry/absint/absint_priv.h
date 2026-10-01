// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ABSINT_PRIV_H
#define RZ_ABSINT_PRIV_H

#include <rz_inquiry/rz_absint.h>

static inline ut64 rz_absint_block_get_start(RzAbsIntBlock *block) {
	return block->entry_state->pc;
}

/** end is inclusive */
static inline ut64 rz_absint_block_get_end(RzAbsIntBlock *block) {
	return block->node->end;
}

RZ_IPI bool reset_state(RzAbsIntInstance *inst, RZ_BORROW RzAbsIntState *state, ut64 entry_point);
RZ_IPI bool join_state(RzAbsIntInstance *inst, RZ_BORROW RZ_INOUT RzAbsIntState *a, RZ_BORROW RZ_IN const RzAbsIntState *b);

RZ_IPI void interp_blocks_init(RzAbsIntRunContext *ctx);
RZ_IPI void interp_blocks_fini(RzAbsIntInstance *inst, RzIntervalTree *blocks);
RZ_IPI void interp_block_add_non_fallthrough_target(RzAbsIntBlock *block, ut64 target);
RZ_IPI RZ_OWN RzAbsIntBlock *rz_absint_run_pop(RZ_BORROW RZ_NONNULL RzAbsIntRunContext *ctx);
RZ_IPI bool interp_block_tree_as_str(const RzIntervalTree /* RzAbsIntBlock */ *blocks, RZ_NONNULL RZ_OUT RzStrBuf *sb);

static inline const RzAbsIntValueDomain *val_domain(const RzAbsIntInstance *inst) {
	return inst->config.val_domain;
}

/** Whether during evaluation, analysis results should be collected */
static inline bool interp_is_analyzing(RzAbsIntRunContext *ctx) {
	return ctx->res != NULL;
}

/** Whether during evaluation, new states may be discoveres */
static inline bool interp_is_collecting_states(RzAbsIntRunContext *ctx) {
	return ctx->res == NULL;
}

#endif
