// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ABSINT_PRIV_H
#define RZ_ABSINT_PRIV_H

#include <rz_inquiry/rz_absint.h>

// These functions are actually internal, but need RZ_API to be called from unit tests
RZ_API bool rz_absint_run_context_init(RzAbsIntRunContext *ctx, RzAbsIntInstance *inst);
RZ_API void rz_absint_run_context_fini(RzAbsIntRunContext *ctx);

RZ_API RZ_BORROW RzAbsIntBlock *rz_absint_block_create(RZ_NONNULL RzAbsIntInstance *inst, RZ_NONNULL RZ_OUT RzIntervalTree *dst, RZ_BORROW RZ_NONNULL RzAbsIntState *entry_state);
RZ_API RZ_BORROW RzAbsIntBlock *rz_absint_block_at(RZ_NONNULL RzAbsIntRunContext *ctx, ut64 addr);
RZ_API void rz_absint_block_resolve_bounds(RZ_BORROW RzAbsIntRunContext *ctx, RZ_BORROW RzAbsIntBlock *interp_block, const RzILCacheBlock *il_block);

static inline ut64 rz_absint_block_get_start(RzAbsIntBlock *block) {
	return block->entry_state->pc;
}

/** end is inclusive */
static inline ut64 rz_absint_block_get_end(RzAbsIntBlock *block) {
	return block->node->end;
}

RZ_API void rz_absint_run_push(RZ_BORROW RZ_NONNULL RzAbsIntRunContext *ctx, RZ_BORROW RZ_NONNULL RzAbsIntState *as, bool is_fallthrough);

RZ_API RZ_OWN RzAbsIntState *rz_absint_state_new(RZ_NONNULL RzAbsIntInstance *inst);
RZ_API void rz_absint_state_free(RzAbsIntInstance *inst, RZ_OWN RZ_NULLABLE RzAbsIntState *state);
RZ_API void rz_absint_state_set_pc_const(RzAbsIntState *state, ut64 pc);
RZ_API RZ_OWN RzAbsIntState *rz_absint_state_clone(RZ_NONNULL RzAbsIntInstance *iset, const RzAbsIntState *state);
RZ_API bool rz_absint_state_as_str(RZ_NONNULL RzAbsIntInstance *inst, RZ_NONNULL const RzAbsIntState *state, RZ_NONNULL RZ_OUT RzStrBuf *sb);
RZ_API bool rz_absint_state_as_str_short(RZ_NONNULL RzAbsIntInstance *inst, RZ_NONNULL const RzAbsIntState *astate, RZ_NONNULL RZ_OUT RzStrBuf *sb);

RZ_IPI bool reset_state(RzAbsIntInstance *inst, RZ_BORROW RzAbsIntState *state, ut64 entry_point);
RZ_IPI bool join_state(RzAbsIntInstance *inst, RZ_BORROW RZ_INOUT RzAbsIntState *a, RZ_BORROW RZ_IN const RzAbsIntState *b);

RZ_IPI void interp_blocks_init(RzAbsIntRunContext *ctx);
RZ_IPI void interp_blocks_fini(RzAbsIntInstance *inst, RzIntervalTree *blocks);
RZ_IPI void interp_block_add_non_fallthrough_target(RzAbsIntBlock *block, ut64 target);
RZ_IPI RzAbsIntBlock *rz_absint_run_pop(RZ_BORROW RZ_NONNULL RzAbsIntRunContext *ctx);

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
