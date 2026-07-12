
#ifndef RZ_INTERP_PRIV_H
#define RZ_INTERP_PRIV_H

#include <rz_inquiry/rz_interpreter.h>

// These functions are actually internal, but need RZ_API to be called from unit tests
RZ_API bool rz_interp_run_context_init(RzInterpRunContext *ctx, RzInterpInstance *inst);
RZ_API void rz_interp_run_context_fini(RzInterpRunContext *ctx);
RZ_API RzInterpBlock *rz_interp_block_at(RzInterpRunContext *ctx, ut64 addr);
RZ_API void rz_interp_block_resolve_bounds(RzInterpRunContext *ctx, RzInterpBlock *interp_block, const RzILCacheBlock *il_block);

static inline ut64 rz_interp_block_get_start(RzInterpBlock *block) {
	return block->entry_state->pc;
}

/** end is inclusive */
static inline ut64 rz_interp_block_get_end(RzInterpBlock *block) {
	return block->node->end;
}

RZ_API void rz_interp_run_push(RZ_BORROW RZ_NONNULL RzInterpRunContext *ctx, RZ_BORROW RZ_NONNULL RzInterpAbstrState *as, bool is_fallthrough);

RZ_API RZ_OWN RzInterpAbstrState *rz_interp_abstr_state_new(
	RZ_NONNULL RzInterpInstance *inst);
RZ_API void rz_interp_abstr_state_free(RzInterpInstance *inst, RZ_OWN RZ_NULLABLE RzInterpAbstrState *state);
RZ_API void rz_interp_abstr_state_set_pc_const(RzInterpAbstrState *state, ut64 pc);
RZ_API RZ_OWN RzInterpAbstrState *rz_interp_abstr_state_clone(RZ_NONNULL RzInterpInstance *iset, const RzInterpAbstrState *state);
RZ_API bool rz_interp_abstr_state_as_str(RZ_NONNULL RzInterpInstance *inst, RZ_NONNULL const RzInterpAbstrState *state, RZ_NONNULL RZ_OUT RzStrBuf *sb);
RZ_API void rz_interp_abstr_state_as_str_short(RZ_NONNULL RzInterpInstance *inst, RZ_NONNULL const RzInterpAbstrState *astate, RZ_NONNULL RZ_OUT RzStrBuf *sb);

#endif
