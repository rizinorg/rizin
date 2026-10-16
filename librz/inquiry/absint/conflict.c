// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "./absint_priv.h"

typedef enum {
	CFG_CONFLICT_BLOCK_DROP, ///< The block should be dropped.
	CFG_CONFLICT_BLOCK_SHARED, ///< The block is shared with another function.
	CFG_CONFLICT_BLOCK_FCN_ENTRY, ///< The block is a symbol entry point, and therefore referenced by multiple functions.
	CFG_CONFLICT_BLOCK_N,
} CFGConflictVerdict;

typedef struct {
	int score[CFG_CONFLICT_BLOCK_N];
} CFGConflictScore;

RZ_API RZ_OWN RzAbsIntCFGConflicts *rz_abs_int_cfg_conflict_new();
RZ_API void rz_abs_int_cfg_conflict_free(RZ_OWN RZ_NULLABLE RzAbsIntCFGConflicts *conflicts);
RZ_API bool rz_abs_int_cfg_conflict_add(RZ_NONNULL RzAbsIntCFGConflicts *conflicts, ut64 fcn_id, const RzAbsIntBlock *block);
RZ_API bool rz_abs_int_cfg_conflict_resolve(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAbsIntCFGConflicts *conflicts) {
	// 2. Non-strippable function symbols point to a function entry point.
	// 7. When a jump edge crosses a function entry point, then the jump is likely to be a tail-call.
	// 8. call target is jump instruction, likely function entry.
	// 11. Jump target is noop (hard to say), unlikly to be a function entry (-> shared)
	// 14. Cond. jump targets are unlikely a function entry.
	// 15. Basic blocks before the main entry point of a binary are unlikely to be a function.
}
