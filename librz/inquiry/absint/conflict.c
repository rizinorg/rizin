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

RZ_API RZ_OWN RzAbsIntCFGConflicts *rz_abs_int_cfg_conflict_new() {
	RzAbsIntCFGConflicts *conflicts = RZ_NEW0(RzAbsIntCFGConflicts);
	if (!conflicts) {
		return NULL;
	}
	conflicts->cfg_conflicts = ht_up_new(NULL, NULL);
	if (!conflicts->cfg_conflicts) {
		free(conflicts);
		return NULL;
	}
	return conflicts;
}

RZ_API void rz_abs_int_cfg_conflict_free(RZ_OWN RZ_NULLABLE RzAbsIntCFGConflicts *conflicts) {
	if (!conflicts) {
		return;
	}
	ht_up_free(conflicts->cfg_conflicts);
	free(conflicts);
}

typedef struct {
	ut64 fcn_id;
	const RzAbsIntBlock *block;
} CFGConflictBlock;

/**
 * \brief Adds the basic block to the conflict list.
 *
 * \param conflicts The conflict map.
 * \param fcn_id The id of the function the block belongs to.
 * \param block The block that is used by more than one function.
 *
 * \return True if the block was added successfully, false in case of failure.
 */
RZ_API RzAbsIntCFGConflictAddResult rz_abs_int_cfg_conflict_add(RZ_NONNULL RzAbsIntCFGConflicts *conflicts, ut64 fcn_id, const RzAbsIntBlock *block) {
	rz_return_val_if_fail(conflicts, RZ_ABSINT_CONFLICT_BLOCK_ERROR);
	ut64 block_addr = rz_absint_block_get_start(block);
	RzVector *blocks = ht_up_find(conflicts->cfg_conflicts, block_addr, NULL);
	RzAbsIntCFGConflictAddResult res;
	if (!blocks) {
		res = RZ_ABSINT_CONFLICT_BLOCK_NEW;
		blocks = rz_vector_new(sizeof(CFGConflictBlock), NULL, NULL);
		if (!blocks) {
			return RZ_ABSINT_CONFLICT_BLOCK_ERROR;
		}
		ht_up_insert(conflicts->cfg_conflicts, block_addr, blocks);
	} else {
		res = RZ_ABSINT_CONFLICT_BLOCK_KNOWN;
	}
	CFGConflictBlock cfb = { .fcn_id = fcn_id, .block = block };
	rz_vector_push(blocks, &cfb);
	return res;
}

RZ_API bool rz_abs_int_cfg_conflict_resolve(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAbsIntCFGConflicts *conflicts) {
	// 2. Non-strippable function symbols point to a function entry point.
	// 7. When a jump edge crosses a function entry point, then the jump is likely to be a tail-call.
	// 8. call target is jump instruction, likely function entry.
	// 11. Jump target is noop (hard to say), unlikly to be a function entry (-> shared)
	// 14. Cond. jump targets are unlikely a function entry.
	// 15. Basic blocks before the main entry point of a binary are unlikely to be a function.
}
