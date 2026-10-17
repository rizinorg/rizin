// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This file implements conflict resolution, for a block which are used by multiple functions.
 *
 * There are a few reasons for a functions using the same block:
 *
 * 1. The block is simply shared code. This is common in hand-written assembly.
 * 2. The block is not actually part of the function, but it is the target of a tail call
 *    and was mistakingly added to the function, because the tail call was not identified as such.
 *    In this case the block and its successors are their own function.
 *    And all the successors only call it.
 */


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
	// Positive hints that the block is actually a function entry point:
	// - Non-strippable function symbols point to the block.
	// - A known call instruction targets this block (an CALL xref to it exists).
	// - When a jump edge to the block crosses a function entry point, then the jump is likely to be a tail-call.
	//
	// Negative hints that the block is a function entry point.
	// - Block starts with a noop instruction (-> shared)
	// - An successor of this block is a conditional jump.
	// - Basic blocks before the entry point of a binary are unlikely to be a function.
	//
	// Definitely an invalid block.
	// - Block is located at address 0x0
}
