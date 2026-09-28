// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "absint_priv.h"

static RzAbsIntBlock *interp_block_new(RzAbsIntInstance *inst, RZ_BORROW RZ_NONNULL RzAbsIntState *entry_state) {
	rz_return_val_if_fail(inst && entry_state, NULL);

	RzAbsIntBlock *block = RZ_NEW0(RzAbsIntBlock);
	if (!block) {
		return NULL;
	}
	block->entry_state = rz_absint_state_clone(inst, entry_state);
	if (!block->entry_state) {
		free(block);
		return NULL;
	}
	rz_vector_init(&block->insn_offsets, sizeof(ut16), NULL, NULL);
	rz_vector_init(&block->jump_targets, sizeof(ut64), NULL, NULL);
	return block;
}

static void interp_block_free(RzAbsIntInstance *inst, RzAbsIntBlock *block) {
	if (!block) {
		return;
	}
	rz_absint_state_free(inst, block->entry_state);
	rz_vector_fini(&block->insn_offsets);
	rz_vector_fini(&block->jump_targets);
	free(block);
}

RZ_IPI void interp_blocks_init(RzAbsIntRunContext *ctx) {
	rz_interval_tree_init(&ctx->blocks, NULL);
}

RZ_IPI void interp_blocks_fini(RzAbsIntInstance *inst, RzIntervalTree *blocks) {
	RzIntervalTreeIter it;
	RzAbsIntBlock *block;
	rz_interval_tree_foreach (blocks, it, block) {
		interp_block_free(inst, block);
	}
	rz_interval_tree_fini(blocks);
}

/**
 * \brief Creates a RzAbsIntBlock with the given state.
 *
 * \param inst The abstract instance to access the value domain.
 * \param dst The interval tree to insert the block into.
 * \param entry_state The abstract state at the entry point of the block.
 *
 * \return Pointer to the RzAbsIntBlock or NULL in case of failure.
 */
RZ_API RZ_BORROW RzAbsIntBlock *rz_absint_block_create(RZ_NONNULL RzAbsIntInstance *inst, RZ_NONNULL RZ_OUT RzIntervalTree *dst, RZ_BORROW RZ_NONNULL RzAbsIntState *entry_state) {
	rz_return_val_if_fail(inst && dst && entry_state && entry_state->pc_state == RZ_ABSINT_PC_CONST, NULL);
	RzAbsIntBlock *block = interp_block_new(inst, entry_state);
	if (!block) {
		return NULL;
	}
	RzIntervalNode *node = rz_interval_tree_insert(dst, block->entry_state->pc, block->entry_state->pc, block);
	if (!node) {
		rz_warn_if_reached();
		return NULL;
	}
	block->node = node;
	return block;
}

RZ_IPI void interp_block_add_non_fallthrough_target(RzAbsIntBlock *block, ut64 target) {
	// linear search may be inefficient, but practically the number of targets is often small
	if (rz_vector_contains(&block->jump_targets, &target)) {
		return;
	}
	rz_vector_push(&block->jump_targets, &target);
}

/**
 * \brief Get the RzAbsIntBlock at \p addr.
 *
 * \param ctx The runtime context of the interpreter.
 * \param addr The address of the block.
 *
 * \return Pointer to the block. NULL if there is no block at address or ctx was NULL.
 */
RZ_API RZ_BORROW RzAbsIntBlock *rz_absint_block_at(RZ_NONNULL RzAbsIntRunContext *ctx, ut64 addr) {
	rz_return_val_if_fail(ctx, NULL);
	return rz_interval_tree_at(&ctx->blocks, addr);
}

/** Mark a block that its current entry_state has not been explored fully yet */
static void interp_block_mark_uninterpreted(RzAbsIntRunContext *ctx, RzAbsIntBlock *block) {
	if (block->uninterpreted) {
		return;
	}
	block->uninterpreted = true;
	rz_list_push(ctx->queue, block);
}

/**
 * \brief Helper struct used for searching over all blocks.
 */
typedef struct interp_block_with_op_at_ctx_t {
	ut64 addr; ///< The address at which the found block should start.
	RzAbsIntBlock *found; ///< The found block (NULL it not found).
	size_t *hit_op_idx;
} InterpBlockWithOpAtCtx;

static int interp_block_with_op_at_cmp(const void *a, const void *b, void *user) {
	const ut16 *av = a;
	const ut16 *bv = b;
	return (st32)*av - (st32)*bv;
}

static bool interp_block_with_op_at_cb(RzIntervalNode *node, void *user) {
	InterpBlockWithOpAtCtx *lctx = user;
	RzAbsIntBlock *block = node->data;
	ut16 off = (ut16)(lctx->addr - rz_absint_block_get_start(block));
	// insn_offsets does not contain the first instruction, which is just fine here since we are not looking for that
	size_t hit_op_idx = rz_vector_find_sorted(&block->insn_offsets, &off, interp_block_with_op_at_cmp, NULL);
	if (hit_op_idx != SZT_MAX) {
		lctx->found = block;
		*lctx->hit_op_idx = hit_op_idx + 1; // + 1 because insn_offsets omits the first
		return false;
	}
	return true;
}

/**
 * \brief Finds RzAbsIntBlock which has an instruction packet at \p addr.
 * It stops looking at the first match and returns the block.
 *
 * \param ctx The run context o the interpreter.
 * \param addr The address of the instruction packet, for which we search a block which covers it.
 * \param hit_op_idx The varaible to store the index of the instruction packet into.
 *                   This is the index into all instruction packets of the returned block.
 *
 * \return The block covering the instruction at \p addr. Or NULL if there is no such block.
 */
static RzAbsIntBlock *interp_block_with_op_at(RzAbsIntRunContext *ctx, ut64 addr, RZ_OUT size_t *hit_op_idx) {
	InterpBlockWithOpAtCtx lctx = {
		.addr = addr,
		.found = NULL,
		.hit_op_idx = hit_op_idx
	};
	rz_interval_tree_all_in(&ctx->blocks, addr, true, interp_block_with_op_at_cb, &lctx);
	return lctx.found;
}

static int interp_block_addr_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 incoming_start = *(ut64 *)incoming;
	ut64 other_start = container_of(in_tree, const RzIntervalNode, node)->start;
	if (incoming_start < other_start) {
		return -1;
	}
	if (incoming_start > other_start) {
		return 1;
	}
	return 0;
}

static void interp_block_resize(RzAbsIntRunContext *ctx, RzAbsIntBlock *block, ut64 new_end) {
	// Warning: the resize operation may invalidate the node pointer! But in reality, it only does so
	// if the start address has changed, so it is ok to leave the reference in interp_block->node as-is.
	rz_interval_tree_resize(&ctx->blocks, block->node, rz_absint_block_get_start(block), new_end);
}

/**
 * Resize \p interp_block to cover the instructions, or until the following block.
 * It fills \p RzAbsIntBlock::insn_offsets.
 * It may also split another block if \p interp_block starts at one of its instruction addresses.
 *
 * There are two cases to handle:
 *
 * Case A:
 *
 * Existing Block I at 0x0
 * 0x00 +- Block I
 * 0x04 |
 * 0x08 |        <--- interp_block starts at 0x08.
 * 0x0c |
 * 0x10 +-
 *
 * Becomes:
 *
 * 0x00 +- Block I
 * 0x04 |
 * 0x08 +- Block II
 * 0x0c |
 * 0x10 +-
 *
 *
 * Case B:
 *
 * Existing Block I at 0x0
 * 0x00         <--- interp_block starts here.
 * 0x04
 * 0x08 +- Block I
 * 0x0c |
 * 0x10 +-
 *
 * Becomes:
 *
 * 0x00 +- Block II
 * 0x04 |
 * 0x08 +- Block I
 * 0x0c |
 * 0x10 +-
 */
RZ_API void rz_absint_block_resolve_bounds(RZ_BORROW RzAbsIntRunContext *ctx, RZ_BORROW RzAbsIntBlock *interp_block, const RzILCacheBlock *il_block) {
	if (interp_block->bounds_resolved) {
		return;
	}
	bool trace = (ctx->inst->config.trace_opts & RZ_ABSINT_TRACE_BOUNDS) != 0;
	interp_block->bounds_resolved = true;
	ut64 block_start = rz_absint_block_get_start(interp_block);

	if (trace) {
		RZ_LOG_INFO("Resolving bounds of absint block @ 0x%" PFMT64x "\n", block_start);
	}

	// Blocks may overlap, but one block must not start at an instruction start of another.
	// We have to consider two cases here, depending on the order in which blocks have been discovered.

	// Case A: interp_block would start at an instruction start of another block that starts before us and falls through.
	// We can move the instruction information from the preceding block in that case. This way, case B is already handled as well.
	size_t hit_op_idx = 0;
	RzAbsIntBlock *preceding = interp_block_with_op_at(ctx, rz_absint_block_get_start(interp_block), &hit_op_idx);
	if (preceding) {
		size_t total_ops_count = rz_vector_len(&preceding->insn_offsets) + 1;
		size_t our_ops_count = total_ops_count - hit_op_idx;
		rz_vector_reserve(&interp_block->insn_offsets, our_ops_count - 1);
		for (size_t i = hit_op_idx + 1; i < total_ops_count; i++) {
			ut64 addr = *(ut16 *)rz_vector_index_ptr(&preceding->insn_offsets, i - 1);
			addr += rz_absint_block_get_start(preceding);
			addr -= block_start;
			ut16 off = (ut16)addr;
			rz_vector_push(&interp_block->insn_offsets, &off);
		}
		rz_vector_remove_range(&preceding->insn_offsets, hit_op_idx - 1, rz_vector_len(&preceding->insn_offsets) - (hit_op_idx - 1), NULL);
		rz_vector_shrink(&preceding->insn_offsets);
		interp_block_resize(ctx, interp_block, rz_absint_block_get_end(preceding));
		interp_block_resize(ctx, preceding, block_start - 1);
		preceding->is_fallthrough = true;
		rz_vector_fini(&interp_block->jump_targets);
		memmove(&interp_block->jump_targets, &preceding->jump_targets, sizeof(interp_block->jump_targets));
		rz_vector_init(&preceding->jump_targets, interp_block->jump_targets.elem_size, interp_block->jump_targets.free, interp_block->jump_targets.free_user);

		// The state reachable from the preceding block reaching our start address must be joined into our block's entry state.
		// Hint: For performance, it would actually be better to reinterpret the preceding block before our block, otherwise
		// ours will likely be interperted twice.
		interp_block_mark_uninterpreted(ctx, preceding);

		if (trace) {
			RZ_LOG_INFO("  hit an instruction of a preceding block @ 0x%" PFMT64x "\n\n", rz_absint_block_get_start(preceding));
		}
		return;
	}

	// Case B: Our block will fall through until one instruction start hits exactly another existing block.
	// So we close our block once any of our instructions hit exactly the start of another block.
	// (There is also the case where two non-start instructions hit, but we ignore this for now since results will
	// still be correct)
	// The next candidate for hitting is always the first whose address is greater than or equal to the instruction
	// address (excluding the block start itself, since that would find our own block) so we search forward
	// from a lower bound.
	ut64 search_next_addr = interp_block->node->start + 1;
	RBIter next_it = rz_rbtree_lower_bound_forward(&ctx->blocks.root->node, &search_next_addr, interp_block_addr_cmp, NULL);

	size_t insns_count = rz_pvector_len(il_block->il_ops);
	rz_return_if_fail(insns_count > 0);
	// interp_block->instruction_offsets is assumed to be empty here
	ut64 cur = block_start;
	rz_vector_reserve(&interp_block->insn_offsets, insns_count);
	for (size_t i = 0; i < rz_pvector_len(il_block->il_ops); i++) {
		RzILCacheInsnPkt *insn = rz_pvector_at(il_block->il_ops, i);
		if (i == 0) {
			cur += insn->insn_pkt_size;
			continue;
		}
		// Close block if hitting another block's start address
		while (rz_rbtree_iter_has(&next_it)) {
			RzIntervalNode *next_node = rz_interval_tree_iter_get(&next_it);
			if (next_node->start > cur) {
				break;
			}
			if (next_node->start == cur) {
				// hit found, the block will not include this instruction anymore.
				if (trace) {
					RZ_LOG_INFO("  closing early because an op hit a following block @ 0x%" PFMT64x "\n\n", next_node->start);
				}
				goto close;
			}
			rz_rbtree_iter_next(&next_it);
		}

		ut16 off = cur - block_start;
		rz_vector_push(&interp_block->insn_offsets, &off);
		if (trace) {
			RZ_LOG_INFO("  insn packet @ 0x%" PFMT64x "\n", cur);
		}
		cur += insn->insn_pkt_size;
	}
	if (trace) {
		RZ_LOG_INFO("  resolved until 0x%" PFMT64x " (exclusive) without touching another block\n\n", cur);
	}
close:
	interp_block_resize(ctx, interp_block, cur - 1);
}

/*
 * \brief Register a newly discovered state
 *
 * This will join the state with the already known one at the same pc and add it to the
 * queue for further interpretation if there were changes.
 *
 * \param ctx The runtime context of the interpereter.
 * \param as The abstract state to add. It will be joined with all other states at the same PC.
 * \param is_fallthrough True if the PC of \p as is the starting address of the neighboring block (block didn't branch to some other location in the code).
 */
RZ_API void rz_absint_run_push(RZ_BORROW RZ_NONNULL RzAbsIntRunContext *ctx, RZ_BORROW RZ_NONNULL RzAbsIntState *as, bool is_fallthrough) {
	rz_return_if_fail(interp_is_collecting_states(ctx));
	if (as->pc_state == RZ_ABSINT_PC_ANY) {
		RZ_LOG_DEBUG("Encountered state with unknown/top pc\n");
		return;
	}
	if (as->pc_state != RZ_ABSINT_PC_CONST) {
		rz_warn_if_reached();
		return;
	}
	if (ctx->inst->config.trace_opts & RZ_ABSINT_TRACE_EVAL_BLOCK) {
		RZ_LOG_INFO("  push successor state @ 0x%" PFMT64x "\n", as->pc);
	}
	RzAbsIntBlock *block = rz_absint_block_at(ctx, as->pc);
	if (block) {
		if (join_state(ctx->inst, block->entry_state, as)) {
			interp_block_mark_uninterpreted(ctx, block);
		}
	} else {
		block = rz_absint_block_create(ctx->inst, &ctx->blocks, as);
		if (!block) {
			return;
		}
		interp_block_mark_uninterpreted(ctx, block);
	}
	if (!is_fallthrough) {
		block->non_fallthrough_in = true;
	}
}

RZ_IPI RZ_OWN RzAbsIntBlock *rz_absint_run_pop(RZ_BORROW RZ_NONNULL RzAbsIntRunContext *ctx) {
	RzAbsIntBlock *r = rz_list_pop(ctx->queue);
	if (!r) {
		return NULL;
	}
	r->uninterpreted = false;
	return r;
}

RZ_IPI bool interp_block_tree_as_str(const RzIntervalTree /* RzAbsIntBlock */ *blocks, RZ_NONNULL RZ_OUT RzStrBuf *sb) {
	rz_return_val_if_fail(blocks && sb, false);
	rz_strbuf_append(sb, "============ final absint blocks ============\n\n");
	RzIntervalTreeIter it;
	RzAbsIntBlock *interp_block;
	rz_interval_tree_foreach (blocks, it, interp_block) {
		rz_strbuf_appendf(sb, "0x%" PFMT64x "%s\n", interp_block->entry_state->pc, interp_block->non_fallthrough_in ? " <-" : "");
		if (interp_block->is_fallthrough) {
			rz_strbuf_appendf(sb, "  -> 0x%" PFMT64x " (fallthrough)\n", rz_absint_block_get_end(interp_block) + 1);
		}
		ut64 *it;
		rz_vector_foreach (&interp_block->jump_targets, it) {
			rz_strbuf_appendf(sb, "  -> 0x%" PFMT64x "\n", *it);
		}
		rz_strbuf_append(sb, "\n");
	}
	return true;
}
