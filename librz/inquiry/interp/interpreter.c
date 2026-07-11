// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

#include "rz_analysis.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_log.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_types.h>
#include <rz_vector.h>
#include <rz_util.h>

/////////////////////////////////////////////////////////
/**
 * \name RzInterpAbstrState
 * @{
 */

/**
 * \brief Initializes an abstract state for specified abstract kinds. Optionally with a list of registers.
 * The register name list should always be given if the architecture has some.
 */
RZ_API RZ_OWN RzInterpAbstrState *rz_interp_abstr_state_new(
	RZ_NONNULL RzInterpInstance *inst) {
	rz_return_val_if_fail(inst, NULL);
	RzInterpAbstrState *state = RZ_NEW0(RzInterpAbstrState);
	if (!state) {
		return NULL;
	}
	state->pc_state = RZ_INTERP_PC_UNREACHABLE;
	// Initialize the register file with uninitialized abstract values.
	state->globals = ht_up_new(NULL, NULL);
	for (size_t i = 0; i < inst->il_ctx->reg_binding->regs_count; i++) {
		const char *rname = inst->il_ctx->reg_binding->regs[i].name;
		RzInterpAbstrVal *aval = inst->plugin->val_new_top();
		if (!aval) {
			rz_warn_if_reached();
			ht_up_free(state->globals);
			free(state);
			return NULL;
		}
		ut64 djb2_reg_hash = rz_str_djb2_hash(rname);
		if (!ht_up_insert(state->globals, djb2_reg_hash, aval)) {
			RZ_LOG_ERROR("Failed to add %s to the global variable map.", rname);
			ht_up_free(state->globals);
			free(state);
		}
	}
	state->locals = ht_up_new(NULL, NULL);
	state->lets = ht_up_new(NULL, NULL);
	return state;
}

static void var_set_free(RzInterpInstance *inst, HtUP *vars) {
	if (!vars) {
		return;
	}
	RzIterator *it = ht_up_as_iter(vars);
	RzInterpAbstrVal **v;
	rz_iterator_foreach(it, v) {
		inst->plugin->val_free(*v);
	}
	rz_iterator_free(it);
	ht_up_free(vars);
}

RZ_API void rz_interp_abstr_state_free(RzInterpInstance *inst, RZ_OWN RZ_NULLABLE RzInterpAbstrState *state) {
	if (!state) {
		return;
	}
	var_set_free(inst, state->globals);
	var_set_free(inst, state->locals);
	var_set_free(inst, state->lets);
	free(state);
}

static bool reset_state(RzInterpInstance *inst, RZ_BORROW RzInterpAbstrState *state, ut64 entry_point) {
	state->pc_state = RZ_INTERP_PC_CONST;
	state->pc = entry_point;

	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		ut64 djb2_reg_name = *k;
		RzInterpAbstrVal *av = ht_up_find(state->globals, djb2_reg_name, NULL);
		if (av) {
			inst->plugin->set_top(av);
		}
	}
	rz_iterator_free(it);
	return true;
}

#define STR_TOP    "⊤"
#define STR_BOTTOM "⊥"

RZ_API bool rz_interp_abstr_state_as_str(RZ_NONNULL RzInterpInstance *inst, RZ_NONNULL const RzInterpAbstrState *state, RZ_NONNULL RZ_OUT RzStrBuf *sb) {
	rz_return_val_if_fail(state && sb, false);

	rz_strbuf_append(sb, "Globals\n\n");
	rz_strbuf_append(sb, "\tpc = ");
	if (state->pc_state == RZ_INTERP_PC_CONST) {
		rz_strbuf_appendf(sb, "0x%" PFMT64x, state->pc);
	} else {
		rz_strbuf_append(sb, state->pc_state == RZ_INTERP_PC_ANY ? STR_TOP : STR_BOTTOM);
	}
	rz_strbuf_append(sb, "\n\n");

	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		const char *gname = ht_up_find(inst->var_name_hashes, *k, NULL);
		rz_strbuf_appendf(sb, "\t%s = ", gname);
		RzInterpAbstrVal *av = ht_up_find(state->globals, *k, NULL);
		inst->plugin->val_as_str(av, sb);
		rz_strbuf_append(sb, "\n");
	}
	rz_iterator_free(it);
	return true;
}

RZ_API void rz_interp_abstr_state_as_str_short(RZ_NONNULL RzInterpInstance *inst, RZ_NONNULL const RzInterpAbstrState *astate, RZ_NONNULL RZ_OUT RzStrBuf *sb) {
	bool first = true;
	RzIterator *it = ht_up_as_iter_keys(astate->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		ut64 djb2_reg_name = *k;
		RzInterpAbstrVal *av = ht_up_find(astate->globals, djb2_reg_name, NULL);
		if (!av || inst->plugin->is_top(av)) {
			continue;
		}
		if (!first) {
			rz_strbuf_append(sb, ", ");
		}
		first = false;
		const char *varname = ht_up_find(inst->var_name_hashes, djb2_reg_name, NULL);
		rz_strbuf_appendf(sb, "%s = ", varname);
		inst->plugin->val_as_str(av, sb);
	}
}

static HtUP *var_set_clone(const RzInterpInstance *iset, HtUP *vars) {
	HtUP *r = ht_up_new(NULL, NULL);
	if (!r) {
		return NULL;
	}
	RzIterator *it = ht_up_as_iter_keys(vars);
	ut64 *key;
	rz_iterator_foreach(it, key) {
		RzInterpAbstrVal *val = iset->plugin->val_new_top();
		if (!val) {
			break;
		}
		iset->plugin->copy(val, ht_up_find(vars, *key, NULL));
		ht_up_insert(r, *key, val);
	}
	return r;
}

RZ_API RZ_OWN RzInterpAbstrState *rz_interp_abstr_state_clone(RZ_NONNULL RzInterpInstance *iset, const RzInterpAbstrState *state) {
	RzInterpAbstrState *r = RZ_NEW0(RzInterpAbstrState);
	if (!state) {
		return NULL;
	}
	r->pc = state->pc;
	r->pc_state = state->pc_state;
	r->globals = var_set_clone(iset, state->globals);
	r->locals = var_set_clone(iset, state->locals);
	r->lets = var_set_clone(iset, state->lets);
	return r;
}

/**
 * \brief Join (least upper bound) on var sets
 * \return True if a was changed
 */
static bool join_vars(RzInterpInstance *inst, RZ_BORROW RZ_INOUT HtUP *a, RZ_BORROW RZ_IN HtUP *b) {
	RzIterator *it = ht_up_as_iter_keys(a);
	ut64 *k;
	bool changed = false;
	rz_iterator_foreach(it, k) {
		RzInterpAbstrVal *av = ht_up_find(a, *k, NULL);
		RzInterpAbstrVal *bv = ht_up_find(b, *k, NULL);
		if (!av || !bv) {
			continue;
		}
		if (inst->plugin->join(av, bv)) {
			changed = true;
		}
	}
	return changed;
}

bool join_state(RzInterpInstance *inst, RZ_BORROW RZ_INOUT RzInterpAbstrState *a, RZ_BORROW RZ_IN const RzInterpAbstrState *b) {
	bool global_change = join_vars(inst, a->globals, b->globals);
	bool local_change = join_vars(inst, a->locals, b->locals);
	// lets are not be relevant here since they are immutable within their scope
	return global_change || local_change;
}

/// @}

/////////////////////////////////////////////////////////
/**
 * \name Interpreter Blocks
 * @{
 */

#define UNWRAP_BLOCK(rbnode) ((rbnode) ? container_of(rbnode, RzInterpBlock, _rb) : NULL)

static RzInterpBlock *interp_block_new(RzInterpInstance *inst, RZ_BORROW RZ_NONNULL RzInterpAbstrState *entry_state) {
	RzInterpBlock *block = RZ_NEW0(RzInterpBlock);
	if (!block) {
		return NULL;
	}
	block->entry_state = rz_interp_abstr_state_clone(inst, entry_state);
	if (!block->entry_state) {
		free(block);
		return NULL;
	}
	rz_vector_init(&block->insn_offsets, sizeof(ut16), NULL, NULL);
	rz_vector_init(&block->jump_targets, sizeof(ut64), NULL, NULL);
	return block;
}

static void interp_block_free(RzInterpInstance *inst, RzInterpBlock *block) {
	if (!block) {
		return;
	}
	rz_interp_abstr_state_free(inst, block->entry_state);
	rz_vector_fini(&block->insn_offsets);
	rz_vector_fini(&block->jump_targets);
	free(block);
}

static void interp_blocks_init(RzInterpRunContext *ctx) {
	rz_interval_tree_init(&ctx->blocks, NULL);
}

static void interp_blocks_free(RzInterpRunContext *ctx) {
	RzIntervalTreeIter it;
	RzInterpBlock *block;
	rz_interval_tree_foreach(&ctx->blocks, it, block) {
		interp_block_free(ctx->inst, block);
	}
	rz_interval_tree_fini(&ctx->blocks);
}

static RzInterpBlock *interp_block_create(RzInterpRunContext *ctx, RZ_BORROW RZ_NONNULL RzInterpAbstrState *as) {
	rz_return_val_if_fail(ctx && as && as->pc_state == RZ_INTERP_PC_CONST, NULL);
	RzInterpBlock *block = interp_block_new(ctx->inst, as);
	if (!block) {
		return NULL;
	}
	RzIntervalNode *node = rz_interval_tree_insert(&ctx->blocks, block->entry_state->pc, block->entry_state->pc, block);
	if (!node) {
		rz_warn_if_reached();
		return NULL;
	}
	block->node = node;
	return block;
}

static ut64 interp_block_get_start(RzInterpBlock *block) {
	return block->entry_state->pc;
}

/** end is inclusive */
static ut64 interp_block_get_end(RzInterpBlock *block) {
	return block->node->end;
}

static void interp_block_add_non_fallthrough_target(RzInterpBlock *block, ut64 target) {
	// linear search may be inefficient, but practically the number of targets is often small
	if (rz_vector_contains(&block->jump_targets, &target)) {
		return;
	}
	rz_vector_push(&block->jump_targets, &target);
}

static RzInterpBlock *interp_block_at(RzInterpRunContext *ctx, ut64 addr) {
	return rz_interval_tree_at(&ctx->blocks, addr);
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

/**
 * Resize the block to cover the instructions, or until the following block
 * and fill instruction offsets.
 */
static void interp_block_apply_instructions(RzInterpRunContext *ctx, RzInterpBlock *interp_block, const RzILCacheBlock *il_block) {
	if (interp_block->insns_resolved) {
		return;
	}
	interp_block->insns_resolved = true;
	// Blocks may overlap, but another block must not start at one of our instruction addresses.
	// So we close our block once any of our instructions hit exactly the start of another block.
	// (There is also the case where two non-start instructions hit, but we ignore this for now since results will
	// still be correct)
	// The next candidate for hitting is always the first whose address is greater than or equal to the instruction
	// address (excluding the block start itself, since that would find our own block) so we search forward
	// from a lower bound.
	ut64 search_next_addr = interp_block->node->start + 1;
	RBIter next_it = rz_rbtree_lower_bound_forward(&ctx->blocks.root->node, &search_next_addr, interp_block_addr_cmp, NULL);

	ut64 block_start = interp_block->node->start;
	size_t insns_count = rz_pvector_len(il_block->il_ops);
	rz_return_if_fail(insns_count > 0);
	// interp_block->instruction_offsets is assumed to be empty here
	ut64 cur = block_start;
	rz_vector_reserve(&interp_block->insn_offsets, insns_count);
	for (size_t i = 0; i < rz_pvector_len(il_block->il_ops); i++) {
		RzILCacheInsnPkt *insn = rz_pvector_at(il_block->il_ops, i);
		if (i > 0) {
			// Close block if hitting another block's start address
			while (rz_rbtree_iter_has(&next_it)) {
				RzIntervalNode *next_node = rz_interval_tree_iter_get(&next_it);
				if (next_node->start > cur) {
					break;
				}
				if (next_node->start == cur) {
					// hit found, the block will not include this instruction anymore.
					goto close;
				}
			}

			ut16 off = cur - block_start;
			rz_vector_push(&interp_block->insn_offsets, &off);
		}
		cur += insn->insn_pkt_size;
	}
close:
	// Warning: the resize operation may invalidate the node pointer! But in reality, it only does so
	// if the start address has changed, so it is ok to leave the reference in interp_block->node as-is.
	rz_interval_tree_resize(&ctx->blocks, interp_block->node, block_start, cur - 1);
}

RZ_API void rz_interp_run_push(RZ_BORROW RZ_NONNULL RzInterpRunContext *ctx, RZ_BORROW RZ_NONNULL RzInterpAbstrState *as, bool is_fallthrough) {
	if (as->pc_state == RZ_INTERP_PC_ANY) {
		RZ_LOG_DEBUG("Encountered state with unknown/top pc\n");
		return;
	}
	if (as->pc_state != RZ_INTERP_PC_CONST) {
		rz_warn_if_reached();
		return;
	}
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	rz_interp_abstr_state_as_str_short(ctx->inst, as, &sb);
	RZ_LOG_DEBUG("PUSH 0x%" PFMT64x ": %s\n", as->pc, rz_strbuf_get(&sb));
	rz_strbuf_fini(&sb);
	RzInterpBlock *block = interp_block_at(ctx, as->pc);
	if (block) {
		if (join_state(ctx->inst, block->entry_state, as) && !block->uninterpreted) {
			block->uninterpreted = true;
			rz_list_push(ctx->queue, block);
		}
	} else {
		block = interp_block_create(ctx, as);
		if (!block) {
			return;
		}
		block->uninterpreted = true;
		rz_list_push(ctx->queue, block);
	}
	if (!is_fallthrough) {
		block->non_fallthrough_in = true;
	}
}

static RzInterpBlock *rz_interp_run_pop(RZ_BORROW RZ_NONNULL RzInterpRunContext *ctx) {
	RzInterpBlock *r = rz_list_pop(ctx->queue);
	if (!r) {
		return NULL;
	}
	r->uninterpreted = false;
	return r;
}

/// @}

/////////////////////////////////////////////////////////

RZ_API void rz_interp_yield_rbuf_free(RZ_OWN RZ_NULLABLE RzInterpYieldRBuf *yield_rbufs) {
	if (!yield_rbufs) {
		return;
	}
	if (yield_rbufs->rbuf) {
		rz_th_ring_buf_free(yield_rbufs->rbuf);
	}
	if (yield_rbufs->filter_data && yield_rbufs->filter_data->io_boundaries) {
		rz_pvector_free(yield_rbufs->filter_data->io_boundaries);
	}
	free(yield_rbufs->filter_data);
	free(yield_rbufs);
}

RZ_API RZ_OWN RzInterpYieldRBuf *rz_interp_yield_rbuf_new(RzInterpYieldKind kind,
	RzInterpYieldFilter filter,
	RZ_OWN RZ_NULLABLE void *filter_data) {
	RzInterpYieldRBuf *yield_rbufs = RZ_NEW0(RzInterpYieldRBuf);
	if (!yield_rbufs) {
		return NULL;
	}
	RzThreadRingBuf *rbuf = NULL;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return NULL;
	case RZ_INTERP_YIELD_KIND_CALL_CANDIDATE:
		rbuf = rz_th_ring_buf_new(RZ_INTERP_YIELD_RBUF_SIZE, sizeof(RzAnalysisCallCandidate));
		break;
	case RZ_INTERP_YIELD_KIND_CONTROL_FLOW:
		rbuf = rz_th_ring_buf_new(RZ_INTERP_YIELD_RBUF_SIZE, sizeof(RzInterpCtrlFlow));
		break;
	case RZ_INTERP_YIELD_KIND_XREF:
		if (filter_data) {
			yield_rbufs->filter_data = RZ_NEW0(RzInterpYieldFilterData);
			yield_rbufs->filter_data->io_boundaries = filter_data;
		}
		rbuf = rz_th_ring_buf_new(RZ_INTERP_YIELD_RBUF_SIZE, sizeof(RzAnalysisXRef));
		if (!rbuf) {
			rz_pvector_free(filter_data);
			return NULL;
		}
		break;
	}
	if (!rbuf) {
		free(yield_rbufs);
		return NULL;
	}
	yield_rbufs->kind = kind;
	yield_rbufs->rbuf = rbuf;
	yield_rbufs->filter = filter;
	return yield_rbufs;
}

static bool setup_ipc_objects(
	RZ_OUT RzThreadRingBuf **io_request_rbuf,
	RZ_OUT RzThreadRingBuf **io_result_rbuf,
	RZ_OUT RzThreadRingBuf **entry_points) {
	*io_request_rbuf = NULL;
	*io_result_rbuf = NULL;
	*entry_points = NULL;

	// Setup the IO queues. Each interpreter instance needs it's own queue at
	// for writing IO. Because the writing is done on the IO cache, and each
	// instance needs its own cache.
	*io_request_rbuf = rz_th_ring_buf_new(RZ_INTERP_IO_RBUF_SIZE, sizeof(RzInterpIOReadRequest));
	*io_result_rbuf = rz_th_ring_buf_new(RZ_INTERP_IO_RBUF_SIZE, sizeof(RzInterpIOResult));
	*entry_points = rz_th_ring_buf_new(RZ_INTERP_ENTRY_POINTS_RBUF_SIZE, sizeof(ut64));
	if (!*io_request_rbuf || !*io_result_rbuf || !*entry_points) {
		rz_warn_if_reached();
		goto error_free;
	}

	return true;

error_free:
	rz_th_ring_buf_free(*io_request_rbuf);
	rz_th_ring_buf_free(*io_result_rbuf);
	rz_th_ring_buf_free(*entry_points);
	return false;
}

/**
 * \brief Initializes a new RzInterpSet and returns it.
 * If it fails, all arguments are freed.
 */
RZ_API RZ_OWN RzInterpInstance *rz_interp_instance_new(
	RzAnalysis *analysis,
	RZ_NONNULL RZ_OWN RzInterpValueAbstraction *plugin,
	RZ_NONNULL RZ_BORROW RzILCacheClient *il_cache_client,
	RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM],
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code) {
	rz_return_val_if_fail(plugin && ignored_code && analysis && il_cache_client, NULL);

	RzInterpInstance *inst = RZ_NEW0(RzInterpInstance);
	if (!inst) {
		return NULL;
	}

	const RzAnalysisPlugin *cur = rz_analysis_plugin_current(analysis);
	if (!cur || !cur->arch) {
		goto err_inst;
	}
	inst->arch_name = cur->arch;

	RzAnalysisILContext *il_ctx = rz_analysis_il_context_resolve(analysis);
	if (!il_ctx) {
		RZ_LOG_ERROR("Failed to create analysis IL context.\n");
		goto err_inst;
	}

	RzThreadRingBuf *io_request_rbuf = NULL;
	RzThreadRingBuf *io_result_rbuf = NULL;
	RzThreadRingBuf *entry_points = NULL;
	if (!setup_ipc_objects(&io_request_rbuf, &io_result_rbuf, &entry_points)) {
		goto err_il_ctx;
	}

	inst->a = analysis;
	inst->plugin = plugin;
	inst->run_state = rz_interp_run_state_new();
	inst->il_ctx = il_ctx;

	inst->var_name_hashes = ht_up_new(NULL, free);
	for (size_t i = 0; i < il_ctx->reg_binding->regs_count; i++) {
		const char *rname = il_ctx->reg_binding->regs[i].name;
		ut64 djb2_reg_hash = rz_str_djb2_hash(rname);
		if (!ht_up_insert(inst->var_name_hashes, djb2_reg_hash, rz_str_dup(rname))) {
			RZ_LOG_ERROR("DJB2 hash collision of the register name %s. DJB2 hash = 0x%" PFMT64x "\n",
				rname, djb2_reg_hash);
			goto err_var_name_hashes;
		}
	}

	inst->il_cache_client = il_cache_client;
	inst->entry_points = entry_points;
	inst->yield_rbufs[RZ_INTERP_YIELD_KIND_XREF] = yield_rbufs[RZ_INTERP_YIELD_KIND_XREF];
	inst->yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE] = yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE];
	inst->yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW] = yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW];
	rz_pvector_init(&inst->results, NULL);
	inst->io_request_rbuf = io_request_rbuf;
	inst->io_result_rbuf = io_result_rbuf;
	inst->run_state_sync = rz_th_sem_new(0);
	inst->ignored_code = ignored_code;

	return inst;
err_var_name_hashes:
	ht_up_free(inst->var_name_hashes);
err_il_ctx:
	rz_analysis_il_context_free(il_ctx);
err_inst:
	free(inst);
	return NULL;
}

RZ_API void rz_interp_instance_free(RZ_OWN RZ_NULLABLE RzInterpInstance *iset) {
	if (!iset) {
		return;
	}
	ht_up_free(iset->var_name_hashes);
	if (iset->io_request_rbuf) {
		rz_th_ring_buf_free(iset->io_request_rbuf);
	}
	if (iset->io_result_rbuf) {
		rz_th_ring_buf_free(iset->io_result_rbuf);
	}
	if (iset->entry_points) {
		rz_th_ring_buf_free(iset->entry_points);
	}
	if (iset->run_state_sync) {
		rz_th_sem_free(iset->run_state_sync);
	}
	if (iset->run_state) {
		rz_interp_run_state_free(iset->run_state);
	}
	rz_analysis_il_context_free(iset->il_ctx);
	free(iset);
}

bool report_yield_xref(
	RzInterpRunContext *ctx,
	size_t insn_pkt_size,
	ut64 from,
	const RzInterpAbstrVal *to,
	RzAnalysisXRefType type) {
	RzBitVector to_bv;
	rz_bv_init(&to_bv, 64);
	bool success = true;
	if (!ctx->inst->plugin->to_concrete_const(to, &to_bv) || rz_bv_len(&to_bv) > 64) {
		// Isn't reported
		goto cleanup;
	}
	if (type == RZ_ANALYSIS_XREF_TYPE_CODE &&
		RZ_STR_EQ(ctx->inst->arch_name, "hexagon") &&
		from + insn_pkt_size == rz_bv_to_ut64(&to_bv)) {
		// Ugly work around.
		// Because we don't have RzArch yet the Hexagon plugin adds a JUMP at the
		// end of each and every instruction packet.
		// This is necessary because the RzIL VM would otherwise just add 4 to the PC,
		// which is too little for a packet with 2+ instructions.
		// We don't want to report the code references to the next instruction
		// packet. So skip them here.
		goto cleanup;
	}

	RzInterpYieldRBuf *yrbuf = ctx->inst->yield_rbufs[RZ_INTERP_YIELD_KIND_XREF];
	rz_return_val_if_fail(yrbuf, false);

	ut64 to_addr = rz_bv_to_ut64(&to_bv);
	RzAnalysisXRef xref = { 0 };
	xref.bb_addr = 0; // TODO? ctx->astate->bb_addr;
	xref.from = from;
	xref.to = to_addr;
	xref.type = type;
	if (yrbuf->filter(&xref, yrbuf->filter_data->io_boundaries)) {
		RZ_LOG_DEBUG("prototype: REPORT xref: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n", xref.from, xref.to, rz_analysis_ref_type_tostring(xref.type));
		if (rz_th_ring_buf_put(yrbuf->rbuf, &xref) != RZ_THREAD_RING_BUF_OK) {
			success = false;
			goto cleanup;
		}
	}
cleanup:
	rz_bv_fini(&to_bv);
	return success;
}

/**
 * \brief Report the store of the next PC and report it as possible return point.
 */
static bool report_yield_call_candiate(
	RzInterpRunContext *ctx) {
	RzInterpYieldRBuf *cc_rbuf = ctx->inst->yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE];
	rz_return_val_if_fail(cc_rbuf, false);

	RzAnalysisCallCandidate cc = { 0 };
	// TODO? put the bb addr into the call candidate? Currently we do not know it.
	memcpy(&cc, &ctx->call_cand, sizeof(ctx->call_cand));
	if (rz_th_ring_buf_put(cc_rbuf->rbuf, &cc) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	return true;
}

void write_var_to_state(RzInterpInstance *inst,
	RzInterpAbstrState *astate,
	RzILVarKind kind,
	ut64 var_id,
	const RzInterpAbstrVal *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = astate->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = astate->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = astate->lets;
		break;
	}
	RzInterpAbstrVal *av = ht_up_find(ht_vals, var_id, NULL);
	if (!av) {
		if (kind == RZ_IL_VAR_KIND_GLOBAL) {
			RZ_LOG_WARN("New global variable created: 0x%" PFMT64x "\n", var_id)
			return;
		}
		av = inst->plugin->val_new_top();
		if (!av) {
			rz_warn_if_reached();
			return;
		}
		ht_up_insert(ht_vals, var_id, av);
	}
	inst->plugin->copy(av, data);
}

bool read_var_from_state(RzInterpInstance *inst,
	RzInterpAbstrState *astate,
	RzILVarKind kind,
	ut64 var_id,
	RZ_OUT RzInterpAbstrVal *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return false;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = astate->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = astate->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = astate->lets;
		break;
	}
	RzInterpAbstrVal *av = ht_up_find(ht_vals, var_id, NULL);
	if (!av) {
		// Variable doesn't exist.
		// This should never happen and is a bug.
		rz_warn_if_reached();
		return false;
	}
	inst->plugin->copy(data, av);
	return true;
}

static bool store_abstr_data(
	RzInterpInstance *iset,
	RzILMemIndex mem_idx,
	const RzInterpAbstrVal *addr,
	const RzInterpAbstrVal *src) {
	// TODO: handle with memory abstractions
	return true;
}

bool load_abstr_data(
	RzInterpInstance *inst,
	RzILMemIndex mem_idx,
	const RzBitVector *addr,
	size_t n_bits,
	RZ_OUT RzInterpAbstrVal *out) {
	RzInterpIOReadRequest io_req = { 0 };

	RzBitVector out_bv;
	rz_bv_init(&out_bv, n_bits);

	io_req.addr = addr;
	io_req.ld_data = &out_bv;
	io_req.mem_idx = mem_idx;
	io_req.n_bits = n_bits;
	io_req.big_endian = inst->il_ctx->config->big_endian;
	if (rz_th_ring_buf_put(inst->io_request_rbuf, &io_req) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	RzInterpIOResult io_res = { 0 };
	if (rz_th_ring_buf_take_blocking(inst->io_result_rbuf, &io_res) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	if (!io_res.req_ok) {
		RZ_LOG_WARN("prototype: Failed to read correct number of bytes. Requested: 0x%" PFMTSZx
			    " Received: 0x%" PFMT32x " bits.\n",
			n_bits, rz_bv_len(&out_bv));
		inst->plugin->set_top(out);
		return false;
	}
	inst->plugin->set_const_bv(out, &out_bv);

	char *bytes = rz_bv_as_hex_string(&out_bv, true);
	RZ_LOG_DEBUG("prototype: READ @ mem:%" PFMT32d " 0x%" PFMT64x " : %s\n", mem_idx, rz_bv_to_ut64(io_req.addr), bytes);
	free(bytes);
	return true;
}

static bool set_abstr_pc(RzInterpInstance *inst, RzInterpAbstrState *state, RzInterpAbstrVal *pc) {
	rz_return_val_if_fail(state && pc, false);
	RzBitVector pc_bv;
	rz_bv_init(&pc_bv, 64);
	if (inst->plugin->to_concrete_const(pc, &pc_bv)) {
		state->pc_state = RZ_INTERP_PC_CONST;
		state->pc = rz_bv_to_ut64(&pc_bv);
	} else {
		state->pc_state = RZ_INTERP_PC_ANY;
	}
	rz_bv_fini(&pc_bv);
	RZ_LOG_DEBUG("prototype: set_abstr_pc() - Set PC: 0x%" PFMT64x " (%s)\n",
		state->pc, state->pc_state == RZ_INTERP_PC_CONST ? "Constant" : "Top");
	return true;
}

static bool value_indicates_ret_addr_write(RzInterpRunContext *ctx, RzInterpAbstrVal *val) {
	RzBitVector bv;
	rz_bv_init(&bv, 64);
	// Hint: pc addrs coming from the lifters are currently just opaque bitvectors.
	// So we do not know whether the constant contents of val are actually taken from the architecture's
	// pc register or match the instruction address by chance only.
	// We could add a flag to RzILOpArgsBV that would be set by lifters to indicate that the constant value
	// originates from the pc and use that here.
	// This may also help with the sparc workaround.
	// The downside is that a pattern like this in non-relocatable code would not be detected as call:
	// 0x42 mov lr, 0x4a
	// 0x46 mov pc, r0
	// 0x4a ...
	// but it is questionable whether that should be even detected at all, since there is no way to know
	// if it is intended as call or jump.
	bool ret = ctx->inst->plugin->to_concrete_const(val, &bv) &&
		(rz_bv_to_ut64(&bv) == ctx->il_block_end ||
			// Sparc stores the call instruction PC into o8.
			// The return instruction jumps then to o7+8.
			(rz_str_startswith(ctx->inst->arch_name, "sparc") && rz_bv_to_ut64(&bv) == ctx->astate->pc));
	rz_bv_fini(&bv);
	return ret;
}

static bool eval_pure(RzInterpRunContext *ctx, const RzILOpPure *pure, RZ_OUT RzInterpAbstrVal *out) {
	switch (pure->code) {
	default:
	case RZ_IL_OP_VAR: {
		if (!read_var_from_state(ctx->inst, ctx->astate, pure->op.var.kind, pure->op.var.hash, out)) {
			RZ_LOG_ERROR("prototype: VAR failed to evaluate. The %s '%s' doesn't exist.\n",
				rz_il_var_kind_name(pure->op.var.kind),
				pure->op.var.v);
			return false;
		}
		break;
	}
	case RZ_IL_OP_LET: {
		ut64 vhash = pure->op.let.hash;
		if (!eval_pure(ctx, pure->op.let.exp, out)) {
			RZ_LOG_ERROR("prototype: LET expression failed to evaluate.\n");
			return false;
		}
		write_var_to_state(ctx->inst, ctx->astate, RZ_IL_VAR_KIND_LOCAL_PURE, vhash, out);
		// Evaluate body
		if (!eval_pure(ctx, pure->op.let.body, out)) {
			RZ_LOG_ERROR("prototype: LET body failed to evaluate.\n");
			return false;
		}
		// No need to free the LET variable.
		// It is simply overwritten next time.
		break;
	}
	case RZ_IL_OP_ITE: {
		if (!eval_pure(ctx, pure->op.ite.condition, out)) {
			RZ_LOG_ERROR("prototype: ITE condition failed to evaluate.\n");
			return false;
		}

		RzBitVector cond_bv;
		rz_bv_init(&cond_bv, 64);
		if (!ctx->inst->plugin->to_concrete_const(out, &cond_bv)) {
			// Can't decide which pure to evaluate.
			rz_bv_fini(&cond_bv);
			goto map_to_top;
		}
		bool cond_bool = !rz_bv_is_zero_vector(&cond_bv);

		// TODO: eval both if top
		if (cond_bool) {
			if (!eval_pure(ctx, pure->op.ite.x, out)) {
				RZ_LOG_ERROR("prototype: ITE x failed to evaluate.\n");
				return false;
			}
		} else {
			if (!eval_pure(ctx, pure->op.ite.y, out)) {
				RZ_LOG_ERROR("prototype: ITE y failed to evaluate.\n");
				return false;
			}
		}
		break;
	}
	case RZ_IL_OP_B0:
		ctx->inst->plugin->set_const_bool(out, false);
		break;
	case RZ_IL_OP_B1:
		ctx->inst->plugin->set_const_bool(out, false);
		break;
	case RZ_IL_OP_CAST: {
		if (!eval_pure(ctx, pure->op.cast.val, out)) {
			RZ_LOG_ERROR("prototype: CAST val failed to evaluate.\n");
			return false;
		}
		RzInterpAbstrVal *fill_bit = ctx->inst->plugin->val_new_top();
		if (!fill_bit) {
			return false;
		}
		if (!eval_pure(ctx, pure->op.cast.fill, fill_bit)) {
			RZ_LOG_ERROR("prototype: CAST fill failed to evaluate.\n");
			return false;
		}
		ctx->inst->plugin->eval_cast(pure->op.cast.length, fill_bit, out);
		ctx->inst->plugin->val_free(fill_bit);
		break;
	}
	case RZ_IL_OP_BITV:
		ctx->inst->plugin->set_const_bv(out, pure->op.bitv.value);
		break;
	case RZ_IL_OP_APPEND:
	case RZ_IL_OP_LOGAND:
	case RZ_IL_OP_AND:
	case RZ_IL_OP_LOGOR:
	case RZ_IL_OP_OR:
	case RZ_IL_OP_LOGXOR:
	case RZ_IL_OP_XOR:
	case RZ_IL_OP_ADD:
	case RZ_IL_OP_SUB:
	case RZ_IL_OP_SLE:
	case RZ_IL_OP_ULE:
	case RZ_IL_OP_EQ:
	case RZ_IL_OP_MUL:
	case RZ_IL_OP_MOD:
	case RZ_IL_OP_DIV: {
		RzILOpPure *px;
		RzILOpPure *py;
		if (pure->code == RZ_IL_OP_APPEND) {
			// we use low as the x/out value because in the case of constant operands,
			// appending high bits to a bitvector is more efficient than prepending
			// low bits in place.
			px = pure->op.append.low;
			py = pure->op.append.high;
		} else {
			px = pure->op.binop.x;
			py = pure->op.binop.y;
		}
		if (!eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: binop x failed to evaluate.\n");
			return false;
		}
		// Hint: As an optimization, we could short-circuit if out is top here.
		// However it entirely depends on the plugin whether this is possible, or we lose a lot of precision by doing so.
		RzInterpAbstrVal *y = ctx->inst->plugin->val_new_top();
		if (!y) {
			return false;
		}
		if (!eval_pure(ctx, py, y)) {
			RZ_LOG_ERROR("prototype: binop y failed to evaluate.\n");
			return false;
		}
		ctx->inst->plugin->eval_binop(pure->code, out, y);
		ctx->inst->plugin->val_free(y);
		break;
	}
	case RZ_IL_OP_LOGNOT:
	case RZ_IL_OP_INV:
	case RZ_IL_OP_IS_ZERO:
	case RZ_IL_OP_LSB:
	case RZ_IL_OP_MSB:
	case RZ_IL_OP_NEG: {
		RzILOpPure *x = pure->op.unop.x;
		if (!eval_pure(ctx, x, out)) {
			RZ_LOG_ERROR("prototype: unop x failed to evaluate.\n");
			return false;
		}
		ctx->inst->plugin->eval_unop(pure->code, out);
		break;
	}
	case RZ_IL_OP_SHIFTL:
	case RZ_IL_OP_SHIFTR: {
		RzILOpPure *px = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.x : pure->op.shiftl.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.y : pure->op.shiftl.y;
		RzILOpPure *pfill_bit = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.fill_bit : pure->op.shiftl.fill_bit;
		if (!eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) x failed to evaluate.\n");
			return false;
		}
		// Hint: As an optimization, we could short-circuit if out is top here.
		// However it entirely depends on the plugin whether this is possible, or we lose a lot of precision by doing so.
		RzInterpAbstrVal *y = ctx->inst->plugin->val_new_top();
		if (!y) {
			return false;
		}
		if (!eval_pure(ctx, py, y)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) y failed to evaluate.\n");
			return false;
		}
		RzInterpAbstrVal *fill_bit = ctx->inst->plugin->val_new_top();
		if (!fill_bit) {
			ctx->inst->plugin->val_free(y);
			return false;
		}
		if (!eval_pure(ctx, pfill_bit, fill_bit)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) fill_bit failed to evaluate.\n");
			ctx->inst->plugin->val_free(y);
			return false;
		}
		ctx->inst->plugin->eval_shift(pure->code == RZ_IL_OP_SHIFTR, out, y, fill_bit);
		ctx->inst->plugin->val_free(y);
		ctx->inst->plugin->val_free(fill_bit);
		break;
	}
	case RZ_IL_OP_LOADW:
	case RZ_IL_OP_LOAD: {
		RzILOpPure *key = pure->code == RZ_IL_OP_LOAD ? pure->op.load.key : pure->op.loadw.key;
		RzILMemIndex mem_idx = pure->code == RZ_IL_OP_LOAD ? 0 : pure->op.loadw.mem;
		if (!eval_pure(ctx, key, out)) {
			RZ_LOG_ERROR("prototype: LOAD/LOADW key failed to evaluate.\n");
			return false;
		}

		// Hint: Instead of supporting only a single constant load addr and mapping all other
		// loads to top, if the concrete set of the address is reasonably small, we could load
		// from all possible addresses and join the results.
		RzBitVector ld_addr;
		rz_bv_init(&ld_addr, 64);
		if (!ctx->inst->plugin->to_concrete_const(out, &ld_addr)) {
			rz_bv_fini(&ld_addr);
			goto map_to_top;
		}
		if (rz_bv_len(&ld_addr) == 64) {
			// TODO: Remove normalization.
			// Unset bit 63 is required, because the RzBuffer API only supports
			// st64 addresses.
			RzBitVector mask = { 0 };
			rz_bv_init(&mask, 64);
			rz_bv_set_from_ut64(&mask, 0x7fffffffffffffff);
			rz_bv_and_inplace(&ld_addr, &mask);
		}

		report_yield_xref(ctx, 0, ctx->astate->pc, out, RZ_ANALYSIS_XREF_TYPE_MEM_READ);
		size_t n_bits = pure->code == RZ_IL_OP_LOAD ? ctx->inst->il_ctx->config->mem_key_size : pure->op.loadw.n_bits;
		if (!load_abstr_data(ctx->inst, mem_idx, &ld_addr, n_bits, out)) {
			rz_bv_fini(&ld_addr);
			goto map_to_top;
		}
		rz_bv_fini(&ld_addr);
		break;
	}
	case RZ_IL_OP_SDIV:
	case RZ_IL_OP_SMOD:
	case RZ_IL_OP_FLOAT:
	case RZ_IL_OP_FBITS:
	case RZ_IL_OP_IS_FINITE:
	case RZ_IL_OP_IS_NAN:
	case RZ_IL_OP_IS_INF:
	case RZ_IL_OP_IS_FZERO:
	case RZ_IL_OP_IS_FNEG:
	case RZ_IL_OP_IS_FPOS:
	case RZ_IL_OP_FNEG:
	case RZ_IL_OP_FABS:
	case RZ_IL_OP_FCAST_INT:
	case RZ_IL_OP_FCAST_SINT:
	case RZ_IL_OP_FCAST_FLOAT:
	case RZ_IL_OP_FCAST_SFLOAT:
	case RZ_IL_OP_FCONVERT:
	case RZ_IL_OP_FREQUAL:
	case RZ_IL_OP_FSUCC:
	case RZ_IL_OP_FPRED:
	case RZ_IL_OP_FORDER:
	case RZ_IL_OP_FROUND:
	case RZ_IL_OP_FSQRT:
	case RZ_IL_OP_FRSQRT:
	case RZ_IL_OP_FADD:
	case RZ_IL_OP_FSUB:
	case RZ_IL_OP_FMUL:
	case RZ_IL_OP_FDIV:
	case RZ_IL_OP_FMOD:
	case RZ_IL_OP_FHYPOT:
	case RZ_IL_OP_FPOW:
	case RZ_IL_OP_FMAD:
	case RZ_IL_OP_FROOTN:
	case RZ_IL_OP_FPOWN:
	case RZ_IL_OP_FCOMPOUND:
	case RZ_IL_OP_FEXCEPT:
		RZ_LOG_ERROR("Unhandled pure %" PFMT32d "\n", pure->code);
		// Not implemented.
		goto map_to_top;
	}
	return true;

map_to_top:
	ctx->inst->plugin->set_top(out);
	return true;
}

static bool eval_effect(RzInterpRunContext *ctx,
	const RzILOpEffect *effect,
	size_t insn_pkt_size) {
	rz_return_val_if_fail(ctx->astate->pc_state == RZ_INTERP_PC_CONST, false);
	ut64 pc = ctx->astate->pc;
	RzInterpAbstrVal *eval_out = NULL;

	switch (effect->code) {
	default:
	case RZ_IL_OP_EMPTY:
		break;
	case RZ_IL_OP_NOP: {
		break;
	}
	case RZ_IL_OP_SEQ: {
		if (!eval_effect(ctx, effect->op.seq.x, insn_pkt_size)) {
			goto error;
		}
		if (!eval_effect(ctx, effect->op.seq.y, insn_pkt_size)) {
			goto error;
		}
		break;
	}
	case RZ_IL_OP_SET: {
		eval_out = ctx->inst->plugin->val_new_top();
		ut64 vhash = effect->op.set.hash;
		if (!eval_out || !eval_pure(ctx, effect->op.set.x, eval_out)) {
			goto error;
		}
		RzILVarKind kind = effect->op.set.is_local ? RZ_IL_VAR_KIND_LOCAL : RZ_IL_VAR_KIND_GLOBAL;
		write_var_to_state(ctx->inst, ctx->astate, kind, vhash, eval_out);
		if (value_indicates_ret_addr_write(ctx, eval_out) &&
			kind == RZ_IL_VAR_KIND_GLOBAL) {
			ctx->call_cand.store_addr = pc;
			ctx->call_cand.npc = ctx->il_block_end;
			ctx->call_cand.in_mem = false;
		}
		break;
	}
	case RZ_IL_OP_JMP: {
		eval_out = ctx->inst->plugin->val_new_top();
		if (!eval_out || !eval_pure(ctx, effect->op.jmp.dst, eval_out)) {
			goto error;
		}
		RzBitVector eval_out_bv;
		rz_bv_init(&eval_out_bv, 64);
		bool is_const = ctx->inst->plugin->to_concrete_const(eval_out, &eval_out_bv);
		if (!is_const) {
			RZ_LOG_DEBUG("PC is going to be set to an abstract value! Current PC = 0x%" PFMT64x "\n", pc);
		}
		bool is_call = !!ctx->call_cand.store_addr;

		if (is_const) {
			ut64 target = rz_bv_to_ut64(&eval_out_bv);
			RZ_LOG_DEBUG("prototype: JMP - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", pc, target);
			RzAnalysisXRefType xref_type = RZ_ANALYSIS_XREF_TYPE_CODE;

			if (is_call) {
				// An instruction in this basic block stored the next PC.
				// Report a call candidate and assume this jump is a call.
				ctx->call_cand.candidate_addr = pc;
				ctx->call_cand.target = target;
				report_yield_call_candiate(ctx);

#if 0
				// For a call, we need to push a new frame.
				RzBitVector ret_addr = { 0 };
				rz_bv_init(&ret_addr, rz_bv_len(eval_out.bv));
				rz_bv_set_from_ut64(&ret_addr->call_cand.npc);

				bool found = false;
				ut64 ic = ht_uu_find(plugin_data->bb_invocation_count->call_cand.target, &found);
				stack_frame_push(plugin_data, eval_out.bv, &ret_addr, !found ? 0 : ic);
				rz_bv_fini(&ret_addr);
#endif

				xref_type = RZ_ANALYSIS_XREF_TYPE_CALL;
			}
#if 0
			if (xref_type == RZ_ANALYSIS_XREF_TYPE_CODE && stack_frame_top_ret_addr_cmp(plugin_data, eval_out.bv)) {
				stack_frame_pop(plugin_data, NULL);
				xref_type = RZ_ANALYSIS_XREF_TYPE_RETURN;
			}
#endif

			report_yield_xref(ctx, insn_pkt_size, pc, eval_out,
				xref_type);

			// Clear the call candidate tracking variable.
			memset(&ctx->call_cand, 0, sizeof(ctx->call_cand));
		}

		if (is_call) {
			// For calls, assume control flow will continue like fallthrough.
			// TODO: set data to top that may be changed by the call
		} else {
			set_abstr_pc(ctx->inst, ctx->astate, eval_out);
		}
		rz_bv_fini(&eval_out_bv);
		break;
	}
	case RZ_IL_OP_BRANCH: {
		eval_out = ctx->inst->plugin->val_new_top();
		if (!eval_out || !eval_pure(ctx, effect->op.branch.condition, eval_out)) {
			goto error;
		}
		bool may_be_true = ctx->inst->plugin->may_be_bool(eval_out, true);
		bool may_be_false = ctx->inst->plugin->may_be_bool(eval_out, false);
		ut64 fallthrough_pc = ctx->astate->pc;
		if (may_be_true && may_be_false) {
			RzInterpAbstrState *true_state = rz_interp_abstr_state_clone(ctx->inst, ctx->astate);
			RzInterpAbstrState *false_state = ctx->astate;
			ctx->astate = true_state;
			if (!eval_effect(ctx, effect->op.branch.true_eff, insn_pkt_size)) {
				goto error;
			}
			ctx->astate = false_state;
			if (!eval_effect(ctx, effect->op.branch.false_eff, insn_pkt_size)) {
				goto error;
			}
			if (true_state->pc_state == false_state->pc_state && true_state->pc == false_state->pc) {
				// identical target location, simply join the data and continue
				join_state(ctx->inst, true_state, false_state);
			} else {
				// different jump targets, branch rather than resorting to top pc
				rz_interp_run_push(ctx, true_state, true_state->pc_state == RZ_INTERP_PC_CONST && true_state->pc == fallthrough_pc);
				if (true_state->pc_state == RZ_INTERP_PC_CONST) {
					rz_vector_push(&ctx->block->jump_targets, &true_state->pc);
				}
				// false_state is already in ctx->inst->astate and will be continued automatically
			}
			rz_interp_abstr_state_free(ctx->inst, true_state);
		} else if (may_be_true) {
			if (!eval_effect(ctx, effect->op.branch.true_eff, insn_pkt_size)) {
				goto error;
			}
		} else if (may_be_false) {
			if (!eval_effect(ctx, effect->op.branch.false_eff, insn_pkt_size)) {
				goto error;
			}
		}
		break;
	}
	case RZ_IL_OP_STORE:
	case RZ_IL_OP_STOREW: {
		RzInterpAbstrVal *st_addr = ctx->inst->plugin->val_new_top();
		RzILOpPure *key = effect->code == RZ_IL_OP_STORE ? effect->op.store.key : effect->op.storew.key;
		RzILMemIndex mem_idx = effect->code == RZ_IL_OP_STORE ? 0 : effect->op.storew.mem;
		if (!eval_pure(ctx, key, st_addr)) {
			RZ_LOG_ERROR("prototype: STORE/STOREW key failed to evaluate.\n");
			ctx->inst->plugin->val_free(st_addr);
			goto error;
		}
		RzBitVector st_addr_bv;
		rz_bv_init(&st_addr_bv, 64);
		bool st_addr_is_const = st_addr && ctx->inst->plugin->to_concrete_const(st_addr, &st_addr_bv);
		ctx->inst->plugin->val_free(st_addr);
		if (!st_addr_is_const) {
			rz_bv_fini(&st_addr_bv);
			break;
		}
		if (rz_bv_len(&st_addr_bv) == 64) {
			// TODO: Remove normalization.
			// Unset bit 63 is required, because the RzBuffer API only supports
			// st64 addresses.
			RzBitVector mask = { 0 };
			rz_bv_init(&mask, 64);
			rz_bv_set_from_ut64(&mask, 0x7fffffffffffffff);
			rz_bv_and_inplace(&st_addr_bv, &mask);
		}

		RzILOpPure *pval = effect->code == RZ_IL_OP_STORE ? effect->op.store.value : effect->op.storew.value;
		if (!eval_pure(ctx, pval, eval_out)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			rz_bv_fini(&st_addr_bv);
			goto error;
		}
		if (!eval_out || !eval_pure(ctx, effect->op.branch.condition, eval_out)) {
			rz_bv_fini(&st_addr_bv);
			break;
		}
		if (value_indicates_ret_addr_write(ctx, eval_out)) {
			ctx->call_cand.store_addr = pc;
			ctx->call_cand.npc = ctx->il_block_end;
			ctx->call_cand.in_mem = true;
		}
		report_yield_xref(ctx, insn_pkt_size, pc, st_addr, RZ_ANALYSIS_XREF_TYPE_MEM_WRITE);
		if (!store_abstr_data(ctx->inst, mem_idx, st_addr, eval_out)) {
			rz_bv_fini(&st_addr_bv);
			goto error;
		}
		rz_bv_fini(&st_addr_bv);
		break;
	}
	case RZ_IL_OP_GOTO:
	case RZ_IL_OP_BLK:
	case RZ_IL_OP_REPEAT:
		RZ_LOG_ERROR("Unhandled effect %" PFMT32d "\n", effect->code);
		// Ignore for now.
		break;
	}
	ctx->inst->plugin->val_free(eval_out);
	return true;
error:
	ctx->inst->plugin->val_free(eval_out);
	return false;
}

static bool set_pc(RzInterpAbstrState *state, ut64 pc) {
	rz_return_val_if_fail(state, false);
	state->pc = pc;
	state->pc_state = RZ_INTERP_PC_CONST;
	RZ_LOG_DEBUG("prototype: set_pc() - Set PC: 0x%" PFMT64x " (Constant)\n", pc);
	return true;
}

static bool eval_block(RZ_NONNULL RzInterpRunContext *ctx, RZ_NONNULL const RzILCacheBlock *il_bb) {
	// Reset call candidate tracking for each basic block.
	memset(&ctx->call_cand, 0, sizeof(ctx->call_cand));

	ut64 interp_block_end = interp_block_get_end(ctx->block);

	// Now execute the actual effects of the BLOCK.
	RzInterpAbstrState *astate = ctx->astate;
	void **it;
	rz_pvector_foreach (il_bb->il_ops, it) {
		ut64 pc = astate->pc;

		if (pc > interp_block_end) {
			// block is truncated
			break;
		}

		RZ_LOG_DEBUG("prototype: Eval PC = 0x%" PFMT64x "\n", pc);
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_interp_abstr_state_as_str(ctx->inst, ctx->astate, &sb);
		RZ_LOG_DEBUG("%s\n", rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);

		rz_strbuf_init(&sb);
		if (pc == il_bb->addr) {
			rz_strbuf_append(&sb, "ENTRY ");
		}
		if (rz_vector_index_ptr(&il_bb->il_ops->v, rz_pvector_len(il_bb->il_ops) - 1) == it) {
			rz_strbuf_append(&sb, "EXIT ");
		}
		rz_interp_abstr_state_as_str_short(ctx->inst, ctx->astate, &sb);
		rz_meta_set_string(ctx->inst->a, RZ_META_TYPE_COMMENT, pc, rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);

		RzILCacheInsnPkt *pkt = *it;

		// Prepare next pc, the evalutation may overwrite this.
		ut64 next_pc = pc + pkt->insn_pkt_size;
		set_pc(ctx->astate, next_pc);

		if (!eval_effect(ctx, pkt->effect, pkt->insn_pkt_size)) {
			return false;
		}
		if (astate->pc_state != RZ_INTERP_PC_CONST) {
			// unreachable or unknown jump
			break;
		}
		if (astate->pc != next_pc) {
			// Constant jump other than fallthrough, meaning interpretation will continue in another block
			interp_block_add_non_fallthrough_target(ctx->block, astate->pc);
			break;
		}
	}

	if (astate->pc_state != RZ_INTERP_PC_UNREACHABLE) {
		bool fallthrough = false;
		if (astate->pc_state == RZ_INTERP_PC_CONST && astate->pc == interp_block_end + 1) {
			fallthrough = true;
			ctx->block->fallthrough = true;
		}
		rz_interp_run_push(ctx, ctx->astate, fallthrough);
	}

	return true;
}

/**
 * \brief Run the interpreter from a single entrypoint until a fixpoint is reached
 */
static bool rz_interp_run(RzInterpInstance *inst, ut64 entry_point) {
	// Initialization
	bool success = false;
	RzInterpRunContext ctx = {
		.inst = inst,
		.astate = NULL,
		.queue = rz_list_new()
	};
	if (!ctx.queue) {
		goto cleanup;
	}
	interp_blocks_init(&ctx);

	// Prepare the initial state from the given entry point
	// Hint: nothing speaks against supporting multiple entry points in a single run
	RzInterpAbstrState *estate = rz_interp_abstr_state_new(inst);
	memset(&ctx.call_cand, 0, sizeof(ctx.call_cand));
	if (!reset_state(inst, estate, entry_point)) {
		rz_warn_if_reached();
		rz_interp_abstr_state_free(inst, estate);
		goto cleanup;
	}
	rz_interp_run_push(&ctx, estate, false);
	rz_interp_abstr_state_free(inst, estate);

	// Loop and interpret until a fixpoint has been reached
	while (true) {
		RzInterpBlock *interp_block = rz_interp_run_pop(&ctx);
		if (!interp_block) {
			// No uninterpreted states left, fixpoint reached.
			success = true;
			break;
		}
		ctx.astate = rz_interp_abstr_state_clone(inst, interp_block->entry_state);

		const RzILCacheBlock *il_block = rz_il_cache_client_lift_il_block(inst->il_cache_client, ctx.astate->pc);
		if (!il_block) {
			RZ_LOG_ERROR("interpreter: Lifting failed\n");
			// TODO: handle this better
			break;
		}

		interp_block_apply_instructions(&ctx, interp_block, il_block);

		// DEBUG comments
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		const char *old_cmt = rz_meta_get_string(inst->a, RZ_META_TYPE_COMMENT, il_block->addr);
		if (old_cmt) {
			rz_strbuf_appendf(&sb, "%s; ", old_cmt);
		}
		rz_strbuf_append(&sb, "ENTRY ");
		rz_interp_abstr_state_as_str_short(inst, ctx.astate, &sb);
		// rz_meta_set_string(iset->a, RZ_META_TYPE_COMMENT, il_bb->addr, rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);

		ctx.block = interp_block;
		ctx.il_block_end = il_block->addr + il_block->size;
		// Evaluate the effect on the abstract state.
		if (!eval_block(&ctx, il_block)) {
			RZ_LOG_ERROR("interpreter: Eval failed\n");
			success = false;
			break;
		}
	}

	RzInterpResult *res = RZ_NEW0(RzInterpResult);
	res->entry = entry_point;
	memmove(&res->blocks, &ctx.blocks, sizeof(ctx.blocks));
	memset(&ctx.blocks, 0, sizeof(ctx.blocks));
	rz_pvector_push(&inst->results, res);

cleanup:
	rz_list_free(ctx.queue);
	interp_blocks_free(&ctx);
	return success;
}

/**
 * \brief Interpreter thread
 */
RZ_API bool rz_interp_instance_th(RZ_NONNULL RZ_OWN RzInterpInstance *inst) {
	rz_return_val_if_fail(inst &&
			inst->il_cache_client &&
			inst->yield_rbufs[RZ_INTERP_YIELD_KIND_XREF] &&
			inst->yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE] &&
			inst->yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW] &&
			inst->run_state_sync &&
			inst->plugin,
		false);

	bool success = true;

	RZ_LOG_DEBUG("interpreter: Main: Hello.\n");

	while (true) {
		// INIT
		RZ_LOG_DEBUG("interpreter: Enter INIT\n");
		rz_interp_run_state_set(inst->run_state, RZ_INTERP_RUN_STATE_INIT);

		ut64 entry_point;
		if (rz_th_ring_buf_take_blocking(inst->entry_points, &entry_point) != RZ_THREAD_RING_BUF_OK) {
			// No more entry points to interpret => Terminate.
			// OR.
			success = true;
			break;
		}

		// EMU
		RZ_LOG_DEBUG("interpreter: Enter EMU\n");
		rz_interp_run_state_set(inst->run_state, RZ_INTERP_RUN_STATE_EMU);

		if (!rz_interp_run(inst, entry_point)) {
			RZ_LOG_ERROR("Interpreter run failed for entry point 0x%" PFMT64x "\n", entry_point);
		}

		// CLEAN
		RZ_LOG_DEBUG("interpreter: Enter CLEAN\n");
		rz_interp_run_state_set(inst->run_state, RZ_INTERP_RUN_STATE_CLEAN);

		// Wait until RzInquiry asks to start again.
		rz_th_sem_wait(inst->run_state_sync);
	}

	RZ_LOG_DEBUG("interpreter: Enter TERM\n");
	rz_interp_run_state_set(inst->run_state, RZ_INTERP_RUN_STATE_TERM);
	return success;
}

static void bb_add_target(RzAnalysisBlock *abb, ut64 target) {
	if (abb->jump == UT64_MAX && abb->fail != target) {
		abb->jump = target;
	} else if (abb->fail == UT64_MAX && abb->jump != target) {
		abb->fail = target;
	} else if (abb->fail != target && abb->jump != target) {
		RZ_LOG_WARN("The basic block at 0x%" PFMT64x " has more than two outgoing edges.\n"
			    "\t\tHas jump = 0x%" PFMT64x " fail = 0x%" PFMT64x ". Will miss = 0x%" PFMT64x "\n",
			abb->addr, abb->jump, abb->fail,
			target);
	}
}

RZ_API void rz_interp_result_apply_to_analysis(RZ_NONNULL RzInterpResult *res, RZ_NONNULL RzAnalysis *analysis) {
	rz_return_if_fail(res && analysis);
	// partially copied from rz_inquiry_convert_and_add_to_analysis()
	char name[128];
	RzAnalysisFunction *func = rz_analysis_create_function(analysis, rz_strf(name, "inquiry.0x%" PFMT64x, res->entry), res->entry, RZ_ANALYSIS_FCN_TYPE_FCN);
	RzIntervalTreeIter it;
	RzInterpBlock *block;
	rz_interval_tree_foreach (&res->blocks, it, block) {
		if (block->added_to_analysis) {
			// has been merged into the previous already
			continue;
		}
		ut64 start = interp_block_get_start(block);
		ut64 end_excl = interp_block_get_end(block) + 1;

		if (block->fallthrough && rz_vector_empty(&block->jump_targets)) {
			// Merge consecutive blocks if there is no in-edge between them.
			// Splits like this happen in the first place because interp blocks only reach until the
			// first jump. This may be a call however, which just falls through.
			RzIntervalTreeIter next_it = it;
			while (true) {
				rz_rbtree_iter_next(&next_it);
				RzIntervalNode *next_node = NULL;
				while (rz_rbtree_iter_has(&next_it)) {
					RzIntervalNode *n = rz_interval_tree_iter_get(&next_it);
					if (n->start >= end_excl) {
						if (n->start == end_excl) {
							next_node = n;
						}
						break;
					}
				}
				RzInterpBlock *next_block;
				if (!next_node || (next_block = next_node->data)->non_fallthrough_in) {
					// no consecutive block or there is a consecutive block, but is has an in-edge from somewhere else
					break;
				}
				next_block->added_to_analysis = true;
				end_excl = next_node->end + 1;
				block = next_block;
			}
		}

		// TODO: add_bb should eventually not be used here since it does its own analysis.
		// Instead, we should create the block by hand and apply our analysis info to it.
		// Keep in mind we might have to add info from multiple merged blocks here if (see merging above)
		rz_analysis_add_bb(analysis, start, end_excl - start);
		RzAnalysisBlock *abb = rz_analysis_get_block_at(analysis, start);
		rz_analysis_function_add_block(func, abb);

		// TODO: check if this is a calling block (thus fallthrough) and the following block
		// has no in-edge from somewhere else. If so, merge them.

		abb->jump = UT64_MAX;
		abb->fail = UT64_MAX;
		ut64 *target;
		rz_vector_foreach(&block->jump_targets, target) {
			bb_add_target(abb, *target);
		}
		if (block->fallthrough) {
			bb_add_target(abb, end_excl);
		}
	}
}
