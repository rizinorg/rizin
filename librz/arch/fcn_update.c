// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

static int analyze_function_locally(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 address) {
	rz_return_val_if_fail(analysis && fcn, RZ_ANALYSIS_RET_ERROR);
	RzVector tasks;
	rz_vector_init(&tasks, sizeof(RzAnalysisTaskItem), NULL, NULL);
	RzAnalysisTaskItem item = { fcn, NULL, fcn->stack, address };
	rz_vector_push(&tasks, &item);
	int saved_stack = fcn->stack; // TODO: DO NOT use fcn->stack to keep track of stack during analysis
	int ret = rz_analysis_run_tasks(&tasks);
	rz_vector_fini(&tasks);
	fcn->stack = saved_stack;
	return ret;
}

typedef struct {
	RzAnalysisFunction *fcn;
	HtUP *visited;
} BlockRecurseCtx;

static bool mark_as_visited(RzAnalysisBlock *bb, void *user) {
	BlockRecurseCtx *ctx = user;
	ht_up_insert(ctx->visited, bb->addr, NULL);
	return true;
}

static bool analize_addr_cb(ut64 addr, void *user) {
	BlockRecurseCtx *ctx = user;
	RzAnalysis *analysis = ctx->fcn->analysis;
	RzAnalysisBlock *existing_bb = rz_analysis_get_block_at(analysis, addr);
	if (!existing_bb || !rz_pvector_contains(ctx->fcn->bbs, existing_bb)) {
		size_t old_len = rz_pvector_len(ctx->fcn->bbs);
		analyze_function_locally(ctx->fcn->analysis, ctx->fcn, addr);
		if (old_len != rz_pvector_len(ctx->fcn->bbs)) {
			rz_analysis_block_recurse(rz_analysis_get_block_at(analysis, addr), mark_as_visited, user);
		}
	}
	ht_up_insert(ctx->visited, addr, NULL);
	return true;
}

static bool analize_descendents(RzAnalysisBlock *bb, void *user) {
	return rz_analysis_block_successor_addrs_foreach(bb, analize_addr_cb, user);
}

static void update_vars_analysis(RzAnalysisFunction *fcn, RzAnalysisBlock *block, int align, ut64 from, ut64 to) {
	RzAnalysis *analysis = fcn->analysis;
	ut64 cur_addr;
	int opsz;
	from = align ? from - (from % align) : from;
	to = align ? RZ_ROUND(to, align) : to;
	if (UT64_SUB_OVFCHK(to, from)) {
		return;
	}
	ut64 len = to - from;
	ut8 *buf = malloc(len);
	if (!buf) {
		return;
	}
	if (analysis->iob.read_at(analysis->iob.io, from, buf, len) < len) {
		free(buf);
		return;
	}
	RzAnalysisOp op = { 0 };
	for (cur_addr = from; cur_addr < to; cur_addr += opsz, len -= opsz) {
		rz_analysis_op_init(&op);
		int ret = rz_analysis_op(analysis->coreb.core, &op, cur_addr, buf, len, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL);
		if (ret < 1 || op.size < 1) {
			rz_analysis_op_fini(&op);
			break;
		}
		opsz = op.size;
		rz_analysis_extract_vars(analysis, fcn, &op, rz_analysis_block_get_sp_at(block, cur_addr));
		rz_analysis_op_fini(&op);
	}
	free(buf);
}

// Clear function variable acesses inside in a block
static void clear_bb_vars(RzAnalysisFunction *fcn, RzAnalysisBlock *bb, ut64 from, ut64 to) {
	int i;
	if (rz_pvector_empty(&fcn->vars)) {
		return;
	}
	for (i = 0; i < bb->ninstr; i++) {
		const ut64 addr = rz_analysis_block_get_op_addr(bb, i);
		if (addr < from) {
			continue;
		}
		if (addr >= to || addr == UT64_MAX) {
			break;
		}
		RzPVector *vars = rz_analysis_function_get_vars_used_at(fcn, addr);
		if (vars) {
			RzPVector *vars_clone = rz_pvector_clone(vars);
			void **v;
			rz_pvector_foreach (vars_clone, v) {
				rz_analysis_var_remove_access_at((RzAnalysisVar *)*v, addr);
			}
			rz_pvector_clear(vars_clone);
		}
	}
}

static void update_analysis(RzAnalysis *analysis, RzList /*<RzAnalysisFunction *>*/ *fcns, HtUP *reachable) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	bool old_jmpmid = analysis->opt.jmpmid;
	analysis->opt.jmpmid = true;
	rz_list_foreach (fcns, it, fcn) {
		// Recurse through blocks of function, mark reachable,
		// analyze edges that don't have a block
		RzAnalysisBlock *bb = rz_analysis_get_block_at(analysis, fcn->addr);
		if (!bb) {
			analyze_function_locally(analysis, fcn, fcn->addr);
			bb = rz_analysis_get_block_at(analysis, fcn->addr);
			if (!bb) {
				continue;
			}
		}
		HtUP *ht = ht_up_new(NULL, NULL);
		ht_up_insert(ht, bb->addr, NULL);
		BlockRecurseCtx ctx = { fcn, ht };
		rz_analysis_block_recurse(bb, analize_descendents, &ctx);

		// in this loop we remove non-reachable basic blocks and since
		// we modify the pvector size we cannot loop normally.
		size_t count = rz_pvector_len(fcn->bbs);
		for (size_t i = 0; i < count;) {
			bb = (RzAnalysisBlock *)rz_pvector_at(fcn->bbs, i);
			if (ht_up_find_kv(ht, bb->addr, NULL)) {
				i++;
				continue;
			}
			HtUP *o_visited = ht_up_find(reachable, fcn->addr, NULL);
			if (!ht_up_find_kv(o_visited, bb->addr, NULL)) {
				// Avoid removing blocks that were already not reachable
				i++;
				continue;
			}
			fcn->ninstr -= bb->ninstr;
			rz_analysis_function_remove_block(fcn, bb);
			count = rz_pvector_len(fcn->bbs);
		}

		RzPVector *dup_bbs = rz_pvector_clone(fcn->bbs);
		rz_analysis_block_automerge(dup_bbs);
		rz_analysis_function_delete_unused_vars(fcn);
		rz_pvector_free(dup_bbs);
	}
	analysis->opt.jmpmid = old_jmpmid;
}

static void calc_reachable_and_remove_block(RzList /*<RzAnalysisFunction *>*/ *fcns, RzAnalysisFunction *fcn, RzAnalysisBlock *bb, HtUP *reachable) {
	clear_bb_vars(fcn, bb, bb->addr, bb->addr + bb->size);
	if (!rz_list_contains(fcns, fcn)) {
		rz_list_append(fcns, fcn);

		// Calculate reachable blocks from the start of function
		HtUP *ht = ht_up_new(NULL, NULL);
		BlockRecurseCtx ctx = { fcn, ht };
		rz_analysis_block_recurse(rz_analysis_get_block_at(fcn->analysis, fcn->addr), mark_as_visited, &ctx);
		ht_up_insert(reachable, fcn->addr, ht);
	}
	fcn->ninstr -= bb->ninstr;
	rz_analysis_function_remove_block(fcn, bb);
}

RZ_API void rz_analysis_update_analysis_range(RzAnalysis *analysis, ut64 addr, int size) {
	rz_return_if_fail(analysis);
	RzListIter *it, *it2, *tmp;
	RzAnalysisBlock *bb;
	RzAnalysisFunction *fcn;
	RzList *blocks = rz_analysis_get_blocks_intersect(analysis, addr, size);
	if (rz_list_empty(blocks)) {
		rz_list_free(blocks);
		return;
	}
	RzList *fcns = rz_list_new();
	HtUP *reachable = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
	const int align = rz_analysis_archinfo(analysis, RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN);
	const ut64 end_write = addr + size;

	rz_list_foreach (blocks, it, bb) {
		if (!rz_analysis_block_was_modified(bb)) {
			continue;
		}
		rz_list_foreach_safe (bb->fcns, it2, tmp, fcn) {
			if (align > 1) {
				if ((end_write < rz_analysis_block_get_op_addr(bb, bb->ninstr - 1)) && (!bb->switch_op || end_write < bb->switch_op->addr)) {
					// Special case when instructions are aligned and we don't
					// need to worry about a write messing with the jump instructions
					clear_bb_vars(fcn, bb, addr > bb->addr ? addr : bb->addr, end_write);
					update_vars_analysis(fcn, bb, align, addr > bb->addr ? addr : bb->addr, end_write);
					rz_analysis_function_delete_unused_vars(fcn);
					continue;
				}
			}
			calc_reachable_and_remove_block(fcns, fcn, bb, reachable);
		}
	}
	rz_list_free(blocks); // This will call rz_analysis_block_unref to actually remove blocks from RzAnalysis
	update_analysis(analysis, fcns, reachable);
	ht_up_free(reachable);
	rz_list_free(fcns);
}

RZ_API void rz_analysis_function_update_analysis(RzAnalysisFunction *fcn) {
	rz_return_if_fail(fcn);
	RzListIter *it, *tmp;
	RzAnalysisBlock *bb;
	RzAnalysisFunction *f;
	RzList *fcns = rz_list_new();
	HtUP *reachable = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);

	// in this loop we modify the pvector size we cannot loop normally.
	size_t count = rz_pvector_len(fcn->bbs);
	for (size_t i = 0; i < count;) {
		bb = (RzAnalysisBlock *)rz_pvector_at(fcn->bbs, i);
		if (!rz_analysis_block_was_modified(bb)) {
			i++;
			continue;
		}
		rz_list_foreach_safe (bb->fcns, it, tmp, f) {
			calc_reachable_and_remove_block(fcns, f, bb, reachable);
		}
		count = rz_pvector_len(fcn->bbs);
	}
	update_analysis(fcn->analysis, fcns, reachable);
	ht_up_free(reachable);
	rz_list_free(fcns);
}
