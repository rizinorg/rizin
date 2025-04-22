// SPDX-FileCopyrightText: 2019-2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_hash.h>
#include <rz_util/ht_uu.h>

#define unwrap(rbnode) ((rbnode) ? container_of(rbnode, RzAnalysisBlock, _rb) : NULL)

static void __max_end(RBNode *node) {
	RzAnalysisBlock *block = unwrap(node);
	block->_max_end = block->addr + block->size;
	int i;
	for (i = 0; i < 2; i++) {
		if (node->child[i]) {
			ut64 end = unwrap(node->child[i])->_max_end;
			if (end > block->_max_end) {
				block->_max_end = end;
			}
		}
	}
}

static int __bb_addr_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 incoming_addr = *(ut64 *)incoming;
	const RzAnalysisBlock *in_tree_block = container_of(in_tree, const RzAnalysisBlock, _rb);
	if (incoming_addr < in_tree_block->addr) {
		return -1;
	}
	if (incoming_addr > in_tree_block->addr) {
		return 1;
	}
	return 0;
}

#define D if (analysis && analysis->verbose)

RZ_API void rz_analysis_block_ref(RzAnalysisBlock *bb) {
	rz_return_if_fail(bb->ref > 0); // 0-refd must already be freed.
	bb->ref++;
}

#define DFLT_NINSTR 3

static RzAnalysisBlock *block_new(RzAnalysis *a, ut64 addr, ut64 size) {
	RzAnalysisBlock *block = RZ_NEW0(RzAnalysisBlock);
	if (!block) {
		return NULL;
	}
	block->addr = addr;
	block->size = size;
	block->analysis = a;
	block->ref = 1;
	block->jump = UT64_MAX;
	block->fail = UT64_MAX;
	block->op_pos = RZ_NEWS0(ut16, DFLT_NINSTR);
	block->op_pos_size = DFLT_NINSTR;
	block->sp_entry = ST32_MAX;
	rz_vector_init(&block->sp_delta, sizeof(st16), NULL, NULL);
	block->cmpval = UT64_MAX;
	block->fcns = rz_list_new();
	if (size) {
		rz_analysis_block_update_hash(block);
	}
	return block;
}

static void block_free(RzAnalysisBlock *block) {
	if (!block) {
		return;
	}
	rz_analysis_cond_free(block->cond);
	free(block->op_bytes);
	rz_analysis_switch_op_free(block->switch_op);
	rz_list_free(block->fcns);
	free(block->op_pos);
	rz_vector_fini(&block->sp_delta);
	free(block->parent_reg_arena);
	free(block);
}

void __block_free_rb(RBNode *node, void *user) {
	RzAnalysisBlock *block = unwrap(node);
	block_free(block);
}

RZ_API RzAnalysisBlock *rz_analysis_get_block_at(RzAnalysis *analysis, ut64 addr) {
	RBNode *node = rz_rbtree_find(analysis->bb_tree, &addr, __bb_addr_cmp, NULL);
	return unwrap(node);
}

// This is a special case of what rz_interval_node_all_in() does
static bool all_in(RzAnalysisBlock *node, ut64 addr, RzAnalysisBlockCb cb, void *user) {
	while (node && addr < node->addr) {
		// less than the current node, but might still be contained further down
		node = unwrap(node->_rb.child[0]);
	}
	if (!node) {
		return true;
	}
	if (addr >= node->_max_end) {
		return true;
	}
	if (addr < node->addr + node->size) {
		if (!cb(node, user)) {
			return false;
		}
	}
	// This can be done more efficiently by building the stack manually
	if (!all_in(unwrap(node->_rb.child[0]), addr, cb, user)) {
		return false;
	}
	if (!all_in(unwrap(node->_rb.child[1]), addr, cb, user)) {
		return false;
	}
	return true;
}

RZ_API bool rz_analysis_blocks_foreach_in(RzAnalysis *analysis, ut64 addr, RzAnalysisBlockCb cb, void *user) {
	return all_in(unwrap(analysis->bb_tree), addr, cb, user);
}

static bool block_list_cb(RzAnalysisBlock *block, void *user) {
	RzList *list = user;
	rz_analysis_block_ref(block);
	rz_list_push(list, block);
	return true;
}

RZ_API RzList /*<RzAnalysisBlock *>*/ *rz_analysis_get_blocks_in(RzAnalysis *analysis, ut64 addr) {
	RzList *list = rz_list_newf((RzListFree)rz_analysis_block_unref);
	if (list) {
		rz_analysis_blocks_foreach_in(analysis, addr, block_list_cb, list);
	}
	return list;
}

static void all_intersect(RzAnalysisBlock *node, ut64 addr, ut64 size, RzAnalysisBlockCb cb, void *user) {
	ut64 end = addr + size;
	while (node && end <= node->addr) {
		// less than the current node, but might still be contained further down
		node = unwrap(node->_rb.child[0]);
	}
	if (!node) {
		return;
	}
	if (addr >= node->_max_end) {
		return;
	}
	if (addr < node->addr + node->size) {
		cb(node, user);
	}
	// This can be done more efficiently by building the stack manually
	all_intersect(unwrap(node->_rb.child[0]), addr, size, cb, user);
	all_intersect(unwrap(node->_rb.child[1]), addr, size, cb, user);
}

RZ_API void rz_analysis_blocks_foreach_intersect(RzAnalysis *analysis, ut64 addr, ut64 size, RzAnalysisBlockCb cb, void *user) {
	all_intersect(unwrap(analysis->bb_tree), addr, size, cb, user);
}

RZ_API RzList /*<RzAnalysisBlock *>*/ *rz_analysis_get_blocks_intersect(RzAnalysis *analysis, ut64 addr, ut64 size) {
	RzList *list = rz_list_newf((RzListFree)rz_analysis_block_unref);
	if (!list) {
		return NULL;
	}
	rz_analysis_blocks_foreach_intersect(analysis, addr, size, block_list_cb, list);
	return list;
}

RZ_API RzAnalysisBlock *rz_analysis_create_block(RzAnalysis *analysis, ut64 addr, ut64 size) {
	if (rz_analysis_get_block_at(analysis, addr)) {
		return NULL;
	}
	RzAnalysisBlock *block = block_new(analysis, addr, size);
	if (!block) {
		return NULL;
	}
	rz_rbtree_aug_insert(&analysis->bb_tree, &block->addr, &block->_rb, __bb_addr_cmp, NULL, __max_end);
	return block;
}

RZ_API void rz_analysis_delete_block(RzAnalysisBlock *bb) {
	rz_analysis_block_ref(bb);
	while (!rz_list_empty(bb->fcns)) {
		rz_analysis_function_remove_block(rz_list_first(bb->fcns), bb);
	}
	rz_analysis_block_unref(bb);
}

RZ_API void rz_analysis_block_set_size(RzAnalysisBlock *block, ut64 size) {
	if (block->size == size) {
		return;
	}

	// Update the block's function's cached ranges
	RzAnalysisFunction *fcn;
	RzListIter *iter;
	rz_list_foreach (block->fcns, iter, fcn) {
		if (fcn->meta._min != UT64_MAX && fcn->meta._max == block->addr + block->size) {
			fcn->meta._max = block->addr + size;
		}
	}

	// Do the actual resize
	block->size = size;
	rz_rbtree_aug_update_sum(block->analysis->bb_tree, &block->addr, &block->_rb, __bb_addr_cmp, NULL, __max_end);
}

RZ_API bool rz_analysis_block_relocate(RzAnalysisBlock *block, ut64 addr, ut64 size) {
	if (block->addr == addr) {
		rz_analysis_block_set_size(block, size);
		rz_analysis_block_update_hash(block);
		return true;
	}
	if (rz_analysis_get_block_at(block->analysis, addr)) {
		// Two blocks at the same addr is illegle you know...
		return false;
	}

	// Update the block's function's cached ranges
	RzAnalysisFunction *fcn;
	RzListIter *iter;
	rz_list_foreach (block->fcns, iter, fcn) {
		if (fcn->meta._min != UT64_MAX) {
			if (addr + size > fcn->meta._max) {
				// we extend after the maximum, so we are the maximum afterwards.
				fcn->meta._max = addr + size;
			} else if (block->addr + block->size == fcn->meta._max && addr + size != block->addr + block->size) {
				// we were the maximum before and may not be it afterwards, not trivial to recalculate.
				fcn->meta._min = UT64_MAX;
				continue;
			}
			if (block->addr < fcn->meta._min) {
				// less than the minimum, we know that we are the minimum afterwards.
				fcn->meta._min = addr;
			} else if (block->addr == fcn->meta._min && addr != block->addr) {
				// we were the minimum before and may not be it afterwards, not trivial to recalculate.
				fcn->meta._min = UT64_MAX;
			}
		}
	}

	rz_rbtree_aug_delete(&block->analysis->bb_tree, &block->addr, __bb_addr_cmp, NULL, NULL, NULL, __max_end);
	block->addr = addr;
	block->size = size;
	rz_analysis_block_update_hash(block);
	rz_rbtree_aug_insert(&block->analysis->bb_tree, &block->addr, &block->_rb, __bb_addr_cmp, NULL, __max_end);
	return true;
}

RZ_API RzAnalysisBlock *rz_analysis_block_split(RzAnalysisBlock *bbi, ut64 addr) {
	RzAnalysis *analysis = bbi->analysis;
	rz_return_val_if_fail(bbi && addr >= bbi->addr && addr < bbi->addr + bbi->size && addr != UT64_MAX, 0);
	if (addr == bbi->addr) {
		rz_analysis_block_ref(bbi); // ref to be consistent with splitted return refcount
		return bbi;
	}

	if (rz_analysis_get_block_at(bbi->analysis, addr)) {
		// can't have two bbs at the same addr
		return NULL;
	}

	// create the second block
	RzAnalysisBlock *bb = block_new(analysis, addr, bbi->addr + bbi->size - addr);
	if (!bb) {
		return NULL;
	}
	bb->jump = bbi->jump;
	bb->fail = bbi->fail;
	bb->sp_entry = rz_analysis_block_get_sp_at(bbi, addr);
	bb->switch_op = bbi->switch_op;

	// resize the first block
	rz_analysis_block_set_size(bbi, addr - bbi->addr);
	bbi->jump = addr;
	bbi->fail = UT64_MAX;
	bbi->switch_op = NULL;
	rz_analysis_block_update_hash(bbi);

	// insert the second block into the tree
	rz_rbtree_aug_insert(&analysis->bb_tree, &bb->addr, &bb->_rb, __bb_addr_cmp, NULL, __max_end);

	// insert the second block into all functions of the first
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (bbi->fcns, iter, fcn) {
		rz_analysis_function_add_block(fcn, bb);
	}

	// recalculate offsets and sp deltas of instructions in both bb and bbi
	int i;
	i = 0;
	while (i < bbi->ninstr && rz_analysis_block_get_op_offset(bbi, i) < bbi->size) {
		i++;
	}
	int new_bbi_instr = i;
	st16 sp_delta_base = i > 0 ? rz_analysis_block_get_op_sp_delta(bbi, i - 1) : 0;
	if (bb->addr - bbi->addr == rz_analysis_block_get_op_offset(bbi, i)) {
		// setting instructions of the second block only makes sense if the split happened on an instruction boundary
		bb->ninstr = 0;
		while (i < bbi->ninstr) {
			ut16 off_op = rz_analysis_block_get_op_offset(bbi, i);
			if (off_op >= bbi->size + bb->size) {
				break;
			}
			bb->ninstr++;
			rz_analysis_block_set_op_offset(bb, bb->ninstr - 1, off_op - bbi->size);
			st16 sp_delta = rz_analysis_block_get_op_sp_delta(bbi, i);
			if (sp_delta_base != ST16_MAX && sp_delta != ST16_MAX) {
				rz_analysis_block_set_op_sp_delta(bb, bb->ninstr - 1, sp_delta - sp_delta_base);
			}
			i++;
		}
	}
	bbi->ninstr = new_bbi_instr;
	return bb;
}

RZ_API bool rz_analysis_block_merge(RzAnalysisBlock *a, RzAnalysisBlock *b) {
	if (!rz_analysis_block_is_contiguous(a, b)) {
		return false;
	}

	// check if function lists are identical
	if (rz_list_length(a->fcns) != rz_list_length(b->fcns)) {
		return false;
	}
	RzAnalysisFunction *fcn;
	RzListIter *iter;
	rz_list_foreach (a->fcns, iter, fcn) {
		if (!rz_list_contains(b->fcns, fcn)) {
			return false;
		}
	}

	// Keep a ref to b, but remove all references of b from its functions
	rz_analysis_block_ref(b);
	while (!rz_list_empty(b->fcns)) {
		rz_analysis_function_remove_block(rz_list_first(b->fcns), b);
	}

	// merge ops from b into a
	size_t i;
	for (i = 0; i < b->ninstr; i++) {
		rz_analysis_block_set_op_offset(a, a->ninstr++, a->size + rz_analysis_block_get_op_offset(b, i));
	}

	// merge everything else into a
	a->size += b->size;
	a->jump = b->jump;
	a->fail = b->fail;
	if (a->switch_op) {
		RZ_LOG_DEBUG("Dropping switch table at 0x%" PFMT64x " of block at 0x%" PFMT64x "\n", a->switch_op->addr, a->addr);
		rz_analysis_switch_op_free(a->switch_op);
	}
	a->switch_op = b->switch_op;
	b->switch_op = NULL;
	rz_analysis_block_update_hash(a);

	// kill b completely
	rz_rbtree_aug_delete(&a->analysis->bb_tree, &b->addr, __bb_addr_cmp, NULL, __block_free_rb, NULL, __max_end);

	// invalidate ranges of a's functions
	rz_list_foreach (a->fcns, iter, fcn) {
		fcn->meta._min = UT64_MAX;
	}

	return true;
}

RZ_API void rz_analysis_block_unref(RzAnalysisBlock *bb) {
	if (!bb) {
		return;
	}
	rz_return_if_fail(bb->ref > 0);
	bb->ref--;
	rz_return_if_fail(bb->ref >= rz_list_length(bb->fcns)); // all of the block's functions must hold a reference to it
	if (bb->ref < 1) {
		RzAnalysis *analysis = bb->analysis;
		rz_return_if_fail(!bb->fcns || rz_list_empty(bb->fcns));
		rz_rbtree_aug_delete(&analysis->bb_tree, &bb->addr, __bb_addr_cmp, NULL, __block_free_rb, NULL, __max_end);
	}
}

RZ_API bool rz_analysis_block_successor_addrs_foreach(RzAnalysisBlock *block, RzAnalysisAddrCb cb, void *user) {
#define CB_ADDR(addr) \
	do { \
		if (addr == UT64_MAX) { \
			break; \
		} \
		if (!cb(addr, user)) { \
			return false; \
		} \
	} while (0);

	CB_ADDR(block->jump);
	CB_ADDR(block->fail);
	if (block->switch_op && block->switch_op->cases) {
		RzListIter *iter;
		RzAnalysisCaseOp *caseop;
		rz_list_foreach (block->switch_op->cases, iter, caseop) {
			CB_ADDR(caseop->jump);
		}
	}

	return true;
#undef CB_ADDR
}

typedef struct rz_analysis_block_recurse_context_t {
	RzAnalysis *analysis;
	RzPVector /*<RzAnalysisBlock *>*/ to_visit;
	HtUP *visited;
} RzAnalysisBlockRecurseContext;

static bool block_recurse_successor_cb(ut64 addr, void *user) {
	RzAnalysisBlockRecurseContext *ctx = user;
	if (ht_up_find_kv(ctx->visited, addr, NULL)) {
		// already visited
		return true;
	}
	ht_up_insert(ctx->visited, addr, NULL);
	RzAnalysisBlock *block = rz_analysis_get_block_at(ctx->analysis, addr);
	if (!block) {
		return true;
	}
	rz_pvector_push(&ctx->to_visit, block);
	return true;
}

RZ_API bool rz_analysis_block_recurse(RzAnalysisBlock *block, RzAnalysisBlockCb cb, void *user) {
	bool breaked = false;
	RzAnalysisBlockRecurseContext ctx;
	ctx.analysis = block->analysis;
	rz_pvector_init(&ctx.to_visit, NULL);
	ctx.visited = ht_up_new(NULL, NULL);
	if (!ctx.visited) {
		goto beach;
	}

	ht_up_insert(ctx.visited, block->addr, NULL);
	rz_pvector_push(&ctx.to_visit, block);

	while (!rz_pvector_empty(&ctx.to_visit)) {
		RzAnalysisBlock *cur = rz_pvector_pop(&ctx.to_visit);
		breaked = !cb(cur, user);
		if (breaked) {
			break;
		}
		rz_analysis_block_successor_addrs_foreach(cur, block_recurse_successor_cb, &ctx);
	}

beach:
	ht_up_free(ctx.visited);
	rz_pvector_clear(&ctx.to_visit);
	return !breaked;
}

RZ_API bool rz_analysis_block_recurse_followthrough(RzAnalysisBlock *block, RzAnalysisBlockCb cb, void *user) {
	bool breaked = false;
	RzAnalysisBlockRecurseContext ctx;
	ctx.analysis = block->analysis;
	rz_pvector_init(&ctx.to_visit, NULL);
	ctx.visited = ht_up_new(NULL, NULL);
	if (!ctx.visited) {
		goto beach;
	}

	ht_up_insert(ctx.visited, block->addr, NULL);
	rz_pvector_push(&ctx.to_visit, block);

	while (!rz_pvector_empty(&ctx.to_visit)) {
		RzAnalysisBlock *cur = rz_pvector_pop(&ctx.to_visit);
		bool b = !cb(cur, user);
		if (b) {
			breaked = true;
		} else {
			rz_analysis_block_successor_addrs_foreach(cur, block_recurse_successor_cb, &ctx);
		}
	}

beach:
	ht_up_free(ctx.visited);
	rz_pvector_clear(&ctx.to_visit);
	return !breaked;
}

typedef struct {
	RzAnalysisBlock *bb;
	RzListIter /*<RzAnalysisCaseOp *>*/ *switch_it;
} RecurseDepthFirstCtx;

RZ_API bool rz_analysis_block_recurse_depth_first(RzAnalysisBlock *block, RzAnalysisBlockCb cb, RZ_NULLABLE RzAnalysisBlockCb on_exit, void *user) {
	rz_return_val_if_fail(block && cb, true);
	RzVector path;
	bool breaked = false;
	HtUP *visited = ht_up_new(NULL, NULL);
	rz_vector_init(&path, sizeof(RecurseDepthFirstCtx), NULL, NULL);
	if (!visited) {
		goto beach;
	}
	RzAnalysis *analysis = block->analysis;
	RzAnalysisBlock *cur_bb = block;
	RecurseDepthFirstCtx ctx = { cur_bb, NULL };
	rz_vector_push(&path, &ctx);
	ht_up_insert(visited, cur_bb->addr, NULL);
	breaked = !cb(cur_bb, user);
	if (breaked) {
		goto beach;
	}
	do {
		RecurseDepthFirstCtx *cur_ctx = rz_vector_index_ptr(&path, path.len - 1);
		cur_bb = cur_ctx->bb;
		if (cur_bb->jump != UT64_MAX && !ht_up_find_kv(visited, cur_bb->jump, NULL)) {
			cur_bb = rz_analysis_get_block_at(analysis, cur_bb->jump);
		} else if (cur_bb->fail != UT64_MAX && !ht_up_find_kv(visited, cur_bb->fail, NULL)) {
			cur_bb = rz_analysis_get_block_at(analysis, cur_bb->fail);
		} else {
			if (cur_bb->switch_op && !cur_ctx->switch_it) {
				cur_ctx->switch_it = rz_list_head(cur_bb->switch_op->cases);
			} else if (cur_ctx->switch_it) {
				cur_ctx->switch_it = rz_list_iter_get_next(cur_ctx->switch_it);
			}
			if (cur_ctx->switch_it) {
				RzAnalysisCaseOp *cop = rz_list_iter_get_data(cur_ctx->switch_it);
				while (ht_up_find_kv(visited, cop->jump, NULL)) {
					cur_ctx->switch_it = rz_list_iter_get_next(cur_ctx->switch_it);
					if (!cur_ctx->switch_it) {
						cop = NULL;
						break;
					}
					cop = rz_list_iter_get_data(cur_ctx->switch_it);
				}
				cur_bb = cop ? rz_analysis_get_block_at(analysis, cop->jump) : NULL;
			} else {
				cur_bb = NULL;
			}
		}
		if (cur_bb) {
			RecurseDepthFirstCtx ctx = { cur_bb, NULL };
			rz_vector_push(&path, &ctx);
			ht_up_insert(visited, cur_bb->addr, NULL);
			bool breaked = !cb(cur_bb, user);
			if (breaked) {
				break;
			}
		} else {
			if (on_exit) {
				on_exit(cur_ctx->bb, user);
			}
			rz_vector_pop(&path, NULL);
		}
	} while (!rz_vector_empty(&path));

beach:
	ht_up_free(visited);
	rz_vector_clear(&path);
	return !breaked;
}

static bool recurse_list_cb(RzAnalysisBlock *block, void *user) {
	RzList *list = user;
	rz_analysis_block_ref(block);
	rz_list_push(list, block);
	return true;
}

RZ_API RzList /*<RzAnalysisBlock *>*/ *rz_analysis_block_recurse_list(RzAnalysisBlock *block) {
	RzList *ret = rz_list_newf((RzListFree)rz_analysis_block_unref);
	if (ret) {
		rz_analysis_block_recurse(block, recurse_list_cb, ret);
	}
	return ret;
}

RZ_API void rz_analysis_block_add_switch_case(RzAnalysisBlock *block, ut64 switch_addr, ut64 case_value, ut64 case_addr) {
	if (!block->switch_op) {
		block->switch_op = rz_analysis_switch_op_new(switch_addr, 0, 0, 0);
	}
	rz_analysis_switch_op_add_case(block->switch_op, case_addr, case_value, case_addr);
}

RZ_API bool rz_analysis_block_op_starts_at(RzAnalysisBlock *bb, ut64 addr) {
	if (!rz_analysis_block_contains(bb, addr)) {
		return false;
	}
	ut64 off = addr - bb->addr;
	if (off > UT16_MAX) {
		return false;
	}
	size_t i;
	for (i = 0; i < bb->ninstr; i++) {
		ut16 inst_off = rz_analysis_block_get_op_offset(bb, i);
		if (off == inst_off) {
			return true;
		}
	}
	return false;
}

typedef struct {
	RzAnalysis *analysis;
	RzAnalysisBlock *cur_parent;
	ut64 dst;
	RzPVector /*<RzAnalysisBlock *>*/ *next_visit; // accumulate block of the next level in the tree
	HtUP /*<RzAnalysisBlock *>*/ *visited; // maps addrs to their previous block (or NULL for entry)
} PathContext;

static bool shortest_path_successor_cb(ut64 addr, void *user) {
	PathContext *ctx = user;
	if (ht_up_find_kv(ctx->visited, addr, NULL)) {
		// already visited
		return true;
	}
	ht_up_insert(ctx->visited, addr, ctx->cur_parent);
	RzAnalysisBlock *block = rz_analysis_get_block_at(ctx->analysis, addr);
	if (block) {
		rz_pvector_push(ctx->next_visit, block);
	}
	return addr != ctx->dst; // break if we found our destination
}

RZ_API RZ_NULLABLE RzList /*<RzAnalysisBlock *>*/ *rz_analysis_block_shortest_path(RzAnalysisBlock *block, ut64 dst) {
	RzList *ret = NULL;
	PathContext ctx;
	ctx.analysis = block->analysis;
	ctx.dst = dst;

	// two vectors to swap cur_visit/next_visit
	RzPVector visit_a;
	rz_pvector_init(&visit_a, NULL);
	RzPVector visit_b;
	rz_pvector_init(&visit_b, NULL);
	ctx.next_visit = &visit_a;
	RzPVector *cur_visit = &visit_b; // cur visit is the current level in the tree

	ctx.visited = ht_up_new(NULL, NULL);
	if (!ctx.visited) {
		goto beach;
	}

	ht_up_insert(ctx.visited, block->addr, NULL);
	rz_pvector_push(cur_visit, block);

	// BFS
	while (!rz_pvector_empty(cur_visit)) {
		void **it;
		rz_pvector_foreach (cur_visit, it) {
			RzAnalysisBlock *cur = *it;
			ctx.cur_parent = cur;
			rz_analysis_block_successor_addrs_foreach(cur, shortest_path_successor_cb, &ctx);
		}
		RzPVector *tmp = cur_visit;
		cur_visit = ctx.next_visit;
		ctx.next_visit = tmp;
		rz_pvector_clear(ctx.next_visit);
	}

	// reconstruct the path
	bool found = false;
	RzAnalysisBlock *prev = ht_up_find(ctx.visited, dst, &found);
	RzAnalysisBlock *dst_block = rz_analysis_get_block_at(block->analysis, dst);
	if (found && dst_block) {
		ret = rz_list_newf((RzListFree)rz_analysis_block_unref);
		rz_analysis_block_ref(dst_block);
		rz_list_prepend(ret, dst_block);
		while (prev) {
			rz_analysis_block_ref(prev);
			rz_list_prepend(ret, prev);
			prev = ht_up_find(ctx.visited, prev->addr, NULL);
		}
	}

beach:
	ht_up_free(ctx.visited);
	rz_pvector_clear(&visit_a);
	rz_pvector_clear(&visit_b);
	return ret;
}

RZ_API bool rz_analysis_block_was_modified(RzAnalysisBlock *block) {
	rz_return_val_if_fail(block, false);
	if (!block->analysis->iob.read_at) {
		return false;
	}
	ut8 *buf = malloc(block->size);
	if (!buf) {
		return false;
	}
	if (!block->analysis->iob.read_at(block->analysis->iob.io, block->addr, buf, block->size)) {
		free(buf);
		return false;
	}
	ut32 cur_hash = rz_hash_xxhash(buf, block->size);
	free(buf);
	return block->bbhash != cur_hash;
}

RZ_API void rz_analysis_block_update_hash(RzAnalysisBlock *block) {
	rz_return_if_fail(block);
	if (!block->analysis->iob.read_at) {
		return;
	}
	ut8 *buf = malloc(block->size);
	if (!buf) {
		return;
	}
	if (!block->analysis->iob.read_at(block->analysis->iob.io, block->addr, buf, block->size)) {
		free(buf);
		return;
	}
	block->bbhash = rz_hash_xxhash(buf, block->size);
	free(buf);
}

typedef struct {
	RzAnalysisBlock *block;
	bool reachable;
} NoreturnSuccessor;

static void noreturn_successor_free(NoreturnSuccessor *succ) {
	rz_analysis_block_unref(succ->block);
	free(succ);
}

static bool noreturn_successors_cb(RzAnalysisBlock *block, void *user) {
	HtUP *succs = user;
	NoreturnSuccessor *succ = RZ_NEW0(NoreturnSuccessor);
	if (!succ) {
		return false;
	}
	rz_analysis_block_ref(block);
	succ->block = block;
	succ->reachable = false; // reset for first iteration
	ht_up_insert(succs, block->addr, succ);
	return true;
}

static bool noreturn_successors_reachable_cb(RzAnalysisBlock *block, void *user) {
	HtUP *succs = user;
	NoreturnSuccessor *succ = ht_up_find(succs, block->addr, NULL);
	if (succ) {
		succ->reachable = true;
	}
	return true;
}

static bool noreturn_remove_unreachable_cb(void *user, const ut64 k, const void *v) {
	RzAnalysisFunction *fcn = user;
	NoreturnSuccessor *succ = (NoreturnSuccessor *)v;
	if (!succ->reachable && rz_list_contains(succ->block->fcns, fcn)) {
		rz_analysis_function_remove_block(fcn, succ->block);
	}
	succ->reachable = false; // reset for next iteration
	return true;
}

static bool noreturn_get_blocks_cb(void *user, const ut64 k, const void *v) {
	RzPVector *blocks = user;
	NoreturnSuccessor *succ = (NoreturnSuccessor *)v;
	rz_analysis_block_ref(succ->block);
	rz_pvector_push(blocks, succ->block);
	return true;
}

RZ_API RzAnalysisBlock *rz_analysis_block_chop_noreturn(RzAnalysisBlock *block, ut64 addr) {
	rz_return_val_if_fail(block, NULL);
	if (!rz_analysis_block_contains(block, addr) || addr == block->addr) {
		return block;
	}
	rz_analysis_block_ref(block);

	// Cache all recursive successors of block here.
	// These are the candidates that we might have to remove from functions later.
	HtUP *succs = ht_up_new(NULL, (HtUPFreeValue)noreturn_successor_free); // maps block addr (ut64) => NoreturnSuccessor *
	if (!succs) {
		return block;
	}
	rz_analysis_block_recurse(block, noreturn_successors_cb, succs);

	// Chop the block. Resize and remove all destination addrs
	rz_analysis_block_set_size(block, addr - block->addr);
	rz_analysis_block_update_hash(block);
	block->jump = UT64_MAX;
	block->fail = UT64_MAX;
	rz_analysis_switch_op_free(block->switch_op);
	block->switch_op = NULL;

	// Now, for each fcn, check which of our successors are still reachable in the function remove and the ones that are not.
	RzListIter *lit;
	RzAnalysisFunction *fcn;
	// We need to clone the list because block->fcns will get modified in the loop
	RzList *fcns_cpy = rz_list_clone(block->fcns);
	rz_list_foreach (fcns_cpy, lit, fcn) {
		RzAnalysisBlock *entry = rz_analysis_get_block_at(block->analysis, fcn->addr);
		if (entry && rz_list_contains(entry->fcns, fcn)) {
			rz_analysis_block_recurse(entry, noreturn_successors_reachable_cb, succs);
		}
		ht_up_foreach(succs, noreturn_remove_unreachable_cb, fcn);
	}
	rz_list_free(fcns_cpy);

	// This last step isn't really critical, but nice to have.
	// Prepare to merge blocks with their predecessors if possible
	RzPVector *merge_blocks = rz_pvector_new((RzListFree)rz_analysis_block_unref);
	ht_up_foreach(succs, noreturn_get_blocks_cb, merge_blocks);

	// Free/unref BEFORE doing the merge!
	// Some of the blocks might not be valid anymore later!
	rz_analysis_block_unref(block);
	ht_up_free(succs);

	ut64 block_addr = block->addr; // save the addr to identify the block. the automerge might free it so we must not use the pointer!

	// Do the actual merge
	rz_analysis_block_automerge(merge_blocks);

	// No try to recover the pointer to the block if it still exists
	RzAnalysisBlock *ret = NULL;
	void **vit;
	rz_pvector_foreach (merge_blocks, vit) {
		block = (RzAnalysisBlock *)*vit;
		if (block->addr == block_addr) {
			// block is still there
			ret = block;
			break;
		}
	}

	rz_pvector_free(merge_blocks);
	return ret;
}

typedef struct {
	HtUP *predecessors; // maps a block to its predecessor if it has exactly one, or NULL if there are multiple or the predecessor has multiple successors
	HtUP *visited_blocks; // during predecessor search, mark blocks whose successors we already checked. Value is void *-casted count of successors
	HtUP *blocks; // adresses of the blocks we might want to merge with their predecessors => RzAnalysisBlock *

	RzAnalysisBlock *cur_pred;
	size_t cur_succ_count;
} AutomergeCtx;

static bool count_successors_cb(ut64 addr, void *user) {
	AutomergeCtx *ctx = user;
	ctx->cur_succ_count++;
	return true;
}

static bool automerge_predecessor_successor_cb(ut64 addr, void *user) {
	AutomergeCtx *ctx = user;
	ctx->cur_succ_count++;
	RzAnalysisBlock *block = ht_up_find(ctx->blocks, addr, NULL);
	if (!block) {
		// we shouldn't merge this one so GL_DONT_CARE
		return true;
	}
	bool found;
	RzAnalysisBlock *pred = ht_up_find(ctx->predecessors, (ut64)(size_t)block, &found);
	if (found) {
		if (pred) {
			// only one predecessor found so far, but we are the second so there are multiple now
			ht_up_update(ctx->predecessors, (ut64)(size_t)block, NULL);
		} // else: already found multiple predecessors, nothing to do
	} else {
		// no predecessor found yet, this is the only one until now
		ht_up_insert(ctx->predecessors, (ut64)(size_t)block, ctx->cur_pred);
	}
	return true;
}

static bool automerge_get_predecessors_cb(void *user, const ut64 k, const void *v) {
	AutomergeCtx *ctx = user;
	const RzAnalysisFunction *fcn = (const RzAnalysisFunction *)(size_t)k;

	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		RzAnalysisBlock *block = (RzAnalysisBlock *)*it;
		bool already_visited = false;
		ht_up_find(ctx->visited_blocks, (ut64)(size_t)block, &already_visited);
		if (already_visited) {
			continue;
		}
		ctx->cur_pred = block;
		ctx->cur_succ_count = 0;
		rz_analysis_block_successor_addrs_foreach(block, automerge_predecessor_successor_cb, ctx);
		ht_up_insert(ctx->visited_blocks, (ut64)(size_t)block, (void *)ctx->cur_succ_count);
	}
	return true;
}

// Try to find the contiguous predecessors of all given blocks and merge them if possible,
// i.e. if there are no other blocks that have this block as one of their successors
RZ_API void rz_analysis_block_automerge(RzPVector /*<RzAnalysisBlock *>*/ *blocks) {
	rz_return_if_fail(blocks);
	AutomergeCtx ctx = {
		.predecessors = ht_up_new(NULL, NULL),
		.visited_blocks = ht_up_new(NULL, NULL),
		.blocks = ht_up_new(NULL, NULL)
	};

	HtUP *relevant_fcns = ht_up_new(NULL, NULL); // all the functions that contain some of our blocks (ht abused as a set)
	RzList *fixup_candidates = rz_list_new(); // used further down
	if (!ctx.predecessors || !ctx.visited_blocks || !ctx.blocks || !relevant_fcns || !fixup_candidates) {
		goto beach;
	}

	// Get all the functions and prepare ctx.blocks
	RzAnalysisBlock *block;
	void **it;
	rz_pvector_foreach (blocks, it) {
		block = (RzAnalysisBlock *)*it;
		RzListIter *fit;
		RzAnalysisFunction *fcn;
		rz_list_foreach (block->fcns, fit, fcn) {
			ht_up_insert(relevant_fcns, (ut64)(size_t)fcn, NULL);
		}
		ht_up_insert(ctx.blocks, block->addr, block);
	}

	// Get the single predecessors we might want to merge with
	ht_up_foreach(relevant_fcns, automerge_get_predecessors_cb, &ctx);

	// Now finally do the merging
	// in this loop we remove non-reachable basic blocks and since
	// we modify the pvector size we cannot loop normally.
	size_t count = rz_pvector_len(blocks);
	for (size_t i = 0; i < count;) {
		block = (RzAnalysisBlock *)rz_pvector_at(blocks, i);
		RzAnalysisBlock *predecessor = ht_up_find(ctx.predecessors, (ut64)(size_t)block, NULL);
		if (!predecessor) {
			i++;
			continue;
		}
		size_t pred_succs_count = (size_t)ht_up_find(ctx.visited_blocks, (ut64)(size_t)predecessor, NULL);
		if (pred_succs_count != 1) {
			// we can only merge this predecessor if it has exactly one successor
			i++;
			continue;
		}

		// We are about to merge block into predecessor
		// However if there are other blocks that have block as the predecessor,
		// we would uaf after the merge since block will be freed.
		RzAnalysisBlock *clock;
		for (size_t j = i + 1; j < count; j++) {
			clock = (RzAnalysisBlock *)rz_pvector_at(blocks, j);
			RzAnalysisBlock *fixup_pred = ht_up_find(ctx.predecessors, (ut64)(size_t)clock, NULL);
			if (fixup_pred == block) {
				rz_list_push(fixup_candidates, clock);
			}
		}

		if (!rz_analysis_block_merge(predecessor, block)) {
			rz_list_purge(fixup_candidates);
			i++;
			continue;
		}

		// rz_analysis_block_merge() does checks like contiguous, to that's fine
		// block was merged into predecessor, it is now freed!
		// Update number of successors of the predecessor
		ctx.cur_succ_count = 0;
		rz_analysis_block_successor_addrs_foreach(predecessor, count_successors_cb, &ctx);
		ht_up_update(ctx.visited_blocks, (ut64)(size_t)predecessor, (void *)(size_t)ctx.cur_succ_count);
		RzListIter *bit;
		rz_list_foreach (fixup_candidates, bit, clock) {
			// Make sure all previous pointers to block now go to predecessor
			ht_up_update(ctx.predecessors, (ut64)(size_t)clock, predecessor);
		}
		// Remove it from the list
		rz_pvector_remove_at(blocks, i);
		count = rz_pvector_len(blocks);
		rz_list_purge(fixup_candidates);
	}

beach:
	ht_up_free(ctx.predecessors);
	ht_up_free(ctx.visited_blocks);
	ht_up_free(ctx.blocks);
	ht_up_free(relevant_fcns);
	rz_list_free(fixup_candidates);
}

typedef struct {
	ut64 addr;
	RzAnalysisBlock *ret;
} BlockFromOffsetJmpmidCtx;

static bool block_from_offset_cb(RzAnalysisBlock *block, void *user) {
	BlockFromOffsetJmpmidCtx *ctx = user;
	// If an instruction starts exactly at the search addr, return that block immediately
	if (rz_analysis_block_op_starts_at(block, ctx->addr)) {
		ctx->ret = block;
		return false;
	}
	// else search the closest one
	if (!ctx->ret || ctx->ret->addr < block->addr) {
		ctx->ret = block;
	}
	return true;
}

/**
 * Find a single block that seems to be the "most relevant" one that contains the given offset.
 * This should only be used when explicitly only a single basic block should be considered, for example
 * for user-exposed features, since it can always be that multiple blocks overlap.
 * Use rz_analysis_get_blocks_in() in all other cases!
 */
RZ_API RzAnalysisBlock *rz_analysis_find_most_relevant_block_in(RzAnalysis *analysis, ut64 off) {
	BlockFromOffsetJmpmidCtx ctx = { off, NULL };
	rz_analysis_blocks_foreach_in(analysis, off, block_from_offset_cb, &ctx);
	return ctx.ret;
}

/**
 * @return the offset of the i-th instruction in the basicblock bb or U16_MAX if i is invalid.
 */
RZ_API ut16 rz_analysis_block_get_op_offset(RzAnalysisBlock *block, size_t i) {
	if (i >= block->ninstr) {
		return UT16_MAX;
	}
	return (i > 0 && (i - 1) < block->op_pos_size) ? block->op_pos[i - 1] : 0;
}

/**
 * @return the absolute address of the i-th instruction in block or UT64_MAX if i is invalid.
 */
RZ_API ut64 rz_analysis_block_get_op_addr(RzAnalysisBlock *block, size_t i) {
	ut16 offset = rz_analysis_block_get_op_offset(block, i);
	if (offset == UT16_MAX) {
		return UT64_MAX;
	}
	return block->addr + offset;
}

/**
 * set the offset of the i-th instruction in the basicblock bb
 */
RZ_API bool rz_analysis_block_set_op_offset(RzAnalysisBlock *block, size_t i, ut16 v) {
	// the offset 0 of the instruction 0 is not stored because always 0
	if (i > 0 && v > 0) {
		if (i >= block->op_pos_size) {
			size_t new_pos_size = i * 2;
			ut16 *tmp_op_pos = realloc(block->op_pos, new_pos_size * sizeof(*block->op_pos));
			if (!tmp_op_pos) {
				return false;
			}
			block->op_pos_size = new_pos_size;
			block->op_pos = tmp_op_pos;
		}
		block->op_pos[i - 1] = v;
		return true;
	}
	return true;
}

/**
 * \return the index of the instruction that occupies the given \p addr or -1 if it is not in the block.
 */
RZ_API int rz_analysis_block_get_op_index_in(RzAnalysisBlock *bb, ut64 addr) {
	if (!rz_analysis_block_contains(bb, addr)) {
		return -1;
	}
	ut16 delta_off = addr - bb->addr;
	for (int i = 0; i < bb->ninstr; i++) {
		ut16 delta = rz_analysis_block_get_op_offset(bb, i);
		if (delta > delta_off) {
			return i - 1;
		}
	}
	return bb->ninstr - 1;
}

/**
 * \return the address of the instruction that occupies the given \p addr or UT64_MAX if it is not in the block.
 */
RZ_API ut64 rz_analysis_block_get_op_addr_in(RzAnalysisBlock *bb, ut64 addr) {
	int idx = rz_analysis_block_get_op_index_in(bb, addr);
	if (idx < 0) {
		return UT64_MAX;
	}
	return rz_analysis_block_get_op_addr(bb, idx);
}

/**
 * \return the size of the i-th instruction in a basic block
 */
RZ_API ut64 rz_analysis_block_get_op_size(RzAnalysisBlock *bb, size_t i) {
	if (i >= bb->ninstr) {
		return UT64_MAX;
	}
	ut16 idx_cur = rz_analysis_block_get_op_offset(bb, i);
	ut16 idx_next = rz_analysis_block_get_op_offset(bb, i + 1);
	return idx_next != UT16_MAX ? idx_next - idx_cur : bb->size - idx_cur;
}

/**
 * \return The delta between the stack pointer after executing the i-th op and bb->sp_entry or
 *         ST16_MAX if \p i is out of bounds or the value is currently unknown
 */
RZ_API st16 rz_analysis_block_get_op_sp_delta(RzAnalysisBlock *bb, size_t i) {
	rz_return_val_if_fail(bb, ST16_MAX);
	if (i >= bb->ninstr || i >= rz_vector_len(&bb->sp_delta)) {
		return ST16_MAX;
	}
	return *(st16 *)rz_vector_index_ptr(&bb->sp_delta, i);
}

/**
 * Set the delta between the stack pointer after executing the i-th op and bb->sp_entry to \p delta
 * \return whether the value was actually applied
 */
RZ_API bool rz_analysis_block_set_op_sp_delta(RzAnalysisBlock *bb, size_t i, st16 delta) {
	rz_return_val_if_fail(bb, false);
	if (i >= bb->ninstr) {
		return false;
	}
	size_t len = rz_vector_len(&bb->sp_delta);
	if (len <= i) {
		// if necessary, allocate the array until bb->ninstr and pre-fill with ST16_MAX (unknown)
		st16 *arr = rz_vector_insert_range(&bb->sp_delta, len, NULL, bb->ninstr - len);
		if (!arr) {
			return false;
		}
		for (size_t i = 0; i < bb->ninstr - len; i++) {
			arr[i] = ST16_MAX;
		}
	}
	return !!rz_vector_assign_at(&bb->sp_delta, i, &delta);
}

/**
 * \return The delta between the stack pointer at \p addr and bb->sp_entry or
 *         ST16_MAX if \p addr is out of bounds or the value is currently unknown
 */
RZ_API st16 rz_analysis_block_get_sp_delta_at(RzAnalysisBlock *bb, ut64 addr) {
	rz_return_val_if_fail(bb, ST16_MAX);
	int idx = rz_analysis_block_get_op_index_in(bb, addr);
	if (idx == 0 || addr == bb->addr) {
		// before the first instruction, nothing happened yet compared to sp_entry
		return 0;
	}
	if (idx < 0) {
		return ST16_MAX;
	}
	return rz_analysis_block_get_op_sp_delta(bb, idx - 1);
}

/**
 * Get the delta applied to the stack pointer when running through the entire block
 *
 * \return The delta between the stack pointer after executing the last instruction of
 *         the block and bb->sp_entry or ST16_MAX if the value is currently unknown
 */
RZ_API st16 rz_analysis_block_get_sp_delta_at_end(RzAnalysisBlock *bb) {
	rz_return_val_if_fail(bb, ST16_MAX);
	if (!bb->ninstr) {
		return ST16_MAX;
	}
	return rz_analysis_block_get_op_sp_delta(bb, bb->ninstr - 1);
}

/**
 * \return the the stack pointer value after running through the entire block
 */
RZ_API RzStackAddr rz_analysis_block_get_sp_at_end(RzAnalysisBlock *bb) {
	rz_return_val_if_fail(bb, RZ_STACK_ADDR_INVALID);
	if (bb->sp_entry == RZ_STACK_ADDR_INVALID) {
		return RZ_STACK_ADDR_INVALID;
	}
	st16 delta = rz_analysis_block_get_sp_delta_at_end(bb);
	if (delta == ST16_MAX) {
		return RZ_STACK_ADDR_INVALID;
	}
	return bb->sp_entry + delta;
}

/**
 * \return The stack pointer at \p addr or RZ_STACK_ADDR_INVALID if \p addr is
 *         out of bounds or the value is currently unknown
 */
RZ_API RzStackAddr rz_analysis_block_get_sp_at(RzAnalysisBlock *bb, ut64 addr) {
	rz_return_val_if_fail(bb, RZ_STACK_ADDR_INVALID);
	if (bb->sp_entry == RZ_STACK_ADDR_INVALID) {
		return RZ_STACK_ADDR_INVALID;
	}
	st16 delta = rz_analysis_block_get_sp_delta_at(bb, addr);
	if (delta == ST16_MAX) {
		return RZ_STACK_ADDR_INVALID;
	}
	return bb->sp_entry + delta;
}

/**
 * Successively disassemble the ops in this block and update the contained op addrs.
 * This will not move or resize the block itself or touch anything else around it,
 * it is primarily useful when creating or editing blocks after full function analysis.
 */
RZ_API void rz_analysis_block_analyze_ops(RzAnalysisBlock *block) {
	rz_return_if_fail(block);
	RzAnalysis *a = block->analysis;
	if (!a->iob.read_at) {
		return;
	}
	if (block->addr + block->size <= block->addr) {
		return;
	}
	ut8 *buf = malloc(block->size);
	if (!buf) {
		return;
	}
	if (!a->iob.read_at(a->iob.io, block->addr, buf, block->size)) {
		free(buf);
		return;
	}
	// Try to start at the known sp_entry, or fallback to 0 to at least get relative deltas right
	RzStackAddr init_sp = block->sp_entry != RZ_STACK_ADDR_INVALID ? block->sp_entry : 0;
	RzStackAddr sp = init_sp;
	ut64 addr = block->addr;
	size_t i = 0;

	RzAnalysisOp op = { 0 };
	while (addr < block->addr + block->size) {
		rz_analysis_op_init(&op);
		if (rz_analysis_op(block->analysis, &op, addr,
			    buf + (addr - block->addr), block->addr + block->size - addr, 0) <= 0) {
			rz_analysis_op_fini(&op);
			break;
		}
		block->ninstr = i + 1;
		sp = rz_analysis_op_apply_sp_effect(&op, sp);
		rz_analysis_block_set_op_sp_delta(block, i, sp - init_sp);
		if (i > 0) {
			ut64 off = addr - block->addr;
			if (off >= UT16_MAX) {
				rz_analysis_op_fini(&op);
				break;
			}
			rz_analysis_block_set_op_offset(block, i, (ut16)off);
		}
		i++;
		addr += op.size > 0 ? op.size : 1;
		rz_analysis_op_fini(&op);
	}
	free(buf);
}
