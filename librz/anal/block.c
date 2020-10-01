/* radare - LGPL - Copyright 2019-2020 - pancake, thestr4ng3r */

#include <rz_anal.h>
#include <ht_uu.h>

#include <assert.h>

#define unwrap(rbnode) container_of (rbnode, RzAnalBlock, _rb)

static void __max_end(RBNode *node) {
	RzAnalBlock *block = unwrap (node);
	block->_max_end = block->addr + block->size;
	int i;
	for (i = 0; i < 2; i++) {
		if (node->child[i]) {
			ut64 end = unwrap (node->child[i])->_max_end;
			if (end > block->_max_end) {
				block->_max_end = end;
			}
		}
	}
}

static int __bb_addr_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 incoming_addr = *(ut64 *)incoming;
	const RzAnalBlock *in_tree_block = container_of (in_tree, const RzAnalBlock, _rb);
	if (incoming_addr < in_tree_block->addr) {
		return -1;
	}
	if (incoming_addr > in_tree_block->addr) {
		return 1;
	}
	return 0;
}

#define D if (anal && anal->verbose)

RZ_API void rz_anal_block_ref(RzAnalBlock *bb) {
	assert (bb->ref > 0); // 0-refd must already be freed.
	bb->ref++;
}

#define DFLT_NINSTR 3

static RzAnalBlock *block_new(RzAnal *a, ut64 addr, ut64 size) {
	RzAnalBlock *block = R_NEW0 (RzAnalBlock);
	if (!block) {
		return NULL;
	}
	block->addr = addr;
	block->size = size;
	block->anal = a;
	block->ref = 1;
	block->jump = UT64_MAX;
	block->fail = UT64_MAX;
	block->op_pos = R_NEWS0 (ut16, DFLT_NINSTR);
	block->op_pos_size = DFLT_NINSTR;
	block->stackptr = 0;
	block->parent_stackptr = INT_MAX;
	block->cmpval = UT64_MAX;
	block->fcns = rz_list_new ();
	return block;
}

static void block_free(RzAnalBlock *block) {
	if (!block) {
		return;
	}
	rz_anal_cond_free (block->cond);
	free (block->fingerprint);
	rz_anal_diff_free (block->diff);
	free (block->op_bytes);
	rz_anal_switch_op_free (block->switch_op);
	rz_list_free (block->fcns);
	free (block->op_pos);
	free (block->parent_reg_arena);
	free (block);
}

void __block_free_rb(RBNode *node, void *user) {
	RzAnalBlock *block = unwrap (node);
	block_free (block);
}

RZ_API RzAnalBlock *rz_anal_get_block_at(RzAnal *anal, ut64 addr) {
	RBNode *node = rz_rbtree_find (anal->bb_tree, &addr, __bb_addr_cmp, NULL);
	return node? unwrap (node): NULL;
}

// This is a special case of what rz_interval_node_all_in() does
static bool all_in(RzAnalBlock *node, ut64 addr, RzAnalBlockCb cb, void *user) {
	while (node && addr < node->addr) {
		// less than the current node, but might still be contained further down
		node = unwrap (node->_rb.child[0]);
	}
	if (!node) {
		return true;
	}
	if (addr >= node->_max_end) {
		return true;
	}
	if (addr < node->addr + node->size) {
		if (!cb (node, user)) {
			return false;
		}
	}
	// This can be done more efficiently by building the stack manually
	if (!all_in (unwrap (node->_rb.child[0]), addr, cb, user)) {
		return false;
	}
	if (!all_in (unwrap (node->_rb.child[1]), addr, cb, user)) {
		return false;
	}
	return true;
}

RZ_API bool rz_anal_blocks_foreach_in(RzAnal *anal, ut64 addr, RzAnalBlockCb cb, void *user) {
	return all_in (anal->bb_tree ? unwrap (anal->bb_tree) : NULL, addr, cb, user);
}

static bool block_list_cb(RzAnalBlock *block, void *user) {
	RzList *list = user;
	rz_anal_block_ref (block);
	rz_list_push (list, block);
	return true;
}

RZ_API RzList *rz_anal_get_blocks_in(RzAnal *anal, ut64 addr) {
	RzList *list = rz_list_newf ((RzListFree)rz_anal_block_unref);
	if (list) {
		rz_anal_blocks_foreach_in (anal, addr, block_list_cb, list);
	}
	return list;
}

static void all_intersect(RzAnalBlock *node, ut64 addr, ut64 size, RzAnalBlockCb cb, void *user) {
	ut64 end = addr + size;
	while (node && end <= node->addr) {
		// less than the current node, but might still be contained further down
		node = unwrap (node->_rb.child[0]);
	}
	if (!node) {
		return;
	}
	if (addr >= node->_max_end) {
		return;
	}
	if (addr < node->addr + node->size) {
		cb (node, user);
	}
	// This can be done more efficiently by building the stack manually
	all_intersect (unwrap (node->_rb.child[0]), addr, size, cb, user);
	all_intersect (unwrap (node->_rb.child[1]), addr, size, cb, user);
}

RZ_API void rz_anal_blocks_foreach_intersect(RzAnal *anal, ut64 addr, ut64 size, RzAnalBlockCb cb, void *user) {
	all_intersect (anal->bb_tree ? unwrap (anal->bb_tree) : NULL, addr, size, cb, user);
}

RZ_API RzList *rz_anal_get_blocks_intersect(RzAnal *anal, ut64 addr, ut64 size) {
	RzList *list = rz_list_newf ((RzListFree)rz_anal_block_unref);
	if (!list) {
		return NULL;
	}
	rz_anal_blocks_foreach_intersect (anal, addr, size, block_list_cb, list);
	return list;
}

RZ_API RzAnalBlock *rz_anal_create_block(RzAnal *anal, ut64 addr, ut64 size) {
	if (rz_anal_get_block_at (anal, addr)) {
		return NULL;
	}
	RzAnalBlock *block = block_new (anal, addr, size);
	if (!block) {
		return NULL;
	}
	rz_rbtree_aug_insert (&anal->bb_tree, &block->addr, &block->_rb, __bb_addr_cmp, NULL, __max_end);
	return block;
}

RZ_API void rz_anal_delete_block(RzAnalBlock *bb) {
	rz_anal_block_ref (bb);
	while (!rz_list_empty (bb->fcns)) {
		rz_anal_function_remove_block (rz_list_first (bb->fcns), bb);
	}
	rz_anal_block_unref (bb);
}

RZ_API void rz_anal_block_set_size(RzAnalBlock *block, ut64 size) {
	if (block->size == size) {
		return;
	}

	// Update the block's function's cached ranges
	RzAnalFunction *fcn;
	RzListIter *iter;
	rz_list_foreach (block->fcns, iter, fcn) {
		if (fcn->meta._min != UT64_MAX && fcn->meta._max == block->addr + block->size) {
			fcn->meta._max = block->addr + size;
		}
	}

	// Do the actual resize
	block->size = size;
	rz_rbtree_aug_update_sum (block->anal->bb_tree, &block->addr, &block->_rb, __bb_addr_cmp, NULL, __max_end);
}

RZ_API bool rz_anal_block_relocate(RzAnalBlock *block, ut64 addr, ut64 size) {
	if (block->addr == addr) {
		rz_anal_block_set_size (block, size);
		return true;
	}
	if (rz_anal_get_block_at (block->anal, addr)) {
		// Two blocks at the same addr is illegle you know...
		return false;
	}

	// Update the block's function's cached ranges
	RzAnalFunction *fcn;
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

	rz_rbtree_aug_delete (&block->anal->bb_tree, &block->addr, __bb_addr_cmp, NULL, NULL, NULL, __max_end);
	block->addr = addr;
	block->size = size;
	rz_rbtree_aug_insert (&block->anal->bb_tree, &block->addr, &block->_rb, __bb_addr_cmp, NULL, __max_end);
	return true;
}

RZ_API RzAnalBlock *rz_anal_block_split(RzAnalBlock *bbi, ut64 addr) {
	RzAnal *anal = bbi->anal;
	rz_return_val_if_fail (bbi && addr >= bbi->addr && addr < bbi->addr + bbi->size && addr != UT64_MAX, 0);
	if (addr == bbi->addr) {
		rz_anal_block_ref (bbi); // ref to be consistent with splitted return refcount
		return bbi;
	}

	if (rz_anal_get_block_at (bbi->anal, addr)) {
		// can't have two bbs at the same addr
		return NULL;
	}

	// create the second block
	RzAnalBlock *bb = block_new (anal, addr, bbi->addr + bbi->size - addr);
	if (!bb) {
		return NULL;
	}
	bb->jump = bbi->jump;
	bb->fail = bbi->fail;
	bb->parent_stackptr = bbi->stackptr;

	// resize the first block
	rz_anal_block_set_size (bbi, addr - bbi->addr);
	bbi->jump = addr;
	bbi->fail = UT64_MAX;

	// insert the second block into the tree
	rz_rbtree_aug_insert (&anal->bb_tree, &bb->addr, &bb->_rb, __bb_addr_cmp, NULL, __max_end);

	// insert the second block into all functions of the first
	RzListIter *iter;
	RzAnalFunction *fcn;
	rz_list_foreach (bbi->fcns, iter, fcn) {
		rz_anal_function_add_block (fcn, bb);
	}

	// recalculate offset of instructions in both bb and bbi
	int i;
	i = 0;
	while (i < bbi->ninstr && rz_anal_bb_offset_inst (bbi, i) < bbi->size) {
		i++;
	}
	int new_bbi_instr = i;
	if (bb->addr - bbi->addr == rz_anal_bb_offset_inst (bbi, i)) {
		bb->ninstr = 0;
		while (i < bbi->ninstr) {
			ut16 off_op = rz_anal_bb_offset_inst (bbi, i);
			if (off_op >= bbi->size + bb->size) {
				break;
			}
			rz_anal_bb_set_offset (bb, bb->ninstr, off_op - bbi->size);
			bb->ninstr++;
			i++;
		}
	}
	bbi->ninstr = new_bbi_instr;
	return bb;
}

RZ_API bool rz_anal_block_merge(RzAnalBlock *a, RzAnalBlock *b) {
	if (!rz_anal_block_is_contiguous (a, b)) {
		return false;
	}

	// check if function lists are identical
	if (rz_list_length (a->fcns) != rz_list_length (b->fcns)) {
		return false;
	}
	RzAnalFunction *fcn;
	RzListIter *iter;
	rz_list_foreach (a->fcns, iter, fcn) {
		if (!rz_list_contains (b->fcns, fcn)) {
			return false;
		}
	}

	// Keep a ref to b, but remove all references of b from its functions
	rz_anal_block_ref (b);
	while (!rz_list_empty (b->fcns)) {
		rz_anal_function_remove_block (rz_list_first (b->fcns), b);
	}

	// merge ops from b into a
	size_t i;
	for (i = 0; i < b->ninstr; i++) {
		rz_anal_bb_set_offset (a, a->ninstr++, a->size + rz_anal_bb_offset_inst (b, i));
	}

	// merge everything else into a
	a->size += b->size;
	a->jump = b->jump;
	a->fail = b->fail;

	// kill b completely
	rz_rbtree_aug_delete (&a->anal->bb_tree, &b->addr, __bb_addr_cmp, NULL, __block_free_rb, NULL, __max_end);

	// invalidate ranges of a's functions
	rz_list_foreach (a->fcns, iter, fcn) {
		fcn->meta._min = UT64_MAX;
	}

	return true;
}

RZ_API void rz_anal_block_unref(RzAnalBlock *bb) {
	if (!bb) {
		return;
	}
	assert (bb->ref > 0);
	bb->ref--;
	assert (bb->ref >= rz_list_length (bb->fcns)); // all of the block's functions must hold a reference to it
	if (bb->ref < 1) {
		RzAnal *anal = bb->anal;
		assert (!bb->fcns || rz_list_empty (bb->fcns));
		rz_rbtree_aug_delete (&anal->bb_tree, &bb->addr, __bb_addr_cmp, NULL, __block_free_rb, NULL, __max_end);
	}
}

RZ_API bool rz_anal_block_successor_addrs_foreach(RzAnalBlock *block, RzAnalAddrCb cb, void *user) {
#define CB_ADDR(addr) do { \
		if (addr == UT64_MAX) { \
			break; \
		} \
		if (!cb (addr, user)) { \
			return false; \
		} \
	} while(0);

	CB_ADDR (block->jump);
	CB_ADDR (block->fail);
	if (block->switch_op && block->switch_op->cases) {
		RzListIter *iter;
		RzAnalCaseOp *caseop;
		rz_list_foreach (block->switch_op->cases, iter, caseop) {
			CB_ADDR (caseop->jump);
		}
	}

	return true;
#undef CB_ADDR
}

typedef struct rz_anal_block_recurse_context_t {
	RzAnal *anal;
	RPVector/*<RzAnalBlock>*/ to_visit;
	HtUP *visited;
} RzAnalBlockRecurseContext;

static bool block_recurse_successor_cb(ut64 addr, void *user) {
	RzAnalBlockRecurseContext *ctx = user;
	if (ht_up_find_kv (ctx->visited, addr, NULL)) {
		// already visited
		return true;
	}
	ht_up_insert (ctx->visited, addr, NULL);
	RzAnalBlock *block = rz_anal_get_block_at (ctx->anal, addr);
	if (!block) {
		return true;
	}
	rz_pvector_push (&ctx->to_visit, block);
	return true;
}

RZ_API bool rz_anal_block_recurse(RzAnalBlock *block, RzAnalBlockCb cb, void *user) {
	bool breaked = false;
	RzAnalBlockRecurseContext ctx;
	ctx.anal = block->anal;
	rz_pvector_init (&ctx.to_visit, NULL);
	ctx.visited = ht_up_new0 ();
	if (!ctx.visited) {
		goto beach;
	}

	ht_up_insert (ctx.visited, block->addr, NULL);
	rz_pvector_push (&ctx.to_visit, block);

	while (!rz_pvector_empty (&ctx.to_visit)) {
		RzAnalBlock *cur = rz_pvector_pop (&ctx.to_visit);
		breaked = !cb (cur, user);
		if (breaked) {
			break;
		}
		rz_anal_block_successor_addrs_foreach (cur, block_recurse_successor_cb, &ctx);
	}

beach:
	ht_up_free (ctx.visited);
	rz_pvector_clear (&ctx.to_visit);
	return !breaked;
}

RZ_API bool rz_anal_block_recurse_followthrough(RzAnalBlock *block, RzAnalBlockCb cb, void *user) {
	bool breaked = false;
	RzAnalBlockRecurseContext ctx;
	ctx.anal = block->anal;
	rz_pvector_init (&ctx.to_visit, NULL);
	ctx.visited = ht_up_new0 ();
	if (!ctx.visited) {
		goto beach;
	}

	ht_up_insert (ctx.visited, block->addr, NULL);
	rz_pvector_push (&ctx.to_visit, block);

	while (!rz_pvector_empty (&ctx.to_visit)) {
		RzAnalBlock *cur = rz_pvector_pop (&ctx.to_visit);
		bool b = !cb (cur, user);
		if (b) {
			breaked = true;
		} else {
			rz_anal_block_successor_addrs_foreach (cur, block_recurse_successor_cb, &ctx);
		}
	}

beach:
	ht_up_free (ctx.visited);
	rz_pvector_clear (&ctx.to_visit);
	return !breaked;
}

typedef struct {
	RzAnalBlock *bb;
	RzListIter *switch_it;
} RecurseDepthFirstCtx;

RZ_API bool rz_anal_block_recurse_depth_first(RzAnalBlock *block, RzAnalBlockCb cb, R_NULLABLE RzAnalBlockCb on_exit, void *user) {
	bool breaked = false;
	HtUP *visited = ht_up_new0 ();
	if (!visited) {
		goto beach;
	}
	RzAnal *anal = block->anal;
	RzVector path;
	rz_vector_init (&path, sizeof (RecurseDepthFirstCtx), NULL, NULL);
	RzAnalBlock *cur_bb = block;
	RecurseDepthFirstCtx ctx = { cur_bb, NULL };
	rz_vector_push (&path, &ctx);
	ht_up_insert (visited, cur_bb->addr, NULL);
	breaked = !cb (cur_bb, user);
	if (breaked) {
		goto beach;
	}
	do {
		RecurseDepthFirstCtx *cur_ctx = rz_vector_index_ptr (&path, path.len - 1);
		cur_bb = cur_ctx->bb;
		if (cur_bb->jump != UT64_MAX && !ht_up_find_kv (visited, cur_bb->jump, NULL)) {
			cur_bb = rz_anal_get_block_at (anal, cur_bb->jump);
		} else if (cur_bb->fail != UT64_MAX && !ht_up_find_kv (visited, cur_bb->fail, NULL)) {
			cur_bb = rz_anal_get_block_at (anal, cur_bb->fail);
		} else {
			RzAnalCaseOp *cop = NULL;
			if (cur_bb->switch_op && !cur_ctx->switch_it) {
				cur_ctx->switch_it = cur_bb->switch_op->cases->head;
				cop = rz_list_first (cur_bb->switch_op->cases);
			} else if (cur_ctx->switch_it) {
				while ((cur_ctx->switch_it = rz_list_iter_get_next (cur_ctx->switch_it))) {
					cop = rz_list_iter_get_data (cur_ctx->switch_it);
					if (!ht_up_find_kv (visited, cop->jump, NULL)) {
						break;
					}
					cop = NULL;
				}
			}
			cur_bb = cop ? rz_anal_get_block_at (anal, cop->jump) : NULL;
		}
		if (cur_bb) {
			RecurseDepthFirstCtx ctx = { cur_bb, NULL };
			rz_vector_push (&path, &ctx);
			ht_up_insert (visited, cur_bb->addr, NULL);
			bool breaked = !cb (cur_bb, user);
			if (breaked) {
				break;
			}
		} else {
			if (on_exit) {
				on_exit (cur_ctx->bb, user);
			}
			rz_vector_pop (&path, NULL);
		}
	} while (!rz_vector_empty (&path));

beach:
	ht_up_free (visited);
	rz_vector_clear (&path);
	return !breaked;
}

static bool recurse_list_cb(RzAnalBlock *block, void *user) {
	RzList *list = user;
	rz_anal_block_ref (block);
	rz_list_push (list, block);
	return true;
}

RZ_API RzList *rz_anal_block_recurse_list(RzAnalBlock *block) {
	RzList *ret = rz_list_newf ((RzListFree)rz_anal_block_unref);
	if (ret) {
		rz_anal_block_recurse (block, recurse_list_cb, ret);
	}
	return ret;
}

RZ_API void rz_anal_block_add_switch_case(RzAnalBlock *block, ut64 switch_addr, ut64 case_value, ut64 case_addr) {
	if (!block->switch_op) {
		block->switch_op = rz_anal_switch_op_new (switch_addr, 0, 0, 0);
	}
	rz_anal_switch_op_add_case (block->switch_op, case_addr, case_value, case_addr);
}

RZ_API bool rz_anal_block_op_starts_at(RzAnalBlock *bb, ut64 addr) {
	if (!rz_anal_block_contains (bb, addr)) {
		return false;
	}
	ut64 off = addr - bb->addr;
	if (off > UT16_MAX) {
		return false;
	}
	size_t i;
	for (i = 0; i < bb->ninstr; i++) {
		ut16 inst_off = rz_anal_bb_offset_inst (bb, i);
		if (off == inst_off) {
			return true;
		}
	}
	return false;
}

typedef struct {
	RzAnal *anal;
	RzAnalBlock *cur_parent;
	ut64 dst;
	RPVector/*<RzAnalBlock>*/ *next_visit; // accumulate block of the next level in the tree
	HtUP/*<RzAnalBlock>*/ *visited; // maps addrs to their previous block (or NULL for entry)
} PathContext;

static bool shortest_path_successor_cb(ut64 addr, void *user) {
	PathContext *ctx = user;
	if (ht_up_find_kv (ctx->visited, addr, NULL)) {
		// already visited
		return true;
	}
	ht_up_insert (ctx->visited, addr, ctx->cur_parent);
	RzAnalBlock *block = rz_anal_get_block_at (ctx->anal, addr);
	if (block) {
		rz_pvector_push (ctx->next_visit, block);
	}
	return addr != ctx->dst; // break if we found our destination
}


RZ_API R_NULLABLE RzList/*<RzAnalBlock *>*/ *rz_anal_block_shortest_path(RzAnalBlock *block, ut64 dst) {
	RzList *ret = NULL;
	PathContext ctx;
	ctx.anal = block->anal;
	ctx.dst = dst;

	// two vectors to swap cur_visit/next_visit
	RPVector visit_a;
	rz_pvector_init (&visit_a, NULL);
	RPVector visit_b;
	rz_pvector_init (&visit_b, NULL);
	ctx.next_visit = &visit_a;
	RPVector *cur_visit = &visit_b; // cur visit is the current level in the tree

	ctx.visited = ht_up_new0 ();
	if (!ctx.visited) {
		goto beach;
	}

	ht_up_insert (ctx.visited, block->addr, NULL);
	rz_pvector_push (cur_visit, block);

	// BFS
	while (!rz_pvector_empty (cur_visit)) {
		void **it;
		rz_pvector_foreach (cur_visit, it) {
			RzAnalBlock *cur = *it;
			ctx.cur_parent = cur;
			rz_anal_block_successor_addrs_foreach (cur, shortest_path_successor_cb, &ctx);
		}
		RPVector *tmp = cur_visit;
		cur_visit = ctx.next_visit;
		ctx.next_visit = tmp;
		rz_pvector_clear (ctx.next_visit);
	}

	// reconstruct the path
	bool found = false;
	RzAnalBlock *prev = ht_up_find (ctx.visited, dst, &found);
	RzAnalBlock *dst_block = rz_anal_get_block_at (block->anal, dst);
	if (found && dst_block) {
		ret = rz_list_newf ((RzListFree)rz_anal_block_unref);
		rz_anal_block_ref (dst_block);
		rz_list_prepend (ret, dst_block);
		while (prev) {
			rz_anal_block_ref (prev);
			rz_list_prepend (ret, prev);
			prev = ht_up_find (ctx.visited, prev->addr, NULL);
		}
	}

beach:
	ht_up_free (ctx.visited);
	rz_pvector_clear (&visit_a);
	rz_pvector_clear (&visit_b);
	return ret;
}

typedef struct {
	RzAnalBlock *block;
	bool reachable;
} NoreturnSuccessor;

static void noreturn_successor_free(HtUPKv *kv) {
	NoreturnSuccessor *succ = kv->value;
	rz_anal_block_unref (succ->block);
	free (succ);
}

static bool noreturn_successors_cb(RzAnalBlock *block, void *user) {
	HtUP *succs = user;
	NoreturnSuccessor *succ = R_NEW0 (NoreturnSuccessor);
	if (!succ) {
		return false;
	}
	rz_anal_block_ref (block);
	succ->block = block;
	succ->reachable = false; // reset for first iteration
	ht_up_insert (succs, block->addr, succ);
	return true;
}

static bool noreturn_successors_reachable_cb(RzAnalBlock *block, void *user) {
	HtUP *succs = user;
	NoreturnSuccessor *succ = ht_up_find (succs, block->addr, NULL);
	if (succ) {
		succ->reachable = true;
	}
	return true;
}

static bool noreturn_remove_unreachable_cb(void *user, const ut64 k, const void *v) {
	RzAnalFunction *fcn = user;
	NoreturnSuccessor *succ = (NoreturnSuccessor *)v;
	if (!succ->reachable && rz_list_contains (succ->block->fcns, fcn)) {
		rz_anal_function_remove_block (fcn, succ->block);
	}
	succ->reachable = false; // reset for next iteration
	return true;
}

static bool noreturn_get_blocks_cb(void *user, const ut64 k, const void *v) {
	RzList *blocks = user;
	NoreturnSuccessor *succ = (NoreturnSuccessor *)v;
	rz_anal_block_ref (succ->block);
	rz_list_push (blocks, succ->block);
	return true;
}

RZ_API RzAnalBlock *rz_anal_block_chop_noreturn(RzAnalBlock *block, ut64 addr) {
	rz_return_val_if_fail (block, NULL);
	if (!rz_anal_block_contains (block, addr) || addr == block->addr) {
		return block;
	}
	rz_anal_block_ref (block);

	// Cache all recursive successors of block here.
	// These are the candidates that we might have to remove from functions later.
	HtUP *succs = ht_up_new (NULL, noreturn_successor_free, NULL); // maps block addr (ut64) => NoreturnSuccessor *
	if (!succs) {
		return block;
	}
	rz_anal_block_recurse (block, noreturn_successors_cb, succs);

	// Chop the block. Resize and remove all destination addrs
	rz_anal_block_set_size (block, addr - block->addr);
	block->jump = UT64_MAX;
	block->fail = UT64_MAX;
	rz_anal_switch_op_free (block->switch_op);
	block->switch_op = NULL;

	// Now, for each fcn, check which of our successors are still reachable in the function remove and the ones that are not.
	RzListIter *it;
	RzAnalFunction *fcn;
	// We need to clone the list because block->fcns will get modified in the loop
	RzList *fcns_cpy = rz_list_clone (block->fcns);
	rz_list_foreach (fcns_cpy, it, fcn) {
		RzAnalBlock *entry = rz_anal_get_block_at (block->anal, fcn->addr);
		if (entry && rz_list_contains (entry->fcns, fcn)) {
			rz_anal_block_recurse (entry, noreturn_successors_reachable_cb, succs);
		}
		ht_up_foreach (succs, noreturn_remove_unreachable_cb, fcn);
	}
	rz_list_free (fcns_cpy);

	// This last step isn't really critical, but nice to have.
	// Prepare to merge blocks with their predecessors if possible
	RzList merge_blocks;
	rz_list_init (&merge_blocks);
	merge_blocks.free = (RzListFree)rz_anal_block_unref;
	ht_up_foreach (succs, noreturn_get_blocks_cb, &merge_blocks);

	// Free/unref BEFORE doing the merge!
	// Some of the blocks might not be valid anymore later!
	rz_anal_block_unref (block);
	ht_up_free (succs);

	ut64 block_addr = block->addr; // save the addr to identify the block. the automerge might free it so we must not use the pointer!

	// Do the actual merge
	rz_anal_block_automerge (&merge_blocks);

	// No try to recover the pointer to the block if it still exists
	RzAnalBlock *ret = NULL;
	for (it = merge_blocks.head; it && (block = it->data, 1); it = it->n) {
		if (block->addr == block_addr) {
			// block is still there
			ret = block;
			break;
		}
	}

	rz_list_purge (&merge_blocks);
	return ret;
}

typedef struct {
	HtUP *predecessors; // maps a block to its predecessor if it has exactly one, or NULL if there are multiple or the predecessor has multiple successors
	HtUP *visited_blocks; // during predecessor search, mark blocks whose successors we already checked. Value is void *-casted count of successors
	HtUP *blocks; // adresses of the blocks we might want to merge with their predecessors => RzAnalBlock *

	RzAnalBlock *cur_pred;
	size_t cur_succ_count;
} AutomergeCtx;

static bool automerge_predecessor_successor_cb(ut64 addr, void *user) {
	AutomergeCtx *ctx = user;
	ctx->cur_succ_count++;
	RzAnalBlock *block = ht_up_find (ctx->blocks, addr, NULL);
	if (!block) {
		// we shouldn't merge this one so GL_DONT_CARE
		return true;
	}
	bool found;
	RzAnalBlock *pred = ht_up_find (ctx->predecessors, (ut64)block, &found);
	if (found) {
		if (pred) {
			// only one predecessor found so far, but we are the second so there are multiple now
			ht_up_update (ctx->predecessors, (ut64) block, NULL);
		} // else: already found multiple predecessors, nothing to do
	} else {
		// no predecessor found yet, this is the only one until now
		ht_up_insert (ctx->predecessors, (ut64) block, ctx->cur_pred);
	}
	return true;
}

static bool automerge_get_predecessors_cb(void *user, const ut64 k, const void *v) {
	AutomergeCtx *ctx = user;
	const RzAnalFunction *fcn = (const RzAnalFunction *)k;
	RzListIter *it;
	RzAnalBlock *block;
	rz_list_foreach (fcn->bbs, it, block) {
		bool already_visited;
		ht_up_find (ctx->visited_blocks, (ut64)block, &already_visited);
		if (already_visited) {
			continue;
		}
		ctx->cur_pred = block;
		ctx->cur_succ_count = 0;
		rz_anal_block_successor_addrs_foreach (block, automerge_predecessor_successor_cb, ctx);
		ht_up_insert (ctx->visited_blocks, (ut64)block, (void *)ctx->cur_succ_count);
	}
	return true;
}

// Try to find the contiguous predecessors of all given blocks and merge them if possible,
// i.e. if there are no other blocks that have this block as one of their successors
RZ_API void rz_anal_block_automerge(RzList *blocks) {
	rz_return_if_fail (blocks);
	AutomergeCtx ctx = {
		.predecessors = ht_up_new0 (),
		.visited_blocks = ht_up_new0 (),
		.blocks = ht_up_new0 ()
	};

	HtUP *relevant_fcns = ht_up_new0 (); // all the functions that contain some of our blocks (ht abused as a set)
	RzList *fixup_candidates = rz_list_new (); // used further down
	if (!ctx.predecessors || !ctx.visited_blocks || !ctx.blocks || !relevant_fcns || !fixup_candidates) {
		goto beach;
	}

	// Get all the functions and prepare ctx.blocks
	RzListIter *it;
	RzAnalBlock *block;
	rz_list_foreach (blocks, it, block) {
		RzListIter *fit;
		RzAnalFunction *fcn;
		rz_list_foreach (block->fcns, fit, fcn) {
			ht_up_insert (relevant_fcns, (ut64)fcn, NULL);
		}
		ht_up_insert (ctx.blocks, block->addr, block);
	}

	// Get the single predecessors we might want to merge with
	ht_up_foreach (relevant_fcns, automerge_get_predecessors_cb, &ctx);

	// Now finally do the merging
	RzListIter *tmp;
	rz_list_foreach_safe (blocks, it, tmp, block) {
		RzAnalBlock *predecessor = ht_up_find (ctx.predecessors, (ut64)block, NULL);
		if (!predecessor) {
			continue;
		}
		size_t pred_succs_count = (size_t)ht_up_find (ctx.visited_blocks, (ut64)predecessor, NULL);
		if (pred_succs_count != 1) {
			// we can only merge this predecessor if it has exactly one successor
			continue;
		}

		// We are about to merge block into predecessor
		// However if there are other blocks that have block as the predecessor,
		// we would uaf after the merge since block will be freed.
		RzListIter *bit;
		RzAnalBlock *clock;
		for (bit = it->n; bit && (clock = bit->data, 1); bit = bit->n) {
			RzAnalBlock *fixup_pred = ht_up_find (ctx.predecessors, (ut64)clock, NULL);
			if (fixup_pred == block) {
				rz_list_push (fixup_candidates, clock);
			}
		}

		if (rz_anal_block_merge (predecessor, block)) { // rz_anal_block_merge() does checks like contiguous, to that's fine
			// block was merged into predecessor, it is now freed!
			rz_list_foreach (fixup_candidates, bit, clock) {
				// Make sure all previous pointers to block now go to predecessor
				ht_up_update (ctx.predecessors, (ut64)clock, predecessor);
			}
			// Remove it from the list
			rz_list_split_iter (blocks, it);
			free (it);
		}

		rz_list_purge (fixup_candidates);
	}

beach:
	ht_up_free (ctx.predecessors);
	ht_up_free (ctx.visited_blocks);
	ht_up_free (ctx.blocks);
	ht_up_free (relevant_fcns);
	rz_list_free (fixup_candidates);
}
