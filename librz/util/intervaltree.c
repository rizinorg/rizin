/* rizin - LGPL - Copyright 2019 - thestr4ng3r */

#include <rz_util/rz_intervaltree.h>
#include <rz_util/rz_assert.h>

#define unwrap(rbnode) container_of(rbnode, RzIntervalNode, node)

static void node_max(RBNode *node) {
	RzIntervalNode *intervalnode = unwrap(node);
	intervalnode->max_end = intervalnode->end;
	int i;
	for (i = 0; i < 2; i++) {
		if (node->child[i]) {
			ut64 end = unwrap(node->child[i])->max_end;
			if (end > intervalnode->max_end) {
				intervalnode->max_end = end;
			}
		}
	}
}

static int cmp(const void *incoming, const RBNode *in_tree, void *user) {
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

// like cmp, but handles searches for an exact RzIntervalNode * in the tree instead of only comparing the start values
static int cmp_exact_node(const void *incoming, const RBNode *in_tree, void *user) {
	RzIntervalNode *incoming_node = (RzIntervalNode *)incoming;
	const RzIntervalNode *node = container_of(in_tree, const RzIntervalNode, node);
	if (node == incoming_node) {
		return 0;
	}
	if (incoming_node->start < node->start) {
		return -1;
	}
	if (incoming_node->start > node->start) {
		return 1;
	}
	// Here we have the same start value, but a different pointer.
	// This means we need to guide the caller into the direction where the actual node is.
	// Since we have nothing to compare anymore, we have to iterate through all the same-start children to find the correct path.
	RBIter *path_cache = user;
	if (!path_cache->len) {
		RBNode *cur = (RBNode *)&node->node;
		// go down to the leftmost child that has the same start
		while (cur) {
			path_cache->path[path_cache->len++] = cur;
			if (incoming_node->start <= unwrap(cur)->start) {
				cur = cur->child[0];
			} else {
				cur = cur->child[1];
			}
		}
		// iterate through all children with the same start and stop when the pointer is identical
		// The RBIter works a bit different than normal here. We store each node in the path, including right-descended ones
		// because we want to get the full path in the end.
		while (rz_rbtree_iter_has(path_cache)) {
			RzIntervalNode *intervalnode = rz_rbtree_iter_get(path_cache, RzIntervalNode, node);
			if (intervalnode == incoming_node || intervalnode->start > incoming_node->start) {
				break;
			}
			// rz_rbtree_iter_next does not work here
			RBNode *rbnode = &intervalnode->node;
			if (rbnode->child[1]) {
				// next node after the current is always the leftmost in the right branch
				for (rbnode = rbnode->child[1]; rbnode; rbnode = rbnode->child[0]) {
					path_cache->path[path_cache->len++] = rbnode;
				}
			} else {
				// if there is no right branch, go up
				do {
					rbnode = path_cache->path[--path_cache->len];
				} while (path_cache->len && path_cache->path[path_cache->len - 1]->child[1] == rbnode);
			}
		}
	}

	RBNode *next_child = NULL;
	// Go through the path to find the next node one step down
	size_t i;
	for (i = 0; i < path_cache->len - 1; i++) {
		if (unwrap(path_cache->path[i]) == node) {
			next_child = path_cache->path[i + 1];
			break;
		}
	}

	// Determine the direction from the next child node
	return (next_child && node->node.child[0] == next_child) ? -1 : 1;
}

RZ_API void rz_interval_tree_init(RzIntervalTree *tree, RzIntervalNodeFree free) {
	tree->root = NULL;
	tree->free = free;
}

static void interval_node_free(RBNode *node, void *user) {
	RzIntervalNode *ragenode /* >:-O */ = unwrap(node);
	if (user) {
		((RContRBFree)user)(ragenode->data);
	}
	free(ragenode);
}

RZ_API void rz_interval_tree_fini(RzIntervalTree *tree) {
	if (!tree || !tree->root) {
		return;
	}
	rz_rbtree_free(&tree->root->node, interval_node_free, tree->free);
}

RZ_API bool rz_interval_tree_insert(RzIntervalTree *tree, ut64 start, ut64 end, void *data) {
	rz_return_val_if_fail(end >= start, false);
	RzIntervalNode *node = RZ_NEW0(RzIntervalNode);
	if (!node) {
		return false;
	}
	node->start = start;
	node->end = end;
	node->data = data;
	RBNode *root = tree->root ? &tree->root->node : NULL;
	bool r = rz_rbtree_aug_insert(&root, &start, &node->node, cmp, NULL, node_max);
	tree->root = unwrap(root);
	if (!r) {
		free(node);
	}
	return r;
}

RZ_API bool rz_interval_tree_delete(RzIntervalTree *tree, RzIntervalNode *node, bool free) {
	RBNode *root = &tree->root->node;
	RBIter path_cache = { 0 };
	bool r = rz_rbtree_aug_delete(&root, node, cmp_exact_node, &path_cache, interval_node_free, free ? tree->free : NULL, node_max);
	tree->root = root ? unwrap(root) : NULL;
	return r;
}

RZ_API bool rz_interval_tree_resize(RzIntervalTree *tree, RzIntervalNode *node, ut64 new_start, ut64 new_end) {
	rz_return_val_if_fail(new_end >= new_start, false);
	if (node->start != new_start) {
		// Start change means the tree needs a different structure
		void *data = node->data;
		if (!rz_interval_tree_delete(tree, node, false)) {
			return false;
		}
		return rz_interval_tree_insert(tree, new_start, new_end, data);
	}
	if (node->end != new_end) {
		// Only end change just needs the updated augmented max value to be propagated upwards
		node->end = new_end;
		RBIter path_cache = { 0 };
		return rz_rbtree_aug_update_sum(&tree->root->node, node, &node->node, cmp_exact_node, &path_cache, node_max);
	}
	// no change
	return true;
}

// This must always return the topmost node that matches start!
// Otherwise rz_interval_tree_first_at will break!!!
RZ_API RzIntervalNode *rz_interval_tree_node_at(RzIntervalTree *tree, ut64 start) {
	RzIntervalNode *node = tree->root;
	while (node) {
		if (start < node->start) {
			node = unwrap(node->node.child[0]);
		} else if (start > node->start) {
			node = unwrap(node->node.child[1]);
		} else {
			return node;
		}
	}
	return NULL;
}

RZ_API RBIter rz_interval_tree_first_at(RzIntervalTree *tree, ut64 start) {
	RBIter it = { 0 };

	// Find the topmost node matching start so we have a sub-tree with all entries that we want to find.
	RzIntervalNode *top_intervalnode = rz_interval_tree_node_at(tree, start);
	if (!top_intervalnode) {
		return it;
	}

	// If there are more nodes with the same key, they can be in both children.
	RBNode *node = &top_intervalnode->node;
	while (node) {
		if (start <= unwrap(node)->start) {
			it.path[it.len++] = node;
			node = node->child[0];
		} else {
			node = node->child[1];
		}
	}

	return it;
}

RZ_API RzIntervalNode *rz_interval_tree_node_at_data(RzIntervalTree *tree, ut64 start, void *data) {
	RBIter it = rz_interval_tree_first_at(tree, start);
	while (rz_rbtree_iter_has(&it)) {
		RzIntervalNode *intervalnode = rz_rbtree_iter_get(&it, RzIntervalNode, node);
		if (intervalnode->start != start) {
			break;
		}
		if (intervalnode->data == data) {
			return intervalnode;
		}
		rz_rbtree_iter_next(&it);
	}
	return NULL;
}

RZ_API bool rz_interval_tree_all_at(RzIntervalTree *tree, ut64 start, RzIntervalIterCb cb, void *user) {
	RBIter it = rz_interval_tree_first_at(tree, start);
	bool ret = true;
	while (rz_rbtree_iter_has(&it)) {
		RzIntervalNode *intervalnode = rz_rbtree_iter_get(&it, RzIntervalNode, node);
		if (intervalnode->start != start) {
			break;
		}
		ret = cb(intervalnode, user);
		if (!ret) {
			break;
		}
		rz_rbtree_iter_next(&it);
	}
	return ret;
}

RZ_API bool rz_interval_node_all_in(RzIntervalNode *node, ut64 value, bool end_inclusive, RzIntervalIterCb cb, void *user) {
	while (node && value < node->start) {
		// less than the current node, but might still be contained further down
		node = unwrap(node->node.child[0]);
	}
	if (!node) {
		return true;
	}
	if (end_inclusive ? value > node->max_end : value >= node->max_end) {
		return true;
	}
	if (end_inclusive ? value <= node->end : value < node->end) {
		if (!cb(node, user)) {
			return false;
		}
	}
	// This can be done more efficiently by building the stack manually
	bool ret = rz_interval_node_all_in(unwrap(node->node.child[0]), value, end_inclusive, cb, user);
	if (!ret) {
		return false;
	}
	return rz_interval_node_all_in(unwrap(node->node.child[1]), value, end_inclusive, cb, user);
}

RZ_API bool rz_interval_tree_all_in(RzIntervalTree *tree, ut64 value, bool end_inclusive, RzIntervalIterCb cb, void *user) {
	// all in! 🂡
	return rz_interval_node_all_in(tree->root, value, end_inclusive, cb, user);
}

static bool rz_interval_node_all_intersect(RzIntervalNode *node, ut64 start, ut64 end, bool end_inclusive, RzIntervalIterCb cb, void *user) {
	rz_return_val_if_fail(end >= start, true);
	while (node && (end_inclusive ? end < node->start : end <= node->start)) {
		// less than the current node, but might still be contained further down
		node = unwrap(node->node.child[0]);
	}
	if (!node) {
		return true;
	}
	if (end_inclusive ? start > node->max_end : start >= node->max_end) {
		return true;
	}
	if (end_inclusive ? start <= node->end : start < node->end) {
		if (!cb(node, user)) {
			return false;
		}
	}
	// This can be done more efficiently by building the stack manually
	if (!rz_interval_node_all_intersect(unwrap(node->node.child[0]), start, end, end_inclusive, cb, user)) {
		return false;
	}
	return rz_interval_node_all_intersect(unwrap(node->node.child[1]), start, end, end_inclusive, cb, user);
}

RZ_API bool rz_interval_tree_all_intersect(RzIntervalTree *tree, ut64 start, ut64 end, bool end_inclusive, RzIntervalIterCb cb, void *user) {
	return rz_interval_node_all_intersect(tree->root, start, end, end_inclusive, cb, user);
}
