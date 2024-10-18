// SPDX-FileCopyrightText: 2019 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_INTERVALTREE_H
#define RZ_INTERVALTREE_H

#include "rz_rbtree.h"
#include "../rz_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RzIntervalTree is a special RBTree (augmented red-black tree)
 * that holds its entries, each associated with a interval,
 * ordered by the start of the interval.
 *
 * It allows efficient lookup for intersections with a given interval or value.
 * This is achieved by, at each node, saving the maximum value of the node
 * and all of its children.
 *
 * It can hold multiple entries with the same start or end.
 * For multiple entries with the same start, the ordering is undefined.
 */

typedef struct rz_interval_node_t {
	RBNode node;
	ut64 start; // inclusive, key of the node
	ut64 end; // may be inclusive or exclusive, this is only determined by how they are queried
	ut64 max_end; // augmented value, maximum end of this node and all of its children
	void *data;
} RzIntervalNode;

typedef void (*RzIntervalNodeFree)(void *data);

typedef struct rz_interval_tree_t {
	RzIntervalNode *root;
	RzIntervalNodeFree free;
} RzIntervalTree;

RZ_API void rz_interval_tree_init(RzIntervalTree *tree, RzIntervalNodeFree free);
RZ_API void rz_interval_tree_fini(RzIntervalTree *tree);

// return false if the insertion failed.
RZ_API bool rz_interval_tree_insert(RzIntervalTree *tree, ut64 start, ut64 end, void *data);

// Removes a given node from the tree. The node will be freed.
// If free is true, the data in the node is freed as well.
// false if the removal failed
// Complexity is O(log(n) + m) if there are m nodes with the same start as the given node.
RZ_API bool rz_interval_tree_delete(RzIntervalTree *tree, RzIntervalNode *node, bool free);

// Change start/end of a given node.
// It is more efficient if only the end changed.
// The RzIntervalNode pointer is INVALID after this operation!
// Complexity is O(log(n) + m) if there are m nodes with the same start as the given node.
RZ_API bool rz_interval_tree_resize(RzIntervalTree *tree, RzIntervalNode *node, ut64 new_start, ut64 new_end);

// Returns an iterator that starts at the leftmost node that has the given start
// Iterating over it will yield all nodes with given start, then all with a higher one.
RZ_API RBIter rz_interval_tree_first_at(RzIntervalTree *tree, ut64 start);

// Returns a node that starts at exactly start or NULL
RZ_API RzIntervalNode *rz_interval_tree_node_at(RzIntervalTree *tree, ut64 start);

// Returns a node that starts at exactly start and contains data or NULL
RZ_API RzIntervalNode *rz_interval_tree_node_at_data(RzIntervalTree *tree, ut64 start, void *data);

// Same as rz_interval_tree_node_at, but directly returns the contained value or NULL
static inline void *rz_interval_tree_at(RzIntervalTree *tree, ut64 start) {
	RzIntervalNode *node = rz_interval_tree_node_at(tree, start);
	return node ? node->data : NULL;
}

typedef bool (*RzIntervalIterCb)(RzIntervalNode *node, void *user);

// Call cb for all entries starting at exactly start
RZ_API bool rz_interval_tree_all_at(RzIntervalTree *tree, ut64 start, RzIntervalIterCb cb, void *user);

// Call cb for all entries whose intervals contain value
// end_inclusive if true, all start/end values are considered inclusive/inclusive, else inclusive/exclusive
RZ_API bool rz_interval_tree_all_in(RzIntervalTree *tree, ut64 value, bool end_inclusive, RzIntervalIterCb cb, void *user);

// Call cb for all entries whose intervals intersect the given interval (might not contain it completely)
// end_inclusive if true, all start/end values are considered inclusive/inclusive, else inclusive/exclusive
RZ_API bool rz_interval_tree_all_intersect(RzIntervalTree *tree, ut64 start, ut64 end, bool end_inclusive, RzIntervalIterCb cb, void *user);

typedef RBIter RzIntervalTreeIter;

static inline RzIntervalNode *rz_interval_tree_iter_get(RzIntervalTreeIter *it) {
	return rz_rbtree_iter_get(it, RzIntervalNode, node);
}

static inline bool rz_interval_tree_empty(RzIntervalTree *tree) {
	return tree->root == NULL;
}

#define rz_interval_tree_foreach(tree, it, dat) \
	for ((it) = rz_rbtree_first(&(tree)->root->node); rz_rbtree_iter_has(&it) && (dat = rz_interval_tree_iter_get(&it)->data); rz_rbtree_iter_next(&(it)))

#define rz_interval_tree_foreach_prev(tree, it, dat) \
	for ((it) = rz_rbtree_last(&(tree)->root->node); rz_rbtree_iter_has(&it) && (dat = rz_rbtree_iter_get(&it, RzIntervalNode, node)->data); rz_rbtree_iter_prev(&(it)))

#ifdef __cplusplus
}
#endif

#endif // RZ_INTERVALTREE_H
