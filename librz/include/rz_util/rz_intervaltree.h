/* rizin - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef RZ_INTERVALTREE_H
#define RZ_INTERVALTREE_H

#include "rz_rbtree.h"
#include "../rz_types.h"

/*
 * RIntervalTree is a special RBTree (augmented red-black tree)
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
} RIntervalNode;

typedef void (*RIntervalNodeFree)(void *data);

typedef struct rz_interval_tree_t {
	RIntervalNode *root;
	RIntervalNodeFree free;
} RIntervalTree;

RZ_API void rz_interval_tree_init(RIntervalTree *tree, RIntervalNodeFree free);
RZ_API void rz_interval_tree_fini(RIntervalTree *tree);

// return false if the insertion failed.
RZ_API bool rz_interval_tree_insert(RIntervalTree *tree, ut64 start, ut64 end, void *data);

// Removes a given node from the tree. The node will be freed.
// If free is true, the data in the node is freed as well.
// false if the removal failed
// Complexity is O(log(n) + m) if there are m nodes with the same start as the given node.
RZ_API bool rz_interval_tree_delete(RIntervalTree *tree, RIntervalNode *node, bool free);

// Change start/end of a given node.
// It is more efficient if only the end changed.
// The RIntervalNode pointer is INVALID after this operation!
// Complexity is O(log(n) + m) if there are m nodes with the same start as the given node.
RZ_API bool rz_interval_tree_resize(RIntervalTree *tree, RIntervalNode *node, ut64 new_start, ut64 new_end);

// Returns an iterator that starts at the leftmost node that has the given start
// Iterating over it will yield all nodes with given start, then all with a higher one.
RZ_API RBIter rz_interval_tree_first_at(RIntervalTree *tree, ut64 start);

// Returns a node that starts at exactly start or NULL
RZ_API RIntervalNode *rz_interval_tree_node_at(RIntervalTree *tree, ut64 start);

// Returns a node that starts at exactly start and contains data or NULL
RZ_API RIntervalNode *rz_interval_tree_node_at_data(RIntervalTree *tree, ut64 start, void *data);

// Same as rz_interval_tree_node_at, but directly returns the contained value or NULL
static inline void *rz_interval_tree_at(RIntervalTree *tree, ut64 start) {
	RIntervalNode *node = rz_interval_tree_node_at (tree, start);
	return node ? node->data : NULL;
}

typedef bool (*RIntervalIterCb)(RIntervalNode *node, void *user);

// Call cb for all entries starting at exactly start
RZ_API bool rz_interval_tree_all_at(RIntervalTree *tree, ut64 start, RIntervalIterCb cb, void *user);

// Call cb for all entries whose intervals contain value
// end_inclusive if true, all start/end values are considered inclusive/inclusive, else inclusive/exclusive
RZ_API bool rz_interval_tree_all_in(RIntervalTree *tree, ut64 value, bool end_inclusive, RIntervalIterCb cb, void *user);

// Call cb for all entries whose intervals intersect the given interval (might not contain it completely)
// end_inclusive if true, all start/end values are considered inclusive/inclusive, else inclusive/exclusive
RZ_API bool rz_interval_tree_all_intersect(RIntervalTree *tree, ut64 start, ut64 end, bool end_inclusive, RIntervalIterCb cb, void *user);

typedef RBIter RIntervalTreeIter;

static inline RIntervalNode *rz_interval_tree_iter_get(RIntervalTreeIter *it) {
	return rz_rbtree_iter_get (it, RIntervalNode, node);
}

#define rz_interval_tree_foreach(tree, it, dat) \
	for ((it) = rz_rbtree_first (&(tree)->root->node); rz_rbtree_iter_has (&it) && (dat = rz_interval_tree_iter_get (&it)->data); rz_rbtree_iter_next (&(it)))

#define rz_interval_tree_foreach_prev(tree, it, dat) \
	for ((it) = rz_rbtree_last (&(tree)->root->node); rz_rbtree_iter_has (&it) && (dat = rz_rbtree_iter_get (&it, RIntervalNode, node)->data); rz_rbtree_iter_prev (&(it)))


#endif //RZ_INTERVALTREE_H
