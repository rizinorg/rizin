#ifndef RZ_RBTREE_H
#define RZ_RBTREE_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include "rz_list.h"

#ifdef __cplusplus
extern "C" {
#endif

// max height <= 2 * floor(log2(n + 1))
// We use `int` for size, so <= 2 * 31
#define RZ_RBTREE_MAX_HEIGHT 62

// Singleton can be zero initialized
typedef struct rz_rb_node_t {
	struct rz_rb_node_t *child[2];
	bool red;
} RBNode;

typedef RBNode *RBTree;

// incoming < in_tree  => return < 0
// incoming == in_tree => return == 0
// incoming > in_tree  => return > 0
typedef int (*RBComparator)(const void *incoming, const RBNode *in_tree, void *user);

typedef void (*RBNodeFree)(RBNode *node, void *user);
typedef void (*RBNodeSum)(RBNode *node);

typedef struct rz_rb_iter_t {
	// current depth
	// if len == 0, the iterator is at the end/empty
	// else path[len-1] is the current node
	int len;

	// current path from root to the current node
	// excluding nodes into whose right (or left, for reverse iteration) branch the iterator has descended
	// (these nodes are before the current)
	RBNode *path[RZ_RBTREE_MAX_HEIGHT];
} RBIter;

typedef int (*RContRBCmp)(void *incoming, void *in, void *user);
typedef void (*RContRBFree)(void *);
typedef struct rz_containing_rb_node_t {
	RBNode node;
	void *data;
} RContRBNode;

typedef struct rz_containing_rb_tree_t {
	RContRBNode *root;
	RContRBFree free;
} RContRBTree;

// Routines for augmented red-black trees. The user should provide an aggregation (monoid sum) callback `sum`
// to calculate extra information such as size, sum, ...
RZ_API bool rz_rbtree_aug_delete(RBNode **root, void *data, RBComparator cmp, void *cmp_user, RBNodeFree freefn, void *free_user, RBNodeSum sum);
RZ_API bool rz_rbtree_aug_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, void *cmp_user, RBNodeSum sum);
RZ_API bool rz_rbtree_aug_update_sum(RBNode *root, void *data, RBNode *node, RBComparator cmp, void *cmp_user, RBNodeSum sum);

RZ_API bool rz_rbtree_delete(RBNode **root, void *data, RBComparator cmp, void *cmp_user, RBNodeFree freefn, void *free_user);
RZ_API RBNode *rz_rbtree_find(RBNode *root, void *data, RBComparator cmp, void *user);
RZ_API void rz_rbtree_free(RBNode *root, RBNodeFree freefn, void *user);
RZ_API void rz_rbtree_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, void *user);
// Return the smallest node that is greater than or equal to `data`
RZ_API RBNode *rz_rbtree_lower_bound(RBNode *root, void *data, RBComparator cmp, void *user);
// Return the greatest node that is less than or equal to `data`
RZ_API RBNode *rz_rbtree_upper_bound(RBNode *root, void *data, RBComparator cmp, void *user);

// Create a forward iterator starting from the leftmost node
RZ_API RBIter rz_rbtree_first(RBNode *root);
// Create a backward iterator starting from the rightmost node
RZ_API RBIter rz_rbtree_last(RBNode *root);

// Iterate [lower_bound, end] forward, used with rz_rbtree_iter_next
RZ_API RBIter rz_rbtree_lower_bound_forward(RBNode *root, void *data, RBComparator cmp, void *user);
// Iterate [begin, upper_bound] backward, used with rz_rbtree_iter_prev
RZ_API RBIter rz_rbtree_upper_bound_backward(RBNode *root, void *data, RBComparator cmp, void *user);

// struct Node { int key; RBNode rb; };
// rz_rbtree_iter_get (it, struct Node, rb)
#define rz_rbtree_iter_get(it, struc, rb) (container_of((it)->path[(it)->len - 1], struc, rb))
// If the iterator still contains elements, including the current
#define rz_rbtree_iter_has(it) ((it)->len)
// Move forward
RZ_API void rz_rbtree_iter_next(RBIter *it);
// Move backward
RZ_API void rz_rbtree_iter_prev(RBIter *it);

// Iterate all elements of the forward iterator
#define rz_rbtree_iter_while(it, data, struc, rb) \
	for (; rz_rbtree_iter_has(&it) && (data = rz_rbtree_iter_get(&it, struc, rb)); rz_rbtree_iter_next(&(it)))

// Iterate all elements of the backward iterator
#define rz_rbtree_iter_while_prev(it, data, struc, rb) \
	for (; rz_rbtree_iter_has(&it) && (data = rz_rbtree_iter_get(&it, struc, rb)); rz_rbtree_iter_prev(&(it)))

#define rz_rbtree_foreach(root, it, data, struc, rb) \
	for ((it) = rz_rbtree_first(root); rz_rbtree_iter_has(&it) && (data = rz_rbtree_iter_get(&it, struc, rb)); rz_rbtree_iter_next(&(it)))

#define rz_rbtree_foreach_prev(root, it, data, struc, rb) \
	for ((it) = rz_rbtree_last(root); rz_rbtree_iter_has(&it) && (data = rz_rbtree_iter_get(&it, struc, rb)); rz_rbtree_iter_prev(&(it)))

RZ_API RContRBTree *rz_rbtree_cont_new(void);
RZ_API RContRBTree *rz_rbtree_cont_newf(RContRBFree f);
RZ_API bool rz_rbtree_cont_insert(RContRBTree *tree, void *data, RContRBCmp cmp, void *user);
RZ_API bool rz_rbtree_cont_delete(RContRBTree *tree, void *data, RContRBCmp cmp, void *user);
RZ_API void *rz_rbtree_cont_find(RContRBTree *tree, void *data, RContRBCmp cmp, void *user);

#define rz_rbtree_cont_foreach(tree, it, dat) \
	for ((it) = rz_rbtree_first((tree)->root ? &(tree)->root->node : NULL); rz_rbtree_iter_has(&it) && (dat = rz_rbtree_iter_get(&it, RContRBNode, node)->data); rz_rbtree_iter_next(&(it)))

#define rz_rbtree_cont_foreach_prev(tree, it, dat) \
	for ((it) = rz_rbtree_last((tree)->root ? &(tree)->root->node : NULL); rz_rbtree_iter_has(&it) && (dat = rz_rbtree_iter_get(&it, RContRBNode, node)->data); rz_rbtree_iter_prev(&(it)))

RZ_API void rz_rbtree_cont_free(RContRBTree *tree);

#ifdef __cplusplus
}
#endif

#endif
