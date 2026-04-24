// SPDX-FileCopyrightText: 2017 MaskRay
// SPDX-License-Identifier: BSD-3-Clause

#include "rz_types.h"
#include <stdio.h>

#include <rz_util/rz_rbtree.h>
#include <rz_util.h>

static inline bool red(RBNode *x) {
	return x && rb_is_red(x);
}

static inline RBNode *zag(RBNode *x, int dir, RBNodeSum sum) {
	RBNode *y = rb_child(x, dir);
	rb_set_child(x, dir, rb_child(y, !dir));
	rb_set_child(y, !dir, x);
	rb_set_red(x, true);
	rb_set_red(y, false);
	if (sum) {
		sum(x);
	}
	return y;
}

static inline RBNode *zig_zag(RBNode *x, int dir, RBNodeSum sum) {
	RBNode *y = rb_child(x, dir), *z = rb_child(y, !dir);
	rb_set_child(y, !dir, rb_child(z, dir));
	rb_set_child(z, dir, y);
	rb_set_child(x, dir, rb_child(z, !dir));
	rb_set_child(z, !dir, x);
	rb_set_red(y, true);
	rb_set_red(x, true);
	rb_set_red(z, false);
	if (sum) {
		sum(x);
		sum(y);
	}
	return z;
}

static inline RBIter bound_iter(RBNode *x, void *data, RBComparator cmp, bool upper, void *user) {
	RBIter it = { 0 };
	while (x) {
		int d = cmp(data, x, user);

		if (d == 0) {
			it.path[it.len++] = x;
			return it;
		}

		if (d < 0) {
			if (!upper) {
				it.path[it.len++] = x;
			}
			x = rb_child(x, 0);
		} else {
			if (upper) {
				it.path[it.len++] = x;
			}
			x = rb_child(x, 1);
		}
	}

	return it;
}

/// Returns true if a node with an equal key is deleted
RZ_API bool rz_rbtree_aug_delete(RBNode **root, void *data, RBComparator cmp, void *cmp_user, RBNodeFree freefn, void *free_user, RBNodeSum sum) {
	RBNode head = { { 0 } };
	RBNode *del = NULL, *del_parent = NULL, *g = NULL, *p = NULL, *q = &head, *path[RZ_RBTREE_MAX_HEIGHT];
	int del_dir = 0;
	int d = 1, d2, dep = 0;
	rb_set_child(&head, 0, NULL);
	rb_set_child(&head, 1, *root);
	while (rb_child(q, d)) {
		d2 = d;
		g = p;
		p = q;
		if (del_parent) {
			d = 1;
		} else {
			d = cmp(data, rb_child(q, d2), cmp_user);
			if (d < 0) {
				d = 0;
			} else if (d > 0) {
				d = 1;
			} else {
				del_parent = q;
				del_dir = d2;
			}
		}
		if (q != &head) {
			if (dep >= RZ_RBTREE_MAX_HEIGHT) {
				RZ_LOG_ERROR("Red-black tree depth is too big\n");
				break;
			}
			path[dep++] = q;
		}
		q = rb_child(q, d2);
		if (rb_is_red(q) || red(rb_child(q, d))) {
			continue;
		}
		if (red(rb_child(q, !d))) {
			if (del_parent && rb_child(del_parent, del_dir) == q) {
				del_parent = rb_child(q, !d);
				del_dir = d;
			}
			rb_set_child(p, d2, zag(q, !d, sum));
			p = rb_child(p, d2);
			if (dep >= RZ_RBTREE_MAX_HEIGHT) {
				RZ_LOG_ERROR("Red-black tree depth is too big\n");
				break;
			}
			path[dep++] = p;
		} else {
			RBNode *s = rb_child(p, !d2);
			if (!s) {
				continue;
			}
			if (!red(rb_child(s, 0)) && !red(rb_child(s, 1))) {
				rb_set_red(p, false);
				rb_set_red(s, true);
				rb_set_red(q, true);
			} else {
				int d3 = rb_child(g, 0) != p;
				RBNode *t;
				if (red(rb_child(s, d2))) {
					if (del_parent && rb_child(del_parent, del_dir) == p) {
						del_parent = rb_child(s, d2);
						del_dir = d2;
					}
					t = zig_zag(p, !d2, sum);
				} else {
					if (del_parent && rb_child(del_parent, del_dir) == p) {
						del_parent = s;
						del_dir = d2;
					}
					t = zag(p, !d2, sum);
				}
				rb_set_red(q, true);
				rb_set_red(t, true);
				rb_set_red(rb_child(t, 1), false);
				rb_set_red(rb_child(t, 0), false);
				rb_set_child(g, d3, t);
				path[dep - 1] = t;
				path[dep++] = p;
			}
		}
	}
	if (del_parent) {
		del = rb_child(del_parent, del_dir);
		rb_set_child(p, q != rb_child(p, 0), rb_child(q, rb_child(q, 0) == NULL ? 1 : 0));
		if (del != q) {
			*q = *del;
			rb_set_child(del_parent, del_dir, q);
		}
		if (freefn) {
			freefn(del, free_user);
		}
	}
	if (sum) {
		while (dep--) {
			sum(path[dep] == del ? q : path[dep]);
		}
	}
	if ((*root = rb_child(&head, 1))) {
		rb_set_red(*root, false);
	}
	return del;
}

/// Returns true if the node was inserted successfully
RZ_API bool rz_rbtree_aug_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, void *cmp_user, RBNodeSum sum) {
	rb_set_child(node, 1, NULL);
	rb_set_child(node, 0, NULL);
	if (!*root) {
		*root = node;
		rb_set_red(node, false);
		if (sum) {
			sum(node);
		}
		return true;
	}
	RBNode *t = NULL, *g = NULL, *p = NULL, *q = *root;
	int d = 0, dep = 0;
	bool done = false;
	RBNode *path[RZ_RBTREE_MAX_HEIGHT];
	for (;;) {
		if (!q) {
			q = node;
			rb_set_red(q, true);
			rb_set_child(p, d, q);
			done = true;
		} else if (red(rb_child(q, 0)) && red(rb_child(q, 1))) {
			rb_set_red(rb_child(q, 1), false);
			rb_set_red(rb_child(q, 0), false);
			if (q != *root) {
				rb_set_red(q, true);
			}
		}
		if (rb_is_red(q) && p && rb_is_red(p)) {
			int d3 = t ? rb_child(t, 0) != g : -1, d2 = rb_child(g, 0) != p;
			if (rb_child(p, d2) == q) {
				g = zag(g, d2, sum);
				dep--;
				path[dep - 1] = g;
			} else {
				g = zig_zag(g, d2, sum);
				dep -= 2;
			}
			if (t) {
				rb_set_child(t, d3, g);
			} else {
				*root = g;
			}
		}
		if (done) {
			break;
		}
		d = cmp(data, q, cmp_user);
		t = g;
		g = p;
		p = q;
		if (dep >= RZ_RBTREE_MAX_HEIGHT) {
			RZ_LOG_ERROR("Red-black tree depth is too big\n");
			break;
		}
		path[dep++] = q;
		if (d < 0) {
			d = 0;
			q = rb_child(q, 0);
		} else {
			d = 1;
			q = rb_child(q, 1);
		}
	}
	if (sum) {
		sum(q);
		while (dep) {
			sum(path[--dep]);
		}
	}
	return done;
}

/// Returns true if the sum has been updated, false if node has not been found
RZ_API bool rz_rbtree_aug_update_sum(RBNode *root, void *data, RBNode *node, RBComparator cmp, void *cmp_user, RBNodeSum sum) {
	size_t dep = 0;
	RBNode *path[RZ_RBTREE_MAX_HEIGHT];
	RBNode *cur = root;
	for (;;) {
		if (!cur) {
			return false;
		}
		if (dep >= RZ_RBTREE_MAX_HEIGHT) {
			RZ_LOG_ERROR("Red-black tree depth is too big\n");
			return false;
		}
		path[dep] = cur;
		dep++;
		if (cur == node) {
			break;
		}
		int d = cmp(data, cur, cmp_user);
		cur = rb_child(cur, (d < 0) ? 0 : 1);
	}

	for (; dep > 0; dep--) {
		sum(path[dep - 1]);
	}
	return true;
}

/// Returns true if a node with an equal key is deleted
RZ_API bool rz_rbtree_delete(RBNode **root, void *data, RBComparator cmp, void *cmp_user, RBNodeFree freefn, void *free_user) {
	return rz_rbtree_aug_delete(root, data, cmp, cmp_user, freefn, free_user, NULL);
}

RZ_API RBNode *rz_rbtree_find(RBNode *x, void *data, RBComparator cmp, void *user) {
	RBNode *result = NULL;
	while (x) {
		int d = cmp(data, x, user);
		if (d == 0)
			result = x;
		int dir = (d > 0);
		x = rb_child(x, dir);
	}
	return result;
}

RZ_API void rz_rbtree_free(RZ_NULLABLE RBNode *x, RBNodeFree freefn, void *user) {
	if (!x) {
		return;
	}
	rz_rbtree_free(rb_child(x, 0), freefn, user);
	rz_rbtree_free(rb_child(x, 1), freefn, user);
	freefn(x, user);
}

/// Returns true if the node was inserted successfully
RZ_API bool rz_rbtree_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, void *user) {
	return rz_rbtree_aug_insert(root, data, node, cmp, user, NULL);
}

RZ_API RBNode *rz_rbtree_lower_bound(RBNode *x, void *data, RBComparator cmp, void *user) {
	RBNode *ret = NULL;
	while (x) {
		int d = cmp(data, x, user);
		if (d <= 0)
			ret = x;
		int dir = (d > 0);
		x = rb_child(x, dir);
	}
	return ret;
}

RZ_API RBIter rz_rbtree_lower_bound_forward(RBNode *root, void *data, RBComparator cmp, void *user) {
	return bound_iter(root, data, cmp, false, user);
}

RZ_API RBNode *rz_rbtree_upper_bound(RBNode *x, void *data, RBComparator cmp, void *user) {
	RBNode *ret = NULL;
	while (x) {
		int d = cmp(data, x, user);
		if (d >= 0)
			ret = x;
		int dir = (d >= 0);
		x = rb_child(x, dir);
	}
	return ret;
}

RZ_API RBIter rz_rbtree_upper_bound_backward(RBNode *root, void *data, RBComparator cmp, void *user) {
	return bound_iter(root, data, cmp, true, user);
}

static RBIter _first(RBNode *x, int dir) {
	RBIter it;
	it.len = 0;
	for (; x; x = rb_child(x, dir)) {
		it.path[it.len++] = x;
	}
	return it;
}

RZ_API RBIter rz_rbtree_first(RBNode *tree) {
	return _first(tree, 0);
}

RZ_API RBIter rz_rbtree_last(RBNode *tree) {
	return _first(tree, 1);
}

static inline void _next(RBIter *it, int dir) {
	RBNode *x = it->path[--it->len];
	for (x = rb_child(x, !dir); x; x = rb_child(x, dir)) {
		it->path[it->len++] = x;
	}
}

RZ_API void rz_rbtree_iter_next(RBIter *it) {
	_next(it, 0);
}

RZ_API void rz_rbtree_iter_prev(RBIter *it) {
	_next(it, 1);
}

RZ_API RZ_OWN RContRBTree *rz_rbtree_cont_new(void) {
	return RZ_NEW0(RContRBTree);
}

RZ_API RZ_OWN RContRBTree *rz_rbtree_cont_newf(RContRBFree f) {
	RContRBTree *tree = rz_rbtree_cont_new();
	if (tree) {
		tree->free = f;
	}
	return tree;
}

typedef struct rcrb_cmp_wrap_t {
	RContRBCmp cmp;
	RContRBFree free;
	void *user;
} RCRBCmpWrap;

static int cont_rbtree_cmp_wrapper(const void *incoming, const RBNode *in_tree, void *user) {
	RCRBCmpWrap *cmp_wrap = (RCRBCmpWrap *)user;
	RContRBNode *incoming_node = (RContRBNode *)incoming;
	RContRBNode *in_tree_node = container_of((RBNode *)in_tree, RContRBNode, node);
	return cmp_wrap->cmp(incoming_node->data, in_tree_node->data, cmp_wrap->user);
}

static int cont_rbtree_search_cmp_wrapper(const void *incoming, const RBNode *in_tree, void *user) {
	RCRBCmpWrap *cmp_wrap = (RCRBCmpWrap *)user;
	RContRBNode *in_tree_node = container_of((RBNode *)in_tree, RContRBNode, node);
	return cmp_wrap->cmp((void *)incoming, in_tree_node->data, cmp_wrap->user);
}

static int cont_rbtree_free_cmp_wrapper(const void *data, const RBNode *in_tree, void *user) {
	RCRBCmpWrap *cmp_wrap = (RCRBCmpWrap *)user;
	const int ret = cont_rbtree_cmp_wrapper((void *)data, in_tree, user);
	if (!ret && cmp_wrap->free) { // this is for deleting
		RContRBNode *in_tree_node = container_of((void *)in_tree, RContRBNode, node);
		cmp_wrap->free(in_tree_node->data);
	}
	return ret;
}

RZ_API bool rz_rbtree_cont_insert(RContRBTree *tree, void *data, RContRBCmp cmp, void *user) {
	rz_return_val_if_fail(tree && cmp, false);
	if (!tree->root) {
		tree->root = RZ_NEW0(RContRBNode);
		if (!tree->root) {
			RZ_LOG_ERROR("Failed to allocate new red-black tree root\n");
			return false;
		}
		tree->root->data = data;
		return true;
	}
	RContRBNode *incoming_node = RZ_NEW0(RContRBNode);
	if (!incoming_node) {
		RZ_LOG_ERROR("Failed to allocate new red-black tree node\n");
		return false;
	}
	incoming_node->data = data;
	RCRBCmpWrap cmp_wrap = { cmp, NULL, user };
	RBNode *root_node = &tree->root->node;
	const bool ret = rz_rbtree_aug_insert(&root_node, incoming_node,
		&incoming_node->node, cont_rbtree_cmp_wrapper, &cmp_wrap, NULL);
	if (root_node != (&tree->root->node)) {
		tree->root = container_of(root_node, RContRBNode, node);
	}
	if (!ret) {
		RZ_LOG_ERROR("Failed to insert new red-black tree node\n");
		free(incoming_node);
	}
	return ret;
}

static void cont_node_free(RBNode *node, void *user) {
	RContRBNode *contnode = container_of(node, RContRBNode, node);
	RContRBTree *tree = (RContRBTree *)user;
	if (tree && tree->free) {
		tree->free(contnode->data);
	}
	if (tree && tree->pool) {
		rb_pool_release(tree->pool, contnode);
	} else {
		free(contnode);
	}
}

RZ_API bool rz_rbtree_cont_delete(RContRBTree *tree, void *data, RContRBCmp cmp, void *user) {
	if (!(tree && cmp && tree->root)) {
		return false;
	}
	RCRBCmpWrap cmp_wrap = { cmp, tree->free, user };
	RContRBNode data_wrap;
	memset(&data_wrap, 0, sizeof(RContRBNode));
	data_wrap.data = data;
	RBNode *root_node = &tree->root->node;
	const bool ret = rz_rbtree_aug_delete(&root_node, &data_wrap, cont_rbtree_free_cmp_wrapper, &cmp_wrap, cont_node_free, NULL, NULL);
	if (root_node != (&tree->root->node)) {
		tree->root = container_of(root_node, RContRBNode, node);
	}
	return ret;
}

RZ_API void *rz_rbtree_cont_find(RContRBTree *tree, void *data, RContRBCmp cmp, void *user) {
	rz_return_val_if_fail(tree && cmp, NULL);
	if (!tree->root) {
		return NULL;
	}
	RCRBCmpWrap cmp_wrap = { cmp, NULL, user };
	// RBNode search_node = tree->root->node;
	RBNode *result_node = rz_rbtree_find(&tree->root->node, data, cont_rbtree_search_cmp_wrapper, &cmp_wrap);
	if (result_node) {
		return (container_of(result_node, RContRBNode, node))->data;
	}
	return NULL;
}

RZ_API void rz_rbtree_cont_free(RContRBTree *tree) {
	if (tree && tree->root) {
		rz_rbtree_free(&tree->root->node, cont_node_free, tree);
	}
	free(tree);
}
