// SPDX-License-Identifier: BSD-3-Clause

#include <stdio.h>

#include <rz_util/rz_rbtree.h>
#include <rz_util.h>

static inline bool red(RBNode *x) {
	return x && x->red;
}

static inline RBNode *zag(RBNode *x, int dir, RBNodeSum sum) {
	RBNode *y = x->child[dir];
	x->child[dir] = y->child[!dir];
	y->child[!dir] = x;
	x->red = true;
	y->red = false;
	if (sum) {
		sum(x);
	}
	return y;
}

static inline RBNode *zig_zag(RBNode *x, int dir, RBNodeSum sum) {
	RBNode *y = x->child[dir], *z = y->child[!dir];
	y->child[!dir] = z->child[dir];
	z->child[dir] = y;
	x->child[dir] = z->child[!dir];
	z->child[!dir] = x;
	x->red = y->red = true;
	z->red = false;
	if (sum) {
		sum(x);
		sum(y);
	}
	return z;
}

static inline RBIter bound_iter(RBNode *x, void *data, RBComparator cmp, bool upper, void *user) {
	RBIter it;
	it.len = 0;
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
			x = x->child[0];
		} else {
			if (upper) {
				it.path[it.len++] = x;
			}
			x = x->child[1];
		}
	}

	return it;
}

/*
static void _check1(RBNode *x, int dep, int black, bool leftmost) {
	static int black_;
	if (x) {
		black += !x->red;
		if (x->red && ((x->child[0] && x->child[0]->red) || (x->child[1] && x->child[1]->red))) {
			printf ("error: red violation\n");
		}
		_check1 (x->child[0], dep + 1, black, leftmost);
		_check1 (x->child[1], dep + 1, black, false);
	} else if (leftmost) {
		black_ = black;
	} else if (black_ != black) {
		printf ("error: different black height\n");
	}
}

static void _check(RBNode *x) {
	_check1 (x, 0, 0, true);
}
*/

// Returns true if a node with an equal key is deleted
RZ_API bool rz_rbtree_aug_delete(RBNode **root, void *data, RBComparator cmp, void *cmp_user, RBNodeFree freefn, void *free_user, RBNodeSum sum) {
	RBNode head, *del = NULL, **del_link = NULL, *g = NULL, *p = NULL, *q = &head, *path[RZ_RBTREE_MAX_HEIGHT];
	int d = 1, d2, dep = 0;
	head.child[0] = NULL;
	head.child[1] = *root;
	while (q->child[d]) {
		d2 = d;
		g = p;
		p = q;
		if (del_link) {
			d = 1;
		} else {
			d = cmp(data, q->child[d2], cmp_user);
			if (d < 0) {
				d = 0;
			} else if (d > 0) {
				d = 1;
			} else {
				del_link = &q->child[d2];
			}
		}
		if (q != &head) {
			if (dep >= RZ_RBTREE_MAX_HEIGHT) {
				eprintf("Too deep tree\n");
				break;
			}
			path[dep++] = q;
		}
		q = q->child[d2];
		if (q->red || red(q->child[d])) {
			continue;
		}
		if (red(q->child[!d])) {
			if (del_link && *del_link == q) {
				del_link = &q->child[!d]->child[d];
			}
			p->child[d2] = zag(q, !d, sum);
			p = p->child[d2];
			if (dep >= RZ_RBTREE_MAX_HEIGHT) {
				eprintf("Too deep tree\n");
				break;
			}
			path[dep++] = p;
		} else {
			RBNode *s = p->child[!d2];
			if (!s) {
				continue;
			}
			if (!red(s->child[0]) && !red(s->child[1])) {
				p->red = false;
				q->red = s->red = true;
			} else {
				int d3 = g->child[0] != p;
				RBNode *t;
				if (red(s->child[d2])) {
					if (del_link && *del_link == p) {
						del_link = &s->child[d2]->child[d2];
					}
					t = zig_zag(p, !d2, sum);
				} else {
					if (del_link && *del_link == p) {
						del_link = &s->child[d2];
					}
					t = zag(p, !d2, sum);
				}
				t->red = q->red = true;
				t->child[0]->red = t->child[1]->red = false;
				g->child[d3] = t;
				path[dep - 1] = t;
				path[dep++] = p;
			}
		}
	}
	if (del_link) {
		del = *del_link;
		p->child[q != p->child[0]] = q->child[q->child[0] == NULL];
		if (del != q) {
			*q = *del;
			*del_link = q;
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
	if ((*root = head.child[1])) {
		(*root)->red = false;
	}
	return del;
}

// Returns true if stuff got inserted, else false
RZ_API bool rz_rbtree_aug_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, void *cmp_user, RBNodeSum sum) {
	node->child[0] = node->child[1] = NULL;
	if (!*root) {
		*root = node;
		node->red = false;
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
			q->red = true;
			p->child[d] = q;
			done = true;
		} else if (red(q->child[0]) && red(q->child[1])) {
			q->child[0]->red = q->child[1]->red = false;
			if (q != *root) {
				q->red = true;
			}
		}
		if (q->red && p && p->red) {
			int d3 = t ? t->child[0] != g : -1, d2 = g->child[0] != p;
			if (p->child[d2] == q) {
				g = zag(g, d2, sum);
				dep--;
				path[dep - 1] = g;
			} else {
				g = zig_zag(g, d2, sum);
				dep -= 2;
			}
			if (t) {
				t->child[d3] = g;
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
			eprintf("Too deep tree\n");
			break;
		}
		path[dep++] = q;
		if (d < 0) {
			d = 0;
			q = q->child[0];
		} else {
			d = 1;
			q = q->child[1];
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

// returns true if the sum has been updated, false if node has not been found
RZ_API bool rz_rbtree_aug_update_sum(RBNode *root, void *data, RBNode *node, RBComparator cmp, void *cmp_user, RBNodeSum sum) {
	size_t dep = 0;
	RBNode *path[RZ_RBTREE_MAX_HEIGHT];
	RBNode *cur = root;
	for (;;) {
		if (!cur) {
			return false;
		}
		if (dep >= RZ_RBTREE_MAX_HEIGHT) {
			eprintf("Too deep tree\n");
			return false;
		}
		path[dep] = cur;
		dep++;
		if (cur == node) {
			break;
		}
		int d = cmp(data, cur, cmp_user);
		cur = cur->child[(d < 0) ? 0 : 1];
	}

	for (; dep > 0; dep--) {
		sum(path[dep - 1]);
	}
	return true;
}

RZ_API bool rz_rbtree_delete(RBNode **root, void *data, RBComparator cmp, void *cmp_user, RBNodeFree freefn, void *free_user) {
	return rz_rbtree_aug_delete(root, data, cmp, cmp_user, freefn, free_user, NULL);
}

RZ_API RBNode *rz_rbtree_find(RBNode *x, void *data, RBComparator cmp, void *user) {
	while (x) {
		int d = cmp(data, x, user);
		if (d < 0) {
			x = x->child[0];
		} else if (d > 0) {
			x = x->child[1];
		} else {
			return x;
		}
	}
	return NULL;
}

RZ_API void rz_rbtree_free(RBNode *x, RBNodeFree freefn, void *user) {
	if (x) {
		rz_rbtree_free(x->child[0], freefn, user);
		rz_rbtree_free(x->child[1], freefn, user);
		freefn(x, user);
	}
}

RZ_API void rz_rbtree_insert(RBNode **root, void *data, RBNode *node, RBComparator cmp, void *user) {
	rz_rbtree_aug_insert(root, data, node, cmp, user, NULL);
}

RZ_API RBNode *rz_rbtree_lower_bound(RBNode *x, void *data, RBComparator cmp, void *user) {
	RBNode *ret = NULL;
	while (x) {
		int d = cmp(data, x, user);
		if (d <= 0) {
			ret = x;
			x = x->child[0];
		} else {
			x = x->child[1];
		}
	}
	return ret;
}

RZ_API RBIter rz_rbtree_lower_bound_forward(RBNode *root, void *data, RBComparator cmp, void *user) {
	return bound_iter(root, data, cmp, false, user);
}

RZ_API RBNode *rz_rbtree_upper_bound(RBNode *x, void *data, RBComparator cmp, void *user) {
	void *ret = NULL;
	while (x) {
		int d = cmp(data, x, user);
		if (d < 0) {
			x = x->child[0];
		} else {
			ret = x;
			x = x->child[1];
		}
	}
	return ret;
}

RZ_API RBIter rz_rbtree_upper_bound_backward(RBNode *root, void *data, RBComparator cmp, void *user) {
	return bound_iter(root, data, cmp, true, user);
}

static RBIter _first(RBNode *x, int dir) {
	RBIter it;
	it.len = 0;
	for (; x; x = x->child[dir]) {
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
	for (x = x->child[!dir]; x; x = x->child[dir]) {
		it->path[it->len++] = x;
	}
}

RZ_API void rz_rbtree_iter_next(RBIter *it) {
	_next(it, 0);
}

RZ_API void rz_rbtree_iter_prev(RBIter *it) {
	_next(it, 1);
}

RZ_API RContRBTree *rz_rbtree_cont_new(void) {
	return RZ_NEW0(RContRBTree);
}

RZ_API RContRBTree *rz_rbtree_cont_newf(RContRBFree f) {
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
	if (!ret && cmp_wrap->free) { //this is for deleting
		RContRBNode *in_tree_node = container_of((void *)in_tree, RContRBNode, node);
		cmp_wrap->free(in_tree_node->data);
	}
	return ret;
}

RZ_API bool rz_rbtree_cont_insert(RContRBTree *tree, void *data, RContRBCmp cmp, void *user) {
	rz_return_val_if_fail(tree && cmp, false);
	if (!tree->root) {
		tree->root = RZ_NEW0(RContRBNode);
		if (tree->root) {
			tree->root->data = data;
			//			tree->root->node.red = false;	// not needed since RZ_NEW0 initializes with false anyway
			return true;
		}
		eprintf("Allocation failed\n");
		return false;
	}
	RContRBNode *incoming_node = RZ_NEW0(RContRBNode);
	if (!incoming_node) {
		eprintf("Allocation failed\n");
		return false;
	}
	incoming_node->data = data;
	RCRBCmpWrap cmp_wrap = { cmp, NULL, user };
	RBNode *root_node = &tree->root->node;
	const bool ret = rz_rbtree_aug_insert(&root_node, incoming_node,
		&incoming_node->node, cont_rbtree_cmp_wrapper, &cmp_wrap, NULL);
	if (root_node != (&tree->root->node)) {
		tree->root = container_of(root_node, RContRBNode, node); //cursed augmentation garbage
	}
	if (!ret) {
		eprintf("Insertion failed\n");
		free(incoming_node);
	}
	return ret;
}

static void cont_node_free(RBNode *node, void *user) {
	RContRBNode *contnode = container_of(node, RContRBNode, node);
	if (user) {
		((RContRBFree)user)(contnode->data);
	}
	free(contnode);
}

RZ_API bool rz_rbtree_cont_delete(RContRBTree *tree, void *data, RContRBCmp cmp, void *user) {
	if (!(tree && cmp && tree->root)) {
		return false;
	}
	RCRBCmpWrap cmp_wrap = { cmp, tree->free, user };
	RContRBNode data_wrap = { { { NULL, NULL }, false }, data };
	RBNode *root_node = &tree->root->node;
	const bool ret = rz_rbtree_aug_delete(&root_node, &data_wrap, cont_rbtree_free_cmp_wrapper, &cmp_wrap, cont_node_free, NULL, NULL);
	if (root_node != (&tree->root->node)) { //can this crash?
		tree->root = container_of(root_node, RContRBNode, node); //cursed augmentation garbage
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
		rz_rbtree_free(&tree->root->node, cont_node_free, tree->free);
	}
	free(tree);
}
