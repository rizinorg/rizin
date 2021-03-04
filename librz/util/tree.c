// SPDX-FileCopyrightText: 2007-2015 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

static void tree_dfs_node(RTreeNode *r, RTreeVisitor *vis) {
	RzStack *s;
	RzListIter *it;
	RTreeNode *n;

	s = rz_stack_new(16);
	if (!s) {
		return;
	}
	rz_stack_push(s, r);
	while (!rz_stack_is_empty(s)) {
		RTreeNode *el = (RTreeNode *)rz_stack_pop(s);

		if (vis->pre_visit) {
			vis->pre_visit(el, vis);
		}

		rz_list_foreach_prev(el->children, it, n) {
			if (vis->discover_child) {
				vis->discover_child(n, vis);
			}
			rz_stack_push(s, n);
		}

		if (vis->post_visit) {
			vis->post_visit(el, vis);
		}
	}

	rz_stack_free(s);
}

static void rz_tree_node_free(RTreeNode *n) {
	rz_list_free(n->children);
	if (n->free) {
		n->free(n->data);
	}
	free(n);
}

static void node_free(RTreeNode *n, RTreeVisitor *vis) {
	rz_tree_node_free(n);
}

static void free_all_children(RTree *t) {
	RTreeVisitor vis = { 0 };
	vis.post_visit = (RTreeNodeVisitCb)node_free;
	rz_tree_bfs(t, &vis);
}

static void update_depth(RTreeNode *n, RTreeVisitor *vis) {
	n->depth = n->parent ? n->parent->depth + 1 : 0;
}

static RTreeNode *node_new(RTree *t, void *data) {
	RTreeNode *n = RZ_NEW0(RTreeNode);
	if (!n) {
		return NULL;
	}
	n->children = rz_list_new();
	n->data = data;
	n->tree = t;
	return n;
}

RZ_API RTree *rz_tree_new(void) {
	return RZ_NEW0(RTree);
}

RZ_API void rz_tree_free(RTree *t) {
	if (!t) {
		return;
	}

	free_all_children(t);
	free(t);
}

RZ_API void rz_tree_reset(RTree *t) {
	if (!t) {
		return;
	}

	free_all_children(t);
	t->root = NULL;
}

/* add a node in the RTree t as a child of the RTreeNode node.
 * NOTE: the first call to this function, should add the root
 *       of the tree so the node will be NULL. */
/* TODO: allow to replace the root of the tree and make it a child of the new
 *       node */
RZ_API RTreeNode *rz_tree_add_node(RTree *t, RTreeNode *node, void *child_data) {
	RTreeNode *child;
	RTreeVisitor vis = { 0 };

	/* a NULL node is allowed only the first time, to set the root */
	if (!t || (node && node->tree != t) || (t->root && !node)) {
		return NULL;
	}

	child = node_new(t, child_data);
	if (!node && !t->root) {
		t->root = child;
	} else if (node) {
		rz_list_append(node->children, child);
		node->n_children++;
	}
	child->parent = node;

	/* update depth */
	vis.pre_visit = (RTreeNodeVisitCb)update_depth;
	tree_dfs_node(child, &vis);

	return child;
}

RZ_API void rz_tree_dfs(RTree *t, RTreeVisitor *vis) {
	if (!t || !t->root) {
		return;
	}

	tree_dfs_node(t->root, vis);
}

RZ_API void rz_tree_bfs(RTree *t, RTreeVisitor *vis) {
	RQueue *q;

	if (!t || !t->root) {
		return;
	}

	q = rz_queue_new(16);
	if (!q) {
		return;
	}
	rz_queue_enqueue(q, t->root);
	while (!rz_queue_is_empty(q)) {
		RTreeNode *el = (RTreeNode *)rz_queue_dequeue(q);
		if (!el) {
			rz_queue_free(q);
			return;
		}
		RTreeNode *n;
		RzListIter *it;

		if (vis->pre_visit) {
			vis->pre_visit(el, vis);
		}

		rz_list_foreach (el->children, it, n) {
			if (vis->discover_child) {
				vis->discover_child(n, vis);
			}
			rz_queue_enqueue(q, n);
		}

		if (vis->post_visit) {
			vis->post_visit(el, vis);
		}
	}

	rz_queue_free(q);
}
