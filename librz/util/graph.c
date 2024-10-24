// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

enum {
	WHITE_COLOR = 0,
	GRAY_COLOR,
	BLACK_COLOR
};

static RzGraphNode *rz_graph_node_new(void *data) {
	RzGraphNode *p = RZ_NEW0(RzGraphNode);
	if (p) {
		p->data = data;
		p->free = NULL;
		p->out_nodes = rz_list_new();
		p->in_nodes = rz_list_new();
		p->all_neighbours = rz_list_new();
	}
	return p;
}

static void rz_graph_node_free(RzGraphNode *n) {
	if (!n) {
		return;
	}
	if (n->free) {
		n->free(n->data);
	}
	rz_list_free(n->out_nodes);
	rz_list_free(n->in_nodes);
	rz_list_free(n->all_neighbours);
	free(n);
}

static int node_cmp(unsigned int idx, RzGraphNode *b, void *user) {
	return idx == b->idx ? 0 : -1;
}

// direction == true => forwards
static void dfs_node(RzGraph *g, RzGraphNode *n, RzGraphVisitor *vis, int color[], const bool direction) {
	if (!n) {
		return;
	}
	RzStack *s = rz_stack_new(2 * g->n_edges + 1);
	if (!s) {
		return;
	}
	RzGraphEdge *edg = RZ_NEW0(RzGraphEdge);
	if (!edg) {
		rz_stack_free(s);
		return;
	}
	edg->from = NULL;
	edg->to = n;
	rz_stack_push(s, edg);
	while (!rz_stack_is_empty(s)) {
		RzGraphEdge *cur_edge = (RzGraphEdge *)rz_stack_pop(s);
		RzGraphNode *v, *cur = cur_edge->to, *from = cur_edge->from;
		RzListIter *it;
		int i;

		if (from && cur) {
			if (color[cur->idx] == WHITE_COLOR && vis->tree_edge) {
				vis->tree_edge(cur_edge, vis);
			} else if (color[cur->idx] == GRAY_COLOR && vis->back_edge) {
				vis->back_edge(cur_edge, vis);
			} else if (color[cur->idx] == BLACK_COLOR && vis->fcross_edge) {
				vis->fcross_edge(cur_edge, vis);
			}
		} else if (!cur && from) {
			if (color[from->idx] != BLACK_COLOR && vis->finish_node) {
				vis->finish_node(from, vis);
			}
			color[from->idx] = BLACK_COLOR;
		}
		free(cur_edge);
		if (!cur || color[cur->idx] != WHITE_COLOR) {
			continue;
		}
		if (color[cur->idx] == WHITE_COLOR && vis->discover_node) {
			vis->discover_node(cur, vis);
		}
		color[cur->idx] = GRAY_COLOR;

		edg = RZ_NEW0(RzGraphEdge);
		if (!edg) {
			break;
		}
		edg->from = cur;
		rz_stack_push(s, edg);

		i = 0;
		const RzList *neighbours = direction ? cur->out_nodes : cur->in_nodes;
		rz_list_foreach (neighbours, it, v) {
			edg = RZ_NEW(RzGraphEdge);
			edg->from = cur;
			edg->to = v;
			edg->nth = i++;
			rz_stack_push(s, edg);
		}
	}
	rz_stack_free(s);
}

RZ_API RzGraph *rz_graph_new(void) {
	RzGraph *t = RZ_NEW0(RzGraph);
	if (!t) {
		return NULL;
	}
	t->nodes = rz_list_new();
	if (!t->nodes) {
		rz_graph_free(t);
		return NULL;
	}
	t->nodes->free = (RzListFree)rz_graph_node_free;
	t->n_nodes = 0;
	t->last_index = 0;
	return t;
}

RZ_API void rz_graph_free(RzGraph *t) {
	rz_list_free(t->nodes);
	free(t);
}

RZ_API RzGraphNode *rz_graph_get_node(const RzGraph *t, unsigned int idx) {
	RzListIter *it = rz_list_find(t->nodes, (void *)(size_t)idx, (RzListComparator)node_cmp, NULL);
	if (!it) {
		return NULL;
	}
	return (RzGraphNode *)rz_list_iter_get_data(it);
}

RZ_API RzListIter *rz_graph_node_iter(const RzGraph *t, unsigned int idx) {
	return rz_list_find(t->nodes, (void *)(size_t)idx, (RzListComparator)node_cmp, NULL);
}

RZ_API void rz_graph_reset(RzGraph *t) {
	rz_list_free(t->nodes);
	t->nodes = rz_list_new();
	if (!t->nodes) {
		return;
	}
	t->nodes->free = (RzListFree)rz_graph_node_free;
	t->n_nodes = 0;
	t->n_edges = 0;
	t->last_index = 0;
}

RZ_API RzGraphNode *rz_graph_add_node(RzGraph *t, void *data) {
	if (!t) {
		return NULL;
	}
	RzGraphNode *n = rz_graph_node_new(data);
	if (!n) {
		return NULL;
	}
	n->idx = t->last_index++;
	rz_list_append(t->nodes, n);
	t->n_nodes++;
	return n;
}

RZ_API RzGraphNode *rz_graph_add_nodef(RzGraph *graph, void *data, RzListFree user_free) {
	RzGraphNode *node = rz_graph_add_node(graph, data);
	if (node) {
		node->free = user_free;
	}
	return node;
}

/**
 * \brief Deletes the node \p n from the graph \p t and frees the \p n.
 *
 * \param t The graph to operate on.
 * \param n The node to delete.
 */
RZ_API void rz_graph_del_node(RzGraph *t, RZ_OWN RzGraphNode *n) {
	rz_return_if_fail(t);
	RzGraphNode *gn;
	RzListIter *it;
	if (!n || !rz_list_contains(t->nodes, n)) {
		return;
	}
	rz_list_foreach (n->in_nodes, it, gn) {
		rz_list_delete_data(gn->out_nodes, n);
		rz_list_delete_data(gn->all_neighbours, n);
		t->n_edges--;
	}

	rz_list_foreach (n->out_nodes, it, gn) {
		rz_list_delete_data(gn->in_nodes, n);
		rz_list_delete_data(gn->all_neighbours, n);
		t->n_edges--;
	}

	rz_list_delete_data(t->nodes, n);
	t->n_nodes--;
}

/**
 * \brief Adds an edge (\p from -> \p to) to the graph.
 * If the edge was already added, won't add a duplicate.
 *
 * \param t The graph to add the edge to.
 * \param from The origin node of the edge.
 * \param to The destination node of the edge.
 */
RZ_API void rz_graph_add_edge(RzGraph *t, RzGraphNode *from, RzGraphNode *to) {
	rz_graph_add_edge_at(t, from, to, -1);
}

/**
 * \brief Adds an edge (\p from -> \p to) to the graph at \p from->out_nodes[\p nth].
 * If the edge was already added, it won't add a duplicate.
 *
 * \param t The graph to add the edge to.
 * \param from The origin node of the edge.
 * \param to The destination node of the edge.
 * \param nth The position in the \p from->out_notes list the \p to node should be added.
 */
RZ_API void rz_graph_add_edge_at(RzGraph *t, RzGraphNode *from, RzGraphNode *to, int nth) {
	if (from && to) {
		if (rz_list_contains(from->out_nodes, to)) {
			return;
		}
		rz_list_insert(from->out_nodes, nth, to);
		rz_list_append(from->all_neighbours, to);
		rz_list_append(to->in_nodes, from);
		rz_list_append(to->all_neighbours, from);
		t->n_edges++;
	}
}

// splits the "split_me", so that new node has it's outnodes
RZ_API RzGraphNode *rz_graph_node_split_forward(RzGraph *g, RzGraphNode *split_me, void *data) {
	RzGraphNode *front = rz_graph_add_node(g, data);
	RzList *tmp = front->out_nodes;
	front->out_nodes = split_me->out_nodes;
	split_me->out_nodes = tmp;
	RzListIter *iter;
	RzGraphNode *n;
	rz_list_foreach (front->out_nodes, iter, n) {
		rz_list_delete_data(n->in_nodes, split_me); // optimize me
		rz_list_delete_data(n->all_neighbours, split_me); // boy this all_neighbours is so retarding perf here
		rz_list_delete_data(split_me->all_neighbours, n);
		rz_list_append(n->all_neighbours, front);
		rz_list_append(n->in_nodes, front);
		rz_list_append(front->all_neighbours, n);
	}
	return front;
}

RZ_API void rz_graph_del_edge(RzGraph *t, RzGraphNode *from, RzGraphNode *to) {
	if (!from || !to || !rz_graph_adjacent(t, from, to)) {
		return;
	}
	rz_list_delete_data(from->out_nodes, to);
	rz_list_delete_data(from->all_neighbours, to);
	rz_list_delete_data(to->in_nodes, from);
	rz_list_delete_data(to->all_neighbours, from);
	t->n_edges--;
}

// XXX remove comments and static inline all this stuff
/* returns the list of nodes reachable from `n` */
RZ_API const RzList *rz_graph_get_neighbours(const RzGraph *g, const RzGraphNode *n) {
	return n ? n->out_nodes : NULL;
}

/* returns the n-th nodes reachable from the give node `n`.
 * This, of course, depends on the order of the nodes. */
RZ_API RzGraphNode *rz_graph_nth_neighbour(const RzGraph *g, const RzGraphNode *n, int nth) {
	return n ? (RzGraphNode *)rz_list_get_n(n->out_nodes, nth) : NULL;
}

/* returns the list of nodes that can reach `n` */
RZ_API const RzList *rz_graph_innodes(const RzGraph *g, const RzGraphNode *n) {
	return n ? n->in_nodes : NULL;
}

/* returns the list of nodes reachable from `n` and that can reach `n`. */
RZ_API const RzList *rz_graph_all_neighbours(const RzGraph *g, const RzGraphNode *n) {
	return n ? n->all_neighbours : NULL;
}

RZ_API const RzList *rz_graph_get_nodes(const RzGraph *g) {
	return g ? g->nodes : NULL;
}

/**
 * \brief Checks if the edge \p from -> \p to exists in the graph.
 * For this it checks the neighbors of \p from.
 *
 * \param g The graph to check.
 * \param from The pointer to the source node of the edge. The pointer must be a node in the graph.
 * \param to The destination node of the edge. The pointer must be a node in the graph.
 *
 * NOTE: It only compares the pointer of \p to against the neighbor list of \p from.
 * If the pointer doesn't match it returns false. Even if the node content is the same.
 *
 * \returns true If there is an edge from the node `from` to the node `to`
 * \return false Otherwise
 */
RZ_API bool rz_graph_adjacent(const RzGraph *g, const RzGraphNode *from, const RzGraphNode *to) {
	if (!g || !from) {
		return false;
	}
	return rz_list_contains(from->out_nodes, to);
}

RZ_API void rz_graph_dfs_node(RzGraph *g, RzGraphNode *n, RzGraphVisitor *vis) {
	if (!g || !n || !vis) {
		return;
	}
	int *color = RZ_NEWS0(int, g->last_index);
	if (color) {
		dfs_node(g, n, vis, color, true);
		free(color);
	}
}

RZ_API void rz_graph_dfs_node_reverse(RzGraph *g, RzGraphNode *n, RzGraphVisitor *vis) {
	if (!g || !n || !vis) {
		return;
	}
	int *color = RZ_NEWS0(int, g->last_index);
	if (color) {
		dfs_node(g, n, vis, color, false);
		free(color);
	}
}

RZ_API void rz_graph_dfs(RzGraph *g, RzGraphVisitor *vis) {
	rz_return_if_fail(g && vis);
	RzGraphNode *n;
	RzListIter *it;

	int *color = RZ_NEWS0(int, g->last_index);
	if (color) {
		rz_list_foreach (g->nodes, it, n) {
			if (color[n->idx] == WHITE_COLOR) {
				dfs_node(g, n, vis, color, true);
			}
		}
		free(color);
	}
}
