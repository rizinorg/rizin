// SPDX-FileCopyrightText: 2025-2026 heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_graph.h>
#include <rz_util/rz_iterator.h>
#include <rz_util/rz_stack.h>
#include "graph_priv.h"

/**
 * \brief DFS traversal colors.
 */
typedef enum {
	WHITE_COLOR = 0, ///< Node not visited yet.
	GRAY_COLOR, ///< Node discovered, not finished.
	BLACK_COLOR ///< Node fully processed.
} DfsColor;

typedef struct {
	RzGraphNode *from;
	RzGraphNode *to;
} DfsEntry;

/**
 * DFS entry, used for stack element to keep track of parent and current node
 * \param from
 * \param to
 * \return the entry to push or pop in stack (emulation of recursive DFS)
 */
static DfsEntry *dfs_entry_new(RzGraphNode *from, RzGraphNode *to) {
	DfsEntry *entry = RZ_NEW0(DfsEntry);
	if (!entry) {
		return NULL;
	}
	entry->from = from;
	entry->to = to;
	return entry;
}

static void dfs_entry_free(DfsEntry *entry) {
	if (entry) {
		free(entry);
	}
}

/**
 * DFS edge policy, decide which visitor callback to call based on edge color
 * \param g graph
 * \param from
 * \param to
 * \param edge_color color array for all nodes, used to determine edge is visited or not, and end point or not
 * \param visitor callbacks
 */
static void dfs_edge_policy(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to, ut8 *edge_color, RzGraphVisitor *visitor) {
	// assert g, from, to, edge_color, visitor NON NULL

	RzGraphEdge edge = {
		.from = from,
		.to = to,
		.data = NULL
	};
	RzGraphEdge *real_edge = g->impl_ops->find_edge(g, from, to);
	if (real_edge) {
		edge.data = real_edge->data;
	}

	switch (edge_color[to->_vec_id]) {
	case WHITE_COLOR:
		if (visitor->tree_edge) {
			visitor->tree_edge(&edge, visitor);
		}
		break;
	case GRAY_COLOR:
		if (visitor->back_edge) {
			visitor->back_edge(&edge, visitor);
		}
		break;
	case BLACK_COLOR:
		if (visitor->fcross_edge) {
			visitor->fcross_edge(&edge, visitor);
		}
		break;
	}
}

/**
 * Helper function to push neighbours of current node into stack for DFS.
 */
static void dfs_push_neighbours(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node, RzStack *stack, bool forward, RzGraphVisitor *visitor) {
	// assert g, node, stack, visitor NON NULL
	RzIterator *edge_iter = forward ? g->impl_ops->get_out_edges(g, node) : g->impl_ops->get_in_edges(g, node);
	if (!edge_iter) {
		return;
	}

	RzGraphEdge *edge;
	DfsEntry *entry;
	rz_iterator_foreach(edge_iter, edge) {
		RzGraphNode *neighbour = forward ? edge->to : edge->from;
		entry = dfs_entry_new(node, neighbour);
		if (entry) {
			rz_stack_push(stack, entry);
		}
	}

	rz_iterator_free(edge_iter);
}

/**
 * DFS from one entry point, used for both specified start node and foreach node without parent
 * DFS is emulated by stack to avoid recursion, each stack element is a DfsEntry struct to keep track of parent and current node, and determine edge type by color
 * DFS edge policy is implemented in dfs_edge_policy function, which calls corresponding visitor callback based on edge color
 * \param g graph
 * \param root root, can be NULL or specified start node, if NULL, DFS will be performed for each node without parent
 * \param visitor callbacks
 * \param color color array for all nodes, used to determine edge is visited or not, and end point or not
 * \param stack stack for emulating recursive DFS, each element is a DfsEntry struct to keep track of parent and current node
 * \param forward_search true for normal DFS, false for reverse DFS
 */
static void dfs_from_entry(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *root, RzGraphVisitor *visitor, ut8 *color, RzStack *stack, bool forward_search) {
	rz_return_if_fail(g && root && visitor && color && stack);

	// build root node as first to start search
	DfsEntry *entry = dfs_entry_new(NULL, root);
	if (!entry) {
		return;
	}
	rz_stack_push(stack, entry);

	while (!rz_stack_is_empty(stack)) {
		DfsEntry *cur_entry = rz_stack_pop(stack);
		RzGraphNode *from = cur_entry->from;
		RzGraphNode *to = cur_entry->to;
		dfs_entry_free(cur_entry);

		// from = parent/root, to = NULL, end point as finish
		// DFS branch end
		if (from && !to) {
			if (color[from->_vec_id] != BLACK_COLOR) {
				if (visitor->finish_node) {
					visitor->finish_node(from, visitor);
				}
				// mark BLACK
				color[from->_vec_id] = BLACK_COLOR;
			}
			continue;
		}

		// normal node (has in and out)
		if (from && to) {
			dfs_edge_policy(g, from, to, color, visitor);
		}

		// CORLOR changes
		// check unvisited only
		if (color[to->_vec_id] != WHITE_COLOR) {
			continue;
		}

		// mark gray as partial-visited
		if (visitor->discover_node) {
			visitor->discover_node(to, visitor);
		}
		color[to->_vec_id] = GRAY_COLOR;

		// push neighbours into queue, set finish ep as last task
		DfsEntry *ep_entry = dfs_entry_new(to, NULL);
		if (!ep_entry) {
			break;
		}
		rz_stack_push(stack, ep_entry);
		dfs_push_neighbours(g, to, stack, forward_search, visitor);
	}
}

/**
 * DFS implementation, used for all DFS variants, if start is NULL, DFS will be performed for each node without parent, otherwise DFS will be performed from specified start node
 * actually prepare environments (color array and stack) for DFS and call dfs_from_entry to perform DFS
 * \param g graph
 * \param start start node, can be NULL or specified start node, if NULL, DFS will be performed for each node without parent
 * \param visitor callbacks
 * \param forward_search true for normal DFS, false for reverse DFS
 */
static void dfs_impl(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *start, RzGraphVisitor *visitor, bool forward_search) {
	rz_return_if_fail(g && visitor);
	ut64 n = rz_pvector_len(g->node_vec);
	if (n == 0) {
		return;
	}

	// keep same order of g->node_vec
	ut8 *node_colors = RZ_NEWS0(ut8, n);
	if (!node_colors) {
		return;
	}

	// |E| * 2 + root
	RzStack *recur_stack = rz_stack_new(g->n_edges * 2 + 1);
	if (!recur_stack) {
		RZ_LOG_WARN("Failed to create stack for DFS, abort DFS")
		free(node_colors);
		return;
	}

	if (start) {
		// specify one entry
		dfs_from_entry(g, start, visitor, node_colors, recur_stack, forward_search);
		rz_stack_free(recur_stack);
		free(node_colors);
		return;
	}

	// foreach node without parent
	for (ut64 i = 0; i < n; ++i) {
		RzGraphNode *node = rz_pvector_at(g->node_vec, i);
		if (!node) {
			continue;
		}
		if (node_colors[node->_vec_id] == WHITE_COLOR) {
			dfs_from_entry(g, node, visitor, node_colors, recur_stack, forward_search);
		}
	}

	rz_stack_free(recur_stack);
	free(node_colors);
}

/**
 * Wrapper function for DFS, use visitor pattern to provide callbacks for DFS events
 * User can implement the visitor callbacks to perform operations
 * discover_node: called when a node is first discovered (marked GRAY)
 * finish_node: called when a node is finished (marked BLACK)
 * tree_edge: called when a tree edge is found (to a WHITE node)
 * back_edge: called when a back edge is found (to a GRAY node)
 * fcross_edge: called when a forward or cross edge is found (to a BLACK node)
 * \param g graph
 * \param vis callback
 */
RZ_API void rz_graph_dfs(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphVisitor *vis) {
	dfs_impl(g, NULL, vis, true);
}

/**
 * Wrapper function for DFS, use visitor pattern to provide callbacks for DFS events
 * User can implement the visitor callbacks to perform operations
 * discover_node: called when a node is first discovered (marked GRAY)
 * finish_node: called when a node is finished (marked BLACK)
 * tree_edge: called when a tree edge is found (to a WHITE node)
 * back_edge: called when a back edge is found (to a GRAY node)
 * fcross_edge: called when a forward or cross edge is found (to a BLACK node)
 * \param g graph
 * \param vis callback
 */
RZ_API void rz_graph_dfs_reverse(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphVisitor *vis) {
	dfs_impl(g, NULL, vis, false);
}

/**
 * Wrapper function for DFS, use visitor pattern to provide callbacks for DFS events
 * Would perform DFS from specified start node, if start is NULL, DFS will be performed for each node without parent
 * User can implement the visitor callbacks to perform operations
 * discover_node: called when a node is first discovered (marked GRAY)
 * finish_node: called when a node is finished (marked BLACK)
 * tree_edge: called when a tree edge is found (to a WHITE node)
 * back_edge: called when a back edge is found (to a GRAY node)
 * fcross_edge: called when a forward or cross edge is found (to a BLACK node)
 * \param g graph
 * \param visitor callback
 */
RZ_API void rz_graph_dfs_from_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *start, RzGraphVisitor *visitor) {
	dfs_impl(g, start, visitor, true);
}

/**
 * Wrapper function for DFS, use visitor pattern to provide callbacks for DFS events
 * Would perform DFS from specified start node, if start is NULL, DFS will be performed for each node without parent
 * User can implement the visitor callbacks to perform operations
 * discover_node: called when a node is first discovered (marked GRAY)
 * finish_node: called when a node is finished (marked BLACK)
 * tree_edge: called when a tree edge is found (to a WHITE node)
 * back_edge: called when a back edge is found (to a GRAY node)
 * fcross_edge: called when a forward or cross edge is found (to a BLACK node)
 * \param g graph
 * \param vis callback
 */
RZ_API void rz_graph_dfs_reverse_from_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *start, RzGraphVisitor *vis) {
	dfs_impl(g, start, vis, false);
}

/**
 * Push out-edges of \p node onto \p stack as DfsEntry items.
 * When \p cmp is non-NULL the edges are first sorted in ascending order by
 * \p cmp so that the last pushed (= highest sorted) edge is popped first by
 * the LIFO stack, matching the traversal order used for layout.
 */
static void find_back_edges_push(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node, RzStack *stack, RzGraphEdgeCmp cmp, void *user) {
	RzIterator *edge_iter = g->impl_ops->get_out_edges(g, node);
	if (!edge_iter) {
		return;
	}

	if (cmp) {
		RzPVector /*<RzGraphEdge *>*/ *edges_vec = rz_pvector_new(NULL);
		if (!edges_vec) {
			rz_iterator_free(edge_iter);
			return;
		}
		RzGraphEdge *e;
		rz_iterator_foreach(edge_iter, e) {
			rz_pvector_push(edges_vec, e);
		}
		rz_iterator_free(edge_iter);
		if (rz_pvector_len(edges_vec) > 1) {
			rz_pvector_sort(edges_vec, (RzPVectorComparator)cmp, user);
		}
		ut64 len = rz_pvector_len(edges_vec);
		for (ut64 i = 0; i < len; i++) {
			RzGraphEdge *se = rz_pvector_at(edges_vec, i);
			if (!se) {
				continue;
			}
			DfsEntry *entry = dfs_entry_new(node, se->to);
			if (entry) {
				rz_stack_push(stack, entry);
			}
		}
		rz_pvector_free(edges_vec);
	} else {
		RzGraphEdge *e;
		rz_iterator_foreach(edge_iter, e) {
			DfsEntry *entry = dfs_entry_new(node, e->to);
			if (entry) {
				rz_stack_push(stack, entry);
			}
		}
		rz_iterator_free(edge_iter);
	}
}

/**
 * Find back edges in a DFS traversal of \p g.
 * When \p cmp is non-NULL, outgoing edges of each node are sorted by \p cmp
 * before being pushed onto the DFS stack, controlling which edges are classified
 * as back edges (greedy feedback arc set selection).
 * Returns a list of borrowed RzGraphEdge pointers (owned by the graph).
 * Caller must free the list itself but must NOT free the elements.
 */
RZ_API RZ_OWN RzList /*<RzGraphEdge *>*/ *rz_graph_find_back_edges(RzGraph /*<NodeType *, EdgeType *>*/ *g, RZ_NULLABLE RzGraphEdgeCmp cmp, void *user) {
	rz_return_val_if_fail(g, NULL);

	RzList /*<RzGraphEdge *>*/ *back_edges = rz_list_new(); // borrowed pointers, no element free fn
	if (!back_edges) {
		return NULL;
	}

	ut64 n = rz_pvector_len(g->node_vec);
	if (n == 0) {
		return back_edges;
	}

	ut8 *color = RZ_NEWS0(ut8, n);
	if (!color) {
		rz_list_free(back_edges);
		return NULL;
	}

	RzStack *stack = rz_stack_new(g->n_edges * 2 + 1);
	if (!stack) {
		free(color);
		rz_list_free(back_edges);
		return NULL;
	}

	for (ut64 i = 0; i < n; i++) {
		RzGraphNode *root = rz_pvector_at(g->node_vec, i);
		if (!root || color[root->_vec_id] != WHITE_COLOR) {
			continue;
		}

		DfsEntry *entry = dfs_entry_new(NULL, root);
		if (!entry) {
			break;
		}
		rz_stack_push(stack, entry);

		while (!rz_stack_is_empty(stack)) {
			DfsEntry *cur = rz_stack_pop(stack);
			RzGraphNode *from = cur->from;
			RzGraphNode *to = cur->to;
			dfs_entry_free(cur);

			/* finish sentinel: from=node, to=NULL */
			if (from && !to) {
				if (color[from->_vec_id] != BLACK_COLOR) {
					color[from->_vec_id] = BLACK_COLOR;
				}
				continue;
			}

			/* edge classification */
			if (from && to && color[to->_vec_id] == GRAY_COLOR) {
				RzGraphEdge *real_edge = g->impl_ops->find_edge(g, from, to);
				if (real_edge) {
					rz_list_append(back_edges, real_edge);
				}
			}

			if (!to || color[to->_vec_id] != WHITE_COLOR) {
				continue;
			}

			color[to->_vec_id] = GRAY_COLOR;

			DfsEntry *ep = dfs_entry_new(to, NULL);
			if (!ep) {
				break;
			}
			rz_stack_push(stack, ep);
			find_back_edges_push(g, to, stack, cmp, user);
		}
	}

	rz_stack_free(stack);
	free(color);
	return back_edges;
}

/**
 * Per-node state for iterative Tarjan SCC.
 */
typedef struct {
	RzGraphNode *node;
	RzPVector /*<RzGraphNode *>*/ *neighbors; ///< owned snapshot of out-neighbors collected at entry
	ut64 neighbor_idx; ///< next neighbor to process
} TarjanFrame;

static TarjanFrame *tarjan_frame_new(RzGraphNode *node, RzPVector /*<RzGraphNode *>*/ *neighbors) {
	TarjanFrame *f = RZ_NEW0(TarjanFrame);
	if (!f) {
		rz_pvector_free(neighbors);
		return NULL;
	}
	f->node = node;
	f->neighbors = neighbors;
	f->neighbor_idx = 0;
	return f;
}

static void tarjan_frame_free(TarjanFrame *f) {
	if (f) {
		rz_pvector_free(f->neighbors);
		free(f);
	}
}

/**
 * Find all strongly connected components (SCCs) of \p g using Tarjan's algorithm.
 * Returns an owned RzPVector of owned RzPVector<RzGraphNode *> (borrowed nodes).
 * Each inner vector is one SCC; SCCs with a single node and no self-loop are trivial.
 * Caller must free the outer vector (and each inner vector); nodes are not freed.
 */
RZ_API RZ_OWN RzPVector /*<RzPVector<RzGraphNode *> *>*/ *rz_graph_find_sccs(RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	rz_return_val_if_fail(g, NULL);

	RzPVector /*<RzPVector<RzGraphNode *> *>*/ *sccs = rz_pvector_new((RzPVectorFree)rz_pvector_free);
	if (!sccs) {
		return NULL;
	}

	ut64 n = rz_pvector_len(g->node_vec);
	if (n == 0) {
		return sccs;
	}

	ut64 *disc = RZ_NEWS(ut64, n);
	ut64 *low = RZ_NEWS(ut64, n);
	bool *on_stack = RZ_NEWS0(bool, n);
	if (!disc || !low || !on_stack) {
		free(disc);
		free(low);
		free(on_stack);
		rz_pvector_free(sccs);
		return NULL;
	}
	memset(disc, 0xff, sizeof(ut64) * n); // UT64_MAX = unvisited

	/* SCC membership stack (borrowed node pointers) */
	RzStack *scc_stack = rz_stack_new(n + 1);
	/* DFS work stack of TarjanFrame* */
	RzStack *work_stack = rz_stack_new(n + 1);
	if (!scc_stack || !work_stack) {
		free(disc);
		free(low);
		free(on_stack);
		rz_pvector_free(sccs);
		rz_stack_free(scc_stack);
		rz_stack_free(work_stack);
		return NULL;
	}

	ut64 timer = 0;

	for (ut64 i = 0; i < n; i++) {
		RzGraphNode *root = rz_pvector_at(g->node_vec, i);
		if (!root || disc[root->_vec_id] != UT64_MAX) {
			continue;
		}

		/* Collect neighbors once and build initial frame */
		RzPVector /*<RzGraphNode *>*/ *root_nb = rz_pvector_new(NULL);
		if (!root_nb) {
			break;
		}
		RzIterator *it = g->impl_ops->get_out_edges(g, root);
		if (it) {
			RzGraphEdge *e;
			rz_iterator_foreach(it, e) {
				rz_pvector_push(root_nb, e->to);
			}
			rz_iterator_free(it);
		}
		TarjanFrame *rf = tarjan_frame_new(root, root_nb);
		if (!rf) {
			break;
		}
		disc[root->_vec_id] = low[root->_vec_id] = timer++;
		on_stack[root->_vec_id] = true;
		rz_stack_push(scc_stack, root);
		rz_stack_push(work_stack, rf);

		while (!rz_stack_is_empty(work_stack)) {
			TarjanFrame *frame = rz_stack_peek(work_stack);
			RzGraphNode *u = frame->node;

			if (frame->neighbor_idx < rz_pvector_len(frame->neighbors)) {
				RzGraphNode *v = rz_pvector_at(frame->neighbors, frame->neighbor_idx++);
				if (!v) {
					continue;
				}
				if (disc[v->_vec_id] == UT64_MAX) {
					/* tree edge: push new frame for v */
					RzPVector /*<RzGraphNode *>*/ *v_nb = rz_pvector_new(NULL);
					if (!v_nb) {
						break;
					}
					RzIterator *vit = g->impl_ops->get_out_edges(g, v);
					if (vit) {
						RzGraphEdge *e;
						rz_iterator_foreach(vit, e) {
							rz_pvector_push(v_nb, e->to);
						}
						rz_iterator_free(vit);
					}
					TarjanFrame *vf = tarjan_frame_new(v, v_nb);
					if (!vf) {
						break;
					}
					disc[v->_vec_id] = low[v->_vec_id] = timer++;
					on_stack[v->_vec_id] = true;
					rz_stack_push(scc_stack, v);
					rz_stack_push(work_stack, vf);
				} else if (on_stack[v->_vec_id]) {
					/* back/cross edge within SCC */
					if (disc[v->_vec_id] < low[u->_vec_id]) {
						low[u->_vec_id] = disc[v->_vec_id];
					}
				}
			} else {
				/* done with u: pop frame, propagate low, check SCC root */
				rz_stack_pop(work_stack);
				TarjanFrame *done = frame; // same pointer as peeked
				RzGraphNode *done_node = done->node;
				tarjan_frame_free(done);

				if (!rz_stack_is_empty(work_stack)) {
					TarjanFrame *parent_frame = rz_stack_peek(work_stack);
					RzGraphNode *p = parent_frame->node;
					if (low[done_node->_vec_id] < low[p->_vec_id]) {
						low[p->_vec_id] = low[done_node->_vec_id];
					}
				}

				if (low[done_node->_vec_id] == disc[done_node->_vec_id]) {
					/* done_node is SCC root: extract SCC */
					RzPVector /*<RzGraphNode *>*/ *scc = rz_pvector_new(NULL);
					if (!scc) {
						break;
					}
					while (true) {
						RzGraphNode *w = rz_stack_pop(scc_stack);
						if (!w) {
							break;
						}
						on_stack[w->_vec_id] = false;
						rz_pvector_push(scc, w);
						if (w == done_node) {
							break;
						}
					}
					rz_pvector_push(sccs, scc);
				}
			}
		}
	}

	/* cleanup any leftover work frames on error */
	while (!rz_stack_is_empty(work_stack)) {
		TarjanFrame *f = rz_stack_pop(work_stack);
		tarjan_frame_free(f);
	}

	rz_stack_free(scc_stack);
	rz_stack_free(work_stack);
	free(disc);
	free(low);
	free(on_stack);
	return sccs;
}
