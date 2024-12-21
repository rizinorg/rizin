// SPDX-FileCopyrightText: 2025-2026 heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_graph.h>
#include <rz_util/rz_iterator.h>
#include <rz_util/rz_stack.h>

enum {
	WHITE_COLOR = 0,
	GRAY_COLOR,
	BLACK_COLOR
};

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
static void dfs_edge_policy(RzGraph *g, RzGraphNode *from, RzGraphNode *to, ut8 *edge_color, RzGraphVisitorNew *visitor) {
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
 * Helper function to push neighbours of current node into stack for DFS
 * @param g
 * @param node
 * @param stack
 * @param forward
 */
static void dfs_push_neighbours(RzGraph *g, RzGraphNode *node, RzStack *stack, bool forward) {
	// assert g, node, stack NON NULL
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
static void dfs_from_entry(RzGraph *g, RzGraphNode *root, RzGraphVisitorNew *visitor, ut8 *color, RzStack *stack, bool forward_search) {
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
		dfs_push_neighbours(g, to, stack, forward_search);
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
static void dfs_impl(RzGraph *g, RzGraphNode *start, RzGraphVisitorNew *visitor, bool forward_search) {
	rz_return_if_fail(g && start && visitor);
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
 * @param g graph
 * @param vis callback
 */
RZ_API void rz_graph_dfs(RzGraph *g, RzGraphVisitorNew *vis) {
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
 * @param g graph
 * @param vis callback
 */
RZ_API void rz_graph_dfs_reverse(RzGraph *g, RzGraphVisitorNew *vis) {
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
 * @param g graph
 * @param visitor callback
 */
RZ_API void rz_graph_dfs_from_node(RzGraph *g, RzGraphNode *start, RzGraphVisitorNew *visitor) {
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
 * @param g graph
 * @param vis callback
 */
RZ_API void rz_graph_dfs_reverse_from_node(RzGraph *g, RzGraphNode *start, RzGraphVisitorNew *vis) {
	dfs_impl(g, start, vis, false);
}
