// SPDX-FileCopyrightText: 2025-2026 heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_graph.h>
#include "graph_priv.h"

typedef struct rz_graph_list_edge_impl_t {
	HtUP /*<RzPVector<RzGraphEdge *>*/ *in_edges; ///< maps node hash_id to its incoming edge vector
	HtUP /*<RzPVector<RzGraphEdge *>*/ *out_edges; ///< maps node hash_id to its outgoing edge vector
} RzGraphListImpl;

typedef struct rz_graph_matrix_edge_impl_t {
	RzGraphEdge **matrix; // index by matrix[from_vec_id][to_vec_id]
	ut64 capacity;
} RzGraphMatrixImpl;

#define MATRIX_DEFAULT_CAPACITY 512

/* Edge Extract and Builds */

/**
 * \brief helper func,
 * create a new edge from \p from to \p to with user data.
 *
 * \param from source node
 * \param to destination node
 * \param data user data attached to edge
 * \return A new RzGraphEdgeNew or NULL on failure
 */
static RzGraphEdge *edge_new(RzGraphNode *from, RzGraphNode *to, void *data) {
	RzGraphEdge *e = RZ_NEW0(RzGraphEdge);
	if (!e) {
		return NULL;
	}
	e->from = from;
	e->to = to;
	e->data = data;
	return e;
}

/**
 * \brief helper func,
 * Free an edge struct only, user data is freed by graph.
 * \param e edge to free
 */
// user data free by graph not edge_free
static inline void edge_free(RzGraphEdge *e) {
	free(e);
}

/**
 * \brief helper func,
 * Create a new RzPVector to hold edges.
 * \param edge_data_free optional free callback for edge user data
 * \return A new RzPVector or NULL on failure
 */
static inline RZ_OWN RzPVector /*<RzGraphEdge *>*/ *edge_vec_new(RzGraphEdgeDataFree edge_data_free) {
	return rz_pvector_new(edge_data_free);
}

/**
 * \brief helper func,
 * Find the index of an edge (from -> to) in graph edge set
 *
 * Linear scan through \p vec to locate the edge matching \p from and \p to.
 *
 * \param vec the edge vector to search
 * \param from source node
 * \param to destination node
 * \return index of the edge if found, or (ut64)-1 if not found
 */
static ut64 edge_vec_find_eid(RzPVector /*<RzGraphEdge *>*/ *vec, RzGraphNode *from, RzGraphNode *to) {
	void **it;
	ut64 i = 0;
	rz_pvector_foreach (vec, it) {
		RzGraphEdge *e = (RzGraphEdge *)(*it);
		if (e->from == from && e->to == to) {
			return i;
		}
		++i;
	}
	return -1;
}

/* Double direction Adjacency List Impl */

/**
 * \brief Add a directed edge (from -> to) in the adjacency list implementation.
 *
 * Inserts the edge into both the out_edges table of \p from and
 * the in_edges table of \p to. Skips if the edge already exists.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \param user_data user data attached to the edge
 * \return true on success, false if edge already exists or on failure
 */
static bool rz_graph_list_impl_add_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to, void *user_data) {
	rz_return_val_if_fail(g && from && to, false);
	RzGraphListImpl *impl = (RzGraphListImpl *)g->impl;

	// check output edge of from exist
	bool found = false;
	RzPVector /*<RzGraphEdge *>*/ *out_vec = ht_up_find(impl->out_edges, from->hash_id, &found);

	// no output, cold boot to build output
	if (!found) {
		out_vec = edge_vec_new((RzGraphEdgeDataFree)edge_free);
		if (!out_vec) {
			return false;
		}
		ht_up_insert(impl->out_edges, from->hash_id, out_vec);
	}

	// search edge in graph, skip if already exist
	if (edge_vec_find_eid(out_vec, from, to) != -1) {
		return false;
	}

	// check input
	RzPVector /*<RzGraphEdge *>*/ *in_vec = ht_up_find(impl->in_edges, to->hash_id, &found);
	if (!found) {
		in_vec = edge_vec_new((RzGraphEdgeDataFree)edge_free);
		if (!in_vec) {
			return false;
		}
		ht_up_insert(impl->in_edges, to->hash_id, in_vec);
	}

	// build out edge and in edge, and maintain the edge table
	// our view: oe to carry user data, ie carry a ref copy only
	RzGraphEdge *oe = edge_new(from, to, user_data);
	RzGraphEdge *ie = edge_new(from, to, user_data);

	rz_pvector_push(out_vec, oe);
	rz_pvector_push(in_vec, ie);
	return true;
}

/**
 * \brief Delete a directed edge (from -> to) in the adjacency list implementation.
 *
 * Removes the edge from both the out_edges table of \p from and
 * the in_edges table of \p to. Frees edge user data via graph callback.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \return true on success, false if edge not found
 */
static bool rz_graph_list_impl_del_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to) {
	rz_return_val_if_fail(g && from && to, false);
	RzGraphListImpl *impl = g->impl;

	// remove from out edges
	bool found = false;
	RzPVector /*<RzGraphEdge *>*/ *out_vec = ht_up_find(impl->out_edges, from->hash_id, &found);
	if (!found || !out_vec) {
		return false;
	}
	ut64 eid = edge_vec_find_eid(out_vec, from, to);
	if (eid == -1) {
		return false;
	}
	RzGraphEdge *oe = rz_pvector_at(out_vec, eid);
	// free user data
	if (g->edge_data_free && oe->data) {
		g->edge_data_free(oe->data);
	}
	oe->data = NULL;
	edge_free(oe);
	rz_pvector_remove_at(out_vec, eid);

	// remove in edge
	RzPVector /*<RzGraphEdge *>*/ *in_vec = ht_up_find(impl->in_edges, to->hash_id, &found);
	if (found && in_vec) {
		eid = edge_vec_find_eid(in_vec, from, to);
		if (eid != -1) {
			RzGraphEdge *ie = rz_pvector_at(in_vec, eid);
			ie->data = NULL;
			edge_free(ie);
			rz_pvector_remove_at(in_vec, eid);
		}
	}

	return true;
}

/**
 * \brief Check if a directed edge (from -> to) exists in the adjacency list.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \return true if the edge exists, false otherwise
 */
static bool rz_graph_list_impl_has_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to) {
	rz_return_val_if_fail(g && from && to, false);
	RzGraphListImpl *impl = (RzGraphListImpl *)g->impl;

	bool found = false;
	RzPVector /*<RzGraphEdge *>*/ *out_vec = ht_up_find(impl->out_edges, from->hash_id, &found);
	if (!found || !out_vec) {
		return false;
	}

	bool is_exist = (edge_vec_find_eid(out_vec, from, to) != -1);
	return is_exist;
}

/**
 * \brief Find and return the edge (from -> to) in the adjacency list.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \return the edge if found, or NULL if not found
 */
static RzGraphEdge *rz_graph_list_impl_find_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to) {
	rz_return_val_if_fail(g && from && to, NULL);
	RzGraphListImpl *impl = (RzGraphListImpl *)g->impl;

	bool found = false;
	RzPVector /*<RzGraphEdge *>*/ *out_vec = ht_up_find(impl->out_edges, from->hash_id, &found);
	if (!found || !out_vec) {
		return NULL;
	}

	ut64 eid = edge_vec_find_eid(out_vec, from, to);
	if (eid == -1) {
		return NULL;
	}
	return rz_pvector_at(out_vec, eid);
}

// no build-in vector iter
typedef struct {
	RZ_BORROW const RzPVector /*<RzGraphEdge *>*/ *vec; // borrow
	ut64 cur_id;
} RzGraphListIterState;

/**
 * \brief Iterator next callback for RzPVector-backed iteration.
 *
 * Returns the next element in the borrowed pvector, or NULL when exhausted.
 *
 * \param iter the iterator
 * \return next element pointer, or NULL
 */
static void *pvecotr_iter_next(RzIterator *iter) {
	RzGraphListIterState *state = (RzGraphListIterState *)iter->u;
	ut64 vec_size = rz_pvector_len(state->vec);
	while (state->cur_id < vec_size) {
		void *elem = rz_pvector_at(state->vec, state->cur_id);
		state->cur_id += 1;
		if (elem) {
			return elem;
		}
	}
	return NULL;
}

/**
 * \brief Wrap an RzPVector as a read-only RzIterator.
 *
 * The iterator borrows the vector; freeing the iterator does not
 * free the underlying vector elements.
 *
 * \param vec the pvector to iterate over (borrowed)
 * \return A new RzIterator, or NULL on failure
 */
static RZ_OWN RzIterator *pvector_as_iter(RzPVector /*<RzGraphEdge *>*/ *vec) {
	if (!vec) {
		return NULL;
	}

	// free state only, dont broke pvector nodes of graph
	RzGraphListIterState *state = RZ_NEW0(RzGraphListIterState);
	if (!state) {
		return NULL;
	}
	state->cur_id = 0;
	state->vec = vec;

	RzIterator *iter = rz_iterator_new(
		(rz_iterator_next_cb)pvecotr_iter_next,
		NULL,
		free,
		state);
	return iter;
}

/**
 * \brief Get an iterator over all outgoing edges of \p node (list impl).
 *
 * \param g graph
 * \param node the node whose out-edges to iterate
 * \return A new edge iterator owned by caller, or NULL if no out-edges
 */
static RZ_OWN RzIterator *rz_graph_list_impl_get_out_edges(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	rz_return_val_if_fail(g, NULL);
	RzGraphListImpl *impl = (RzGraphListImpl *)g->impl;
	bool found = false;
	RzPVector /*<RzGraphEdge *>*/ *out_vec = ht_up_find(impl->out_edges, node->hash_id, &found);
	if (!found || !out_vec) {
		return NULL;
	}
	RzIterator *iter = pvector_as_iter(out_vec);
	return iter;
}

/**
 * \brief Get an iterator over all incoming edges of \p node (list impl).
 *
 * \param g graph
 * \param node the node whose in-edges to iterate
 * \return A new edge iterator owned by caller, or NULL if no in-edges
 */
static RZ_OWN RzIterator *rz_graph_list_impl_get_in_edges(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	rz_return_val_if_fail(g, NULL);
	RzGraphListImpl *impl = (RzGraphListImpl *)g->impl;
	bool found = false;
	RzPVector /*<RzGraphEdge *>*/ *in_vec = ht_up_find(impl->in_edges, node->hash_id, &found);
	if (!found || !in_vec) {
		return NULL;
	}
	RzIterator *iter = pvector_as_iter(in_vec);
	return iter;
}

/**
 * \brief Add a node to the adjacency list implementation (no-op).
 *
 * In the list-based implementation, nodes are managed by the graph itself.
 * An orphan node simply has no edges in the edge table.
 *
 * \param g graph
 * \param node node to add
 * \return always true
 */
static inline RZ_OWN bool rz_graph_list_impl_add_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	rz_return_val_if_fail(g && node, false);
	// no explicit node in list-based
	// all leaved to graph to manage nodes
	// an orphan node will not have any edge in list edge table
	return true;
}

/**
 * \brief Delete a node from the adjacency list, removing all associated edges.
 *
 * First removes all outgoing edges (node -> dest), cleaning up the
 * corresponding in-edges of neighbour nodes. Then removes all incoming
 * edges (src -> node), cleaning up the corresponding out-edges of
 * neighbour nodes. Edge user data is freed via graph callback.
 *
 * \param g graph
 * \param node node to delete
 * \return true on success, false on failure
 */
static RZ_OWN bool rz_graph_list_impl_del_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	rz_return_val_if_fail(g && node, false);
	RzGraphListImpl *impl = (RzGraphListImpl *)g->impl;

	// remove all node -> dest
	bool found = false;
	RZ_BORROW RzPVector /*<RzGraphEdge *>*/ *out_vec = ht_up_find(impl->out_edges, node->hash_id, &found);
	if (found && out_vec) {
		ut64 i = rz_pvector_len(out_vec);
		while (i-- > 0) {
			RzGraphEdge *node_to_dest_as_oe = (RzGraphEdge *)rz_pvector_at(out_vec, i);
			RzGraphNode *dest_node = node_to_dest_as_oe->to;
			// remove related neighbour (mirror) nodes' in-edges
			RzPVector /*<RzGraphEdge *>*/ *in_edges_of_dest = ht_up_find(impl->in_edges, dest_node->hash_id, &found);
			if (found && in_edges_of_dest) {
				// find id of node_to_dest_as_ie
				ut64 eid = edge_vec_find_eid(in_edges_of_dest, node, dest_node);
				if (eid != -1) {
					// do not free edge data
					RzGraphEdge *node_to_dest_as_ie = rz_pvector_at(in_edges_of_dest, eid);
					edge_free(node_to_dest_as_ie);
					rz_pvector_remove_at(in_edges_of_dest, eid);
				}
			}

			// clean and delete edge struct
			// NOTE: reverse iteration allows safe rz_pvector_remove_at —
			// removing from the tail does not shift earlier indices.
			if (g->edge_data_free && node_to_dest_as_oe->data) {
				g->edge_data_free(node_to_dest_as_oe->data);
			}
			edge_free(node_to_dest_as_oe);
			rz_pvector_remove_at(out_vec, i);

			g->n_edges -= 1;
		}
		ht_up_delete(impl->out_edges, node->hash_id);
	}

	// remove all src -> node
	RzPVector /*<RzGraphEdge *>*/ *in_vec = ht_up_find(impl->in_edges, node->hash_id, &found);
	if (found && in_vec) {
		ut64 i = rz_pvector_len(in_vec);
		while (i-- > 0) {
			RzGraphEdge *src_to_node_as_ie = (RzGraphEdge *)rz_pvector_at(in_vec, i);
			RzGraphNode *src_node = src_to_node_as_ie->from;
			// remove related neighbour (mirror) nodes' out-edges
			RzPVector /*<RzGraphEdge *>*/ *out_edges_of_src = ht_up_find(impl->out_edges, src_node->hash_id, &found);
			if (found && out_edges_of_src) {
				// find src_to_node_as_oe in out edge vec of src node
				ut64 eid = edge_vec_find_eid(out_edges_of_src, src_node, node);
				if (eid != -1) {
					RzGraphEdge *src_to_node_as_oe = rz_pvector_at(out_edges_of_src, eid);
					if (g->edge_data_free && src_to_node_as_oe->data) {
						g->edge_data_free(src_to_node_as_oe->data);
					}
					edge_free(src_to_node_as_oe);
					rz_pvector_remove_at(out_edges_of_src, eid);
				}
			}

			// free struct
			// NOTE: reverse iteration allows safe rz_pvector_remove_at —
			// removing from the tail does not shift earlier indices.
			edge_free(src_to_node_as_ie);
			rz_pvector_remove_at(in_vec, i);
			g->n_edges -= 1;
		}
		ht_up_delete(impl->in_edges, node->hash_id);
	}

	return true;
}

/**
 * \brief Finalize and free the adjacency list implementation.
 *
 * Frees both the in_edges and out_edges hash tables and the impl struct itself.
 *
 * \param impl the list impl to finalize
 */
static void rz_graph_list_impl_fini(void *impl) {
	if (!impl) {
		return;
	}

	RzGraphListImpl *list_impl = impl;
	ht_up_free(list_impl->out_edges);
	ht_up_free(list_impl->in_edges);
	free(list_impl);
}

/**
 * \brief HtUP value free callback to free an edge vector.
 *
 * Registered as ht_up free callback, called when a hash table entry
 * holding an edge RzPVector is removed.
 *
 * \param value the RzPVector to free
 */
static void edge_vec_free_cb(void *value) {
	RzPVector /*<RzGraphEdge *>*/ *vec = (RzPVector /*<RzGraphEdge *>*/ *)value;
	rz_pvector_free(vec);
}

/**
 * \brief Initialize a new adjacency list graph implementation.
 *
 * Allocates and sets up in_edges and out_edges hash tables.
 *
 * \return A new RzGraphListImpl, or NULL on failure
 */
static RzGraphListImpl *rz_graph_list_impl_init(void) {
	RzGraphListImpl *impl = RZ_NEW0(RzGraphListImpl);
	if (!impl) {
		return NULL;
	}
	impl->out_edges = ht_up_new(NULL, edge_vec_free_cb);
	impl->in_edges = ht_up_new(NULL, edge_vec_free_cb);
	if (!impl->out_edges || !impl->in_edges) {
		rz_graph_list_impl_fini(impl);
		return NULL;
	}
	return impl;
}

/* Adjacency Matrix Impl */
/**
 * -------------------------
 * ->       | to1 | to2 | to3 | ... |
 * -> from1 |     |     |     | ... |
 * -> from2 |     |     |     | ... |
 * -> from3 |     |     |     | ... |
 * ......
 * -------------------------
 */

/**
 * \brief Get a pointer to the matrix cell for edge (from -> to).
 *
 * \param impl matrix impl
 * \param from_vec_id vec id of source node
 * \param to_vec_id vec id of destination node
 * \return pointer to the RzGraphEdgeNew* cell in the matrix
 */
static inline RzGraphEdge **matrix_cell(const RzGraphMatrixImpl *impl, ut64 from_vec_id, ut64 to_vec_id) {
	return &(impl->matrix[from_vec_id * impl->capacity + to_vec_id]);
}

/**
 * \brief Grow the adjacency matrix if needed to hold at least \p required nodes.
 *
 * If the current capacity is sufficient, returns immediately. Otherwise
 * allocates a larger matrix and copies the old data over.
 *
 * \param impl matrix impl
 * \param required the minimum capacity needed
 * \return true on success, false on allocation failure
 */
static bool rz_graph_matrix_impl_require_capacity(RzGraphMatrixImpl *impl, ut64 required) {
	if (required <= impl->capacity) {
		return true;
	}
	ut64 new_cap = impl->capacity;
	while (new_cap < required) {
		new_cap *= 2;
	}

	RzGraphEdge **new_matrix = RZ_NEWS0(RzGraphEdge *, new_cap * new_cap);
	if (!new_matrix) {
		RZ_LOG_WARN("Failed to adjust matrix capacity to %" PFMT64u, new_cap);
		return false;
	}

	// move old to new matrix
	for (ut32 r = 0; r < impl->capacity; ++r) {
		for (ut32 c = 0; c < impl->capacity; ++c) {
			new_matrix[r * new_cap + c] = impl->matrix[r * impl->capacity + c];
		}
	}

	free(impl->matrix);
	impl->matrix = new_matrix;
	impl->capacity = new_cap;
	return true;
}

/**
 * \brief Add a directed edge (from -> to) in the matrix implementation.
 *
 * Sets the matrix cell at [from._vec_id][to._vec_id]. Fails if the edge already exists.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \param user_data user data attached to the edge
 * \return true on success, false if edge already exists or on allocation failure
 */
static bool rz_graph_matrix_impl_add_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to, void *user_data) {
	rz_return_val_if_fail(g && from && to, false);
	RzGraphMatrixImpl *impl = (RzGraphMatrixImpl *)g->impl;
	RzGraphEdge **cell = matrix_cell(impl, from->_vec_id, to->_vec_id);
	if (*cell) {
		// already exist edge
		return false;
	}

	RzGraphEdge *e = edge_new(from, to, user_data);
	if (!e) {
		return false;
	}
	*cell = e;
	return true;
}

/**
 * \brief Delete a directed edge (from -> to) in the matrix implementation.
 *
 * Clears the matrix cell and frees edge user data via graph callback.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \return true on success, false if no such edge
 */
static bool rz_graph_matrix_impl_del_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to) {
	rz_return_val_if_fail(g && from && to, false);
	RzGraphMatrixImpl *impl = (RzGraphMatrixImpl *)g->impl;
	RzGraphEdge **cell = matrix_cell(impl, from->_vec_id, to->_vec_id);
	if (!*cell) {
		// no such edge
		return false;
	}

	// free user data
	if (g->edge_data_free && (*cell)->data) {
		g->edge_data_free((*cell)->data);
	}
	edge_free(*cell);
	*cell = NULL;
	return true;
}

/**
 * \brief Check if a directed edge (from -> to) exists in the matrix.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \return true if the edge exists, false otherwise
 */
static bool rz_graph_matrix_has_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to) {
	rz_return_val_if_fail(g && from && to, false);
	RzGraphMatrixImpl *impl = g->impl;
	return *matrix_cell(impl, from->_vec_id, to->_vec_id) != NULL;
}

/**
 * \brief Find and return the edge (from -> to) in the matrix.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \return the edge if found, or NULL
 */
static RzGraphEdge *rz_graph_matrix_find_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to) {
	rz_return_val_if_fail(g && from && to, NULL);
	RzGraphMatrixImpl *impl = g->impl;
	return *matrix_cell(impl, from->_vec_id, to->_vec_id);
}

typedef struct {
	RZ_BORROW const RzGraph /*<NodeType *, EdgeType *>*/ *g;
	ut64 node_vid;
	ut32 cur;
	bool scan_out; // true to scan out edge or in edge
} RzGraphMatrixIterState;

/**
 * \brief Iterator next callback for matrix edge iteration.
 *
 * Scans the matrix row (out-edges) or column (in-edges) for the given
 * node, skipping deleted (NULL) nodes.
 *
 * \param it the iterator
 * \return next RzGraphEdgeNew* or NULL when exhausted
 */
static void *matrix_edge_iter_next(RzIterator *it) {
	RzGraphMatrixIterState *state = (RzGraphMatrixIterState *)it->u;
	ut64 n = rz_pvector_len(state->g->node_vec);

	while (state->cur < n) {
		ut64 cur = state->cur;
		// check if be deleted, should skip deleted holes
		RzGraphNode *candidate_node = rz_pvector_at(state->g->node_vec, cur);
		if (!candidate_node) {
			state->cur += 1;
			continue;
		}

		RzGraphEdge *e;
		if (state->scan_out) {
			e = *matrix_cell((RzGraphMatrixImpl *)state->g->impl, state->node_vid, cur);
		} else {
			e = *matrix_cell((RzGraphMatrixImpl *)state->g->impl, cur, state->node_vid);
		}

		if (e) {
			state->cur += 1;
			return e;
		}

		state->cur += 1;
	}

	return NULL;
}

/**
 * \brief Create a matrix edge iterator for a given node.
 *
 * Wraps the matrix scan logic into an RzIterator. The iterator scans
 * either a row (out-edges) or a column (in-edges) of the matrix.
 *
 * \param g graph (borrowed)
 * \param node_vid vec id of the node
 * \param scan_out true for outgoing edges, false for incoming edges
 * \return A new RzIterator, or NULL on failure
 */
static RzIterator *matrix_edge_as_iter(const RzGraph /*<NodeType *, EdgeType *>*/ *g, ut64 node_vid, bool scan_out) {
	RzGraphMatrixIterState *state = RZ_NEW0(RzGraphMatrixIterState);
	if (!state) {
		return NULL;
	}
	state->g = g;
	state->node_vid = node_vid;
	state->cur = 0;
	state->scan_out = scan_out;

	RzIterator *iter = rz_iterator_new(
		(rz_iterator_next_cb)matrix_edge_iter_next,
		NULL,
		free,
		state);
	return iter;
}

/**
 * \brief Get an iterator over all incoming edges of \p node (matrix impl).
 *
 * \param g graph
 * \param node the node whose in-edges to iterate
 * \return A new edge iterator, or NULL if node is NULL
 */
static RzIterator *rz_graph_matrix_impl_get_in_edges(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	if (!node) {
		return NULL;
	}
	return matrix_edge_as_iter(g, node->_vec_id, false);
}

/**
 * \brief Get an iterator over all outgoing edges of \p node (matrix impl).
 *
 * \param g graph
 * \param node the node whose out-edges to iterate
 * \return A new edge iterator, or NULL if node is NULL
 */
static RzIterator *rz_graph_matrix_impl_get_out_edges(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	if (!node) {
		return NULL;
	}
	return matrix_edge_as_iter(g, node->_vec_id, true);
}

/**
 * \brief Add a node to the matrix implementation.
 *
 * Ensures the matrix has enough capacity to hold the new node's vec id.
 * May trigger a matrix resize.
 *
 * \param g graph
 * \param node node to add
 * \return true on success, false if capacity growth fails
 */
static bool rz_graph_matrix_impl_add_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	rz_return_val_if_fail(g && node, false);
	RzGraphMatrixImpl *impl = g->impl;
	if (!rz_graph_matrix_impl_require_capacity(impl, node->_vec_id + 1)) {
		return false;
	}
	return true;
}

/**
 * \brief Delete a node from the matrix, clearing all associated edges.
 *
 * Zeroes out the entire row (out-edges) and column (in-edges) for \p node,
 * freeing edge user data and edge structs along the way.
 *
 * \param g graph
 * \param node node to delete
 * \return true on success, false on failure
 */
static bool rz_graph_matrix_impl_del_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	rz_return_val_if_fail(g && node, false);
	RzGraphMatrixImpl *impl = g->impl;
	ut64 vec_id = node->_vec_id;
	ut64 n = rz_pvector_len(g->node_vec);

	// remove all related out edges -> matrix[vec_id][j]
	for (ut64 c = 0; c < n; ++c) {
		RzGraphEdge **cell = matrix_cell(impl, vec_id, c);
		if (*cell) {
			if (g->edge_data_free && (*cell)->data) {
				g->edge_data_free((*cell)->data);
			}
			edge_free(*cell);
			*cell = NULL;
			g->n_edges -= 1;
		}
	}

	// remove all related in edges -> matrix[i][vec_id]
	for (ut64 r = 0; r < n; ++r) {
		RzGraphEdge **cell = matrix_cell(impl, r, vec_id);
		if (*cell) {
			if (g->edge_data_free && (*cell)->data) {
				g->edge_data_free((*cell)->data);
			}
			edge_free(*cell);
			*cell = NULL;
			g->n_edges -= 1;
		}
	}
	return true;
}

/**
 * \brief Finalize and free the adjacency matrix implementation.
 *
 * Frees all remaining edge structs in the matrix, then the matrix array
 * and the impl struct itself.
 *
 * \param impl the matrix impl to finalize
 */
static void rz_matrix_fini(void *impl) {
	if (!impl) {
		return;
	}
	RzGraphMatrixImpl *matrix_impl = (RzGraphMatrixImpl *)impl;
	for (ut64 i = 0; i < matrix_impl->capacity * matrix_impl->capacity; ++i) {
		if (matrix_impl->matrix[i]) {
			free(matrix_impl->matrix[i]);
			matrix_impl->matrix[i] = NULL;
		}
	}
	free(matrix_impl->matrix);
	free(matrix_impl);
}

/**
 * \brief Initialize a new adjacency matrix graph implementation.
 *
 * Allocates the matrix with the given \p capacity. Falls back to
 * MATRIX_DEFAULT_CAPACITY if capacity is 0.
 *
 * \param capacity initial matrix dimension (number of nodes)
 * \return A new RzGraphMatrixImpl, or NULL on failure
 */
static RzGraphMatrixImpl *rz_graph_matrix_impl_init(ut64 capacity) {
	RzGraphMatrixImpl *impl = RZ_NEW0(RzGraphMatrixImpl);
	if (!impl) {
		return NULL;
	}
	impl->capacity = capacity ? capacity : MATRIX_DEFAULT_CAPACITY;
	impl->matrix = RZ_NEWS0(RzGraphEdge *, impl->capacity * impl->capacity);
	if (!impl->matrix) {
		RZ_LOG_WARN("Failed to init graph matrix with capacity %" PFMT64u, impl->capacity)
		rz_matrix_fini(impl);
		return NULL;
	}
	return impl;
}

/* register operation */
static const RzGraphImplOps list_impl_ops = {
	.add_edge = rz_graph_list_impl_add_edge,
	.del_edge = rz_graph_list_impl_del_edge,
	.has_edge = rz_graph_list_impl_has_edge,
	.find_edge = rz_graph_list_impl_find_edge,
	.get_out_edges = rz_graph_list_impl_get_out_edges,
	.get_in_edges = rz_graph_list_impl_get_in_edges,
	.add_node = rz_graph_list_impl_add_node,
	.del_node = rz_graph_list_impl_del_node,
	.fini = rz_graph_list_impl_fini
};

static const RzGraphImplOps matrix_impl_ops = {
	.add_edge = rz_graph_matrix_impl_add_edge,
	.del_edge = rz_graph_matrix_impl_del_edge,
	.has_edge = rz_graph_matrix_has_edge,
	.find_edge = rz_graph_matrix_find_edge,
	.get_out_edges = rz_graph_matrix_impl_get_out_edges,
	.get_in_edges = rz_graph_matrix_impl_get_in_edges,
	.add_node = rz_graph_matrix_impl_add_node,
	.del_node = rz_graph_matrix_impl_del_node,
	.fini = rz_matrix_fini
};

/* RZ_API Graph Operations */

/**
 * \brief Default hash function for node identifiers.
 *
 * Simply casts the pointer to ut64 as the hash value.
 *
 * \param identifier the node identifier
 * \return hash value
 */
static ut64 rz_graph_node_default_hash(const void *identifier) {
	return (ut64)(uintptr_t)identifier;
}

/**
 * \brief Returns the number nodes the graph has.
 */
RZ_API ut64 rz_graph_get_n_nodes(RZ_NONNULL const RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	rz_return_val_if_fail(g, 0);
	return g->n_nodes;
}

/**
 * \brief Returns the number edges the graph has.
 */
RZ_API ut64 rz_graph_get_n_edges(RZ_NONNULL const RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	rz_return_val_if_fail(g, 0);
	return g->n_edges;
}

/**
 * \brief Returns the implementation type of the graph. Or INT_MAX in case of failure.
 */
RZ_API RzGraphImplType rz_graph_get_impl_type(RZ_NONNULL const RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	rz_return_val_if_fail(g, INT_MAX);
	return g->impl_type;
}

/**
 * \brief Get the data pointer of the node.
 */
RZ_API const void *rz_graph_node_get_data(RZ_NONNULL const RzGraphNode *node) {
	rz_return_val_if_fail(node, NULL);
	return node->data;
}

/**
 * \brief Get the mutable data pointer of the node.
 */
RZ_API RZ_BORROW void *rz_graph_node_get_data_mut(RZ_NONNULL RZ_BORROW RzGraphNode *node) {
	rz_return_val_if_fail(node, NULL);
	return node->data;
}

/**
 * \brief Set the data pointer of the edge.
 */
RZ_API void rz_graph_edge_set_data(RZ_NONNULL RZ_BORROW RzGraphEdge *edge, RZ_NULLABLE RZ_OWN void *data) {
	rz_return_if_fail(edge);
	edge->data = data;
}

/**
 * \brief Get the data pointer of the edge.
 */
RZ_API const void *rz_graph_edge_get_data(RZ_NONNULL const RzGraphEdge *edge) {
	rz_return_val_if_fail(edge, NULL);
	return edge->data;
}

/**
 * \brief Get the mutable data pointer of the edge.
 */
RZ_API RZ_BORROW void *rz_graph_edge_get_data_mut(RZ_NONNULL RZ_BORROW RzGraphEdge *edge) {
	rz_return_val_if_fail(edge, NULL);
	return edge->data;
}

RZ_API const RzGraphNode *rz_graph_edge_get_from(RZ_NONNULL const RzGraphEdge *edge) {
	rz_return_val_if_fail(edge, NULL);
	return edge->from;
}

RZ_API const RzGraphNode *rz_graph_edge_get_to(RZ_NONNULL const RzGraphEdge *edge) {
	rz_return_val_if_fail(edge, NULL);
	return edge->to;
}

/**
 * \brief Create a new RzGraphNew with the specified implementation type.
 *
 * Initializes a graph with either an adjacency list or adjacency matrix
 * backend. Sets up the node hash table, node vector, and dispatches
 * to the appropriate impl initializer.
 *
 * \param impl_type RZ_GRAPH_IMPL_LIST or RZ_GRAPH_IMPL_MATRIX
 * \param user_hash optional custom hash function for node identifiers, use default hash if NULL
 * \param node_free callback to free node user data, or NULL
 * \param edge_free callback to free edge user data, or NULL
 * \return A new RzGraphNew, or NULL on failure
 */
RZ_API RZ_OWN RzGraph /*<NodeType *, EdgeType *>*/ *rz_graph_new(RzGraphImplType impl_type, RZ_NULLABLE RzGraphIdentifierHash user_hash, RzGraphNodeDataFree node_free, RzGraphEdgeDataFree edge_free) {
	RzGraph /*<NodeType *, EdgeType *>*/ *g = RZ_NEW0(RzGraph);
	if (!g) {
		return NULL;
	}

	// unable to wrap node_data_free as node_free here
	// free by iterates g->node_vec
	g->nodes = ht_up_new(NULL, NULL);
	if (!g->nodes) {
		free(g);
		return NULL;
	}

	// reference of g->nodes, but ordered
	g->node_vec = rz_pvector_new(NULL);
	if (!g->node_vec) {
		ht_up_free(g->nodes);
		free(g);
		return NULL;
	}

	// use default hash if hash is NULL
	if (!user_hash) {
		user_hash = rz_graph_node_default_hash;
	}

	g->hash_func = user_hash;
	g->node_data_free = node_free;
	g->edge_data_free = edge_free;
	g->impl_type = impl_type;

	switch (impl_type) {
	case RZ_GRAPH_IMPL_LIST: {
		RzGraphListImpl *impl = rz_graph_list_impl_init();
		if (!impl) {
			goto fail_clean;
		}

		g->impl_ops = &list_impl_ops;
		g->impl = impl;
		return g;
	}
	case RZ_GRAPH_IMPL_MATRIX: {
		RzGraphMatrixImpl *impl = rz_graph_matrix_impl_init(MATRIX_DEFAULT_CAPACITY);
		if (!impl) {
			goto fail_clean;
		}
		g->impl_ops = &matrix_impl_ops;
		g->impl = impl;
		return g;
	}
	default:
		goto fail_clean;
	}
fail_clean:
	rz_pvector_free(g->node_vec);
	ht_up_free(g->nodes);
	free(g);
	return NULL;
}

/**
 * \brief Free an RzGraphNew and all its contents.
 *
 * Finalizes the impl backend, frees all node user data via the registered
 * callback, and releases all internal containers.
 *
 * \param g graph to free, or NULL (no-op)
 */
RZ_API void rz_graph_free(RZ_NULLABLE RZ_OWN RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	if (!g) {
		return;
	}

	// free edge user data before destroying the impl
	if (g->edge_data_free && g->impl_ops && g->impl && g->node_vec) {
		void **nit;
		rz_pvector_foreach (g->node_vec, nit) {
			RzGraphNode *node = (RzGraphNode *)(*nit);
			if (!node) {
				continue;
			}
			RzIterator *edge_it = g->impl_ops->get_out_edges(g, node);
			if (!edge_it) {
				continue;
			}
			RzGraphEdge *e;
			rz_iterator_foreach(edge_it, e) {
				if (e->data) {
					g->edge_data_free(e->data);
					e->data = NULL;
				}
			}
			rz_iterator_free(edge_it);
		}
	}

	// cleaned inner impl data
	if (g->impl_ops && g->impl) {
		g->impl_ops->fini(g->impl);
	}

	// clean user data of all nodes
	if (g->nodes && g->node_vec) {
		void **it;
		rz_pvector_foreach (g->node_vec, it) {
			RzGraphNode *node = (RzGraphNode *)(*it);
			if (!node) {
				continue;
			}
			if (g->node_data_free && node->data) {
				g->node_data_free(node->data);
				node->data = NULL;
			}
			free(node);
			*it = NULL;
		}
	}

	// clean hash table container since all nodes data has been cleaned
	ht_up_free(g->nodes);
	g->nodes = NULL;

	// clean node_vec container
	if (g->node_vec) {
		rz_pvector_free(g->node_vec);
		g->node_vec = NULL;
	}

	free(g);
}

/**
 * \brief Reset graph to an empty state, preserving its configuration.
 *
 * Finalizes the current impl, frees all nodes and edges, then
 * re-initializes the impl backend with a fresh state.
 *
 * \param g graph to reset
 */
RZ_API void rz_graph_reset(RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	rz_return_if_fail(g);

	// free edge user data before destroying the impl
	if (g->edge_data_free && g->impl_ops && g->impl && g->node_vec) {
		void **nit;
		rz_pvector_foreach (g->node_vec, nit) {
			RzGraphNode *node = (RzGraphNode *)(*nit);
			if (!node) {
				continue;
			}
			RzIterator *edge_it = g->impl_ops->get_out_edges(g, node);
			if (!edge_it) {
				continue;
			}
			RzGraphEdge *e;
			rz_iterator_foreach(edge_it, e) {
				if (e->data) {
					g->edge_data_free(e->data);
					e->data = NULL;
				}
			}
			rz_iterator_free(edge_it);
		}
	}

	if (g->impl_ops && g->impl) {
		g->impl_ops->fini(g->impl);
		g->impl = NULL;
	}

	// free node and data
	void **it;

	// free nodes to fix leak
	rz_pvector_foreach (g->node_vec, it) {
		RzGraphNode *node = (RzGraphNode *)(*it);
		if (node) {
			if (g->node_data_free && node->data) {
				g->node_data_free(node->data);
			}
			free(node);
		}
	}

	// clean all nodes
	if (g->nodes) {
		ht_up_free(g->nodes);
		g->nodes = NULL;
	}

	// clean reference
	if (g->node_vec) {
		rz_pvector_free(g->node_vec);
		g->node_vec = NULL;
	}

	// re-init
	g->nodes = ht_up_new(NULL, NULL);
	g->n_nodes = 0;
	g->n_edges = 0;
	g->node_vec = rz_pvector_new(NULL);

	switch (g->impl_type) {
	case RZ_GRAPH_IMPL_LIST:
		g->impl = rz_graph_list_impl_init();
		if (!g->impl) {
			RZ_LOG_WARN("Failed to reset, clear data only");
			return;
		}
		break;
	case RZ_GRAPH_IMPL_MATRIX:
		g->impl = rz_graph_matrix_impl_init(MATRIX_DEFAULT_CAPACITY);
		if (!g->impl) {
			RZ_LOG_WARN("Failed to reset, clear data only");
			return;
		}
		break;
	default:
		RZ_LOG_WARN("Unknown graph impl type %d, failed to reset, clear data only", g->impl_type);
	}
}

static RzGraphNode *internal_add(RzGraph /*<NodeType *, EdgeType *>*/ *g, RZ_OWN void *node_data, ut64 hash_id) {
	RzGraphNode *node = RZ_NEW0(RzGraphNode);
	if (!node) {
		return NULL;
	}
	node->hash_id = hash_id;
	node->data = node_data;

	// insert node into hash table
	if (!ht_up_insert(g->nodes, hash_id, node)) {
		if (g->node_data_free && node->data) {
			g->node_data_free(node->data);
		}
		node->data = NULL;
		free(node);
		return NULL;
	}

	// push node reference into vec and update
	node->_vec_id = rz_pvector_len(g->node_vec);
	rz_pvector_push(g->node_vec, node);

	// dispatch to impl to maintain edge data structure if needed
	if (!g->impl_ops->add_node(g, node)) {
		// revert if failed
		rz_pvector_pop(g->node_vec);
		ht_up_delete(g->nodes, hash_id);
		free(node);
		return NULL;
	}

	// good
	g->n_nodes += 1;
	return node;
}

/**
 * \brief Add a node to, or get an existing one from the graph.
 *
 * Hashes the \p identifier and checks if a node with this has already exists.
 * If so, it returns it instead.
 * If it doesn't it creates the new node, inserts it and returns the pointer to it.
 *
 * \param g The graph.
 * \param node_data Data attached to the node. NULL is considered valid data!
 * \param identifier Used by the hash function to generate the node hash. If NULL, it'll use \p node_data as identifier
 * \return The previous or new node, or NULL in case of failure.
 */
RZ_API RZ_BORROW RzGraphNode *rz_graph_add_get_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, RZ_NULLABLE RZ_OWN void *node_data, const void *identifier) {
	rz_return_val_if_fail(g, NULL);
	const void *id = identifier ? identifier : (const void *)node_data;

	ut64 hash_id = g->hash_func(id);

	RzGraphNode *node = ht_up_find(g->nodes, hash_id, NULL);
	if (node) {
		return node;
	}
	return internal_add(g, node_data, hash_id);
}

/**
 * \brief Add a new node with user data to the graph.
 *
 * Hashes the \p identifier to create a unique node id, inserts it into the graph.
 * Fails if a node with the same hash already exists.
 *
 * \param g The graph.
 * \param node_data Data attached to the node. NULL is considered valid data!
 * \param identifier Used by the hash function to generate the node hash. If NULL, it'll use \p node_data as identifier
 * \return The newly created node, or NULL on failure
 */
RZ_API RZ_BORROW RzGraphNode *rz_graph_add_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, RZ_NULLABLE RZ_OWN void *node_data, const void *identifier) {
	rz_return_val_if_fail(g, NULL);
	const void *id = identifier ? identifier : (const void *)node_data;

	ut64 hash_id = g->hash_func(id);

	if (ht_up_find(g->nodes, hash_id, NULL)) {
		RZ_LOG_WARN("Node already exist, return NULL\n");
		return NULL;
	}
	return internal_add(g, node_data, hash_id);
}

/**
 * \brief Delete a node from the graph, removing all associated edges.
 *
 * Dispatches to the impl backend to clean up edges, then removes the
 * node from the hash table and node vector, and frees node user data.
 *
 * \param g graph
 * \param node node to delete (ownership transferred)
 * \return true on success, false if node not found or impl fails
 */
RZ_API bool rz_graph_del_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, RZ_OWN RzGraphNode *node) {
	rz_return_val_if_fail(g && node, false);
	bool found = false;
	ht_up_find(g->nodes, node->hash_id, &found);
	if (!found) {
		RZ_LOG_WARN("Node not exist, failed to delete");
		return false;
	}

	// dispatch to impl to maintain edge data struct if needed
	if (!g->impl_ops->del_node(g, node)) {
		RZ_LOG_WARN("Impl failed to delete node, failed to delete");
		return false;
	}

	// remove from hash table
	ht_up_delete(g->nodes, node->hash_id);

	// set node reference as NULL
	rz_pvector_set(g->node_vec, node->_vec_id, NULL);

	// clean user data
	if (g->node_data_free && node->data) {
		g->node_data_free(node->data);
		node->data = NULL;
	}
	free(node);

	g->n_nodes -= 1;
	return true;
}

/**
 * \brief Find a node in the graph by its identifier.
 *
 * Hashes the \p identifier and looks up the node in the hash table.
 *
 * \param g graph
 * \param identifier the identifier to search for
 * \return the node if found (borrowed), or NULL
 */
RZ_API RZ_BORROW RzGraphNode *rz_graph_find_node(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *identifier) {
	rz_return_val_if_fail(g && g->hash_func && identifier, NULL);
	ut64 hash_id = g->hash_func(identifier);
	return ht_up_find(g->nodes, hash_id, NULL);
}

/**
 * \brief Add a directed edge between two nodes.
 *
 * Dispatches to the impl backend to create the edge.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \param user_data user data attached to the edge
 * \return true on success, false if edge already exists or on failure
 */
RZ_API bool rz_graph_add_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to, void *user_data) {
	rz_return_val_if_fail(g && from && to, false);
	if (!g->impl_ops->add_edge(g, from, to, user_data)) {
		return false;
	}
	g->n_edges += 1;
	return true;
}

/**
 * \brief Delete a directed edge between two nodes.
 *
 * Dispatches to the impl backend to remove the edge and free its data.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \param user_data unused
 * \return true on success, false if edge not found
 */
RZ_API bool rz_graph_del_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to, RZ_NULLABLE void *user_data) {
	rz_return_val_if_fail(g && from && to, false);
	if (!g->impl_ops->del_edge(g, from, to)) {
		return false;
	}
	g->n_edges -= 1;
	return true;
}

/**
 * \brief Check if a directed edge exists between two nodes.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \param user_data unused
 * \return true if the edge exists, false otherwise
 */
RZ_API bool rz_graph_has_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to, RZ_NULLABLE void *user_data) {
	rz_return_val_if_fail(g && from && to, false);
	return g->impl_ops->has_edge(g, from, to);
}

/**
 * \brief Find and return the edge between two nodes.
 *
 * \param g graph
 * \param from source node
 * \param to destination node
 * \return the edge if found (borrowed), or NULL
 */
RZ_API RZ_BORROW RzGraphEdge *rz_graph_find_edge(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *from, RzGraphNode *to) {
	rz_return_val_if_fail(g && from && to, NULL);
	return g->impl_ops->find_edge(g, from, to);
}

/**
 * \brief Get an iterator over all nodes in the graph.
 *
 * The iterator walks the node_vec in insertion order. Caller owns
 * the returned iterator and must free it after use.
 *
 * \param g graph
 * \return A new node iterator, or NULL on failure
 */
RZ_API RZ_OWN RzIterator *rz_graph_get_nodes(const RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	rz_return_val_if_fail(g, NULL);
	RzIterator *iter = pvector_as_iter(g->node_vec);
	return iter;
}

/**
 * \brief Return the number of nodes in the graph.
 *
 * \param g graph
 * \return node count
 */
RZ_API ut64 rz_graph_count_nodes(const RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	rz_return_val_if_fail(g, 0);
	return g->n_nodes;
}

/**
 * \brief Return the number of edges in the graph.
 *
 * \param g graph
 * \return edge count
 */
RZ_API ut64 rz_graph_count_edges(const RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	rz_return_val_if_fail(g, 0);
	return g->n_edges;
}

typedef struct {
	RzIterator *edge_iter;
	bool use_from;
} RzNeighbourIterState;

/**
 * \brief Iterator next callback that extracts neighbour nodes from edges.
 *
 * Depending on \p use_from, returns either edge->from (for in-neighbours)
 * or edge->to (for out-neighbours).
 *
 * \param it the iterator
 * \return next neighbour node, or NULL when exhausted
 */
static void *neighbour_iter_next(RzIterator *it) {
	RzNeighbourIterState *state = (RzNeighbourIterState *)it->u;
	RzGraphEdge *edge = rz_iterator_next(state->edge_iter);
	if (!edge) {
		return NULL;
	}

	if (state->use_from) {
		return edge->from;
	} else {
		return edge->to;
	}
}

/**
 * \brief Free callback for neighbour iterator state.
 *
 * Frees the inner edge iterator and the state struct.
 *
 * \param user_data the RzNeighbourIterState to free
 */
static void neighbour_iter_free(void *user_data) {
	RzNeighbourIterState *state = (RzNeighbourIterState *)user_data;
	if (!state) {
		return;
	}
	rz_iterator_free(state->edge_iter);
	state->edge_iter = NULL;
	free(state);
}

/**
 * \brief Wrap an edge iterator as a neighbour node iterator.
 *
 * Takes ownership of \p edge_iter and produces an iterator that yields
 * neighbour nodes instead of edges.
 *
 * \param edge_iter the edge iterator to wrap (ownership transferred)
 * \param use_from if true, yield edge->from; otherwise yield edge->to
 * \return A new neighbour iterator, or NULL on failure
 */
static RZ_OWN RzIterator *as_neighbour_iter(RZ_OWN RzIterator *edge_iter, bool use_from) {
	rz_return_val_if_fail(edge_iter, NULL);
	RzNeighbourIterState *state = RZ_NEW0(RzNeighbourIterState);
	if (!state) {
		return NULL;
	}
	state->edge_iter = edge_iter;
	state->use_from = use_from;

	RzIterator *iter = rz_iterator_new(
		neighbour_iter_next,
		NULL,
		neighbour_iter_free,
		state);
	return iter;
}

/**
 * \brief Get an iterator over all outgoing neighbour nodes of \p n.
 *
 * \param g graph
 * \param n the node
 * \return A new neighbour iterator owned by caller, or NULL
 */
RZ_API RZ_OWN RzIterator *rz_graph_out_neighbors(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *n) {
	rz_return_val_if_fail(g && n, NULL);
	RzIterator *edge_iter = g->impl_ops->get_out_edges(g, n);
	if (!edge_iter) {
		return NULL;
	}
	RzIterator *iter = as_neighbour_iter(edge_iter, false);
	if (!iter) {
		rz_iterator_free(edge_iter);
		return NULL;
	}
	return iter;
}

/**
 * \brief Get an iterator over all incoming neighbour nodes of \p n.
 *
 * \param g graph
 * \param n the node
 * \return A new neighbour iterator owned by caller, or NULL
 */
RZ_API RZ_OWN RzIterator *rz_graph_in_neighbors(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *n) {
	rz_return_val_if_fail(g && n, NULL);
	RzIterator *edge_iter = g->impl_ops->get_in_edges(g, n);
	if (!edge_iter) {
		return NULL;
	}
	RzIterator *iter = as_neighbour_iter(edge_iter, true);
	if (!iter) {
		rz_iterator_free(edge_iter);
		return NULL;
	}
	return iter;
}

/**
 * \brief Get the nth neighbour node of \p n.
 *
 * Iterates through out-edges or in-edges of \p n and returns the
 * neighbour at position \p nth (0-indexed).
 *
 * \param g graph
 * \param n the node
 * \param nth 0-based index of the desired neighbour
 * \param out_neighbor if true, get outgoing neighbours; otherwise incoming
 * \return the nth neighbour node, or NULL if not enough neighbours
 */
RZ_API RzGraphNode *rz_graph_nth_neighbour(const RzGraph /*<NodeType *, EdgeType *>*/ *g, const RzGraphNode *n, ut64 nth, bool out_neighbor) {
	rz_return_val_if_fail(g && n, NULL);
	RzIterator *edge_iter = out_neighbor ? g->impl_ops->get_out_edges((RzGraph /*<NodeType *, EdgeType *>*/ *)g, (RzGraphNode *)n) : g->impl_ops->get_in_edges((RzGraph /*<NodeType *, EdgeType *>*/ *)g, (RzGraphNode *)n);
	if (!edge_iter) {
		return NULL;
	}

	RzGraphEdge *edge;
	ut64 i = 0;
	while ((edge = rz_iterator_next(edge_iter)) != NULL) {
		if (i == nth) {
			rz_iterator_free(edge_iter);
			return out_neighbor ? edge->to : edge->from;
		}
		i += 1;
	}
	rz_iterator_free(edge_iter);
	return NULL;
}

/**
 * \brief Get an iterator over all outgoing edges of \p node.
 *
 * NOTE: edge iter is owned by caller, caller should free after use
 *
 * \param g graph
 * \param node node to get edges
 * \return A new edge iterator, caller should free after use, or NULL if no edge or error
 */
RZ_API RZ_OWN RzIterator *rz_graph_out_edges(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	rz_return_val_if_fail(g && node, NULL);
	return g->impl_ops->get_out_edges(g, node);
}

/**
 * \brief Get an iterator over all incoming edges of \p node.
 *
 * NOTE: edge iter is owned by caller, caller should free after use
 *
 * \param g graph
 * \param node node to get edges
 * \return A new edge iterator, caller should free after use, or NULL if no edge or error
 */
RZ_API RZ_OWN RzIterator *rz_graph_in_edges(RzGraph /*<NodeType *, EdgeType *>*/ *g, RzGraphNode *node) {
	rz_return_val_if_fail(g && node, NULL);
	return g->impl_ops->get_in_edges(g, node);
}

RZ_API ut64 rz_graph_out_degree(const RzGraph /*<NodeType *, EdgeType *>*/ *g, const RzGraphNode *node) {
	rz_return_val_if_fail(g && node, 0);
	ut32 count = 0;
	RzIterator *it = g->impl_ops->get_out_edges((RzGraph /*<NodeType *, EdgeType *>*/ *)g, (RzGraphNode *)node);
	if (it) {
		RzGraphEdge *e;
		rz_iterator_foreach(it, e) {
			count += 1;
		}
		rz_iterator_free(it);
	}
	return count;
}

RZ_API ut64 rz_graph_in_degree(const RzGraph /*<NodeType *, EdgeType *>*/ *g, const RzGraphNode *node) {
	rz_return_val_if_fail(g && node, 0);
	ut32 count = 0;
	RzIterator *it = g->impl_ops->get_in_edges((RzGraph /*<NodeType *, EdgeType *>*/ *)g, (RzGraphNode *)node);
	if (it) {
		RzGraphEdge *e;
		rz_iterator_foreach(it, e) {
			count += 1;
		}
		rz_iterator_free(it);
	}
	return count;
}

RZ_API RzGraphNode *rz_graph_find_node_by_hashid(RzGraph /*<NodeType *, EdgeType *>*/ *g, ut64 hash_id) {
	rz_return_val_if_fail(g, NULL);

	bool found;
	RzGraphNode *node = ht_up_find(g->nodes, hash_id, &found);
	if (found && node) {
		return node;
	}

	return NULL;
}

RZ_API ut64 rz_graph_node_get_id(RZ_NONNULL const RzGraphNode *node) {
	rz_return_val_if_fail(node, 0);
	return node->hash_id;
}

/**
 * \brief Returns the index of the node in the internal vector.
 *
 * DO NOT USE!
 *
 * It only exists for compatibility reasons and because refactoring is
 * more effort than currently acceptable.
 *
 * Justification:
 * The old implementations had exactly two identifiers for nodes.
 * The pointer to the node itself, or its index into the internal list storing it.
 * I skip the part how what a not good design decision this was.
 * But in the new graph this data is considered private (index into lists/hash table)
 * or are not expected by the graph user to be tracked (the individual node pointers).
 *
 * Sadly the json output of the graph still uses the vector indices as "ids".
 * We can't replace them with the actual hash_id of a node. Because most graphs don't implement a hash function.
 * For these cases the pointer is used internally as node hash.
 * And printing it in json output would not be stable.
 * Hence this hack.
 */
RZ_DEPRECATE RZ_API ut64 rz_graph_node_get_vec_id(RZ_NONNULL const RzGraphNode *node) {
	rz_return_val_if_fail(node, 0);
	return node->_vec_id;
}

/**
 * \brief Returns the internal node vector of the graph.
 *
 * DO NOT USE!
 *
 * It only exists for compatibility reasons and because refactoring is
 * more effort than currently acceptable.
 */
RZ_DEPRECATE RZ_API const RzPVector /*<RzGraphNode *>*/ *rz_graph_get_node_vec(RZ_NONNULL const RzGraph /*<NodeType *, EdgeType *>*/ *g) {
	rz_return_val_if_fail(g, NULL);
	return g->node_vec;
}

RZ_API bool rz_graph_del_node_by_id(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *identifier) {
	rz_return_val_if_fail(g && identifier, false);
	RzGraphNode *node = rz_graph_find_node(g, identifier);
	if (!node) {
		return false;
	}
	return rz_graph_del_node(g, node);
}

RZ_API bool rz_graph_add_edge_by_id(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *from_id, const void *to_id, void *user_data) {
	rz_return_val_if_fail(g && from_id && to_id, false);
	RzGraphNode *from = rz_graph_find_node(g, from_id);
	RzGraphNode *to = rz_graph_find_node(g, to_id);
	if (!from || !to) {
		return false;
	}
	return rz_graph_add_edge(g, from, to, user_data);
}

RZ_API bool rz_graph_del_edge_by_id(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *from_id, const void *to_id, RZ_NULLABLE void *user_data) {
	rz_return_val_if_fail(g && from_id && to_id, false);
	RzGraphNode *from = rz_graph_find_node(g, from_id);
	RzGraphNode *to = rz_graph_find_node(g, to_id);
	if (!from || !to) {
		return false;
	}
	return rz_graph_del_edge(g, from, to, user_data);
}

RZ_API bool rz_graph_has_edge_by_id(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *from_id, const void *to_id, RZ_NULLABLE void *user_data) {
	rz_return_val_if_fail(g && from_id && to_id, false);
	RzGraphNode *from = rz_graph_find_node(g, from_id);
	RzGraphNode *to = rz_graph_find_node(g, to_id);
	if (!from || !to) {
		return false;
	}
	return rz_graph_has_edge(g, from, to, user_data);
}

RZ_API RZ_NULLABLE RZ_BORROW RzGraphEdge *rz_graph_find_edge_by_id(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *from_id, const void *to_id) {
	rz_return_val_if_fail(g && from_id && to_id, NULL);
	RzGraphNode *from = rz_graph_find_node(g, from_id);
	RzGraphNode *to = rz_graph_find_node(g, to_id);
	if (!from || !to) {
		return NULL;
	}
	return rz_graph_find_edge(g, from, to);
}

RZ_API RZ_OWN RzIterator *rz_graph_out_edges_by_id(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *identifier) {
	rz_return_val_if_fail(g && identifier, NULL);
	RzGraphNode *node = rz_graph_find_node(g, identifier);
	if (!node) {
		return NULL;
	}
	return rz_graph_out_edges(g, node);
}

RZ_API RZ_OWN RzIterator *rz_graph_in_edges_by_id(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *identifier) {
	rz_return_val_if_fail(g && identifier, NULL);
	RzGraphNode *node = rz_graph_find_node(g, identifier);
	if (!node) {
		return NULL;
	}
	return rz_graph_in_edges(g, node);
}

RZ_API RZ_OWN RzIterator *rz_graph_out_neighbors_by_id(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *identifier) {
	rz_return_val_if_fail(g && identifier, NULL);
	RzGraphNode *node = rz_graph_find_node(g, identifier);
	if (!node) {
		return NULL;
	}
	return rz_graph_out_neighbors(g, node);
}

RZ_API RZ_OWN RzIterator *rz_graph_in_neighbors_by_id(RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *identifier) {
	rz_return_val_if_fail(g && identifier, NULL);
	RzGraphNode *node = rz_graph_find_node(g, identifier);
	if (!node) {
		return NULL;
	}
	return rz_graph_in_neighbors(g, node);
}

RZ_API ut64 rz_graph_out_degree_by_id(const RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *identifier) {
	rz_return_val_if_fail(g && identifier, 0);
	RzGraphNode *node = rz_graph_find_node((RzGraph /*<NodeType *, EdgeType *>*/ *)g, identifier);
	if (!node) {
		return 0;
	}
	return rz_graph_out_degree(g, node);
}

RZ_API ut64 rz_graph_in_degree_by_id(const RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *identifier) {
	rz_return_val_if_fail(g && identifier, 0);
	RzGraphNode *node = rz_graph_find_node((RzGraph /*<NodeType *, EdgeType *>*/ *)g, identifier);
	if (!node) {
		return 0;
	}
	return rz_graph_in_degree(g, node);
}

RZ_API RZ_NULLABLE RZ_BORROW RzGraphNode *rz_graph_nth_neighbour_by_id(const RzGraph /*<NodeType *, EdgeType *>*/ *g, const void *identifier, ut64 nth, bool out_neighbor) {
	rz_return_val_if_fail(g && identifier, NULL);
	RzGraphNode *node = rz_graph_find_node((RzGraph /*<NodeType *, EdgeType *>*/ *)g, identifier);
	if (!node) {
		return NULL;
	}
	return rz_graph_nth_neighbour(g, node, nth, out_neighbor);
}
