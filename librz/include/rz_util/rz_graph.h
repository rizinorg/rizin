// SPDX-FileCopyrightText: 2025-2026 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_GRAPH_H
#define RZ_GRAPH_H

#include <rz_list.h>
#include <rz_vector.h>
#include <rz_util/ht_up.h>
#include <rz_util/rz_iterator.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_graph_t_new RzGraph;
typedef struct rz_graph_node_t_new RzGraphNode;
typedef struct rz_graph_edge_t_new RzGraphEdge;
typedef struct rz_graph_impl_ops_t RzGraphImplOps;

typedef ut64 (*RzGraphIdentifierHash)(RZ_NULLABLE const void *data);
typedef void (*RzGraphNodeDataFree)(void *data);
typedef void (*RzGraphEdgeDataFree)(void *data);
typedef bool (*RzGraphEdgeChooser)(const RzGraphEdge *data, void *cb_data);

/**
 * \brief Macro to cast an integer to a void pointer.
 * Useful for graphs which use integers as node data.
 */
#define RZ_GRAPH_INT_AS_DATA(n) ((void *)(utptr)(n))

/**
 * \brief The default capacity in number of nodes of the adjacency
 * matrix implementation.
 * NOTE: The current matrix implementation is really just an adjacency matrix
 * and has an exponential memory footprint.
 * This default capacity has already uses up to:
 * 256 * 256 * sizeof(RzGraphEdge *) bytes = 500 KiB
 */
#define RZ_GRAPH_MATRIX_DEFAULT_CAPACITY 256

typedef enum {
	RZ_GRAPH_IMPL_LIST,
	/**
	 * \brief A n x n adjacency matrix.
	 * Should only be used for known small graphs. Otherwise it can quickly
	 * lead to OOM events because its size is `O(n x n x sizeof(void *))`
	 *
	 * ATTENTION: This implementation is not thread-safe!
	 * If an element is added beyond its capacity, it will reallocate the matrix
	 * array and possibly invalidate currently in use pointers into it.
	 */
	RZ_GRAPH_IMPL_MATRIX
} RzGraphImplType;

typedef enum {
	RZ_GRAPH_STATUS_OK,
	RZ_GRAPH_STATUS_EXISTED,
	RZ_GRAPH_STATUS_MISSING_NODE,
	RZ_GRAPH_STATUS_MISSING_EDGE,
	RZ_GRAPH_STATUS_UPDATED,
	RZ_GRAPH_STATUS_NOT_UPDATED,
	RZ_GRAPH_STATUS_ERR,
} RzGraphStatus;

// Graph
RZ_API RZ_OWN RzGraph *rz_graph_new(RzGraphImplType impl_type, RZ_NULLABLE RzGraphIdentifierHash user_hash, RzGraphNodeDataFree node_free, RzGraphEdgeDataFree edge_free);
RZ_API void rz_graph_free(RzGraph *g);
RZ_API void rz_graph_reset(RzGraph *g);

// Nodes
RZ_API RzGraphStatus rz_graph_add_node(
	RzGraph /*<NodeType *, EdgeType *>*/ *g,
	RZ_NULLABLE RZ_OWN void *node_data,
	RZ_OUT RZ_NULLABLE RZ_BORROW RzGraphNode **node_ptr);
RZ_API RzGraphStatus rz_graph_del_node(RzGraph *g, RZ_OWN RzGraphNode *node);
RZ_API RZ_BORROW RzGraphNode *rz_graph_find_node(RzGraph *g, ut64 id);

// Edges
RZ_API RzGraphStatus rz_graph_add_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to, void *edge_data);
RZ_API RzGraphStatus rz_graph_update_edge(RZ_BORROW RzGraph *g, RZ_OWN RzGraphNode *from, RZ_OWN RzGraphNode *to, RZ_OWN void *edge_data, RZ_NULLABLE RzGraphEdgeChooser cb, void *cb_data);
RZ_API RzGraphStatus rz_graph_update_edge_by_id(RZ_NONNULL RZ_BORROW RzGraph *g, ut64 from_id, ut64 to_id, RZ_NULLABLE RZ_OWN void *edge_data, RZ_NULLABLE RzGraphEdgeChooser cb, void *cb_data);
RZ_API RzGraphStatus rz_graph_del_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to);
RZ_API RzGraphStatus rz_graph_del_edges(RZ_BORROW RzGraph *g, RZ_NULLABLE RzGraphEdgeChooser cb, void *cb_data);
RZ_API RzGraphStatus rz_graph_has_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to);
RZ_API RZ_BORROW RzGraphEdge *rz_graph_find_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to);

RZ_API RZ_OWN RzIterator *rz_graph_out_edges(RzGraph *g, RzGraphNode *node);
RZ_API RZ_OWN RzIterator *rz_graph_in_edges(RzGraph *g, RzGraphNode *node);
RZ_API RZ_OWN RzIterator *rz_graph_out_neighbors(RzGraph *g, RzGraphNode *n);
RZ_API RZ_OWN RzIterator *rz_graph_in_neighbors(RzGraph *g, RzGraphNode *n);

// utils
RZ_API ut64 rz_graph_count_nodes(const RzGraph *g);
RZ_API ut64 rz_graph_count_edges(const RzGraph *g);
RZ_API RZ_OWN RzIterator *rz_graph_get_nodes(const RzGraph *g);
RZ_API ut64 rz_graph_mem_usage(const RzGraph *g);

/**
 * Get a label for a dot graph edge.
 * Can return NULL if the default arrow should be used.
 * Otherwise it must return a string of the form: [<formatting options>]
 */
typedef RZ_OWN char *(*RzGraphEdgeFormatter)(const RzGraphEdge *e);
/**
 * Get a label for a dot graph node.
 * Can return NULL if the node's hash id should be used as label.
 * Otherwise it must return a string of the form: [<formatting options>]
 */
typedef RZ_OWN char *(*RzGraphNodeFormatter)(const RzGraphNode *n);

RZ_API RZ_OWN char *rz_graph_as_dot_str(const RzGraph *g,
	RZ_NULLABLE const char *name,
	RZ_NULLABLE RzGraphNodeFormatter node_formatter,
	RZ_NULLABLE RzGraphEdgeFormatter edge_formatter);

// DFS and visitor mode
typedef struct rz_graph_visitor_t_new RzGraphVisitor;
struct rz_graph_visitor_t_new {
	void (*discover_node)(RzGraphNode *n, RzGraphVisitor *vis);
	void (*finish_node)(RzGraphNode *n, RzGraphVisitor *vis);
	void (*tree_edge)(const RzGraphEdge *e, RzGraphVisitor *vis);
	void (*back_edge)(const RzGraphEdge *e, RzGraphVisitor *vis);
	void (*fcross_edge)(const RzGraphEdge *e, RzGraphVisitor *vis);
	void *visitor_data; ///< caller-owned context passed to node/edge callbacks
};

/**
 * Comparator for sorting outgoing edges before DFS traversal.
 * Used by rz_graph_find_back_edges to control which edges become back edges.
 * Follows the same sign convention as RzPVectorComparator.
 */
typedef int (*RzGraphEdgeCmp)(const RzGraphEdge *a, const RzGraphEdge *b, void *user);

RZ_API void rz_graph_dfs_from_node(RzGraph *g, RzGraphNode *start, RzGraphVisitor *visitor);
RZ_API void rz_graph_dfs_reverse_from_node(RzGraph *g, RzGraphNode *start, RzGraphVisitor *vis);
RZ_API void rz_graph_dfs(RzGraph *g, RzGraphVisitor *vis);
RZ_API void rz_graph_dfs_reverse(RzGraph *g, RzGraphVisitor *vis);

RZ_API RzGraphNode *rz_graph_nth_neighbour(const RzGraph *g, const RzGraphNode *n, ut64 nth, bool out_neighbor);
RZ_API ut64 rz_graph_out_degree(const RzGraph *g, const RzGraphNode *n);
RZ_API ut64 rz_graph_in_degree(const RzGraph *g, const RzGraphNode *n);

// Getters and setters
RZ_DEPRECATE RZ_API ut64 rz_graph_node_get_vec_id(RZ_NONNULL const RzGraphNode *node);
RZ_DEPRECATE RZ_API const RzPVector *rz_graph_get_node_vec(RZ_NONNULL const RzGraph *g);

RZ_API RzGraphImplType rz_graph_get_impl_type(RZ_NONNULL const RzGraph *g);
RZ_API ut64 rz_graph_get_n_nodes(RZ_NONNULL const RzGraph *g);
RZ_API ut64 rz_graph_get_n_edges(RZ_NONNULL const RzGraph *g);
RZ_API ut64 rz_graph_node_get_id(RZ_NONNULL const RzGraphNode *node);
RZ_API const void *rz_graph_node_get_data(RZ_NONNULL const RzGraphNode *node);
RZ_API RZ_BORROW void *rz_graph_node_get_data_mut(RZ_NONNULL RZ_BORROW RzGraphNode *node);
RZ_API void rz_graph_edge_set_data(RZ_NONNULL RZ_BORROW RzGraphEdge *edge, RZ_NULLABLE RZ_OWN void *data);
RZ_API const void *rz_graph_edge_get_data(RZ_NONNULL const RzGraphEdge *edge);
RZ_API RZ_BORROW void *rz_graph_edge_get_data_mut(RZ_NONNULL RZ_BORROW RzGraphEdge *edge);
RZ_API const RzGraphNode *rz_graph_edge_get_from(RZ_NONNULL const RzGraphEdge *edge);
RZ_API const RzGraphNode *rz_graph_edge_get_to(RZ_NONNULL const RzGraphEdge *edge);

// Node/edge operations by identifier object
RZ_API RzGraphStatus rz_graph_del_node_by_id(RzGraph *g, ut64 id);
RZ_API RzGraphStatus rz_graph_add_edge_by_id(RzGraph *g, ut64 from_id, ut64 to_id, RZ_OWN void *edge_data);
RZ_API RzGraphStatus rz_graph_del_edge_by_id(RzGraph *g, ut64 from_id, ut64 to_id);
RZ_API RzGraphStatus rz_graph_has_edge_by_id(RzGraph *g, ut64 from_id, ut64 to_id);
RZ_API RZ_NULLABLE RZ_BORROW RzGraphEdge *rz_graph_find_edge_by_id(RzGraph *g, ut64 from_id, ut64 to_id);
RZ_API RZ_OWN RzIterator *rz_graph_out_edges_by_id(RzGraph *g, ut64 id);
RZ_API RZ_OWN RzIterator *rz_graph_in_edges_by_id(RzGraph *g, ut64 id);
RZ_API RZ_OWN RzIterator *rz_graph_out_neighbors_by_id(RzGraph *g, ut64 id);
RZ_API RZ_OWN RzIterator *rz_graph_in_neighbors_by_id(RzGraph *g, ut64 id);
RZ_API ut64 rz_graph_out_degree_by_id(const RzGraph *g, ut64 id);
RZ_API ut64 rz_graph_in_degree_by_id(const RzGraph *g, ut64 id);
RZ_API RZ_NULLABLE RZ_BORROW RzGraphNode *rz_graph_nth_neighbour_by_id(const RzGraph *g, ut64 id, ut64 nth, bool out_neighbor);

// Graph algorithms
/**
 * Find back edges in a DFS traversal of \p g.
 * When \p cmp is non-NULL, outgoing edges of each node are sorted by \p cmp
 * before being pushed onto the DFS stack, controlling which edges are classified
 * as back edges (greedy feedback arc set selection).
 * Returns a list of borrowed RzGraphEdge pointers (owned by the graph).
 * Caller must free the list itself but must NOT free the elements.
 */
RZ_API RZ_OWN RzList /*<RzGraphEdge *>*/ *rz_graph_find_back_edges(RzGraph *g, RZ_NULLABLE RzGraphEdgeCmp cmp, void *user);

/**
 * Find all strongly connected components (SCCs) of \p g using Tarjan's algorithm.
 * Returns an owned RzPVector of owned RzPVector<RzGraphNode *> (borrowed nodes).
 * Each inner vector is one SCC; SCCs with a single node and no self-loop are trivial.
 * Caller must free the outer vector (and each inner vector); nodes are not freed.
 */
RZ_API RZ_OWN RzPVector /*<RzPVector<RzGraphNode *> *>*/ *rz_graph_find_sccs(RzGraph *g);

#ifdef __cplusplus
}
#endif

#endif // RZ_GRAPH_H
