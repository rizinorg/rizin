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

/**
 * \brief Represents a node in a graph, node should be hashable.
 * and support both list-based graph and matrix-based graph.
 */
typedef struct rz_graph_t_new RzGraph;
typedef struct rz_graph_node_t_new RzGraphNode;
typedef struct rz_graph_edge_t_new RzGraphEdge;
typedef struct rz_graph_impl_ops_t RzGraphImplOps;

typedef ut64 (*RzGraphIdentifierHash)(const void *data);
typedef void (*RzGraphNodeDataFree)(void *data);
typedef void (*RzGraphEdgeDataFree)(void *data);

typedef enum {
	RZ_GRAPH_IMPL_LIST,
	RZ_GRAPH_IMPL_MATRIX
} RzGraphImplType;

// Graph
RZ_API RZ_OWN RzGraph *rz_graph_new(RzGraphImplType impl_type, RZ_NULLABLE RzGraphIdentifierHash user_hash, RzGraphNodeDataFree node_free, RzGraphEdgeDataFree edge_free);
RZ_API void rz_graph_free(RzGraph *g);
RZ_API void rz_graph_reset(RzGraph *g);

// Nodes
RZ_API RZ_BORROW RzGraphNode *rz_graph_add_node(RzGraph *g, void *user_data, const void *identifier);
RZ_API bool rz_graph_del_node(RzGraph *g, RZ_OWN RzGraphNode *node);
RZ_API RZ_BORROW RzGraphNode *rz_graph_find_node(RzGraph *g, const void *identifier);

// Edges
RZ_API bool rz_graph_add_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to, void *user_data);
RZ_API bool rz_graph_del_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to, RZ_NULLABLE void *user_data);
RZ_API bool rz_graph_has_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to, RZ_NULLABLE void *user_data);
RZ_API RZ_BORROW RzGraphEdge *rz_graph_find_edge(RzGraph *g, RzGraphNode *from, RzGraphNode *to);

RZ_API RZ_OWN RzIterator *rz_graph_out_edges(RzGraph *g, RzGraphNode *node);
RZ_API RZ_OWN RzIterator *rz_graph_in_edges(RzGraph *g, RzGraphNode *node);
RZ_API RZ_OWN RzIterator *rz_graph_out_neighbors(RzGraph *g, RzGraphNode *n);
RZ_API RZ_OWN RzIterator *rz_graph_in_neighbors(RzGraph *g, RzGraphNode *n);

// utils
RZ_API ut64 rz_graph_count_nodes(const RzGraph *g);
RZ_API ut64 rz_graph_count_edges(const RzGraph *g);
RZ_API RZ_OWN RzIterator *rz_graph_get_nodes(const RzGraph *g);

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

// Node/edge lookup by raw hash_id (ut64)
RZ_API RzGraphNode *rz_graph_find_node_by_hashid(RzGraph *g, ut64 hash_id);

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
RZ_API bool rz_graph_del_node_by_id(RzGraph *g, const void *identifier);
RZ_API bool rz_graph_add_edge_by_id(RzGraph *g, const void *from_id, const void *to_id, void *user_data);
RZ_API bool rz_graph_del_edge_by_id(RzGraph *g, const void *from_id, const void *to_id, RZ_NULLABLE void *user_data);
RZ_API bool rz_graph_has_edge_by_id(RzGraph *g, const void *from_id, const void *to_id, RZ_NULLABLE void *user_data);
RZ_API RZ_NULLABLE RZ_BORROW RzGraphEdge *rz_graph_find_edge_by_id(RzGraph *g, const void *from_id, const void *to_id);
RZ_API RZ_OWN RzIterator *rz_graph_out_edges_by_id(RzGraph *g, const void *identifier);
RZ_API RZ_OWN RzIterator *rz_graph_in_edges_by_id(RzGraph *g, const void *identifier);
RZ_API RZ_OWN RzIterator *rz_graph_out_neighbors_by_id(RzGraph *g, const void *identifier);
RZ_API RZ_OWN RzIterator *rz_graph_in_neighbors_by_id(RzGraph *g, const void *identifier);
RZ_API ut64 rz_graph_out_degree_by_id(const RzGraph *g, const void *identifier);
RZ_API ut64 rz_graph_in_degree_by_id(const RzGraph *g, const void *identifier);
RZ_API RZ_NULLABLE RZ_BORROW RzGraphNode *rz_graph_nth_neighbour_by_id(const RzGraph *g, const void *identifier, ut64 nth, bool out_neighbor);

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
