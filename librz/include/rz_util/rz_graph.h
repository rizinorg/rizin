#ifndef RZ_GRAPH_H
#define RZ_GRAPH_H

#include <rz_list.h>
#include <rz_vector.h>
#include <rz_util/ht_up.h>
#include <rz_util/rz_iterator.h>

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

struct rz_graph_node_t_new {
	ut64 hash_id;
	ut64 _vec_id; // for matrix graph and DFS, by building hash_id <-> vec_id map
	void *data;
};

// wrapper for edge in list-based graph
struct rz_graph_edge_t_new {
	RZ_BORROW RzGraphNode *from;
	RZ_BORROW RzGraphNode *to;
	void *data;
};

struct rz_graph_impl_ops_t {
	// For edges
	bool (*add_edge)(RzGraph *graph, RzGraphNode *from, RzGraphNode *to, void *user_data);
	bool (*del_edge)(RzGraph *graph, RzGraphNode *from, RzGraphNode *to);
	bool (*has_edge)(RzGraph *graph, RzGraphNode *from, RzGraphNode *to);

	// Extract edge from graph
	RZ_BORROW RzGraphEdge *(*find_edge)(RzGraph *g, RzGraphNode *from, RzGraphNode *to);

	// Return neighbors as iterator
	RZ_OWN RzIterator *(*get_out_edges)(RzGraph *graph, RzGraphNode *node);
	RZ_OWN RzIterator *(*get_in_edges)(RzGraph *graph, RzGraphNode *node);

	bool (*add_node)(RzGraph *graph, RzGraphNode *node);
	bool (*del_node)(RzGraph *graph, RzGraphNode *node);

	// free manager
	void (*fini)(void *impl);
};

struct rz_graph_t_new {
	ut64 n_nodes;
	ut64 n_edges;

	HtUP *nodes; // <hash_id, RzGraphNode>
	RzPVector *node_vec; // <vec_id, RzGraphNode> for DFS
	const RzGraphImplOps *impl_ops; // graph implementation ops
	void *impl; // graph implementation specific data
	RzGraphImplType impl_type;

	// user defined fns
	RzGraphIdentifierHash hash_func; // hash function can be specified by user
	RzGraphNodeDataFree node_data_free;
	RzGraphEdgeDataFree edge_data_free;
};

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
RZ_API ut64 rz_graph_adapter_get_node_id(RzGraphNode *node);

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
#endif // RZ_GRAPH_H
