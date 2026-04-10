// SPDX-FileCopyrightText: 2025-2026 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef GRAPH_PRIV_H
#define GRAPH_PRIV_H

#include <rz_util/rz_graph.h>

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
	bool (*del_edges)(RzGraph *graph, RzGraphEdgeChooser callback, void *cb_data);
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

	HtUP /*<hash_id, RzGraphNode *>*/ *nodes;
	RzPVector /*<RzGraphNode *>*/ *node_vec; // Indexed by vec_id for DFS
	const RzGraphImplOps *impl_ops; // graph implementation ops
	void *impl; // graph implementation specific data
	RzGraphImplType impl_type;

	// user defined fns
	RzGraphIdentifierHash hash_func; // hash function can be specified by user
	RzGraphNodeDataFree node_data_free;
	RzGraphEdgeDataFree edge_data_free;
};

#endif // GRAPH_PRIV_H
