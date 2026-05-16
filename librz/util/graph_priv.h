// SPDX-FileCopyrightText: 2025-2026 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef GRAPH_PRIV_H
#define GRAPH_PRIV_H

#include <rz_util/rz_graph.h>

struct rz_graph_node_t_new {
	/**
	 * \brief The unique ID of the node. Determined by hashing the node data.
	 */
	ut64 hash_id;
	/**
	 * \brief The offset into the RzGraph->node_vec.
	 * This offset DOES NOT change after the node was created.
	 * It is always in the range of `[0, m)` where `m` is the maximum number of nodes
	 * the graph had at any given time.
	 * It can be used as index in implementation specific arrays.
	 *
	 * Also used in DFS and for building the hash_id <-> vec_id map.
	 */
	ut64 _vec_id;
	/**
	 * \brief The node data pointer.
	 */
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
	/**
	 * \brief Number of nodes in the graph.
	 * ATTENTION: Never use this for iteration over rz_graph_t_new.node_vec!
	 * Always use rz_pvector_len(node_vec).
	 */
	ut64 n_nodes;
	ut64 n_edges;

	/**
	 * \brief Hash id to node pointer map.
	 * The node pointers are owned by node_vec not this map.
	 */
	HtUP /*<hash_id, RzGraphNode *>*/ *nodes;
	/**
	 * \brief Unused offsets into node_vec. Offsets get unused
	 * because a node was deleted at that offset before.
	 * On node deletion it will push the freed _vec_id to the tail.
	 * On node creation it will check the head of the vector and, if there is any,
	 * use that id for the new node.
	 * If free_vec_ids is empty, it pushes to the tail of node_vec.
	 */
	RzVector /*<size_t>*/ *free_vec_ids;
	/**
	 * \brief The vector of all graph nodes. Indexed by RzGraphNode->_vec_id.
	 * It might contain NULL at offsets where a node was deleted.
	 */
	RzPVector /*<RzGraphNode *>*/ *node_vec;
	const RzGraphImplOps *impl_ops; // graph implementation ops
	void *impl; // graph implementation specific data
	RzGraphImplType impl_type;

	// user defined fns
	RzGraphIdentifierHash hash_func; // hash function can be specified by user
	RzGraphNodeDataFree node_data_free;
	RzGraphEdgeDataFree edge_data_free;
};

#endif // GRAPH_PRIV_H
