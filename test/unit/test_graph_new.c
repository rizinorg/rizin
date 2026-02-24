// SPDX-FileCopyrightText: 2025-2026 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static ut64 simple_hash(const void *data) {
	return *(ut64 *)data;
}

static void topo_sorting(RzGraphNode *n, RzGraphVisitor *vis) {
	RzList *order = (RzList *)vis->data;
	rz_list_prepend(order, n->data);
}

static bool test_graph_basic(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);
	mu_assert_notnull(g, "graph creation");
	mu_assert_eq(rz_graph_count_nodes(g), 0, "n_nodes.start");
	mu_assert_eq(rz_graph_count_edges(g), 0, "n_edges.start");

	rz_graph_free(g);

	RzGraph *g2 = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);
	mu_assert_notnull(g2, "graph creation matrix");
	mu_assert_eq(rz_graph_count_nodes(g2), 0, "n_nodes.start.matrix");
	mu_assert_eq(rz_graph_count_edges(g2), 0, "n_edges.start.matrix");

	rz_graph_free(g2);
	mu_end;
}

// Test node addition and lookup
static bool test_graph_nodes(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);
	mu_assert_notnull(g, "graph creation");

	// Add nodes with integer data
	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	mu_assert_notnull(n1, "add_node.1");
	mu_assert_eq(rz_graph_count_nodes(g), 1, "n_nodes.1");
	mu_assert_ptreq(n1->data, (void *)1, "node_data.1");

	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	mu_assert_notnull(n2, "add_node.2");
	mu_assert_eq(rz_graph_count_nodes(g), 2, "n_nodes.2");

	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);
	mu_assert_notnull(n3, "add_node.3");
	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.3");

	RzGraphNode *found1 = rz_graph_find_node(g, (void *)BASE + 1);
	mu_assert_ptreq(found1, n1, "find_node.1");

	RzGraphNode *found2 = rz_graph_find_node(g, (void *)BASE + 2);
	mu_assert_ptreq(found2, n2, "find_node.2");

	RzGraphNode *found_null = rz_graph_find_node(g, (void *)BASE + 0x42);
	mu_assert_null(found_null, "find_node.nonexistent");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_edges(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	// Add edges
	bool success = rz_graph_add_edge(g, n1, n2, NULL);
	mu_assert_true(success, "add_edge.1->2");
	mu_assert_eq(rz_graph_count_edges(g), 1, "n_edges.1");

	success = rz_graph_add_edge(g, n1, n3, NULL);
	mu_assert_true(success, "add_edge.1->3");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.2");

	success = rz_graph_add_edge(g, n2, n3, NULL);
	mu_assert_true(success, "add_edge.2->3");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.3");

	// assert more edges
	bool has_edge = rz_graph_has_edge(g, n1, n2, NULL);
	mu_assert_true(has_edge, "has_edge.1->2");

	has_edge = rz_graph_has_edge(g, n2, n1, NULL);
	mu_assert_false(has_edge, "has_edge.2->1.false");

	has_edge = rz_graph_has_edge(g, n1, n3, NULL);
	mu_assert_true(has_edge, "has_edge.1->3");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_edge_deletion(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.initial");

	bool success = rz_graph_del_edge(g, n1, n2, NULL);
	mu_assert_true(success, "del_edge.1->2");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.after_del");

	bool has_edge = rz_graph_has_edge(g, n1, n2, NULL);
	mu_assert_false(has_edge, "has_edge.1->2.deleted");

	has_edge = rz_graph_has_edge(g, n2, n3, NULL);
	mu_assert_true(has_edge, "has_edge.2->3.exists");

	rz_graph_free(g);
	mu_end;
}

// Test out-edges iterator
static bool test_graph_in_out_edges(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);
	RzGraphNode *n4 = rz_graph_add_node(g, (void *)4, (void *)BASE + 4);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n1, n4, NULL);

	// out edges
	RzIterator *it = rz_graph_out_edges(g, n1);
	mu_assert_notnull(it, "out_edges_iterator");

	int count = 0;
	RzGraphEdge *edge;
	rz_iterator_foreach(it, edge) {
		mu_assert_ptreq(edge->from, n1, "out_edge.from");
		mu_assert_true(edge->to == n2 || edge->to == n3 || edge->to == n4, "out_edge.to");
		count++;
	}
	mu_assert_eq(count, 3, "out_edges.count");
	rz_iterator_free(it);

	// in edges
	rz_graph_add_edge(g, n2, n4, NULL);
	rz_graph_add_edge(g, n3, n4, NULL);
	it = rz_graph_in_edges(g, n4);
	mu_assert_notnull(it, "in_edges_iterator");

	count = 0;
	rz_iterator_foreach(it, edge) {
		mu_assert_ptreq(edge->to, n4, "in_edge.to");
		mu_assert_true(edge->from == n1 || edge->from == n2 || edge->from == n3, "in_edge.from");
		count++;
	}
	mu_assert_eq(count, 3, "in_edges.count");
	rz_iterator_free(it);

	// clean
	rz_graph_free(g);
	mu_end;
}

// Test out-neighbors iterator
static bool test_graph_in_out_neighbors(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);

	// n1 out neighbours
	RzIterator *it = rz_graph_out_neighbors(g, n1);
	mu_assert_notnull(it, "out_neighbors_iterator");

	int count = 0;
	RzGraphNode *neighbor;
	rz_iterator_foreach(it, neighbor) {
		mu_assert_true(neighbor == n2 || neighbor == n3, "out_neighbor");
		count++;
	}
	mu_assert_eq(count, 2, "out_neighbors.count");

	rz_iterator_free(it);

	// Get in neighbours
	rz_graph_add_edge(g, n2, n3, NULL);

	it = rz_graph_in_neighbors(g, n3);
	mu_assert_notnull(it, "in_neighbors_iterator");

	count = 0;
	rz_iterator_foreach(it, neighbor) {
		mu_assert_true(neighbor == n1 || neighbor == n2, "in_neighbor");
		count++;
	}
	mu_assert_eq(count, 2, "in_neighbors.count");
	rz_iterator_free(it);

	rz_graph_free(g);
	mu_end;
}

// Test node deletion
static bool test_graph_node_deletion(void) {
	// TODO: solve warning here
	// capacity check failed of vec
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);

	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.before_del");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.before_del");

	// delete n2
	bool success = rz_graph_del_node(g, n2);
	mu_assert_true(success, "del_node.2");
	mu_assert_eq(rz_graph_count_nodes(g), 2, "n_nodes.after_del");
	mu_assert_eq(rz_graph_count_edges(g), 1, "n_edges.after_del");

	// cannot find now
	RzGraphNode *found = rz_graph_find_node(g, (void *)2);
	mu_assert_null(found, "find_node.deleted");

	// edge n1->n3 still found
	bool has_edge = rz_graph_has_edge(g, n1, n3, NULL);
	mu_assert_true(has_edge, "has_edge.1->3.exists");

	rz_graph_free(g);
	mu_end;
}

// Test graph reset
static bool test_graph_reset(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.before_reset");

	rz_graph_reset(g);
	mu_assert_eq(rz_graph_count_nodes(g), 0, "n_nodes.after_reset");
	mu_assert_eq(rz_graph_count_edges(g), 0, "n_edges.after_reset");
	mu_assert_eq(g->impl_type, RZ_GRAPH_IMPL_LIST, "impl_type_after_reset");

	rz_graph_free(g);
	mu_end;
}

// Test nth neighbor
static bool test_graph_nth_neighbor(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);
	RzGraphNode *n4 = rz_graph_add_node(g, (void *)4, (void *)BASE + 4);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n1, n4, NULL);

	// Get nth out-neighbors
	RzGraphNode *neighbor0 = rz_graph_nth_neighbour(g, n1, 0, true);
	mu_assert_notnull(neighbor0, "nth_neighbor.0");

	RzGraphNode *neighbor1 = rz_graph_nth_neighbour(g, n1, 1, true);
	mu_assert_notnull(neighbor1, "nth_neighbor.1");

	RzGraphNode *neighbor2 = rz_graph_nth_neighbour(g, n1, 2, true);
	mu_assert_notnull(neighbor2, "nth_neighbor.2");

	RzGraphNode *neighbor3 = rz_graph_nth_neighbour(g, n1, 3, true);
	mu_assert_null(neighbor3, "nth_neighbor.out_of_bounds");

	rz_graph_free(g);
	mu_end;
}

// Test DFS traversal
static bool test_graph_dfs(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);
	RzGraphNode *n4 = rz_graph_add_node(g, (void *)4, (void *)BASE + 4);
	RzGraphNode *n5 = rz_graph_add_node(g, (void *)5, (void *)BASE + 5);

	// simple DAG
	// n1 --> n2 -->n4 --> n5
	// \--> n3 --->/
	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n2, n4, NULL);
	rz_graph_add_edge(g, n3, n4, NULL);
	rz_graph_add_edge(g, n4, n5, NULL);

	// Test DFS with topological sort visitor
	RzGraphVisitor vis = { 0 };
	RzList *topo_sort_list = rz_list_new();
	vis.data = topo_sort_list;
	vis.finish_node = topo_sorting;

	rz_graph_dfs_from_node(g, n1, &vis);

	// check that all nodes were visited
	mu_assert_eq(rz_list_length((RzList *)vis.data), 5, "dfs.visited_count");

	rz_list_free(topo_sort_list);
	vis.data = NULL;
	rz_graph_free(g);
	mu_end;
}

// all nodes
static bool test_graph_get_nodes(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	RzIterator *it = rz_graph_get_nodes(g);
	mu_assert_notnull(it, "get_nodes_iterator");

	int count = 0;
	RzGraphNode *node;
	rz_iterator_foreach(it, node) {
		mu_assert_true(node == n1 || node == n2 || node == n3, "node_in_graph");
		count += 1;
	}
	mu_assert_eq(count, 3, "nodes.count");

	rz_iterator_free(it);
	rz_graph_free(g);
	mu_end;
}

static bool test_graph_find_edge(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	rz_graph_add_edge(g, n1, n2, (void *)100);
	rz_graph_add_edge(g, n2, n3, (void *)200);
	rz_graph_add_edge(g, n2, n1, (void *)400);

	// can find edge
	RzGraphEdge *edge = rz_graph_find_edge(g, n1, n2);
	mu_assert_notnull(edge, "find_edge.1->2");
	mu_assert_ptreq(edge->from, n1, "edge.from");
	mu_assert_ptreq(edge->to, n2, "edge.to");
	mu_assert_ptreq(edge->data, (void *)100, "edge.data");

	edge = rz_graph_find_edge(g, n2, n1);
	mu_assert_notnull(edge, "find_edge.2->1");
	mu_assert_ptreq(edge->from, n2, "edge.from");
	mu_assert_ptreq(edge->to, n1, "edge.to");
	mu_assert_ptreq(edge->data, (void *)400, "edge.data");

	// no such edge
	edge = rz_graph_find_edge(g, n1, n3);
	mu_assert_null(edge, "find_edge.nonexistent");

	rz_graph_free(g);
	mu_end;
}

// test complex graph
static bool test_graph_complex(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	// 10 nodes
	ut64 BASE = 0x40000000;
	RzGraphNode *nodes[10];
	for (int i = 0; i < 10; i++) {
		nodes[i] = rz_graph_add_node(g, (void *)(size_t)(i + 1), (void *)(size_t)(BASE + i + 1));
		mu_assert_notnull(nodes[i], "add_node");
	}

	mu_assert_eq(rz_graph_count_nodes(g), 10, "n_nodes.10");

	// Add various edges
	rz_graph_add_edge(g, nodes[0], nodes[1], NULL);
	rz_graph_add_edge(g, nodes[0], nodes[2], NULL);
	rz_graph_add_edge(g, nodes[1], nodes[2], NULL);
	rz_graph_add_edge(g, nodes[1], nodes[3], NULL);
	rz_graph_add_edge(g, nodes[1], nodes[4], NULL);
	rz_graph_add_edge(g, nodes[2], nodes[4], NULL);
	rz_graph_add_edge(g, nodes[3], nodes[5], NULL);
	rz_graph_add_edge(g, nodes[4], nodes[6], NULL);
	rz_graph_add_edge(g, nodes[5], nodes[8], NULL);
	rz_graph_add_edge(g, nodes[6], nodes[7], NULL);
	rz_graph_add_edge(g, nodes[6], nodes[8], NULL);
	rz_graph_add_edge(g, nodes[7], nodes[9], NULL);

	mu_assert_eq(rz_graph_count_edges(g), 12, "n_edges.12");

	// test various connections
	mu_assert_true(rz_graph_has_edge(g, nodes[0], nodes[1], NULL), "has_edge.0->1");
	mu_assert_true(rz_graph_has_edge(g, nodes[1], nodes[4], NULL), "has_edge.1->4");
	mu_assert_false(rz_graph_has_edge(g, nodes[0], nodes[9], NULL), "has_edge.0->9.false");

	rz_graph_free(g);
	mu_end;
}

// Test node addition and lookup
static bool test_graph_nodes_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);
	mu_assert_notnull(g, "graph creation");

	// Add nodes with integer data
	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	mu_assert_notnull(n1, "add_node.1");
	mu_assert_eq(rz_graph_count_nodes(g), 1, "n_nodes.1");
	mu_assert_ptreq(n1->data, (void *)1, "node_data.1");

	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	mu_assert_notnull(n2, "add_node.2");
	mu_assert_eq(rz_graph_count_nodes(g), 2, "n_nodes.2");

	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);
	mu_assert_notnull(n3, "add_node.3");
	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.3");

	RzGraphNode *found1 = rz_graph_find_node(g, (void *)BASE + 1);
	mu_assert_ptreq(found1, n1, "find_node.1");

	RzGraphNode *found2 = rz_graph_find_node(g, (void *)BASE + 2);
	mu_assert_ptreq(found2, n2, "find_node.2");

	RzGraphNode *found_null = rz_graph_find_node(g, (void *)BASE + 0x42);
	mu_assert_null(found_null, "find_node.nonexistent");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_edges_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	// Add edges
	bool success = rz_graph_add_edge(g, n1, n2, NULL);
	mu_assert_true(success, "add_edge.1->2");
	mu_assert_eq(rz_graph_count_edges(g), 1, "n_edges.1");

	success = rz_graph_add_edge(g, n1, n3, NULL);
	mu_assert_true(success, "add_edge.1->3");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.2");

	success = rz_graph_add_edge(g, n2, n3, NULL);
	mu_assert_true(success, "add_edge.2->3");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.3");

	// assert more edges
	bool has_edge = rz_graph_has_edge(g, n1, n2, NULL);
	mu_assert_true(has_edge, "has_edge.1->2");

	has_edge = rz_graph_has_edge(g, n2, n1, NULL);
	mu_assert_false(has_edge, "has_edge.2->1.false");

	has_edge = rz_graph_has_edge(g, n1, n3, NULL);
	mu_assert_true(has_edge, "has_edge.1->3");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_edge_deletion_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.initial");

	bool success = rz_graph_del_edge(g, n1, n2, NULL);
	mu_assert_true(success, "del_edge.1->2");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.after_del");

	bool has_edge = rz_graph_has_edge(g, n1, n2, NULL);
	mu_assert_false(has_edge, "has_edge.1->2.deleted");

	has_edge = rz_graph_has_edge(g, n2, n3, NULL);
	mu_assert_true(has_edge, "has_edge.2->3.exists");

	rz_graph_free(g);
	mu_end;
}

// Test out-edges iterator
static bool test_graph_in_out_edges_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);
	RzGraphNode *n4 = rz_graph_add_node(g, (void *)4, (void *)BASE + 4);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n1, n4, NULL);

	// out edges
	RzIterator *it = rz_graph_out_edges(g, n1);
	mu_assert_notnull(it, "out_edges_iterator");

	int count = 0;
	RzGraphEdge *edge;
	rz_iterator_foreach(it, edge) {
		mu_assert_ptreq(edge->from, n1, "out_edge.from");
		mu_assert_true(edge->to == n2 || edge->to == n3 || edge->to == n4, "out_edge.to");
		count++;
	}
	mu_assert_eq(count, 3, "out_edges.count");
	rz_iterator_free(it);

	// in edges
	rz_graph_add_edge(g, n2, n4, NULL);
	rz_graph_add_edge(g, n3, n4, NULL);
	it = rz_graph_in_edges(g, n4);
	mu_assert_notnull(it, "in_edges_iterator");

	count = 0;
	rz_iterator_foreach(it, edge) {
		mu_assert_ptreq(edge->to, n4, "in_edge.to");
		mu_assert_true(edge->from == n1 || edge->from == n2 || edge->from == n3, "in_edge.from");
		count++;
	}
	mu_assert_eq(count, 3, "in_edges.count");
	rz_iterator_free(it);

	// clean
	rz_graph_free(g);
	mu_end;
}

// Test out-neighbors iterator
static bool test_graph_in_out_neighbors_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);

	// n1 out neighbours
	RzIterator *it = rz_graph_out_neighbors(g, n1);
	mu_assert_notnull(it, "out_neighbors_iterator");

	int count = 0;
	RzGraphNode *neighbor;
	rz_iterator_foreach(it, neighbor) {
		mu_assert_true(neighbor == n2 || neighbor == n3, "out_neighbor");
		count++;
	}
	mu_assert_eq(count, 2, "out_neighbors.count");

	rz_iterator_free(it);

	// Get in neighbours
	rz_graph_add_edge(g, n2, n3, NULL);
	it = rz_graph_in_neighbors(g, n3);
	mu_assert_notnull(it, "in_neighbors_iterator");

	count = 0;
	rz_iterator_foreach(it, neighbor) {
		mu_assert_true(neighbor == n1 || neighbor == n2, "in_neighbor");
		count++;
	}
	mu_assert_eq(count, 2, "in_neighbors.count");
	rz_iterator_free(it);

	rz_graph_free(g);
	mu_end;
}

// Test node deletion
static bool test_graph_node_deletion_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);

	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.before_del");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.before_del");

	// delete n2
	bool success = rz_graph_del_node(g, n2);
	mu_assert_true(success, "del_node.2");
	mu_assert_eq(rz_graph_count_nodes(g), 2, "n_nodes.after_del");
	mu_assert_eq(rz_graph_count_edges(g), 1, "n_edges.after_del");

	// cannot find now
	RzGraphNode *found = rz_graph_find_node(g, (void *)2);
	mu_assert_null(found, "find_node.deleted");

	// edge n1->n3 still found
	bool has_edge = rz_graph_has_edge(g, n1, n3, NULL);
	mu_assert_true(has_edge, "has_edge.1->3.exists");

	rz_graph_free(g);
	mu_end;
}

// Test graph reset
static bool test_graph_reset_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.before_reset");

	rz_graph_reset(g);
	mu_assert_eq(rz_graph_count_nodes(g), 0, "n_nodes.after_reset");
	mu_assert_eq(rz_graph_count_edges(g), 0, "n_edges.after_reset");
	mu_assert_eq(g->impl_type, RZ_GRAPH_IMPL_MATRIX, "impl_type_after_reset");

	rz_graph_free(g);
	mu_end;
}

// Test nth neighbor
static bool test_graph_nth_neighbor_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);
	RzGraphNode *n4 = rz_graph_add_node(g, (void *)4, (void *)BASE + 4);

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n1, n4, NULL);

	// Get nth out-neighbors
	RzGraphNode *neighbor0 = rz_graph_nth_neighbour(g, n1, 0, true);
	mu_assert_notnull(neighbor0, "nth_neighbor.0");

	RzGraphNode *neighbor1 = rz_graph_nth_neighbour(g, n1, 1, true);
	mu_assert_notnull(neighbor1, "nth_neighbor.1");

	RzGraphNode *neighbor2 = rz_graph_nth_neighbour(g, n1, 2, true);
	mu_assert_notnull(neighbor2, "nth_neighbor.2");

	RzGraphNode *neighbor3 = rz_graph_nth_neighbour(g, n1, 3, true);
	mu_assert_null(neighbor3, "nth_neighbor.out_of_bounds");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_dfs_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);
	RzGraphNode *n4 = rz_graph_add_node(g, (void *)4, (void *)BASE + 4);
	RzGraphNode *n5 = rz_graph_add_node(g, (void *)5, (void *)BASE + 5);

	// simple DAG
	// n1 --> n2 -->n4 --> n5
	// \--> n3 --->/
	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n2, n4, NULL);
	rz_graph_add_edge(g, n3, n4, NULL);
	rz_graph_add_edge(g, n4, n5, NULL);

	// Test DFS with topological sort visitor
	RzGraphVisitor vis = { 0 };
	RzList *topo_sort_list = rz_list_new();
	vis.data = topo_sort_list;
	vis.finish_node = topo_sorting;

	rz_graph_dfs_from_node(g, n1, &vis);

	// check that all nodes were visited
	mu_assert_eq(rz_list_length((RzList *)vis.data), 5, "dfs.visited_count");

	rz_list_free(topo_sort_list);
	vis.data = NULL;
	rz_graph_free(g);
	mu_end;
}

// all nodes
static bool test_graph_get_nodes_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	RzIterator *it = rz_graph_get_nodes(g);
	mu_assert_notnull(it, "get_nodes_iterator");

	int count = 0;
	RzGraphNode *node;
	rz_iterator_foreach(it, node) {
		mu_assert_true(node == n1 || node == n2 || node == n3, "node_in_graph");
		count += 1;
	}
	mu_assert_eq(count, 3, "nodes.count");

	rz_iterator_free(it);
	rz_graph_free(g);
	mu_end;
}

static bool test_graph_find_edge_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	ut64 BASE = 0x40000000;
	RzGraphNode *n1 = rz_graph_add_node(g, (void *)1, (void *)BASE + 1);
	RzGraphNode *n2 = rz_graph_add_node(g, (void *)2, (void *)BASE + 2);
	RzGraphNode *n3 = rz_graph_add_node(g, (void *)3, (void *)BASE + 3);

	rz_graph_add_edge(g, n1, n2, (void *)100);
	rz_graph_add_edge(g, n2, n3, (void *)200);
	rz_graph_add_edge(g, n2, n1, (void *)400);

	// can find edge
	RzGraphEdge *edge = rz_graph_find_edge(g, n1, n2);
	mu_assert_notnull(edge, "find_edge.1->2");
	mu_assert_ptreq(edge->from, n1, "edge.from");
	mu_assert_ptreq(edge->to, n2, "edge.to");
	mu_assert_ptreq(edge->data, (void *)100, "edge.data");

	edge = rz_graph_find_edge(g, n2, n1);
	mu_assert_notnull(edge, "find_edge.2->1");
	mu_assert_ptreq(edge->from, n2, "edge.from");
	mu_assert_ptreq(edge->to, n1, "edge.to");
	mu_assert_ptreq(edge->data, (void *)400, "edge.data");

	// no such edge
	edge = rz_graph_find_edge(g, n1, n3);
	mu_assert_null(edge, "find_edge.nonexistent");

	rz_graph_free(g);
	mu_end;
}

// test complex graph
static bool test_graph_complex_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	// 10 nodes
	ut64 BASE = 0x40000000;
	RzGraphNode *nodes[10];
	for (int i = 0; i < 10; i++) {
		nodes[i] = rz_graph_add_node(g, (void *)(size_t)(i + 1), (void *)(size_t)(BASE + i + 1));
		mu_assert_notnull(nodes[i], "add_node");
	}

	mu_assert_eq(rz_graph_count_nodes(g), 10, "n_nodes.10");

	// Add various edges
	rz_graph_add_edge(g, nodes[0], nodes[1], NULL);
	rz_graph_add_edge(g, nodes[0], nodes[2], NULL);
	rz_graph_add_edge(g, nodes[1], nodes[2], NULL);
	rz_graph_add_edge(g, nodes[1], nodes[3], NULL);
	rz_graph_add_edge(g, nodes[1], nodes[4], NULL);
	rz_graph_add_edge(g, nodes[2], nodes[4], NULL);
	rz_graph_add_edge(g, nodes[3], nodes[5], NULL);
	rz_graph_add_edge(g, nodes[4], nodes[6], NULL);
	rz_graph_add_edge(g, nodes[5], nodes[8], NULL);
	rz_graph_add_edge(g, nodes[6], nodes[7], NULL);
	rz_graph_add_edge(g, nodes[6], nodes[8], NULL);
	rz_graph_add_edge(g, nodes[7], nodes[9], NULL);

	mu_assert_eq(rz_graph_count_edges(g), 12, "n_edges.12");

	// test various connections
	mu_assert_true(rz_graph_has_edge(g, nodes[0], nodes[1], NULL), "has_edge.0->1");
	mu_assert_true(rz_graph_has_edge(g, nodes[1], nodes[4], NULL), "has_edge.1->4");
	mu_assert_false(rz_graph_has_edge(g, nodes[0], nodes[9], NULL), "has_edge.0->9.false");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_impl_equivalence(void) {
	// Create both graphs
	RzGraph *g_list = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);
	RzGraph *g_matrix = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	// Add same nodes to both
	ut64 BASE = 0x40000000;
	RzGraphNode *l_nodes[5], *m_nodes[5];
	for (int i = 0; i < 5; i++) {
		l_nodes[i] = rz_graph_add_node(g_list, (void *)(size_t)(i + 1), (void *)(size_t)(BASE + i + 1));
		m_nodes[i] = rz_graph_add_node(g_matrix, (void *)(size_t)(i + 1), (void *)(size_t)(BASE + i + 1));
	}

	mu_assert_eq(rz_graph_count_nodes(g_list), rz_graph_count_nodes(g_matrix), "same node count");

	// Add same edges to both
	rz_graph_add_edge(g_list, l_nodes[0], l_nodes[1], NULL);
	rz_graph_add_edge(g_matrix, m_nodes[0], m_nodes[1], NULL);

	rz_graph_add_edge(g_list, l_nodes[0], l_nodes[2], NULL);
	rz_graph_add_edge(g_matrix, m_nodes[0], m_nodes[2], NULL);

	rz_graph_add_edge(g_list, l_nodes[1], l_nodes[3], NULL);
	rz_graph_add_edge(g_matrix, m_nodes[1], m_nodes[3], NULL);

	rz_graph_add_edge(g_list, l_nodes[2], l_nodes[4], NULL);
	rz_graph_add_edge(g_matrix, m_nodes[2], m_nodes[4], NULL);

	mu_assert_eq(rz_graph_count_edges(g_list), rz_graph_count_edges(g_matrix), "same edge count");

	// Test has_edge returns same results
	mu_assert_eq(
		rz_graph_has_edge(g_list, l_nodes[0], l_nodes[1], NULL),
		rz_graph_has_edge(g_matrix, m_nodes[0], m_nodes[1], NULL),
		"same has_edge result for 0->1");

	mu_assert_eq(
		rz_graph_has_edge(g_list, l_nodes[1], l_nodes[0], NULL),
		rz_graph_has_edge(g_matrix, m_nodes[1], m_nodes[0], NULL),
		"same has_edge result for 1->0 (false)");

	// Test out-neighbor count is same
	RzIterator *l_it = rz_graph_out_neighbors(g_list, l_nodes[0]);
	RzIterator *m_it = rz_graph_out_neighbors(g_matrix, m_nodes[0]);

	int l_count = 0, m_count = 0;
	RzGraphNode *node;
	rz_iterator_foreach(l_it, node) {
		l_count++;
	}
	rz_iterator_foreach(m_it, node) {
		m_count++;
	}

	mu_assert_eq(l_count, m_count, "same out-neighbor count");

	rz_iterator_free(l_it);
	rz_iterator_free(m_it);

	rz_graph_free(g_list);
	rz_graph_free(g_matrix);
	mu_end;
}

static int all_tests(void) {
	mu_run_test(test_graph_basic);
	// list impl
	mu_run_test(test_graph_nodes);
	mu_run_test(test_graph_edges);
	mu_run_test(test_graph_edge_deletion);
	mu_run_test(test_graph_in_out_edges);
	mu_run_test(test_graph_in_out_neighbors);
	mu_run_test(test_graph_node_deletion);
	mu_run_test(test_graph_reset);
	mu_run_test(test_graph_nth_neighbor);
	mu_run_test(test_graph_dfs);
	mu_run_test(test_graph_get_nodes);
	mu_run_test(test_graph_find_edge);
	mu_run_test(test_graph_complex);

	// matrix impl
	mu_run_test(test_graph_nodes_matrix);
	mu_run_test(test_graph_edges_matrix);
	mu_run_test(test_graph_edge_deletion_matrix);
	mu_run_test(test_graph_in_out_edges_matrix);
	mu_run_test(test_graph_in_out_neighbors_matrix);
	mu_run_test(test_graph_node_deletion_matrix);
	mu_run_test(test_graph_reset_matrix);
	mu_run_test(test_graph_nth_neighbor_matrix);
	mu_run_test(test_graph_dfs_matrix);
	mu_run_test(test_graph_get_nodes_matrix);
	mu_run_test(test_graph_find_edge_matrix);
	mu_run_test(test_graph_complex_matrix);

	mu_run_test(test_graph_impl_equivalence);

	return tests_passed != tests_run;
}

mu_main(all_tests)