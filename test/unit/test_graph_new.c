// SPDX-FileCopyrightText: 2025-2026 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include "rz_util/rz_graph.h"

static ut64 simple_hash(const void *data) {
	return (ut64)(utptr)data;
}

#define BASE 0x40000000

static ut64 simple_hash_base(const void *data) {
	return (ut64)(utptr)data + BASE;
}

static ut64 str_hash(RZ_NULLABLE const void *data) {
	return rz_str_djb2_hash(data);
}

static void topo_sorting(RzGraphNode *n, RzGraphVisitor *vis) {
	RzList *order = (RzList *)vis->visitor_data;
	rz_list_prepend(order, rz_graph_node_get_data_mut(n));
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
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);
	mu_assert_notnull(g, "graph creation");

	// Add nodes with integer data
	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_notnull(n1, "add_node.1");
	mu_assert_eq(rz_graph_count_nodes(g), 1, "n_nodes.1");
	mu_assert_ptreq(rz_graph_node_get_data(n1), RZ_GRAPH_INT_AS_DATA(1), "node_data.1");
	RzGraphNode *n1_same = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1_same), RZ_GRAPH_STATUS_EXISTED, "Should exist");
	mu_assert_eq(n1, n1_same, "Should be the same node pointer.");
	mu_assert_eq(n1, n1_same, "rz_graph_add_get_node() did not return same node");

	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_notnull(n2, "add_node.2");
	mu_assert_eq(rz_graph_count_nodes(g), 2, "n_nodes.2");

	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_notnull(n3, "add_node.3");
	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.3");

	RzGraphNode *found1 = rz_graph_find_node(g, BASE + 1);
	mu_assert_ptreq(found1, n1, "find_node.1");

	RzGraphNode *found2 = rz_graph_find_node(g, BASE + 2);
	mu_assert_ptreq(found2, n2, "find_node.2");

	RzGraphNode *found_null = rz_graph_find_node(g, BASE + 0x42);
	mu_assert_null(found_null, "find_node.nonexistent");

	rz_graph_free(g);
	mu_end;
}

// TODO: Add test for removing nodes and checking that nodes_vec is never larger than n.

static bool test_graph_edges(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, NULL, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *arr[16] = { 0 };

	// Add edges
	mu_assert_eq(rz_graph_add_edge(g, n1, n2, NULL), RZ_GRAPH_STATUS_OK, "add_edge.1->2");
	mu_assert_eq(rz_graph_count_edges(g), 1, "n_edges.1");

	mu_assert_eq(rz_graph_add_edge_by_id(g, 1, 9, NULL), RZ_GRAPH_STATUS_MISSING_NODE, "add_edge.1->2");
	mu_assert_eq(rz_graph_count_edges(g), 1, "n_edges.1");

	mu_assert_eq(rz_graph_add_edge_by_id(g, 1, 3, NULL), RZ_GRAPH_STATUS_OK, "add_edge.1->3");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.2");

	mu_assert_eq(rz_graph_add_edge(g, n2, n3, NULL), RZ_GRAPH_STATUS_OK, "add_edge.2->3");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.3");

	// assert more edges
	mu_assert_eq(rz_graph_has_edge(g, n1, n2), RZ_GRAPH_STATUS_OK, "has_edge.1->2");
	mu_assert_eq(rz_graph_has_edge(g, n2, n1), RZ_GRAPH_STATUS_MISSING_EDGE, "has_edge.2->1.false");
	mu_assert_eq(rz_graph_has_edge(g, n1, n3), RZ_GRAPH_STATUS_OK, "has_edge.1->3");

	// Add 16 more nodes (more than LIST_IMPL_DEFAULT_NODE_VEC_SIZE)
	// then add an edge and check if it fails somehow.
	for (size_t i = 0; i < RZ_ARRAY_SIZE(arr); ++i) {
		arr[i] = NULL;
		mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(i + 4), &arr[i]), RZ_GRAPH_STATUS_OK, "Failed to add");
		mu_assert_notnull(arr[i], "Was NULL, should not.");
	}
	mu_assert_eq(rz_graph_add_edge(g, arr[8], n3, NULL), RZ_GRAPH_STATUS_OK, "add_edge.12->3");
	mu_assert_eq(rz_graph_count_edges(g), 4, "n_edges.4");
	mu_assert_eq(rz_graph_has_edge_by_id(g, 8 + 4, 3), RZ_GRAPH_STATUS_OK, "has_edge.12->3");

	mu_assert_eq(rz_graph_del_node(g, arr[8]), RZ_GRAPH_STATUS_EXISTED, "Del failed");
	// Node pointer is freed by del.
	arr[8] = NULL;
	mu_assert_eq(rz_graph_has_edge_by_id(g, 8 + 4, 3), RZ_GRAPH_STATUS_MISSING_EDGE, "has_edge.12->3 fail");

	// Node should be placed at the edge list index of just deleted node 11.
	RzGraphNode *nx = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(0xffff), &nx), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_eq(rz_graph_add_edge(g, nx, n3, NULL), RZ_GRAPH_STATUS_OK, "add_edge.0xffff->3");
	mu_assert_eq(rz_graph_count_edges(g), 4, "n_edges.4");
	mu_assert_eq(rz_graph_has_edge(g, nx, n3), RZ_GRAPH_STATUS_OK, "has_edge.0xffff->3");

	mu_assert_eq(rz_graph_del_edge_by_id(g, 2, 99), RZ_GRAPH_STATUS_OK, "del_edge not existing");
	mu_assert_eq(rz_graph_count_edges(g), 4, "n_edges.4");

	mu_assert_eq(rz_graph_del_edge_by_id(g, 2, 3), RZ_GRAPH_STATUS_EXISTED, "del_edge_id.2->3");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.3");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_edge_deletion(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.initial");

	mu_assert_eq(rz_graph_del_edge(g, n1, n2), RZ_GRAPH_STATUS_EXISTED, "del_edge.1->2");
	mu_assert_eq(rz_graph_del_edge(g, n1, n2), RZ_GRAPH_STATUS_OK, "del_edge non 1->2");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.after_del");

	mu_assert_eq(rz_graph_has_edge(g, n1, n2), RZ_GRAPH_STATUS_MISSING_EDGE, "has_edge.1->2.deleted");

	mu_assert_eq(rz_graph_has_edge(g, n2, n3), RZ_GRAPH_STATUS_OK, "has_edge.2->3.exists");

	rz_graph_free(g);
	mu_end;
}

static bool dst_is_n3(const RzGraphEdge *e, void *user) {
	return rz_graph_node_get_id(rz_graph_edge_get_to(e)) == 3;
}

static bool test_graph_edge_deletion_multi(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n1, n4, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	mu_assert_eq(rz_graph_count_edges(g), 4, "n_edges.initial");

	mu_assert_eq(rz_graph_del_edges(g, dst_is_n3, NULL), RZ_GRAPH_STATUS_EXISTED, "del_edge x->3");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.after_del");

	mu_assert_eq(rz_graph_has_edge(g, n1, n2), RZ_GRAPH_STATUS_OK, "has_edge.1->2.exists");
	mu_assert_eq(rz_graph_has_edge(g, n1, n4), RZ_GRAPH_STATUS_OK, "has_edge.1->4.exists");

	mu_assert_eq(rz_graph_del_edges(g, NULL, NULL), RZ_GRAPH_STATUS_EXISTED, "del_edge all");
	mu_assert_eq(rz_graph_count_edges(g), 0, "n_edges.after_del");

	mu_assert_eq(rz_graph_del_edges(g, NULL, NULL), RZ_GRAPH_STATUS_OK, "del_edge none");

	rz_graph_free(g);
	mu_end;
}

static bool is_from_one(const RzGraphEdge *e, void *user_data) {
	ut64 num = (utptr)rz_graph_edge_get_data(e);
	return (num >> 4) == 1;
}

static bool test_graph_edges_data_update(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, RZ_GRAPH_INT_AS_DATA(0x12));
	rz_graph_add_edge(g, n1, n3, RZ_GRAPH_INT_AS_DATA(0x13));
	rz_graph_add_edge(g, n1, n4, RZ_GRAPH_INT_AS_DATA(0x14));
	rz_graph_add_edge(g, n2, n3, RZ_GRAPH_INT_AS_DATA(0x23));
	mu_assert_eq(rz_graph_count_edges(g), 4, "n_edges.initial");

	mu_assert_eq(rz_graph_update_edge_by_id(g, 3, 9, RZ_GRAPH_INT_AS_DATA(0x33), NULL, NULL),
		RZ_GRAPH_STATUS_MISSING_NODE, "missing node expected");

	mu_assert_eq(rz_graph_update_edge(g, n3, n3, RZ_GRAPH_INT_AS_DATA(0x33), NULL, NULL),
		RZ_GRAPH_STATUS_OK, "add edge");
	mu_assert_eq(rz_graph_count_edges(g), 5, "n_edges.added");

	mu_assert_eq(rz_graph_update_edge_by_id(g, 2, 3, RZ_GRAPH_INT_AS_DATA(0xff), is_from_one, NULL),
		RZ_GRAPH_STATUS_NOT_UPDATED, "updated");
	RzGraphEdge *e = rz_graph_find_edge(g, n2, n3);
	mu_assert_notnull(e, "Not NULL");
	ut64 edge_data = (utptr)rz_graph_edge_get_data(e);
	mu_assert_eq(edge_data, 0x23, "Edge data changed.");

	mu_assert_eq(rz_graph_update_edge_by_id(g, 1, 3, RZ_GRAPH_INT_AS_DATA(0xff), is_from_one, NULL),
		RZ_GRAPH_STATUS_UPDATED, "updated");
	e = rz_graph_find_edge(g, n1, n3);
	mu_assert_notnull(e, "Not NULL");
	edge_data = (utptr)rz_graph_edge_get_data(e);
	mu_assert_eq(edge_data, 0xff, "Edge data did not change.");

	rz_graph_free(g);
	mu_end;
}

// Test out-edges iterator
static bool test_graph_in_out_edges(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n1, n4, NULL);

	// out edges
	RzIterator *it = rz_graph_out_edges(g, n1);
	mu_assert_notnull(it, "out_edges_iterator");

	int count = 0;
	RzGraphEdge *edge;
	rz_iterator_foreach(it, edge) {
		mu_assert_ptreq(rz_graph_edge_get_from(edge), n1, "out_edge.from");
		mu_assert_true(rz_graph_edge_get_to(edge) == n2 || rz_graph_edge_get_to(edge) == n3 || rz_graph_edge_get_to(edge) == n4, "out_edge.to");
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
		mu_assert_ptreq(rz_graph_edge_get_to(edge), n4, "in_edge.to");
		mu_assert_true(rz_graph_edge_get_from(edge) == n1 || rz_graph_edge_get_from(edge) == n2 || rz_graph_edge_get_from(edge) == n3, "in_edge.from");
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
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

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
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);
	mu_assert_eq(rz_graph_del_node_by_id(g, 1), RZ_GRAPH_STATUS_OK, "Not existing node failed");

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);

	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.before_del");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.before_del");

	// delete n2
	mu_assert_eq(rz_graph_del_node(g, n2), RZ_GRAPH_STATUS_EXISTED, "del_node.2");
	mu_assert_eq(rz_graph_count_nodes(g), 2, "n_nodes.after_del");
	mu_assert_eq(rz_graph_count_edges(g), 1, "n_edges.after_del");

	// cannot find now
	RzGraphNode *found = rz_graph_find_node(g, 2);
	mu_assert_null(found, "find_node.deleted");

	// edge n1->n3 still found
	mu_assert_eq(rz_graph_has_edge(g, n1, n3), RZ_GRAPH_STATUS_OK, "has_edge.1->3.exists");

	mu_assert_eq(rz_graph_del_node_by_id(g, 0x40000003), RZ_GRAPH_STATUS_EXISTED, "del failed");

	rz_graph_free(g);
	mu_end;
}

// Test graph reset
static bool test_graph_reset(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);

	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), NULL), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), NULL), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), NULL), RZ_GRAPH_STATUS_OK, "Failed to add");

	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), NULL), RZ_GRAPH_STATUS_EXISTED, "Failed to get existed with NULL out_ptr");

	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.before_reset");

	rz_graph_reset(g);
	mu_assert_eq(rz_graph_count_nodes(g), 0, "n_nodes.after_reset");
	mu_assert_eq(rz_graph_count_edges(g), 0, "n_edges.after_reset");
	mu_assert_eq(rz_graph_get_impl_type(g), RZ_GRAPH_IMPL_LIST, "impl_type_after_reset");

	rz_graph_free(g);
	mu_end;
}

// Test nth neighbor
static bool test_graph_nth_neighbor(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");

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
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n5 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(5), &n5), RZ_GRAPH_STATUS_OK, "Failed to add");

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
	vis.visitor_data = topo_sort_list;
	vis.finish_node = topo_sorting;

	rz_graph_dfs_from_node(g, n1, &vis);

	// check that all nodes were visited
	mu_assert_eq(rz_list_length((RzList *)vis.visitor_data), 5, "dfs.visited_count");

	rz_list_free(topo_sort_list);
	vis.visitor_data = NULL;
	rz_graph_free(g);
	mu_end;
}

// all nodes
static bool test_graph_get_nodes(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

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
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, RZ_GRAPH_INT_AS_DATA(100));
	rz_graph_add_edge(g, n2, n3, RZ_GRAPH_INT_AS_DATA(200));
	rz_graph_add_edge(g, n2, n1, RZ_GRAPH_INT_AS_DATA(400));

	// can find edge
	RzGraphEdge *edge = rz_graph_find_edge(g, n1, n2);
	mu_assert_notnull(edge, "find_edge.1->2");
	mu_assert_ptreq(rz_graph_edge_get_from(edge), n1, "edge.from");
	mu_assert_ptreq(rz_graph_edge_get_to(edge), n2, "edge.to");
	mu_assert_ptreq(rz_graph_edge_get_data(edge), RZ_GRAPH_INT_AS_DATA(100), "edge.data");

	edge = rz_graph_find_edge(g, n2, n1);
	mu_assert_notnull(edge, "find_edge.2->1");
	mu_assert_ptreq(rz_graph_edge_get_from(edge), n2, "edge.from");
	mu_assert_ptreq(rz_graph_edge_get_to(edge), n1, "edge.to");
	mu_assert_ptreq(rz_graph_edge_get_data(edge), RZ_GRAPH_INT_AS_DATA(400), "edge.data");

	// no such edge
	edge = rz_graph_find_edge(g, n1, n3);
	mu_assert_null(edge, "find_edge.nonexistent");

	rz_graph_free(g);
	mu_end;
}

// test complex graph
static bool test_graph_complex(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);

	// 10 nodes
	RzGraphNode *nodes[10];
	for (int i = 0; i < 10; i++) {
		nodes[i] = NULL;
		mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA((i + 1)), &nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to add");
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
	mu_assert_eq(rz_graph_has_edge(g, nodes[0], nodes[1]), RZ_GRAPH_STATUS_OK, "has_edge.0->1");
	mu_assert_eq(rz_graph_has_edge(g, nodes[1], nodes[4]), RZ_GRAPH_STATUS_OK, "has_edge.1->4");
	mu_assert_eq(rz_graph_has_edge(g, nodes[0], nodes[9]), RZ_GRAPH_STATUS_MISSING_EDGE, "has_edge.0->9.false");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_node_edge_data(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, str_hash, free, free);

	char nname[2] = { 0 };
	// 10 nodes
	RzGraphNode *nodes[10];
	for (int i = 0; i < 10; i++) {
		nodes[i] = NULL;
		rz_strf(nname, "%d", i);
		mu_assert_eq(rz_graph_add_node(g, rz_str_dup(nname), &nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to add");
		mu_assert_notnull(nodes[i], "add_node");
		mu_assert_eq(rz_graph_add_edge(g, nodes[i], nodes[i], malloc(16)), RZ_GRAPH_STATUS_OK, "Failed to add self-ref edge");
	}
	mu_assert_eq(rz_graph_count_edges(g), 10, "n_edges.10");

	mu_assert_eq(rz_graph_add_edge_by_id(g, str_hash("0"), str_hash("0"), malloc(16)), RZ_GRAPH_STATUS_EXISTED, "add existing edge, data must be freed");
	mu_assert_eq(rz_graph_count_edges(g), 10, "n_edges.10");

	for (int i = 1; i < 10; i++) {
		mu_assert_eq(rz_graph_add_edge(g, nodes[i - 1], nodes[i], malloc(16)), RZ_GRAPH_STATUS_OK, "Failed to add back edge");
	}

	for (int i = 0; i < 10; i++) {
		rz_strf(nname, "%d", i);
		RzGraphNode *n = rz_graph_find_node(g, str_hash(nname));
		mu_assert_notnull(n, "find node");
		mu_assert_streq(rz_graph_node_get_data(n), nname, "Name mismatch");
	}

	for (int i = 0; i < 10; i++) {
		mu_assert_eq(rz_graph_has_edge(g, nodes[i], nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to has self-ref edge");
		if (i != 0) {
			mu_assert_eq(rz_graph_has_edge(g, nodes[i - 1], nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to has back edge");
		}
	}

	mu_assert_eq(rz_graph_del_edge_by_id(g, str_hash("00"), str_hash("0")), RZ_GRAPH_STATUS_OK, "Not existing node.");
	mu_assert_eq(rz_graph_count_edges(g), 19, "n_edges.10");
	mu_assert_eq(rz_graph_del_edge_by_id(g, str_hash("0"), str_hash("0")), RZ_GRAPH_STATUS_EXISTED, "Del edge with data.");
	mu_assert_eq(rz_graph_count_edges(g), 18, "n_edges.9");

	rz_graph_free(g);

	mu_end;
}

// Test node addition and lookup
static bool test_graph_nodes_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);
	mu_assert_notnull(g, "graph creation");

	// Add nodes with integer data
	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_notnull(n1, "add_node.1");
	mu_assert_eq(rz_graph_count_nodes(g), 1, "n_nodes.1");
	mu_assert_ptreq(rz_graph_node_get_data(n1), RZ_GRAPH_INT_AS_DATA(1), "node_data.1");

	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_notnull(n2, "add_node.2");
	mu_assert_eq(rz_graph_count_nodes(g), 2, "n_nodes.2");

	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_notnull(n3, "add_node.3");
	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.3");

	RzGraphNode *found1 = rz_graph_find_node(g, BASE + 1);
	mu_assert_ptreq(found1, n1, "find_node.1");

	RzGraphNode *found2 = rz_graph_find_node(g, BASE + 2);
	mu_assert_ptreq(found2, n2, "find_node.2");

	RzGraphNode *found_null = rz_graph_find_node(g, BASE + 0x42);
	mu_assert_null(found_null, "find_node.nonexistent");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_edges_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, NULL, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

	// Add edges
	mu_assert_eq(rz_graph_add_edge(g, n1, n2, NULL), RZ_GRAPH_STATUS_OK, "add_edge.1->2");
	mu_assert_eq(rz_graph_count_edges(g), 1, "n_edges.1");

	mu_assert_eq(rz_graph_add_edge(g, n1, n3, NULL), RZ_GRAPH_STATUS_OK, "add_edge.1->3");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.2");

	mu_assert_eq(rz_graph_add_edge(g, n2, n3, NULL), RZ_GRAPH_STATUS_OK, "add_edge.2->3");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.3");

	// assert more edges
	mu_assert_eq(rz_graph_has_edge(g, n1, n2), RZ_GRAPH_STATUS_OK, "has_edge.1->2");

	mu_assert_eq(rz_graph_has_edge(g, n2, n1), RZ_GRAPH_STATUS_MISSING_EDGE, "has_edge.2->1.false");

	mu_assert_eq(rz_graph_has_edge(g, n1, n3), RZ_GRAPH_STATUS_OK, "has_edge.1->3");

	mu_assert_eq(rz_graph_del_edge_by_id(g, 2, 8), RZ_GRAPH_STATUS_OK, "del_edge not existing");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.3");

	mu_assert_eq(rz_graph_del_edge_by_id(g, 2, 3), RZ_GRAPH_STATUS_EXISTED, "del_edge_id.2->3");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.2");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_edge_deletion_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.initial");

	mu_assert_eq(rz_graph_del_edge(g, n1, n2), RZ_GRAPH_STATUS_EXISTED, "del_edge.1->2");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.after_del");

	mu_assert_eq(rz_graph_has_edge(g, n1, n2), RZ_GRAPH_STATUS_MISSING_EDGE, "has_edge.1->2.deleted");

	mu_assert_eq(rz_graph_has_edge(g, n2, n3), RZ_GRAPH_STATUS_OK, "has_edge.2->3.exists");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_edge_deletion_multi_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n1, n4, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	mu_assert_eq(rz_graph_count_edges(g), 4, "n_edges.initial");

	mu_assert_eq(rz_graph_del_edges(g, dst_is_n3, NULL), RZ_GRAPH_STATUS_EXISTED, "del_edge x->3");
	mu_assert_eq(rz_graph_count_edges(g), 2, "n_edges.after_del");

	mu_assert_eq(rz_graph_has_edge(g, n1, n2), RZ_GRAPH_STATUS_OK, "has_edge.1->2.exists");
	mu_assert_eq(rz_graph_has_edge(g, n1, n4), RZ_GRAPH_STATUS_OK, "has_edge.1->4.exists");

	mu_assert_eq(rz_graph_del_edges(g, NULL, NULL), RZ_GRAPH_STATUS_EXISTED, "del_edge all");
	mu_assert_eq(rz_graph_count_edges(g), 0, "n_edges.after_del");

	mu_assert_eq(rz_graph_del_edges(g, NULL, NULL), RZ_GRAPH_STATUS_OK, "del_edge none");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_edges_data_update_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, RZ_GRAPH_INT_AS_DATA(0x12));
	rz_graph_add_edge(g, n1, n3, RZ_GRAPH_INT_AS_DATA(0x13));
	rz_graph_add_edge(g, n1, n4, RZ_GRAPH_INT_AS_DATA(0x14));
	rz_graph_add_edge(g, n2, n3, RZ_GRAPH_INT_AS_DATA(0x23));
	mu_assert_eq(rz_graph_count_edges(g), 4, "n_edges.initial");

	mu_assert_eq(rz_graph_update_edge_by_id(g, 3, 9, RZ_GRAPH_INT_AS_DATA(0x33), NULL, NULL),
		RZ_GRAPH_STATUS_MISSING_NODE, "missing node expected");

	mu_assert_eq(rz_graph_update_edge(g, n3, n3, RZ_GRAPH_INT_AS_DATA(0x33), NULL, NULL),
		RZ_GRAPH_STATUS_OK, "add edge");
	mu_assert_eq(rz_graph_count_edges(g), 5, "n_edges.added");

	mu_assert_eq(rz_graph_update_edge_by_id(g, 2, 3, RZ_GRAPH_INT_AS_DATA(0xff), is_from_one, NULL),
		RZ_GRAPH_STATUS_NOT_UPDATED, "not updated");
	RzGraphEdge *e = rz_graph_find_edge(g, n2, n3);
	mu_assert_notnull(e, "Not NULL");
	ut64 edge_data = (utptr)rz_graph_edge_get_data(e);
	mu_assert_eq(edge_data, 0x23, "Edge data changed.");

	mu_assert_eq(rz_graph_update_edge_by_id(g, 1, 3, RZ_GRAPH_INT_AS_DATA(0xff), is_from_one, NULL),
		RZ_GRAPH_STATUS_UPDATED, "updated");
	e = rz_graph_find_edge(g, n1, n3);
	mu_assert_notnull(e, "Not NULL");
	edge_data = (utptr)rz_graph_edge_get_data(e);
	mu_assert_eq(edge_data, 0xff, "Edge data did not change.");

	rz_graph_free(g);
	mu_end;
}

// Test out-edges iterator
static bool test_graph_in_out_edges_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);
	rz_graph_add_edge(g, n1, n4, NULL);

	// out edges
	RzIterator *it = rz_graph_out_edges(g, n1);
	mu_assert_notnull(it, "out_edges_iterator");

	int count = 0;
	RzGraphEdge *edge;
	rz_iterator_foreach(it, edge) {
		mu_assert_ptreq(rz_graph_edge_get_from(edge), n1, "out_edge.from");
		mu_assert_true(rz_graph_edge_get_to(edge) == n2 || rz_graph_edge_get_to(edge) == n3 || rz_graph_edge_get_to(edge) == n4, "out_edge.to");
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
		mu_assert_ptreq(rz_graph_edge_get_to(edge), n4, "in_edge.to");
		mu_assert_true(rz_graph_edge_get_from(edge) == n1 || rz_graph_edge_get_from(edge) == n2 || rz_graph_edge_get_from(edge) == n3, "in_edge.from");
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
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

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
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, NULL);
	rz_graph_add_edge(g, n2, n3, NULL);
	rz_graph_add_edge(g, n1, n3, NULL);

	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.before_del");
	mu_assert_eq(rz_graph_count_edges(g), 3, "n_edges.before_del");

	// delete n2
	mu_assert_eq(rz_graph_del_node(g, n2), RZ_GRAPH_STATUS_EXISTED, "del_node.2");
	mu_assert_eq(rz_graph_count_nodes(g), 2, "n_nodes.after_del");
	mu_assert_eq(rz_graph_count_edges(g), 1, "n_edges.after_del");

	// cannot find now
	RzGraphNode *found = rz_graph_find_node(g, 2);
	mu_assert_null(found, "find_node.deleted");

	// edge n1->n3 still found
	mu_assert_eq(rz_graph_has_edge(g, n1, n3), RZ_GRAPH_STATUS_OK, "has_edge.1->3.exists");

	rz_graph_free(g);
	mu_end;
}

// Test graph reset
static bool test_graph_reset_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), NULL), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), NULL), RZ_GRAPH_STATUS_OK, "Failed to add");
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), NULL), RZ_GRAPH_STATUS_OK, "Failed to add");

	mu_assert_eq(rz_graph_count_nodes(g), 3, "n_nodes.before_reset");

	rz_graph_reset(g);
	mu_assert_eq(rz_graph_count_nodes(g), 0, "n_nodes.after_reset");
	mu_assert_eq(rz_graph_count_edges(g), 0, "n_edges.after_reset");
	mu_assert_eq(rz_graph_get_impl_type(g), RZ_GRAPH_IMPL_MATRIX, "impl_type_after_reset");

	rz_graph_free(g);
	mu_end;
}

// Test nth neighbor
static bool test_graph_nth_neighbor_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");

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
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(4), &n4), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n5 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(5), &n5), RZ_GRAPH_STATUS_OK, "Failed to add");

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
	vis.visitor_data = topo_sort_list;
	vis.finish_node = topo_sorting;

	rz_graph_dfs_from_node(g, n1, &vis);

	// check that all nodes were visited
	mu_assert_eq(rz_list_length((RzList *)vis.visitor_data), 5, "dfs.visited_count");

	rz_list_free(topo_sort_list);
	vis.visitor_data = NULL;
	rz_graph_free(g);
	mu_end;
}

// all nodes
static bool test_graph_get_nodes_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

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
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n2, RZ_GRAPH_INT_AS_DATA(100));
	rz_graph_add_edge(g, n2, n3, RZ_GRAPH_INT_AS_DATA(200));
	rz_graph_add_edge(g, n2, n1, RZ_GRAPH_INT_AS_DATA(400));

	// can find edge
	RzGraphEdge *edge = rz_graph_find_edge(g, n1, n2);
	mu_assert_notnull(edge, "find_edge.1->2");
	mu_assert_ptreq(rz_graph_edge_get_from(edge), n1, "edge.from");
	mu_assert_ptreq(rz_graph_edge_get_to(edge), n2, "edge.to");
	mu_assert_ptreq(rz_graph_edge_get_data(edge), RZ_GRAPH_INT_AS_DATA(100), "edge.data");

	edge = rz_graph_find_edge(g, n2, n1);
	mu_assert_notnull(edge, "find_edge.2->1");
	mu_assert_ptreq(rz_graph_edge_get_from(edge), n2, "edge.from");
	mu_assert_ptreq(rz_graph_edge_get_to(edge), n1, "edge.to");
	mu_assert_ptreq(rz_graph_edge_get_data(edge), RZ_GRAPH_INT_AS_DATA(400), "edge.data");

	// no such edge
	edge = rz_graph_find_edge(g, n1, n3);
	mu_assert_null(edge, "find_edge.nonexistent");

	rz_graph_free(g);
	mu_end;
}

// test complex graph
static bool test_graph_complex_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	// 10 nodes
	RzGraphNode *nodes[10];
	for (int i = 0; i < 10; i++) {
		nodes[i] = NULL;
		mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA((i + 1)), &nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to add");
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
	mu_assert_eq(rz_graph_has_edge(g, nodes[0], nodes[1]), RZ_GRAPH_STATUS_OK, "has_edge.0->1");
	mu_assert_eq(rz_graph_has_edge(g, nodes[1], nodes[4]), RZ_GRAPH_STATUS_OK, "has_edge.1->4");
	mu_assert_eq(rz_graph_has_edge(g, nodes[0], nodes[9]), RZ_GRAPH_STATUS_MISSING_EDGE, "has_edge.0->9.false");

	rz_graph_free(g);
	mu_end;
}

static bool test_graph_mem_usage_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, str_hash, free, free);
	mu_assert_eq(rz_graph_mem_usage(g), RZ_GRAPH_MATRIX_DEFAULT_CAPACITY * RZ_GRAPH_MATRIX_DEFAULT_CAPACITY * sizeof(RzGraphEdge *), "Wrong memory usage");
	rz_graph_free(g);
	mu_end;
}

static bool test_graph_node_edge_data_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, str_hash, free, free);

	char nname[2] = { 0 };
	// 10 nodes
	RzGraphNode *nodes[10];
	for (int i = 0; i < 10; i++) {
		nodes[i] = NULL;
		rz_strf(nname, "%d", i);
		mu_assert_eq(rz_graph_add_node(g, rz_str_dup(nname), &nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to add");
		mu_assert_notnull(nodes[i], "add_node");
		mu_assert_eq(rz_graph_add_edge(g, nodes[i], nodes[i], malloc(16)), RZ_GRAPH_STATUS_OK, "Failed to add self-ref edge");
	}
	mu_assert_eq(rz_graph_count_edges(g), 10, "n_edges.10");

	mu_assert_eq(rz_graph_add_edge_by_id(g, str_hash("0"), str_hash("0"), malloc(16)), RZ_GRAPH_STATUS_EXISTED, "add existing edge, data must be freed");
	mu_assert_eq(rz_graph_count_edges(g), 10, "n_edges.10");

	for (int i = 1; i < 10; i++) {
		mu_assert_eq(rz_graph_add_edge(g, nodes[i - 1], nodes[i], malloc(16)), RZ_GRAPH_STATUS_OK, "Failed to add back edge");
	}

	for (int i = 0; i < 10; i++) {
		rz_strf(nname, "%d", i);
		RzGraphNode *n = rz_graph_find_node(g, str_hash(nname));
		mu_assert_notnull(n, "find node");
		mu_assert_streq(rz_graph_node_get_data(n), nname, "Name mismatch");
	}

	for (int i = 0; i < 10; i++) {
		mu_assert_eq(rz_graph_has_edge(g, nodes[i], nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to has self-ref edge");
		if (i != 0) {
			mu_assert_eq(rz_graph_has_edge(g, nodes[i - 1], nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to has back edge");
		}
	}

	mu_assert_eq(rz_graph_del_edge_by_id(g, str_hash("00"), str_hash("0")), RZ_GRAPH_STATUS_OK, "Not existing node.");
	mu_assert_eq(rz_graph_count_edges(g), 19, "n_edges.10");
	mu_assert_eq(rz_graph_del_edge_by_id(g, str_hash("0"), str_hash("0")), RZ_GRAPH_STATUS_EXISTED, "Del edge with data.");
	mu_assert_eq(rz_graph_count_edges(g), 18, "n_edges.9");

	rz_graph_free(g);

	mu_end;
}

static bool test_graph_capacity_realloc_matrix(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, str_hash, free, free);

	char name[32] = { 0 };
	RzGraphNode *nodes[RZ_GRAPH_MATRIX_DEFAULT_CAPACITY + 1];
	// Fill adjacency matrix
	for (size_t i = 0; i < RZ_GRAPH_MATRIX_DEFAULT_CAPACITY; ++i) {
		nodes[i] = NULL;
		rz_strf(name, "%" PFMTSZu, i);
		mu_assert_eq(rz_graph_add_node(g, rz_str_dup(name), &nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to add");
		mu_assert_notnull(nodes[i], "add_node");
	}

	RzGraphNode *ni;
	RzGraphNode *nj;
	// Fill every single edge cell
	for (size_t i = 0; i < RZ_GRAPH_MATRIX_DEFAULT_CAPACITY; ++i) {
		for (size_t j = 0; j < RZ_GRAPH_MATRIX_DEFAULT_CAPACITY; ++j) {
			ni = nodes[i];
			nj = nodes[j];
			rz_strf(name, "%" PFMTSZu "->%" PFMTSZu, i, j);
			mu_assert_eq(rz_graph_add_edge(g, ni, nj, rz_str_dup(name)), RZ_GRAPH_STATUS_OK, "Failed to add i->j");
		}
	}

	// Should reallocate the matrix memory.
	size_t i = RZ_GRAPH_MATRIX_DEFAULT_CAPACITY;
	nodes[i] = NULL;
	rz_strf(name, "%" PFMTSZu, i);
	mu_assert_eq(rz_graph_add_node(g, rz_str_dup(name), &nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to add overflow node");
	// Add edges to the node including a self-ref
	for (size_t j = 0; j <= RZ_GRAPH_MATRIX_DEFAULT_CAPACITY; ++j) {
		ni = nodes[i];
		nj = nodes[j];
		rz_strf(name, "%" PFMTSZu "->%" PFMTSZu, i, j);
		mu_assert_eq(rz_graph_add_edge(g, ni, nj, rz_str_dup(name)), RZ_GRAPH_STATUS_OK, "Failed to add i->j");
		if (i != j) {
			rz_strf(name, "%" PFMTSZu "->%" PFMTSZu, j, i);
			mu_assert_eq(rz_graph_add_edge(g, nj, ni, rz_str_dup(name)), RZ_GRAPH_STATUS_OK, "Failed to add j->i");
		}
	}

	for (size_t i = 0; i <= RZ_GRAPH_MATRIX_DEFAULT_CAPACITY; ++i) {
		rz_strf(name, "%" PFMTSZu, i);
		RzGraphNode *n = rz_graph_find_node(g, str_hash(name));
		mu_assert_notnull(n, "Did not find node");
		const char *nname = rz_graph_node_get_data(n);
		mu_assert_streq(name, nname, "Node name mismatch");

		for (size_t j = 0; j <= RZ_GRAPH_MATRIX_DEFAULT_CAPACITY; ++j) {
			ni = nodes[i];
			nj = nodes[j];
			rz_strf(name, "%" PFMTSZu "->%" PFMTSZu, i, j);
			RzGraphEdge *e = rz_graph_find_edge(g, ni, nj);
			mu_assert_notnull(e, "Failed to find i->j");
			const char *ename = rz_graph_edge_get_data(e);
			mu_assert_streq(name, ename, "Edge name mismatch");

			rz_strf(name, "%" PFMTSZu "->%" PFMTSZu, j, i);
			e = rz_graph_find_edge(g, nj, ni);
			mu_assert_notnull(e, "Failed to find j->i");
			ename = rz_graph_edge_get_data(e);
			mu_assert_streq(name, ename, "Edge name mismatch");
		}
	}

	rz_graph_free(g);

	mu_end;
}

static bool test_graph_impl_equivalence(void) {
	// Create both graphs
	RzGraph *g_list = rz_graph_new(RZ_GRAPH_IMPL_LIST, simple_hash_base, NULL, NULL);
	RzGraph *g_matrix = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, simple_hash_base, NULL, NULL);

	// Add same nodes to both
	RzGraphNode *l_nodes[5], *m_nodes[5];
	for (int i = 0; i < 5; i++) {
		l_nodes[i] = NULL;
		mu_assert_eq(rz_graph_add_node(g_list, RZ_GRAPH_INT_AS_DATA((i + 1)), &l_nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to add");
		m_nodes[i] = NULL;
		mu_assert_eq(rz_graph_add_node(g_matrix, RZ_GRAPH_INT_AS_DATA((i + 1)), &m_nodes[i]), RZ_GRAPH_STATUS_OK, "Failed to add");
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
		rz_graph_has_edge(g_list, l_nodes[0], l_nodes[1]),
		rz_graph_has_edge(g_matrix, m_nodes[0], m_nodes[1]),
		"same has_edge result for 0->1");

	mu_assert_eq(
		rz_graph_has_edge(g_list, l_nodes[1], l_nodes[0]),
		rz_graph_has_edge(g_matrix, m_nodes[1], m_nodes[0]),
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

static RZ_OWN char *node_formatter(const RzGraphNode *n) {
	return rz_str_newf("[label=\"0x%" PFMT64x "\"]", rz_graph_node_get_id(n));
}

static RZ_OWN char *edge_formatter(const RzGraphEdge *e) {
	ut64 d = (utptr)rz_graph_edge_get_data(e);
	return rz_str_newf("[label=%" PFMT64d "]", d);
}

static bool test_graph_as_dot_str(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, NULL, NULL, NULL);
	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(1), &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(2), &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(3), &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

	rz_graph_add_edge(g, n1, n1, RZ_GRAPH_INT_AS_DATA(100));
	rz_graph_add_edge(g, n2, n1, RZ_GRAPH_INT_AS_DATA(200));
	rz_graph_add_edge(g, n3, n1, RZ_GRAPH_INT_AS_DATA(400));

	char *ul_dot = rz_graph_as_dot_str(g, NULL, NULL, NULL);
	const char *ul_expected =
		"digraph {\n"
		"   1 -> 1\n"
		"   2 -> 1\n"
		"   3 -> 1\n"
		"}\n";
	mu_assert_streq(ul_dot, ul_expected, "Mismatch in unlabeled graph result.");
	free(ul_dot);

	char *l_dot = rz_graph_as_dot_str(g, "test", node_formatter, edge_formatter);
	const char *l_expected =
		"digraph \"test\" {\n"
		"   1 [label=\"0x1\"]\n"
		"   1 -> 1 [label=100]\n"
		"   2 [label=\"0x2\"]\n"
		"   2 -> 1 [label=200]\n"
		"   3 [label=\"0x3\"]\n"
		"   3 -> 1 [label=400]\n"
		"}\n";
	mu_assert_streq(l_dot, l_expected, "Mismatch in unlabeled graph result.");
	free(l_dot);

	rz_graph_free(g);
	mu_end;
}

static int all_tests(void) {
	mu_run_test(test_graph_basic);
	// list impl
	mu_run_test(test_graph_nodes);
	mu_run_test(test_graph_edges);
	mu_run_test(test_graph_edge_deletion);
	mu_run_test(test_graph_edge_deletion_multi);
	mu_run_test(test_graph_edges_data_update);
	mu_run_test(test_graph_in_out_edges);
	mu_run_test(test_graph_in_out_neighbors);
	mu_run_test(test_graph_node_deletion);
	mu_run_test(test_graph_reset);
	mu_run_test(test_graph_nth_neighbor);
	mu_run_test(test_graph_dfs);
	mu_run_test(test_graph_get_nodes);
	mu_run_test(test_graph_find_edge);
	mu_run_test(test_graph_complex);
	mu_run_test(test_graph_node_edge_data);

	// matrix impl
	mu_run_test(test_graph_nodes_matrix);
	mu_run_test(test_graph_edges_matrix);
	mu_run_test(test_graph_edge_deletion_matrix);
	mu_run_test(test_graph_edge_deletion_multi_matrix);
	mu_run_test(test_graph_edges_data_update_matrix);
	mu_run_test(test_graph_in_out_edges_matrix);
	mu_run_test(test_graph_in_out_neighbors_matrix);
	mu_run_test(test_graph_node_deletion_matrix);
	mu_run_test(test_graph_reset_matrix);
	mu_run_test(test_graph_nth_neighbor_matrix);
	mu_run_test(test_graph_dfs_matrix);
	mu_run_test(test_graph_get_nodes_matrix);
	mu_run_test(test_graph_find_edge_matrix);
	mu_run_test(test_graph_complex_matrix);
	mu_run_test(test_graph_node_edge_data_matrix);
	mu_run_test(test_graph_mem_usage_matrix);

	mu_run_test(test_graph_capacity_realloc_matrix);

	mu_run_test(test_graph_impl_equivalence);

	mu_run_test(test_graph_as_dot_str);

	return tests_passed != tests_run;
}

mu_main(all_tests)

#undef BASE
