// SPDX-FileCopyrightText: 2025-2026 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include "rz_util/rz_graph.h"

// Basic block node data structure
typedef struct bb_data {
	ut64 bb_id;
	char *bb_name; // Name of the basic block (e.g., "bb_entry", "bb_loop_header")
	ut64 entry_addr; // Entry address of the basic block
	ut64 size; // Size of the basic block in bytes
	ut64 *instruction_ids; // Array of instruction IDs (optional)
	ut32 n_instructions; // Number of instructions
} BasicBlockNodeData;

// Edge decorator for CFG edges
typedef struct edge_decorator {
	ut8 edge_type; // 0: fallthrough, 1: conditional_true, 2: conditional_false, 3: jump
	char *condition; // Optional condition string (e.g., "n <= 0", "i % 2 == 0")
} EdgeData;

// Edge types
#define EDGE_TYPE_FALLTHROUGH 0
#define EDGE_TYPE_COND_TRUE   1
#define EDGE_TYPE_COND_FALSE  2
#define EDGE_TYPE_JUMP        3

static void bb_data_free(void *data) {
	BasicBlockNodeData *bb = (BasicBlockNodeData *)data;
	if (!bb) {
		return;
	}

	if (bb->bb_name) {
		free(bb->bb_name);
		bb->bb_name = NULL;
	}

	if (bb->instruction_ids) {
		free(bb->instruction_ids);
		bb->instruction_ids = NULL;
	}

	free(bb);
}

static void edge_decorator_free(void *data) {
	EdgeData *edge = (EdgeData *)data;
	if (!edge) {
		return;
	}

	if (edge->condition) {
		free(edge->condition);
		edge->condition = NULL;
	}

	free(edge);
}

// DJB2 hash
static ut64 string_hash(const char *data) {
	const char *str = (const char *)data;
	ut64 hash = 5381;
	int c;

	while ((c = *str++)) {
		hash = ((hash << 5) + hash) + c; // hash * 33 + c
	}

	return hash;
}

static ut64 node_hash(const void *data) {
	const BasicBlockNodeData *n = data;
	return string_hash(n->bb_name);
}

static BasicBlockNodeData *create_bb_data(const char *name, ut64 bb_id, ut64 entry_addr, ut64 size) {
	BasicBlockNodeData *bb = RZ_NEW0(BasicBlockNodeData);
	if (!bb) {
		return NULL;
	}

	bb->bb_name = rz_str_dup(name);
	bb->bb_id = bb_id;
	bb->entry_addr = entry_addr;
	bb->size = size;
	bb->n_instructions = 0;
	bb->instruction_ids = NULL;

	return bb;
}

static EdgeData *create_edge_data(ut8 edge_type, const char *condition) {
	EdgeData *edge = RZ_NEW0(EdgeData);
	if (!edge) {
		return NULL;
	}

	edge->edge_type = edge_type;
	edge->condition = condition ? strdup(condition) : NULL;

	return edge;
}

// Test basic CFG creation with string identifiers
static bool test_cfg_basic(void) {
	RzGraph *cfg = rz_graph_new(RZ_GRAPH_IMPL_LIST, node_hash, bb_data_free, edge_decorator_free);
	mu_assert_notnull(cfg, "cfg creation");

	// Create basic blocks
	BasicBlockNodeData *bb_entry = create_bb_data("bb_entry", 1, 0x1000, 16);
	BasicBlockNodeData *bb_ret = create_bb_data("bb_return", 2, 0x1010, 8);

	mu_assert_notnull(bb_entry, "bb_entry creation");
	mu_assert_notnull(bb_ret, "bb_ret creation");

	// Add nodes to CFG
	RzGraphNode *node_entry = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_entry, &node_entry), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *node_ret = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_ret, &node_ret), RZ_GRAPH_STATUS_OK, "Failed to add");

	mu_assert_notnull(node_entry, "add node_entry");
	mu_assert_notnull(node_ret, "add node_ret");
	mu_assert_eq(rz_graph_count_nodes(cfg), 2, "n_nodes");

	// Add edge
	EdgeData *edge_data = create_edge_data(EDGE_TYPE_FALLTHROUGH, NULL);
	bool success = rz_graph_add_edge(cfg, node_entry, node_ret, edge_data);
	mu_assert_true(success, "add edge");
	mu_assert_eq(rz_graph_count_edges(cfg), 1, "n_edges");

	// Test node lookup by name
	RzGraphNode *found = rz_graph_find_node(cfg, string_hash("bb_entry"));
	mu_assert_ptreq(found, node_entry, "find bb_entry");

	found = rz_graph_find_node(cfg, string_hash("bb_return"));
	mu_assert_ptreq(found, node_ret, "find bb_return");

	rz_graph_free(cfg);
	mu_end;
}

/**
 *
 * int foo(int n) {
 *     int sum = 0;              // bb_entry
 *     if (n <= 0) {             // bb_check_n
 *         return 0;             // bb_ret_zero
 *     }
 *     for (int i = 0; i < n; i++) {  // bb_loop_init -> bb_loop_cond
 *         if (i % 2 == 0) {          // bb_loop_body_check
 *             sum += i;              // bb_even
 *         } else {
 *             sum += 1;              // bb_odd
 *         }
 *         if (sum > 100) {           // bb_check_sum (merge point)
 *             break;                 // -> bb_ret_sum
 *         }
 *     }                              // bb_loop_inc -> bb_loop_cond
 *     return sum;                    // bb_ret_sum
 * }
 * CFG Basic Blocks (11 blocks, 13 edges):
 *
 * ID=0  bb_entry
 * ID=1  bb_check_n
 * ID=2  bb_ret_zero
 * ID=3  bb_loop_init
 * ID=4  bb_loop_cond
 * ID=5  bb_loop_body_check
 * ID=6  bb_even
 * ID=7  bb_odd
 * ID=8  bb_check_sum
 * ID=9  bb_loop_inc
 * ID=10 bb_ret_sum
 *
 *  0. entry -> check_n              (fallthrough)
 *  1. check_n -> ret_zero           (true: n <= 0)
 *  2. check_n -> loop_init          (false: n > 0)
 *  3. loop_init -> loop_cond        (fallthrough)
 *  4. loop_cond -> loop_body_check  (true: i < n)
 *  5. loop_cond -> ret_sum          (false: i >= n, loop exit)
 *  6. loop_body_check -> even       (true: i % 2 == 0)
 *  7. loop_body_check -> odd        (false: i % 2 != 0)
 *  8. even -> check_sum             (fallthrough)
 *  9. odd -> check_sum              (fallthrough)
 * 10. check_sum -> ret_sum          (true: sum > 100, break)
 * 11. check_sum -> loop_inc         (false: sum <= 100)
 * 12. loop_inc -> loop_cond         (fallthrough, back edge)
 */
static bool test_cfg_foo_function(void) {
	RzGraph *cfg = rz_graph_new(RZ_GRAPH_IMPL_LIST, node_hash, bb_data_free, edge_decorator_free);
	mu_assert_notnull(cfg, "cfg creation");

	// Create basic blocks for foo function
	BasicBlockNodeData *bb_entry = create_bb_data("bb_entry", 0, 0x1000, 8);
	BasicBlockNodeData *bb_check_n = create_bb_data("bb_check_n", 1, 0x1008, 12);
	BasicBlockNodeData *bb_ret_zero = create_bb_data("bb_ret_zero", 2, 0x1014, 8);
	BasicBlockNodeData *bb_loop_init = create_bb_data("bb_loop_init", 3, 0x101c, 8);
	BasicBlockNodeData *bb_loop_cond = create_bb_data("bb_loop_cond", 4, 0x1024, 12);
	BasicBlockNodeData *bb_loop_body_check = create_bb_data("bb_loop_body_check", 5, 0x1030, 12);
	BasicBlockNodeData *bb_even = create_bb_data("bb_even", 6, 0x103c, 8);
	BasicBlockNodeData *bb_odd = create_bb_data("bb_odd", 7, 0x1044, 8);
	BasicBlockNodeData *bb_check_sum = create_bb_data("bb_check_sum", 8, 0x104c, 12);
	BasicBlockNodeData *bb_loop_inc = create_bb_data("bb_loop_inc", 9, 0x1058, 8);
	BasicBlockNodeData *bb_ret_sum = create_bb_data("bb_ret_sum", 10, 0x1060, 8);

	// Add nodes to CFG
	RzGraphNode *n_entry = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_entry, &n_entry), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_check_n = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_check_n, &n_check_n), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_ret_zero = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_ret_zero, &n_ret_zero), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_loop_init = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_loop_init, &n_loop_init), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_loop_cond = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_loop_cond, &n_loop_cond), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_loop_body_check = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_loop_body_check, &n_loop_body_check), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_even = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_even, &n_even), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_odd = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_odd, &n_odd), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_check_sum = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_check_sum, &n_check_sum), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_loop_inc = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_loop_inc, &n_loop_inc), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_ret_sum = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_ret_sum, &n_ret_sum), RZ_GRAPH_STATUS_OK, "Failed to add");

	mu_assert_eq(rz_graph_count_nodes(cfg), 11, "n_nodes");

	// Build CFG edges
	// bb_entry -> bb_check_n (fallthrough)
	rz_graph_add_edge(cfg, n_entry, n_check_n,
		create_edge_data(EDGE_TYPE_FALLTHROUGH, NULL));

	// bb_check_n -> bb_ret_zero (n <= 0, true)
	rz_graph_add_edge(cfg, n_check_n, n_ret_zero,
		create_edge_data(EDGE_TYPE_COND_TRUE, "n <= 0"));

	// bb_check_n -> bb_loop_init (n > 0, false)
	rz_graph_add_edge(cfg, n_check_n, n_loop_init,
		create_edge_data(EDGE_TYPE_COND_FALSE, "n > 0"));

	// bb_loop_init -> bb_loop_cond (fallthrough)
	rz_graph_add_edge(cfg, n_loop_init, n_loop_cond,
		create_edge_data(EDGE_TYPE_FALLTHROUGH, NULL));

	// bb_loop_cond -> bb_loop_body_check (i < n, true)
	rz_graph_add_edge(cfg, n_loop_cond, n_loop_body_check,
		create_edge_data(EDGE_TYPE_COND_TRUE, "i < n"));

	// bb_loop_cond -> bb_ret_sum (i >= n, false - loop exit)
	rz_graph_add_edge(cfg, n_loop_cond, n_ret_sum,
		create_edge_data(EDGE_TYPE_COND_FALSE, "i >= n"));

	// bb_loop_body_check -> bb_even (i % 2 == 0, true)
	rz_graph_add_edge(cfg, n_loop_body_check, n_even,
		create_edge_data(EDGE_TYPE_COND_TRUE, "i % 2 == 0"));

	// bb_loop_body_check -> bb_odd (i % 2 != 0, false)
	rz_graph_add_edge(cfg, n_loop_body_check, n_odd,
		create_edge_data(EDGE_TYPE_COND_FALSE, "i % 2 != 0"));

	// bb_even -> bb_check_sum (fallthrough)
	rz_graph_add_edge(cfg, n_even, n_check_sum,
		create_edge_data(EDGE_TYPE_FALLTHROUGH, NULL));

	// bb_odd -> bb_check_sum (fallthrough)
	rz_graph_add_edge(cfg, n_odd, n_check_sum,
		create_edge_data(EDGE_TYPE_FALLTHROUGH, NULL));

	// bb_check_sum -> bb_ret_sum (sum > 100, true - break)
	rz_graph_add_edge(cfg, n_check_sum, n_ret_sum,
		create_edge_data(EDGE_TYPE_COND_TRUE, "sum > 100"));

	// bb_check_sum -> bb_loop_inc (sum <= 100, false)
	rz_graph_add_edge(cfg, n_check_sum, n_loop_inc,
		create_edge_data(EDGE_TYPE_COND_FALSE, "sum <= 100"));

	// bb_loop_inc -> bb_loop_cond (fallthrough - back edge)
	rz_graph_add_edge(cfg, n_loop_inc, n_loop_cond,
		create_edge_data(EDGE_TYPE_FALLTHROUGH, NULL));

	mu_assert_eq(rz_graph_count_edges(cfg), 13, "n_edges");

	// verify some critical one
	mu_assert_true(rz_graph_has_edge(cfg, n_entry, n_check_n), "edge: entry->check_n");
	mu_assert_true(rz_graph_has_edge(cfg, n_loop_inc, n_loop_cond), "edge: loop_inc->loop_cond (back edge)");
	mu_assert_true(rz_graph_has_edge(cfg, n_check_sum, n_ret_sum), "edge: check_sum->ret_sum (break)");

	// verify out-neighbors of bb_check_n (should have 2)
	RzIterator *it = rz_graph_out_neighbors(cfg, n_check_n);
	int count = 0;
	RzGraphNode *neighbor;
	rz_iterator_foreach(it, neighbor) {
		count++;
	}
	rz_iterator_free(it);
	mu_assert_eq(count, 2, "bb_check_n out-neighbors");

	// verify in-neighbors of bb_check_sum (should have 2: bb_even and bb_odd)
	it = rz_graph_in_neighbors(cfg, n_check_sum);
	count = 0;
	rz_iterator_foreach(it, neighbor) {
		count++;
	}
	rz_iterator_free(it);
	mu_assert_eq(count, 2, "bb_check_sum in-neighbors");

	// verify in-neighbors of bb_loop_cond (should have 2: bb_loop_init and bb_loop_inc)
	it = rz_graph_in_neighbors(cfg, n_loop_cond);
	count = 0;
	rz_iterator_foreach(it, neighbor) {
		count++;
	}
	rz_iterator_free(it);
	mu_assert_eq(count, 2, "bb_loop_cond in-neighbors (includes back edge)");

	rz_graph_free(cfg);
	mu_end;
}

// Test edge data retrieval
static bool test_cfg_edge_data(void) {
	RzGraph *cfg = rz_graph_new(RZ_GRAPH_IMPL_LIST, node_hash, bb_data_free, edge_decorator_free);

	BasicBlockNodeData *bb1 = create_bb_data("bb1", 1, 0x1000, 16);
	BasicBlockNodeData *bb2 = create_bb_data("bb2", 2, 0x1010, 16);
	BasicBlockNodeData *bb3 = create_bb_data("bb3", 3, 0x1020, 16);

	RzGraphNode *n1 = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb1, &n1), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n2 = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb2, &n2), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n3 = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb3, &n3), RZ_GRAPH_STATUS_OK, "Failed to add");

	EdgeData *edge1 = create_edge_data(EDGE_TYPE_COND_TRUE, "x > 0");
	EdgeData *edge2 = create_edge_data(EDGE_TYPE_COND_FALSE, "x <= 0");

	rz_graph_add_edge(cfg, n1, n2, edge1);
	rz_graph_add_edge(cfg, n1, n3, edge2);

	RzGraphEdge *found_edge = rz_graph_find_edge(cfg, n1, n2);
	mu_assert_notnull(found_edge, "find edge 1->2");

	const EdgeData *data = (const EdgeData *)rz_graph_edge_get_data(found_edge);
	mu_assert_notnull(data, "edge data not null");
	mu_assert_eq(data->edge_type, EDGE_TYPE_COND_TRUE, "edge type");
	mu_assert_streq(data->condition, "x > 0", "edge condition");

	found_edge = rz_graph_find_edge(cfg, n1, n3);
	mu_assert_notnull(found_edge, "find edge 1->3");

	data = (const EdgeData *)rz_graph_edge_get_data(found_edge);
	mu_assert_eq(data->edge_type, EDGE_TYPE_COND_FALSE, "edge type false");
	mu_assert_streq(data->condition, "x <= 0", "edge condition false");

	rz_graph_free(cfg);
	mu_end;
}

static void tmp_discover(RzGraphNode *n, RzGraphVisitor *v) {
	BasicBlockNodeData *bb = (BasicBlockNodeData *)rz_graph_node_get_data_mut(n);
	rz_list_append((RzList *)v->visitor_data, (void *)(size_t)bb->bb_id);
}

// Test DFS on CFG
static bool test_cfg_dfs(void) {
	RzGraph *cfg = rz_graph_new(RZ_GRAPH_IMPL_LIST, node_hash, bb_data_free, edge_decorator_free);

	// Create a simple CFG
	BasicBlockNodeData *bb_entry = create_bb_data("entry", 0, 0x1000, 8);
	BasicBlockNodeData *bb_if_true = create_bb_data("if_true", 1, 0x1008, 8);
	BasicBlockNodeData *bb_if_false = create_bb_data("if_false", 2, 0x1010, 8);
	BasicBlockNodeData *bb_merge = create_bb_data("merge", 3, 0x1018, 8);
	BasicBlockNodeData *bb_exit = create_bb_data("exit", 4, 0x1020, 8);

	RzGraphNode *n_entry = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_entry, &n_entry), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_if_true = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_if_true, &n_if_true), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_if_false = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_if_false, &n_if_false), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_merge = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_merge, &n_merge), RZ_GRAPH_STATUS_OK, "Failed to add");
	RzGraphNode *n_exit = NULL;
	mu_assert_eq(rz_graph_add_node(cfg, bb_exit, &n_exit), RZ_GRAPH_STATUS_OK, "Failed to add");

	// Build CFG
	rz_graph_add_edge(cfg, n_entry, n_if_true, create_edge_data(EDGE_TYPE_COND_TRUE, NULL));
	rz_graph_add_edge(cfg, n_entry, n_if_false, create_edge_data(EDGE_TYPE_COND_FALSE, NULL));
	rz_graph_add_edge(cfg, n_if_true, n_merge, create_edge_data(EDGE_TYPE_FALLTHROUGH, NULL));
	rz_graph_add_edge(cfg, n_if_false, n_merge, create_edge_data(EDGE_TYPE_FALLTHROUGH, NULL));
	rz_graph_add_edge(cfg, n_merge, n_exit, create_edge_data(EDGE_TYPE_FALLTHROUGH, NULL));

	// Perform DFS with counting visitor
	RzList *visited = rz_list_new();

	RzGraphVisitor vis = { 0 };
	vis.visitor_data = visited;
	vis.discover_node = tmp_discover;
	rz_graph_dfs_from_node(cfg, n_entry, &vis);

	// All 5 nodes should be discovered
	mu_assert_eq(rz_list_length(visited), 5, "dfs discover count");

	rz_list_free(visited);
	rz_graph_free(cfg);
	mu_end;
}

// Test string hash collisions (edge case)
static bool test_string_hash_lookup(void) {
	RzGraph *cfg = rz_graph_new(RZ_GRAPH_IMPL_LIST, node_hash, bb_data_free, edge_decorator_free);

	// Add several nodes with different names
	const char *names[] = {
		"bb_entry", "bb_loop", "bb_exit", "bb_return",
		"bb_if_true", "bb_if_false", "bb_merge", "bb_call"
	};

	for (int i = 0; i < 8; i++) {
		BasicBlockNodeData *bb = create_bb_data(names[i], i, 0x1000 + i * 16, 16);
		RzGraphNode *n = NULL;
		mu_assert_eq(rz_graph_add_node(cfg, bb, &n), RZ_GRAPH_STATUS_OK, "Failed to add");
		mu_assert_notnull(n, "add node");
	}

	mu_assert_eq(rz_graph_count_nodes(cfg), 8, "n_nodes");

	// Verify all nodes can be found by name
	for (int i = 0; i < 8; i++) {
		RzGraphNode *found = rz_graph_find_node(cfg, string_hash(names[i]));
		mu_assert_notnull(found, "find node by name");

		const BasicBlockNodeData *data = (const BasicBlockNodeData *)rz_graph_node_get_data(found);
		mu_assert_streq(data->bb_name, names[i], "node name matches");
	}

	rz_graph_free(cfg);
	mu_end;
}

static int all_tests(void) {
	// CFG case
	mu_run_test(test_cfg_basic);
	mu_run_test(test_cfg_foo_function);
	mu_run_test(test_cfg_edge_data);
	mu_run_test(test_cfg_dfs);
	mu_run_test(test_string_hash_lookup);

	return tests_passed != tests_run;
}

mu_main(all_tests)
