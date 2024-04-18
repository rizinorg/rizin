// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static void topo_sorting(RzGraphNode *n, RzGraphVisitor *vis) {
	RzList *order = (RzList *)vis->data;
	rz_list_prepend(order, n);
}

#define check_list(act, exp, descr) \
	do { \
		RzListIter *ita = rz_list_iterator(act); \
		RzListIter *ite = rz_list_iterator(exp); \
		int diff = 0; \
		while (rz_list_iter_next(ita) && rz_list_iter_next(ite)) { \
			int a = (int)(size_t)rz_list_iter_get(ita); \
			int e = (int)(size_t)rz_list_iter_get(ite); \
			if (a != e) { \
				eprintf("[-][%s] test failed (actual: %d; expected: %d)\n", descr, a, e); \
				diff = 1; \
			} \
		} \
		mu_assert_false(ita || ite || diff, "(one list shorter or different)"); \
	} while (0)

static bool test_legacy_graph(void) {
	RzGraph *g = rz_graph_new();

	mu_assert_eq(g->n_nodes, 0, "n_nodes.start");
	rz_graph_add_node(g, (void *)1);
	mu_assert_eq(g->n_nodes, 1, "n_nodes.insert");
	rz_graph_reset(g);
	mu_assert_eq(g->n_nodes, 0, "n_nodes.reset");

	RzGraphNode *gn = rz_graph_add_node(g, (void *)1);
	mu_assert_ptreq(rz_graph_get_node(g, gn->idx), gn, "get_node.1");
	RzGraphNode *gn2 = rz_graph_add_node(g, (void *)2);
	mu_assert_ptreq(rz_graph_get_node(g, gn2->idx), gn2, "get_node.2");
	rz_graph_add_edge(g, gn, gn2);
	mu_assert_true(rz_graph_adjacent(g, gn, gn2), "is_adjacent.1");
	RzList *exp_gn_neigh = rz_list_new();
	rz_list_append(exp_gn_neigh, gn2);
	check_list(rz_graph_get_neighbours(g, gn), exp_gn_neigh, "get_neighbours.1");

	RzGraphNode *gn3 = rz_graph_add_node(g, (void *)3);
	rz_graph_add_edge(g, gn, gn3);
	rz_list_append(exp_gn_neigh, gn3);
	check_list(rz_graph_get_neighbours(g, gn), exp_gn_neigh, "get_neighbours.2");
	rz_list_free(exp_gn_neigh);

	RzGraphNode *gn4 = rz_graph_add_node(g, (void *)4);
	RzGraphNode *gn5 = rz_graph_add_node(g, (void *)5);
	RzGraphNode *gn6 = rz_graph_add_node(g, (void *)6);
	RzGraphNode *gn7 = rz_graph_add_node(g, (void *)7);
	RzGraphNode *gn8 = rz_graph_add_node(g, (void *)8);
	RzGraphNode *gn9 = rz_graph_add_node(g, (void *)9);
	RzGraphNode *gn10 = rz_graph_add_node(g, (void *)10);
	RzList *exp_nodes = rz_list_new();
	rz_list_append(exp_nodes, gn);
	rz_list_append(exp_nodes, gn2);
	rz_list_append(exp_nodes, gn3);
	rz_list_append(exp_nodes, gn4);
	rz_list_append(exp_nodes, gn5);
	rz_list_append(exp_nodes, gn6);
	rz_list_append(exp_nodes, gn7);
	rz_list_append(exp_nodes, gn8);
	rz_list_append(exp_nodes, gn9);
	rz_list_append(exp_nodes, gn10);
	const RzList *nodes = rz_graph_get_nodes(g);
	mu_assert_eq(g->n_nodes, 10, "n_nodes.again");
	check_list(nodes, exp_nodes, "get_all_nodes");
	rz_list_free(exp_nodes);

	rz_graph_add_edge(g, gn2, gn3);
	rz_graph_add_edge(g, gn2, gn4);
	rz_graph_add_edge(g, gn2, gn5);
	rz_graph_add_edge(g, gn3, gn5);
	rz_graph_add_edge(g, gn5, gn7);
	rz_graph_add_edge(g, gn7, gn9);
	rz_graph_add_edge(g, gn9, gn10);
	rz_graph_add_edge(g, gn4, gn6);
	rz_graph_add_edge(g, gn6, gn8);
	rz_graph_add_edge(g, gn6, gn9);
	rz_graph_add_edge(g, gn8, gn10);

	rz_graph_add_edge(g, gn5, gn4);
	rz_graph_add_edge(g, gn6, gn7);
	rz_graph_add_edge(g, gn7, gn8);
	rz_graph_add_edge(g, gn8, gn9);
	mu_assert_eq(g->n_edges, 17, "n_edges");
	rz_graph_add_edge(g, gn8, gn9);
	mu_assert_eq(g->n_edges, 17, "n_edges");
	rz_graph_del_edge(g, gn8, gn9);
	mu_assert_eq(rz_graph_adjacent(g, gn8, gn9), false, "is_adjacent.0");
	mu_assert_eq(g->n_edges, 16, "n_edges.1");
	rz_graph_add_edge(g, gn9, gn8);
	mu_assert_eq(g->n_edges, 17, "n_edges.2");
	mu_assert_eq(rz_graph_adjacent(g, gn9, gn8), true, "is_adjacent");
	rz_graph_del_edge(g, gn9, gn8);
	rz_graph_add_edge(g, gn8, gn9);
	mu_assert_eq(rz_graph_adjacent(g, gn9, gn8), false, "is_adjacent.1");
	mu_assert_eq(rz_graph_adjacent(g, gn8, gn9), true, "is_adjacent.2");

	RzGraphVisitor vis = { 0 };
	vis.data = rz_list_new();
	vis.finish_node = (RzGraphNodeCallback)topo_sorting;
	rz_graph_dfs_node(g, gn, &vis);
	RzList *exp_order = rz_list_new();
	rz_list_append(exp_order, gn);
	rz_list_append(exp_order, gn2);
	rz_list_append(exp_order, gn3);
	rz_list_append(exp_order, gn5);
	rz_list_append(exp_order, gn4);
	rz_list_append(exp_order, gn6);
	rz_list_append(exp_order, gn7);
	rz_list_append(exp_order, gn8);
	rz_list_append(exp_order, gn9);
	rz_list_append(exp_order, gn10);
	check_list((RzList *)vis.data, exp_order, "topo_order");
	rz_list_free(exp_order);
	rz_list_free((RzList *)vis.data);

	RzList *exp_innodes = rz_list_new();
	rz_list_append(exp_innodes, gn);
	rz_list_append(exp_innodes, gn2);
	check_list(rz_graph_innodes(g, gn3), exp_innodes, "in_nodes");
	rz_list_free(exp_innodes);
	RzList *exp_allnodes = rz_list_new();
	rz_list_append(exp_allnodes, gn);
	rz_list_append(exp_allnodes, gn2);
	rz_list_append(exp_allnodes, gn5);
	check_list(rz_graph_all_neighbours(g, gn3), exp_allnodes, "in/out_nodes");
	rz_list_free(exp_allnodes);

	rz_graph_del_node(g, gn);
	rz_graph_del_node(g, gn2);
	mu_assert_eq(g->n_nodes, 8, "n_nodes.del_node");
	mu_assert_eq(g->n_edges, 12, "n_edges.del_node");

	// Test invalid removal
	rz_graph_del_node(g, NULL);
	RzGraphNode dummy = { 0 };
	rz_graph_del_node(g, &dummy);

	rz_graph_free(g);
	mu_end;
}

static int all_tests() {
	mu_run_test(test_legacy_graph);
	return tests_passed != tests_run;
}

mu_main(all_tests)