// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static ut64 ptr_hash(const void *data) {
	return (ut64)(uintptr_t)data;
}

static void topo_sorting(RzGraphNode *n, RzGraphVisitor *vis) {
	RzList *order = (RzList *)vis->visitor_data;
	rz_list_prepend(order, n);
}

static bool test_legacy_graph(void) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, ptr_hash, NULL, NULL);

	mu_assert_eq(rz_graph_count_nodes(g), 0, "n_nodes.start");
	mu_assert_eq(rz_graph_add_node(g, (void *)1, NULL), RZ_GRAPH_STATUS_OK, "Failed add");
	mu_assert_eq(rz_graph_count_nodes(g), 1, "n_nodes.insert");
	rz_graph_reset(g);
	mu_assert_eq(rz_graph_count_nodes(g), 0, "n_nodes.reset");

	RzGraphNode *gn = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)1, &gn), RZ_GRAPH_STATUS_OK, "Failed add");
	mu_assert_ptreq(rz_graph_find_node(g, rz_graph_node_get_id(gn)), gn, "get_node.1");
	RzGraphNode *gn2 = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)2, &gn2), RZ_GRAPH_STATUS_OK, "Failed add");
	mu_assert_ptreq(rz_graph_find_node(g, rz_graph_node_get_id(gn2)), gn2, "get_node.2");
	rz_graph_add_edge(g, gn, gn2, NULL);
	mu_assert_true(rz_graph_has_edge(g, gn, gn2), "is_adjacent.1");

	// Check out-neighbors of gn: should contain gn2
	{
		RzIterator *it = rz_graph_out_neighbors(g, gn);
		mu_assert_notnull(it, "get_neighbours.1.iter");
		int count = 0;
		RzGraphNode *nb;
		rz_iterator_foreach(it, nb) {
			mu_assert_ptreq(nb, gn2, "get_neighbours.1");
			count++;
		}
		mu_assert_eq(count, 1, "get_neighbours.1.count");
		rz_iterator_free(it);
	}

	RzGraphNode *gn3 = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)3, &gn3), RZ_GRAPH_STATUS_OK, "Failed add");
	rz_graph_add_edge(g, gn, gn3, NULL);

	// Check out-neighbors of gn: gn2 and gn3
	{
		RzIterator *it = rz_graph_out_neighbors(g, gn);
		mu_assert_notnull(it, "get_neighbours.2.iter");
		int count = 0;
		RzGraphNode *nb;
		rz_iterator_foreach(it, nb) {
			mu_assert_true(nb == gn2 || nb == gn3, "get_neighbours.2");
			count++;
		}
		mu_assert_eq(count, 2, "get_neighbours.2.count");
		rz_iterator_free(it);
	}

	RzGraphNode *gn4 = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)4, &gn4), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *gn5 = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)5, &gn5), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *gn6 = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)6, &gn6), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *gn7 = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)7, &gn7), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *gn8 = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)8, &gn8), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *gn9 = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)9, &gn9), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *gn10 = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)10, &gn10), RZ_GRAPH_STATUS_OK, "Failed add");
	mu_assert_eq(rz_graph_count_nodes(g), 10, "n_nodes.again");

	// Check all nodes are present
	{
		RzIterator *it = rz_graph_get_nodes(g);
		mu_assert_notnull(it, "get_all_nodes.iter");
		int count = 0;
		RzGraphNode *nd;
		rz_iterator_foreach(it, nd) {
			count++;
		}
		mu_assert_eq(count, 10, "get_all_nodes.count");
		rz_iterator_free(it);
	}

	rz_graph_add_edge(g, gn2, gn3, NULL);
	rz_graph_add_edge(g, gn2, gn4, NULL);
	rz_graph_add_edge(g, gn2, gn5, NULL);
	rz_graph_add_edge(g, gn3, gn5, NULL);
	rz_graph_add_edge(g, gn5, gn7, NULL);
	rz_graph_add_edge(g, gn7, gn9, NULL);
	rz_graph_add_edge(g, gn9, gn10, NULL);
	rz_graph_add_edge(g, gn4, gn6, NULL);
	rz_graph_add_edge(g, gn6, gn8, NULL);
	rz_graph_add_edge(g, gn6, gn9, NULL);
	rz_graph_add_edge(g, gn8, gn10, NULL);

	rz_graph_add_edge(g, gn5, gn4, NULL);
	rz_graph_add_edge(g, gn6, gn7, NULL);
	rz_graph_add_edge(g, gn7, gn8, NULL);
	rz_graph_add_edge(g, gn8, gn9, NULL);
	mu_assert_eq(rz_graph_count_edges(g), 17, "n_edges");
	rz_graph_del_edge(g, gn8, gn9);
	mu_assert_eq(rz_graph_has_edge(g, gn8, gn9), false, "is_adjacent.0");
	mu_assert_eq(rz_graph_count_edges(g), 16, "n_edges.1");
	rz_graph_add_edge(g, gn9, gn8, NULL);
	mu_assert_eq(rz_graph_count_edges(g), 17, "n_edges.2");
	mu_assert_eq(rz_graph_has_edge(g, gn9, gn8), true, "is_adjacent");
	rz_graph_del_edge(g, gn9, gn8);
	rz_graph_add_edge(g, gn8, gn9, NULL);
	mu_assert_eq(rz_graph_has_edge(g, gn9, gn8), false, "is_adjacent.1");
	mu_assert_eq(rz_graph_has_edge(g, gn8, gn9), true, "is_adjacent.2");

	RzGraphVisitor vis = { 0 };
	vis.visitor_data = rz_list_new();
	vis.finish_node = topo_sorting;
	rz_graph_dfs_from_node(g, gn, &vis);
	mu_assert_eq(rz_list_length((RzList *)vis.visitor_data), 10, "topo_order.count");
	rz_list_free((RzList *)vis.visitor_data);

	// Check in-neighbors of gn3: gn and gn2
	{
		RzIterator *it = rz_graph_in_neighbors(g, gn3);
		mu_assert_notnull(it, "in_nodes.iter");
		int count = 0;
		RzGraphNode *nb;
		rz_iterator_foreach(it, nb) {
			mu_assert_true(nb == gn || nb == gn2, "in_nodes");
			count++;
		}
		mu_assert_eq(count, 2, "in_nodes.count");
		rz_iterator_free(it);
	}

	// All neighbors of gn3: in={gn, gn2} + out={gn5}
	{
		int count = 0;
		RzGraphNode *nb;
		RzIterator *it = rz_graph_in_neighbors(g, gn3);
		rz_iterator_foreach(it, nb) {
			mu_assert_true(nb == gn || nb == gn2, "all_neighbours.in");
			count++;
		}
		rz_iterator_free(it);
		it = rz_graph_out_neighbors(g, gn3);
		rz_iterator_foreach(it, nb) {
			mu_assert_ptreq(nb, gn5, "all_neighbours.out");
			count++;
		}
		rz_iterator_free(it);
		mu_assert_eq(count, 3, "all_neighbours.count");
	}

	mu_assert_eq(rz_graph_del_node(g, gn), RZ_GRAPH_STATUS_EXISTED, "Wrong return value");
	mu_assert_eq(rz_graph_del_node(g, gn2), RZ_GRAPH_STATUS_EXISTED, "Wrong return value");
	mu_assert_eq(rz_graph_count_nodes(g), 8, "n_nodes.del_node");
	mu_assert_eq(rz_graph_count_edges(g), 12, "n_edges.del_node");

	rz_graph_free(g);
	mu_end;
}

/* =========================================================================
 * Tests for rz_graph_find_back_edges
 * ========================================================================= */

static bool test_find_back_edges_simple(void) {
	/* A -> B -> C -> A  (single cycle, back edge = C->A) */
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, ptr_hash, NULL, NULL);
	RzGraphNode *a = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)1, &a), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *b = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)2, &b), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *c = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)3, &c), RZ_GRAPH_STATUS_OK, "Failed add");
	rz_graph_add_edge(g, a, b, NULL);
	rz_graph_add_edge(g, b, c, NULL);
	rz_graph_add_edge(g, c, a, NULL);

	RzList *back = rz_graph_find_back_edges(g, NULL, NULL);
	mu_assert_notnull(back, "back_edges not null");
	mu_assert_eq(rz_list_length(back), 1, "one back edge");
	RzGraphEdge *e = rz_list_get_n(back, 0);
	mu_assert_ptreq(rz_graph_edge_get_from(e), c, "back edge from C");
	mu_assert_ptreq(rz_graph_edge_get_to(e), a, "back edge to A");
	rz_list_free(back);

	rz_graph_free(g);
	mu_end;
}

static bool test_find_back_edges_dag(void) {
	/* DAG: A->B, A->C, B->D, C->D — no back edges */
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, ptr_hash, NULL, NULL);
	RzGraphNode *a = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)1, &a), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *b = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)2, &b), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *c = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)3, &c), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *d = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)4, &d), RZ_GRAPH_STATUS_OK, "Failed add");
	rz_graph_add_edge(g, a, b, NULL);
	rz_graph_add_edge(g, a, c, NULL);
	rz_graph_add_edge(g, b, d, NULL);
	rz_graph_add_edge(g, c, d, NULL);

	RzList *back = rz_graph_find_back_edges(g, NULL, NULL);
	mu_assert_notnull(back, "back_edges not null");
	mu_assert_eq(rz_list_length(back), 0, "no back edges in DAG");
	rz_list_free(back);

	rz_graph_free(g);
	mu_end;
}

static bool test_find_back_edges_self_loop(void) {
	/* A -> A  (self loop) */
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, ptr_hash, NULL, NULL);
	RzGraphNode *a = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)1, &a), RZ_GRAPH_STATUS_OK, "Failed add");
	rz_graph_add_edge(g, a, a, NULL);

	RzList *back = rz_graph_find_back_edges(g, NULL, NULL);
	mu_assert_notnull(back, "back_edges not null");
	mu_assert_eq(rz_list_length(back), 1, "self-loop is a back edge");
	rz_list_free(back);

	rz_graph_free(g);
	mu_end;
}

static bool test_find_back_edges_multiple_cycles(void) {
	/* Two independent cycles: A->B->A and C->D->C */
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, ptr_hash, NULL, NULL);
	RzGraphNode *a = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)1, &a), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *b = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)2, &b), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *c = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)3, &c), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *d = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)4, &d), RZ_GRAPH_STATUS_OK, "Failed add");
	rz_graph_add_edge(g, a, b, NULL);
	rz_graph_add_edge(g, b, a, NULL);
	rz_graph_add_edge(g, c, d, NULL);
	rz_graph_add_edge(g, d, c, NULL);

	RzList *back = rz_graph_find_back_edges(g, NULL, NULL);
	mu_assert_notnull(back, "back_edges not null");
	mu_assert_eq(rz_list_length(back), 2, "two back edges for two cycles");
	rz_list_free(back);

	rz_graph_free(g);
	mu_end;
}

/* =========================================================================
 * Tests for rz_graph_find_sccs
 * ========================================================================= */

static bool test_find_sccs_dag(void) {
	/* DAG: A->B->D, A->C->D — each node is its own SCC */
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, ptr_hash, NULL, NULL);
	RzGraphNode *a = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)1, &a), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *b = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)2, &b), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *c = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)3, &c), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *d = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)4, &d), RZ_GRAPH_STATUS_OK, "Failed add");
	rz_graph_add_edge(g, a, b, NULL);
	rz_graph_add_edge(g, a, c, NULL);
	rz_graph_add_edge(g, b, d, NULL);
	rz_graph_add_edge(g, c, d, NULL);

	RzPVector *sccs = rz_graph_find_sccs(g);
	mu_assert_notnull(sccs, "sccs not null");
	mu_assert_eq(rz_pvector_len(sccs), 4, "four trivial SCCs in DAG");
	/* Each SCC must contain exactly one node */
	void **it;
	rz_pvector_foreach (sccs, it) {
		RzPVector *scc = (RzPVector *)*it;
		mu_assert_eq(rz_pvector_len(scc), 1, "each SCC size is 1");
	}
	rz_pvector_free(sccs);

	rz_graph_free(g);
	mu_end;
}

static bool test_find_sccs_single_cycle(void) {
	/* A->B->C->A forms one SCC of size 3 */
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, ptr_hash, NULL, NULL);
	RzGraphNode *a = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)1, &a), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *b = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)2, &b), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *c = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)3, &c), RZ_GRAPH_STATUS_OK, "Failed add");
	rz_graph_add_edge(g, a, b, NULL);
	rz_graph_add_edge(g, b, c, NULL);
	rz_graph_add_edge(g, c, a, NULL);

	RzPVector *sccs = rz_graph_find_sccs(g);
	mu_assert_notnull(sccs, "sccs not null");
	mu_assert_eq(rz_pvector_len(sccs), 1, "one SCC");
	RzPVector *scc = rz_pvector_at(sccs, 0);
	mu_assert_eq(rz_pvector_len(scc), 3, "SCC contains all 3 nodes");
	/* Verify all nodes are present */
	bool has_a = false, has_b = false, has_c = false;
	void **it;
	rz_pvector_foreach (scc, it) {
		RzGraphNode *n = (RzGraphNode *)*it;
		if (n == a)
			has_a = true;
		if (n == b)
			has_b = true;
		if (n == c)
			has_c = true;
	}
	mu_assert_true(has_a && has_b && has_c, "all cycle nodes in SCC");
	rz_pvector_free(sccs);

	rz_graph_free(g);
	mu_end;
}

static bool test_find_sccs_mixed(void) {
	/* Two cycles connected by a DAG edge:
	 *   A->B->A  (SCC1={A,B})
	 *   A->C->D->C (SCC2={C,D}), C is also reachable from A
	 *   Expected: SCC {A,B}, SCC {C,D} */
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, ptr_hash, NULL, NULL);
	RzGraphNode *a = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)1, &a), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *b = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)2, &b), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *c = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)3, &c), RZ_GRAPH_STATUS_OK, "Failed add");
	RzGraphNode *d = NULL;
	mu_assert_eq(rz_graph_add_node(g, (void *)4, &d), RZ_GRAPH_STATUS_OK, "Failed add");
	rz_graph_add_edge(g, a, b, NULL);
	rz_graph_add_edge(g, b, a, NULL);
	rz_graph_add_edge(g, a, c, NULL);
	rz_graph_add_edge(g, c, d, NULL);
	rz_graph_add_edge(g, d, c, NULL);

	RzPVector *sccs = rz_graph_find_sccs(g);
	mu_assert_notnull(sccs, "sccs not null");
	mu_assert_eq(rz_pvector_len(sccs), 2, "two SCCs");

	bool found_ab = false, found_cd = false;
	void **it;
	rz_pvector_foreach (sccs, it) {
		RzPVector *scc = (RzPVector *)*it;
		if (rz_pvector_len(scc) == 2) {
			bool ha = false, hb = false, hc = false, hd = false;
			void **jt;
			rz_pvector_foreach (scc, jt) {
				RzGraphNode *n = (RzGraphNode *)*jt;
				if (n == a)
					ha = true;
				if (n == b)
					hb = true;
				if (n == c)
					hc = true;
				if (n == d)
					hd = true;
			}
			if (ha && hb)
				found_ab = true;
			if (hc && hd)
				found_cd = true;
		}
	}
	mu_assert_true(found_ab, "SCC {A,B} found");
	mu_assert_true(found_cd, "SCC {C,D} found");
	rz_pvector_free(sccs);

	rz_graph_free(g);
	mu_end;
}

static int all_tests() {
	mu_run_test(test_legacy_graph);
	mu_run_test(test_find_back_edges_simple);
	mu_run_test(test_find_back_edges_dag);
	mu_run_test(test_find_back_edges_self_loop);
	mu_run_test(test_find_back_edges_multiple_cycles);
	mu_run_test(test_find_sccs_dag);
	mu_run_test(test_find_sccs_single_cycle);
	mu_run_test(test_find_sccs_mixed);
	return tests_passed != tests_run;
}

mu_main(all_tests)
