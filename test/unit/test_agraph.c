// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-FileCopyrightText: 2025 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_agraph.h>
#include <rz_util.h>
#include "minunit.h"

bool test_graph_to_agraph() {
	RzCore *core = rz_core_new();
	rz_core_cmd0(core, "ac A");
	rz_core_cmd0(core, "ac B");
	rz_core_cmd0(core, "ac C");
	rz_core_cmd0(core, "ac D");
	rz_core_cmd0(core, "acb B A");
	rz_core_cmd0(core, "acb C A");
	rz_core_cmd0(core, "acb D B");
	rz_core_cmd0(core, "acb D C");

	RzGraph *graph = rz_analysis_class_get_inheritance_graph(core->analysis);
	mu_assert_notnull(graph, "Couldn't create the graph");
	mu_assert_eq(rz_graph_count_nodes(graph), 4, "Wrong node count");

	RzAGraph *agraph = rz_core_create_agraph_from_graph(graph, false);
	mu_assert_notnull(agraph, "Couldn't create the agraph");
	mu_assert_eq(rz_graph_count_nodes(agraph->graph), 4, "Wrong agraph node count");

	RzIterator *iter = rz_graph_get_nodes(agraph->graph);
	mu_assert_notnull(iter, "get_nodes iterator");
	RzGraphNode *node;
	int i = 0;
	rz_iterator_foreach(iter, node) {
		const RzANode *info = rz_graph_node_get_data(node);
		switch (i++) {
		case 0:
			mu_assert_streq(info->title, "A", "Wrong node name");
			mu_assert_eq(rz_graph_out_degree(agraph->graph, node), 2, "Wrong node out-nodes");
			{
				RzIterator *out_iter = rz_graph_out_neighbors(agraph->graph, node);
				mu_assert_notnull(out_iter, "out_neighbors iter A");
				RzGraphNode *out_node;
				int j = 0;
				rz_iterator_foreach(out_iter, out_node) {
					const RzANode *out_info = rz_graph_node_get_data(out_node);
					switch (j++) {
					case 0:
						mu_assert_streq(out_info->title, "B", "Wrong node name");
						break;
					case 1:
						mu_assert_streq(out_info->title, "C", "Wrong node name");
						break;
					}
				}
				rz_iterator_free(out_iter);
			}
			break;
		case 1:
			mu_assert_streq(info->title, "B", "Wrong node name");
			mu_assert_eq(rz_graph_out_degree(agraph->graph, node), 1, "Wrong node out-nodes");
			mu_assert_eq(rz_graph_in_degree(agraph->graph, node), 1, "Wrong node in-nodes");
			{
				RzIterator *out_iter = rz_graph_out_neighbors(agraph->graph, node);
				mu_assert_notnull(out_iter, "out_neighbors iter B");
				RzGraphNode *out_node;
				int j = 0;
				rz_iterator_foreach(out_iter, out_node) {
					const RzANode *out_info = rz_graph_node_get_data(out_node);
					switch (j++) {
					case 0:
						mu_assert_streq(out_info->title, "D", "Wrong node name");
						break;
					}
				}
				rz_iterator_free(out_iter);
			}
			break;
		case 2:
			mu_assert_streq(info->title, "C", "Wrong node name");
			mu_assert_eq(rz_graph_out_degree(agraph->graph, node), 1, "Wrong node out-nodes");
			mu_assert_eq(rz_graph_in_degree(agraph->graph, node), 1, "Wrong node in-nodes");
			{
				RzIterator *out_iter = rz_graph_out_neighbors(agraph->graph, node);
				mu_assert_notnull(out_iter, "out_neighbors iter C");
				RzGraphNode *out_node;
				int j = 0;
				rz_iterator_foreach(out_iter, out_node) {
					const RzANode *out_info = rz_graph_node_get_data(out_node);
					switch (j++) {
					case 0:
						mu_assert_streq(out_info->title, "D", "Wrong node name");
						break;
					}
				}
				rz_iterator_free(out_iter);
			}
			break;
		case 3:
			mu_assert_streq(info->title, "D", "Wrong node name");
			mu_assert_eq(rz_graph_in_degree(agraph->graph, node), 2, "Wrong node in-nodes");
			break;
		default:
			break;
		}
	}
	rz_iterator_free(iter);
	rz_core_free(core);
	rz_graph_free(graph);
	rz_agraph_free(agraph);
	mu_end;
}

/* Helper: look up an RzANode by title inside an RzAGraph. */
static RzANode *find_anode(RzAGraph *ag, const char *title) {
	return rz_agraph_get_node(ag, title);
}

/*
 * Build a minimal RzAGraph (no canvas, no core) with the given nodes and edges.
 * Nodes are added in the order of `titles`; edges are added in the order of `edges`.
 * Returns the graph; caller must rz_agraph_free() it.
 */
/*
 * build_agraph: allocate an RzAGraph with the given nodes and edges.
 * The caller must keep a live RzCons (rz_cons_new) for the lifetime of the
 * graph, because set_layout calls rz_cons_is_breaked() internally.
 * The caller is responsible for rz_agraph_free() and rz_cons_free().
 */
static RzAGraph *build_agraph(const char **titles, int n_titles,
	const char *edges[][2], int n_edges) {
	RzAGraph *ag = rz_agraph_new(NULL);
	if (!ag) {
		return NULL;
	}
	for (int i = 0; i < n_titles; i++) {
		rz_agraph_add_node(ag, titles[i], "");
	}
	for (int i = 0; i < n_edges; i++) {
		RzANode *from = find_anode(ag, edges[i][0]);
		RzANode *to = find_anode(ag, edges[i][1]);
		if (from && to) {
			rz_agraph_add_edge(ag, from, to);
		}
	}
	return ag;
}

/*
 * test_layout_back_edge_simple
 *
 * Graph (edges created in this order):
 *   A -> B   (nth=-, order=0)
 *   B -> exit (nth=-, order=1)
 *   B -> C   (nth=-, order=2)
 *   C -> A   (nth=-, order=3)
 *
 * DFS traversal (edges sorted by creation order, LIFO stack):
 *   discover A(gray) -> push finish(A), neighbor B
 *   discover B(gray) -> push finish(B), neighbors [exit, C]
 *     pop (B,C): discover C(gray) -> push finish(C), neighbor A
 *       pop (C,A): A is GRAY -> back_edge(C->A)
 *     finish C
 *     pop (B,exit): discover exit(gray) -> finish exit
 *   finish B -> finish A
 *
 * Expected back_edge: C -> A
 * After reversing C->A, DAG has: A->B, B->exit, B->C, A->C
 * Expected layers: A=0, B=1, C=2, exit=2
 *   (exit and C both have max parent layer = 1, so layer = 2)
 *
 * Verified by checking that back_edge C->A is the only edge
 * going from a higher layer to a lower layer in the original graph.
 */
bool test_layout_back_edge_simple() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "C", "exit" };
	const char *edges[][2] = {
		{ "A", "B" },
		{ "B", "exit" },
		{ "B", "C" },
		{ "C", "A" },
	};
	RzAGraph *ag = build_agraph(titles, 4, edges, 4);
	mu_assert_notnull(ag, "build_agraph");

	rz_agraph_compute_layout(ag);

	RzANode *nA = find_anode(ag, "A");
	RzANode *nB = find_anode(ag, "B");
	RzANode *nC = find_anode(ag, "C");
	RzANode *nExit = find_anode(ag, "exit");
	mu_assert_notnull(nA, "node A");
	mu_assert_notnull(nB, "node B");
	mu_assert_notnull(nC, "node C");
	mu_assert_notnull(nExit, "node exit");

	/* Layer assignment reflects the DAG after removing C->A as back_edge */
	mu_assert_eq(nA->layer, 0, "layer A");
	mu_assert_eq(nB->layer, 1, "layer B");
	/* C and exit both have max incoming layer = 1, so layer = 2 */
	mu_assert_eq(nC->layer, 2, "layer C");
	mu_assert_eq(nExit->layer, 2, "layer exit");

	/*
	 * Confirm which edge violates layer monotonicity in the original graph —
	 * that is the back_edge chosen by the DFS.
	 * C->A: layer(C)=2 > layer(A)=0  => back_edge  ✓
	 * A->B: layer(A)=0 < layer(B)=1  => forward    ✓
	 * B->C: layer(B)=1 < layer(C)=2  => forward    ✓
	 * B->exit: layer(B)=1 < layer(exit)=2 => forward ✓
	 */
	mu_assert_true(nC->layer > nA->layer, "C->A is the back_edge (layer C > layer A)");
	mu_assert_true(nA->layer < nB->layer, "A->B is a forward edge");
	mu_assert_true(nB->layer < nC->layer, "B->C is a forward edge");
	mu_assert_true(nB->layer < nExit->layer, "B->exit is a forward edge");

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * test_layout_back_edge_complex
 *
 * Graph (edges created in this order):
 *   A -> B   (order=0)
 *   A -> C   (order=1)
 *   B -> D   (order=2)
 *   B -> A   (order=3)
 *   C -> D   (order=4)
 *   D -> A   (order=5)
 *
 * DFS traversal (edges sorted by creation order, LIFO stack):
 *   discover A(gray) -> neighbors [B(0), C(1)], pushed as (A,B),(A,C)
 *   pop (A,C): discover C(gray) -> neighbor D(4) -> push (C,D)
 *     pop (C,D): discover D(gray) -> neighbor A(5) -> push (D,A)
 *       pop (D,A): A is GRAY -> back_edge(D->A)
 *     finish D; finish C
 *   pop (A,B): discover B(gray) -> neighbors [D(2), A(3)] -> push (B,D),(B,A)
 *     pop (B,A): A is GRAY -> back_edge(B->A)
 *     pop (B,D): D is BLACK -> fcross_edge (not a back_edge)
 *   finish B; finish A
 *
 * Expected back_edges: { D->A, B->A }
 * After reversing both: DAG has A->B, A->C, A->D, C->D  (B->D dropped, B->A reversed)
 * Expected layers: A=0, B=1, C=1, D=2
 *
 * Verified by checking that both D->A and B->A go from higher to lower layer,
 * while all other original edges go from lower to higher layer.
 */
bool test_layout_back_edge_complex() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "C", "D" };
	const char *edges[][2] = {
		{ "A", "B" },
		{ "A", "C" },
		{ "B", "D" },
		{ "B", "A" },
		{ "C", "D" },
		{ "D", "A" },
	};
	RzAGraph *ag = build_agraph(titles, 4, edges, 6);
	mu_assert_notnull(ag, "build_agraph");

	rz_agraph_compute_layout(ag);

	RzANode *nA = find_anode(ag, "A");
	RzANode *nB = find_anode(ag, "B");
	RzANode *nC = find_anode(ag, "C");
	RzANode *nD = find_anode(ag, "D");
	mu_assert_notnull(nA, "node A");
	mu_assert_notnull(nB, "node B");
	mu_assert_notnull(nC, "node C");
	mu_assert_notnull(nD, "node D");

	mu_assert_eq(nA->layer, 0, "layer A");
	mu_assert_eq(nB->layer, 1, "layer B");
	mu_assert_eq(nC->layer, 1, "layer C");
	mu_assert_eq(nD->layer, 2, "layer D");

	/* back_edges: D->A and B->A both go from higher to lower layer */
	mu_assert_true(nD->layer > nA->layer, "D->A is a back_edge (layer D > layer A)");
	mu_assert_true(nB->layer > nA->layer, "B->A is a back_edge (layer B > layer A)");
	/* forward edges */
	mu_assert_true(nA->layer < nB->layer, "A->B is a forward edge");
	mu_assert_true(nA->layer < nC->layer, "A->C is a forward edge");
	mu_assert_true(nB->layer < nD->layer, "B->D is a forward edge");
	mu_assert_true(nC->layer < nD->layer, "C->D is a forward edge");

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * test_layout_topo_sort
 *
 * Diamond graph (no cycles):
 *   A -> B   (order=0)
 *   A -> C   (order=1)
 *   B -> D   (order=2)
 *   C -> D   (order=3)
 *
 * No back_edges. DFS topological finish order: D, B, C, A (or D, C, B, A).
 * assign_layers sets layer = max(parent layers) + 1:
 *   A: no parents -> layer 0
 *   B: parent A(0) -> layer 1
 *   C: parent A(0) -> layer 1
 *   D: parents B(1), C(1) -> layer 2
 *
 * The test verifies the topological property:
 *   for every edge u->v in the graph, layer(u) < layer(v).
 */
bool test_layout_topo_sort_diamond() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "C", "D" };
	const char *edges[][2] = {
		{ "A", "B" },
		{ "A", "C" },
		{ "B", "D" },
		{ "C", "D" },
	};
	RzAGraph *ag = build_agraph(titles, 4, edges, 4);
	mu_assert_notnull(ag, "build_agraph");

	rz_agraph_compute_layout(ag);

	RzANode *nA = find_anode(ag, "A");
	RzANode *nB = find_anode(ag, "B");
	RzANode *nC = find_anode(ag, "C");
	RzANode *nD = find_anode(ag, "D");
	mu_assert_notnull(nA, "node A");
	mu_assert_notnull(nB, "node B");
	mu_assert_notnull(nC, "node C");
	mu_assert_notnull(nD, "node D");

	/* Exact layer values */
	mu_assert_eq(nA->layer, 0, "layer A");
	mu_assert_eq(nB->layer, 1, "layer B");
	mu_assert_eq(nC->layer, 1, "layer C");
	mu_assert_eq(nD->layer, 2, "layer D");

	/* Topological property: every edge goes from lower to higher layer */
	mu_assert_true(nA->layer < nB->layer, "topo: A < B");
	mu_assert_true(nA->layer < nC->layer, "topo: A < C");
	mu_assert_true(nB->layer < nD->layer, "topo: B < D");
	mu_assert_true(nC->layer < nD->layer, "topo: C < D");

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * test_layout_topo_sort_chain
 *
 * Linear chain: A -> B -> C -> D -> E
 *
 * assign_layers produces strictly increasing layers:
 *   A=0, B=1, C=2, D=3, E=4
 *
 * This is the degenerate case where topo sort and layer assignment
 * produce a single unique ordering.
 */
bool test_layout_topo_sort_chain() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "C", "D", "E" };
	const char *edges[][2] = {
		{ "A", "B" },
		{ "B", "C" },
		{ "C", "D" },
		{ "D", "E" },
	};
	RzAGraph *ag = build_agraph(titles, 5, edges, 4);
	mu_assert_notnull(ag, "build_agraph");

	rz_agraph_compute_layout(ag);

	RzANode *nA = find_anode(ag, "A");
	RzANode *nB = find_anode(ag, "B");
	RzANode *nC = find_anode(ag, "C");
	RzANode *nD = find_anode(ag, "D");
	RzANode *nE = find_anode(ag, "E");
	mu_assert_notnull(nA, "node A");
	mu_assert_notnull(nB, "node B");
	mu_assert_notnull(nC, "node C");
	mu_assert_notnull(nD, "node D");
	mu_assert_notnull(nE, "node E");

	mu_assert_eq(nA->layer, 0, "layer A");
	mu_assert_eq(nB->layer, 1, "layer B");
	mu_assert_eq(nC->layer, 2, "layer C");
	mu_assert_eq(nD->layer, 3, "layer D");
	mu_assert_eq(nE->layer, 4, "layer E");

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

int all_tests() {
	mu_run_test(test_graph_to_agraph);
	mu_run_test(test_layout_back_edge_simple);
	mu_run_test(test_layout_back_edge_complex);
	mu_run_test(test_layout_topo_sort_diamond);
	mu_run_test(test_layout_topo_sort_chain);
	return tests_passed != tests_run;
}

mu_main(all_tests)
