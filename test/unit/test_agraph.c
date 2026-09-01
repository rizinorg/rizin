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

/*
 * Golden coordinate tests.
 *
 * Unlike the layer-only assertions above, these pin the exact x/y/layer/
 * pos_in_layer coordinates the layered layout produces. They exist to guard
 * the planned relocation of the layout pass into RzUtil (rizinorg/rizin#992):
 * after the move, the algorithm must reproduce these same coordinates.
 *
 * To keep the values independent of text-rendering (rz_str_bounds on node
 * bodies), every node is given a fixed width/height before layout. The golden
 * values below were captured from the current (pre-relocation) algorithm.
 */
static void agraph_set_uniform_dims(RzAGraph *ag, int w, int h) {
	RzIterator *it = rz_graph_get_nodes(ag->graph);
	RzGraphNode *node;
	rz_iterator_foreach(it, node) {
		RzANode *an = (RzANode *)rz_graph_node_get_data_mut(node);
		an->w = w;
		an->h = h;
	}
	rz_iterator_free(it);
}

#define mu_assert_node_xy(ag, title, ex, ey, el, ep) \
	do { \
		RzANode *_n = find_anode((ag), (title)); \
		mu_assert_notnull(_n, "node " title); \
		mu_assert_eq(_n->x, (ex), "x of " title); \
		mu_assert_eq(_n->y, (ey), "y of " title); \
		mu_assert_eq(_n->layer, (el), "layer of " title); \
		mu_assert_eq(_n->pos_in_layer, (ep), "pos_in_layer of " title); \
	} while (0)

bool test_layout_coords_diamond() {
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
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	/* A on top, B/C side by side in layer 1, D centred at the bottom. */
	mu_assert_node_xy(ag, "A", 15, 0, 0, 0);
	mu_assert_node_xy(ag, "B", 3, 9, 1, 0);
	mu_assert_node_xy(ag, "C", 27, 9, 1, 1);
	mu_assert_node_xy(ag, "D", 15, 18, 2, 0);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

bool test_layout_coords_chain() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "C", "D" };
	const char *edges[][2] = {
		{ "A", "B" },
		{ "B", "C" },
		{ "C", "D" },
	};
	RzAGraph *ag = build_agraph(titles, 4, edges, 3);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	/* A straight vertical chain: same x, one layer apart, 7px vertical pitch. */
	mu_assert_node_xy(ag, "A", 15, 0, 0, 0);
	mu_assert_node_xy(ag, "B", 15, 7, 1, 0);
	mu_assert_node_xy(ag, "C", 15, 14, 2, 0);
	mu_assert_node_xy(ag, "D", 15, 21, 3, 0);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

bool test_layout_coords_backedge() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "C", "exit" };
	const char *edges[][2] = {
		{ "A", "B" },
		{ "B", "exit" },
		{ "B", "C" },
		{ "C", "A" }, /* back edge */
	};
	RzAGraph *ag = build_agraph(titles, 4, edges, 4);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	/* C->A is reversed; exit and C share layer 2. */
	mu_assert_node_xy(ag, "A", 8, 1, 0, 0);
	mu_assert_node_xy(ag, "B", 8, 8, 1, 0);
	mu_assert_node_xy(ag, "exit", -4, 17, 2, 0);
	mu_assert_node_xy(ag, "C", 20, 17, 2, 1);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * Long edge spanning two layers: A->B->C plus a direct A->C. The A->C edge
 * skips layer 1, so the layout inserts one dummy node there (total nodes = 4).
 * This guards the create_dummy_nodes() path, which the simpler shapes miss.
 */
bool test_layout_coords_longedge_one_dummy() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "C" };
	const char *edges[][2] = {
		{ "A", "B" },
		{ "B", "C" },
		{ "A", "C" }, /* spans 2 layers -> 1 dummy */
	};
	RzAGraph *ag = build_agraph(titles, 3, edges, 3);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "A", 15, 0, 0, 0);
	mu_assert_node_xy(ag, "B", 8, 9, 1, 0);
	mu_assert_node_xy(ag, "C", 15, 18, 2, 0);
	/* 3 named nodes + 1 dummy inserted on the long edge */
	mu_assert_eq(rz_graph_count_nodes(ag->graph), 4, "node count incl. dummy");

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * Long edge spanning three layers: A->B->C->D plus a direct A->D, which skips
 * layers 1 and 2, inserting two dummy nodes (total nodes = 6). Guards the
 * multi-dummy chain in create_dummy_nodes().
 */
bool test_layout_coords_longedge_two_dummies() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "C", "D" };
	const char *edges[][2] = {
		{ "A", "B" },
		{ "B", "C" },
		{ "C", "D" },
		{ "A", "D" }, /* spans 3 layers -> 2 dummies */
	};
	RzAGraph *ag = build_agraph(titles, 4, edges, 4);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "A", 15, 0, 0, 0);
	mu_assert_node_xy(ag, "B", 8, 9, 1, 0);
	mu_assert_node_xy(ag, "C", 8, 16, 2, 0);
	mu_assert_node_xy(ag, "D", 15, 25, 3, 0);
	/* 4 named nodes + 2 dummies inserted on the long edge */
	mu_assert_eq(rz_graph_count_nodes(ag->graph), 6, "node count incl. dummies");

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * Wide layer: one root fanning out to four children, which all sit in layer 1.
 * Guards horizontal packing of a wide layer (24px pitch) and centring of the
 * parent over its children.
 */
bool test_layout_coords_wide_fanout() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "R", "C0", "C1", "C2", "C3" };
	const char *edges[][2] = {
		{ "R", "C0" },
		{ "R", "C1" },
		{ "R", "C2" },
		{ "R", "C3" },
	};
	RzAGraph *ag = build_agraph(titles, 5, edges, 4);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "R", 39, 0, 0, 0);
	mu_assert_node_xy(ag, "C0", 3, 11, 1, 0);
	mu_assert_node_xy(ag, "C1", 27, 11, 1, 1);
	mu_assert_node_xy(ag, "C2", 51, 11, 1, 2);
	mu_assert_node_xy(ag, "C3", 75, 11, 1, 3);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * Two independent chains (A->B, X->Y) that merge into a common sink S. The two
 * chains form separate classes that are placed side by side before S is centred
 * between them. Guards the multi-class horizontal placement (compute_classes /
 * place_original).
 */
bool test_layout_coords_two_chains_merge() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "X", "Y", "S" };
	const char *edges[][2] = {
		{ "A", "B" },
		{ "B", "S" },
		{ "X", "Y" },
		{ "Y", "S" },
	};
	RzAGraph *ag = build_agraph(titles, 5, edges, 4);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "A", 3, 0, 0, 0);
	mu_assert_node_xy(ag, "X", 27, 0, 0, 1);
	mu_assert_node_xy(ag, "B", 3, 7, 1, 0);
	mu_assert_node_xy(ag, "Y", 27, 7, 1, 1);
	mu_assert_node_xy(ag, "S", 15, 16, 2, 0);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * Crossing reduction over three layers. Layer 0 = {A, B}, layer 1 = {P, Q, R},
 * layer 2 = {S}. Edges are deliberately interleaved (A->Q, A->R, B->P) so the
 * initial insertion order of layer 1 (P, Q, R) produces edge crossings. The
 * barycenter sweep in minimize_crossings()/layer_sweep() must reorder layer 1
 * to (Q, R, P) to reduce them - note P ends at pos_in_layer 2 despite being
 * inserted first. This is the crossing-minimization path the smaller shapes do
 * not exercise.
 */
bool test_layout_coords_crossing_reduction() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "P", "Q", "R", "S" };
	const char *edges[][2] = {
		{ "A", "Q" },
		{ "A", "R" },
		{ "B", "P" },
		{ "P", "S" },
		{ "Q", "S" },
		{ "R", "S" },
	};
	RzAGraph *ag = build_agraph(titles, 6, edges, 6);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "A", -1, 0, 0, 0);
	mu_assert_node_xy(ag, "B", 35, 0, 0, 1);
	/* layer 1 reordered by the sweep: Q(0), R(1), P(2) */
	mu_assert_node_xy(ag, "Q", -13, 9, 1, 0);
	mu_assert_node_xy(ag, "R", 11, 9, 1, 1);
	mu_assert_node_xy(ag, "P", 35, 9, 1, 2);
	mu_assert_node_xy(ag, "S", 15, 19, 2, 0);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * Asymmetric tree: root with two children whose subtrees differ in size
 * (L has two children, R has one). Exercises the left/right class adjustment
 * in the x-coordinate assignment - root is pulled off-centre toward the
 * heavier subtree rather than sitting at a naive midpoint.
 */
bool test_layout_coords_asym_tree() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "root", "L", "R", "LL", "LR", "RR" };
	const char *edges[][2] = {
		{ "root", "L" },
		{ "root", "R" },
		{ "L", "LL" },
		{ "L", "LR" },
		{ "R", "RR" },
	};
	RzAGraph *ag = build_agraph(titles, 6, edges, 5);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "root", 21, 0, 0, 0);
	mu_assert_node_xy(ag, "L", 3, 9, 1, 0);
	mu_assert_node_xy(ag, "R", 39, 9, 1, 1);
	mu_assert_node_xy(ag, "LL", -9, 18, 2, 0);
	mu_assert_node_xy(ag, "LR", 15, 18, 2, 1);
	mu_assert_node_xy(ag, "RR", 39, 18, 2, 2);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * Two children of differing widths in the same layer. The placement spaces
 * nodes by their widths, so a 40-wide and an 8-wide sibling are not evenly
 * spaced. Guards width-aware horizontal placement.
 */
bool test_layout_coords_varying_widths() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "root", "wide", "narrow" };
	const char *edges[][2] = {
		{ "root", "wide" },
		{ "root", "narrow" },
	};
	RzAGraph *ag = build_agraph(titles, 3, edges, 2);
	mu_assert_notnull(ag, "build_agraph");
	/* non-uniform widths */
	find_anode(ag, "root")->w = 20;
	find_anode(ag, "wide")->w = 40;
	find_anode(ag, "narrow")->w = 8;
	RzIterator *it = rz_graph_get_nodes(ag->graph);
	RzGraphNode *node;
	rz_iterator_foreach(it, node) {
		((RzANode *)rz_graph_node_get_data_mut(node))->h = 4;
	}
	rz_iterator_free(it);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "root", 15, 0, 0, 0);
	mu_assert_node_xy(ag, "wide", -9, 9, 1, 0);
	mu_assert_node_xy(ag, "narrow", 35, 9, 1, 1);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * A node with two parents in the same layer: M is pulled to the barycentre
 * between A and B. Guards the multi-parent averaging in placement.
 */
bool test_layout_coords_two_parents_one_child() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "A", "B", "M", "S" };
	const char *edges[][2] = {
		{ "A", "M" },
		{ "B", "M" },
		{ "M", "S" },
	};
	RzAGraph *ag = build_agraph(titles, 4, edges, 3);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "A", 3, 0, 0, 0);
	mu_assert_node_xy(ag, "B", 27, 0, 0, 1);
	/* M centred between its two parents */
	mu_assert_node_xy(ag, "M", 15, 9, 1, 0);
	mu_assert_node_xy(ag, "S", 15, 16, 2, 0);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * Balanced binary tree over three layers (7 nodes). Exercises deeper recursive
 * placement: the four leaves spread symmetrically and each parent centres over
 * its two children.
 */
bool test_layout_coords_binary_tree() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "r", "a", "b", "aa", "ab", "ba", "bb" };
	const char *edges[][2] = {
		{ "r", "a" },
		{ "r", "b" },
		{ "a", "aa" },
		{ "a", "ab" },
		{ "b", "ba" },
		{ "b", "bb" },
	};
	RzAGraph *ag = build_agraph(titles, 7, edges, 6);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "r", 15, 0, 0, 0);
	mu_assert_node_xy(ag, "a", -9, 9, 1, 0);
	mu_assert_node_xy(ag, "b", 39, 9, 1, 1);
	mu_assert_node_xy(ag, "aa", -21, 20, 2, 0);
	mu_assert_node_xy(ag, "ab", 3, 20, 2, 1);
	mu_assert_node_xy(ag, "ba", 27, 20, 2, 2);
	mu_assert_node_xy(ag, "bb", 51, 20, 2, 3);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/*
 * Larger crossing-heavy graph: a 12-node, 6-layer DAG whose middle layers are
 * deliberately wired so that node order produces many crossings, forcing the
 * minimize_crossings() loop to iterate (the barycenter sweep runs repeatedly
 * until the ordering stabilises). The smaller crossing_reduction case triggers
 * a single reorder; this one exercises convergence over several passes and
 * pins the resulting coordinates for every node.
 */
bool test_layout_coords_large_crossing() {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "rz_cons_new");
	const char *titles[] = { "s", "a0", "a1", "a2", "b0", "b1", "b2",
		"c0", "c1", "c2", "d0", "t" };
	const char *edges[][2] = {
		{ "s", "a0" }, { "s", "a1" }, { "s", "a2" },
		{ "a0", "b2" }, { "a1", "b0" }, { "a2", "b1" },
		{ "b0", "c2" }, { "b1", "c0" }, { "b2", "c1" },
		{ "c0", "d0" }, { "c1", "d0" }, { "c2", "d0" },
		{ "d0", "t" }
	};
	RzAGraph *ag = build_agraph(titles, 12, edges, 13);
	mu_assert_notnull(ag, "build_agraph");
	agraph_set_uniform_dims(ag, 20, 4);
	rz_agraph_compute_layout(ag);

	mu_assert_node_xy(ag, "s", 7, 0, 0, 0);
	mu_assert_node_xy(ag, "a0", -17, 9, 1, 0);
	mu_assert_node_xy(ag, "a1", 7, 9, 1, 1);
	mu_assert_node_xy(ag, "a2", 31, 9, 1, 2);
	/* layer 2 reordered by the sweep: b2(0), b0(1), b1(2) */
	mu_assert_node_xy(ag, "b2", -17, 16, 2, 0);
	mu_assert_node_xy(ag, "b0", 7, 16, 2, 1);
	mu_assert_node_xy(ag, "b1", 31, 16, 2, 2);
	/* layer 3 reordered: c1(0), c2(1), c0(2) */
	mu_assert_node_xy(ag, "c1", -17, 23, 3, 0);
	mu_assert_node_xy(ag, "c2", 7, 23, 3, 1);
	mu_assert_node_xy(ag, "c0", 31, 23, 3, 2);
	mu_assert_node_xy(ag, "d0", 11, 33, 4, 0);
	mu_assert_node_xy(ag, "t", 11, 40, 5, 0);

	rz_agraph_free(ag);
	rz_cons_free();
	mu_end;
}

/* Cancel callback that always aborts; used to drive the is_cancelled path. */
static bool agraph_test_always_cancel(void *user) {
	(void)user;
	return true;
}

/*
 * Cancellation: when the injected is_cancelled callback fires, set_layout()
 * aborts after layer assignment but before x/y coordinate placement. The layers
 * are therefore valid, but every node keeps its default (0,0) coordinate. This
 * guards the RzCons-decoupled cancellation seam (rizinorg/rizin#992) and the
 * mid-layout early-exit that the other goldens never trigger.
 */
bool test_layout_coords_cancelled() {
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
	agraph_set_uniform_dims(ag, 20, 4);

	/* Inject cancellation before running the layout. */
	ag->layout_config.is_cancelled = agraph_test_always_cancel;
	ag->layout_config.user = NULL;
	rz_agraph_compute_layout(ag);

	/* Layers were assigned before the abort... */
	mu_assert_eq(find_anode(ag, "A")->layer, 0, "layer A (assigned pre-abort)");
	mu_assert_eq(find_anode(ag, "B")->layer, 1, "layer B (assigned pre-abort)");
	mu_assert_eq(find_anode(ag, "C")->layer, 1, "layer C (assigned pre-abort)");
	mu_assert_eq(find_anode(ag, "D")->layer, 2, "layer D (assigned pre-abort)");
	/* ...but placement never ran, so coordinates stay at their default. */
	for (int i = 0; i < 4; i++) {
		RzANode *n = find_anode(ag, titles[i]);
		mu_assert_eq(n->x, 0, "x stays default on cancel");
		mu_assert_eq(n->y, 0, "y stays default on cancel");
	}

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
	mu_run_test(test_layout_coords_diamond);
	mu_run_test(test_layout_coords_chain);
	mu_run_test(test_layout_coords_backedge);
	mu_run_test(test_layout_coords_longedge_one_dummy);
	mu_run_test(test_layout_coords_longedge_two_dummies);
	mu_run_test(test_layout_coords_wide_fanout);
	mu_run_test(test_layout_coords_two_chains_merge);
	mu_run_test(test_layout_coords_crossing_reduction);
	mu_run_test(test_layout_coords_asym_tree);
	mu_run_test(test_layout_coords_varying_widths);
	mu_run_test(test_layout_coords_two_parents_one_child);
	mu_run_test(test_layout_coords_binary_tree);
	mu_run_test(test_layout_coords_large_crossing);
	mu_run_test(test_layout_coords_cancelled);
	return tests_passed != tests_run;
}

mu_main(all_tests)
