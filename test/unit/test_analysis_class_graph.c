// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_util/rz_graph_drawable.h>
#include "minunit.h"

bool test_inherit_graph_creation() {
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

	RzIterator iter = (RzIterator){ 0 };
	mu_assert_true(rz_graph_get_nodes(graph, &iter), "get_nodes iterator");
	RzGraphNode *node;
	int i = 0;
	rz_iterator_foreach(&iter, node) {
		const RzGraphNodeInfo *info = rz_graph_node_get_data(node);
		switch (i++) {
		case 0:
			mu_assert_streq(info->def.title, "A", "Wrong node name");
			mu_assert_eq(rz_graph_out_degree(graph, node), 2, "Wrong node out-nodes");
			{
				RzIterator out_iter = (RzIterator){ 0 };
				mu_assert_true(rz_graph_out_neighbors(graph, node, &out_iter), "out_neighbors iter A");
				RzGraphNode *out_node;
				int j = 0;
				rz_iterator_foreach(&out_iter, out_node) {
					const RzGraphNodeInfo *out_info = rz_graph_node_get_data(out_node);
					switch (j++) {
					case 0:
						mu_assert_streq(out_info->def.title, "B", "Wrong node name");
						break;
					case 1:
						mu_assert_streq(out_info->def.title, "C", "Wrong node name");
						break;
					}
				}
				rz_iterator_fini(&out_iter);
			}
			break;
		case 1:
			mu_assert_streq(info->def.title, "B", "Wrong node name");
			mu_assert_eq(rz_graph_out_degree(graph, node), 1, "Wrong node out-nodes");
			mu_assert_eq(rz_graph_in_degree(graph, node), 1, "Wrong node in-nodes");
			{
				RzIterator out_iter = (RzIterator){ 0 };
				mu_assert_true(rz_graph_out_neighbors(graph, node, &out_iter), "out_neighbors iter B");
				RzGraphNode *out_node;
				int j = 0;
				rz_iterator_foreach(&out_iter, out_node) {
					const RzGraphNodeInfo *out_info = rz_graph_node_get_data(out_node);
					switch (j++) {
					case 0:
						mu_assert_streq(out_info->def.title, "D", "Wrong node name");
						break;
					}
				}
				rz_iterator_fini(&out_iter);
			}
			break;
		case 2:
			mu_assert_streq(info->def.title, "C", "Wrong node name");
			mu_assert_eq(rz_graph_out_degree(graph, node), 1, "Wrong node out-nodes");
			mu_assert_eq(rz_graph_in_degree(graph, node), 1, "Wrong node in-nodes");
			{
				RzIterator out_iter = (RzIterator){ 0 };
				mu_assert_true(rz_graph_out_neighbors(graph, node, &out_iter), "out_neighbors iter C");
				RzGraphNode *out_node;
				int j = 0;
				rz_iterator_foreach(&out_iter, out_node) {
					const RzGraphNodeInfo *out_info = rz_graph_node_get_data(out_node);
					switch (j++) {
					case 0:
						mu_assert_streq(out_info->def.title, "D", "Wrong node name");
						break;
					}
				}
				rz_iterator_fini(&out_iter);
			}
			break;
		case 3:
			mu_assert_streq(info->def.title, "D", "Wrong node name");
			mu_assert_eq(rz_graph_in_degree(graph, node), 2, "Wrong node in-nodes");
			break;
		default:
			break;
		}
	}
	rz_iterator_fini(&iter);

	rz_core_free(core);
	rz_graph_free(graph);
	mu_end;
}

static bool has_node_title(RzGraph *graph, const char *title) {
	RzIterator iter = (RzIterator){ 0 };
	if (!rz_graph_get_nodes(graph, &iter)) {
		return false;
	}
	bool found = false;
	RzGraphNode *node;
	rz_iterator_foreach(&iter, node) {
		const RzGraphNodeInfo *info = rz_graph_node_get_data(node);
		if (info && info->def.title && !strcmp(info->def.title, title)) {
			found = true;
			break;
		}
	}
	rz_iterator_fini(&iter);
	return found;
}

bool test_inherit_graph_by_name_diamond() {
	RzCore *core = rz_core_new();
	rz_core_cmd0(core, "ac A");
	rz_core_cmd0(core, "ac B");
	rz_core_cmd0(core, "ac C");
	rz_core_cmd0(core, "ac D");
	rz_core_cmd0(core, "acb B A");
	rz_core_cmd0(core, "acb C A");
	rz_core_cmd0(core, "acb D B");
	rz_core_cmd0(core, "acb D C");

	RzGraph *full_d = rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "D");
	mu_assert_notnull(full_d, "Filtered graph for D should succeed");
	mu_assert_eq(rz_graph_count_nodes(full_d), 4, "D has 3 ancestors plus itself");
	rz_graph_free(full_d);

	RzGraph *full_a = rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "A");
	mu_assert_notnull(full_a, "Filtered graph for A should succeed");
	mu_assert_eq(rz_graph_count_nodes(full_a), 4, "A has 3 descendants plus itself");
	rz_graph_free(full_a);

	RzGraph *branch_b = rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "B");
	mu_assert_notnull(branch_b, "Filtered graph for B should succeed");
	mu_assert_eq(rz_graph_count_nodes(branch_b), 3, "B branch excludes sibling C");
	mu_assert_true(has_node_title(branch_b, "A"), "A ancestor present");
	mu_assert_true(has_node_title(branch_b, "B"), "B target present");
	mu_assert_true(has_node_title(branch_b, "D"), "D subclass present");
	mu_assert_false(has_node_title(branch_b, "C"), "Sibling C excluded");

	RzIterator iter = (RzIterator){ 0 };
	mu_assert_true(rz_graph_get_nodes(branch_b, &iter), "get_nodes iterator");
	RzGraphNode *node;
	int i = 0;
	rz_iterator_foreach(&iter, node) {
		const RzGraphNodeInfo *info = rz_graph_node_get_data(node);
		switch (i++) {
		case 0:
			mu_assert_streq(info->def.title, "A", "Expected A first");
			mu_assert_eq(rz_graph_out_degree(branch_b, node), 1, "A out-degree");
			break;
		case 1:
			mu_assert_streq(info->def.title, "B", "Expected B second");
			mu_assert_eq(rz_graph_in_degree(branch_b, node), 1, "B in-degree");
			mu_assert_eq(rz_graph_out_degree(branch_b, node), 1, "B out-degree");
			break;
		case 2:
			mu_assert_streq(info->def.title, "D", "Expected D third");
			mu_assert_eq(rz_graph_in_degree(branch_b, node), 1, "D in-degree");
			break;
		default:
			mu_assert("Unexpected node index", false);
		}
	}
	rz_iterator_fini(&iter);
	rz_graph_free(branch_b);
	rz_core_free(core);
	mu_end;
}

bool test_inherit_graph_by_name_filtering_and_cycle() {
	RzCore *core = rz_core_new();
	rz_core_cmd0(core, "ac Mammal");
	rz_core_cmd0(core, "ac Cat");
	rz_core_cmd0(core, "ac Dog");
	rz_core_cmd0(core, "ac Human");
	rz_core_cmd0(core, "ac Shepherd");
	rz_core_cmd0(core, "ac Isolated");
	rz_core_cmd0(core, "ac Mixin");
	rz_core_cmd0(core, "ac Hybrid");
	rz_core_cmd0(core, "acb Cat Mammal");
	rz_core_cmd0(core, "acb Dog Mammal");
	rz_core_cmd0(core, "acb Human Mammal");
	rz_core_cmd0(core, "acb Shepherd Dog");
	rz_core_cmd0(core, "acb Hybrid Dog");
	rz_core_cmd0(core, "acb Hybrid Mixin");

	RzGraph *dog = rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "Dog");
	mu_assert_notnull(dog, "Filtered graph for Dog");
	mu_assert_eq(rz_graph_count_nodes(dog), 4, "Mammal, Dog, Shepherd, Hybrid");
	mu_assert_true(has_node_title(dog, "Mammal"), "Mammal included");
	mu_assert_true(has_node_title(dog, "Dog"), "Dog included");
	mu_assert_true(has_node_title(dog, "Shepherd"), "Shepherd included");
	mu_assert_true(has_node_title(dog, "Hybrid"), "Hybrid subclass included");
	mu_assert_false(has_node_title(dog, "Cat"), "Cat sibling excluded");
	mu_assert_false(has_node_title(dog, "Human"), "Human sibling excluded");
	mu_assert_false(has_node_title(dog, "Isolated"), "Isolated class excluded");
	mu_assert_false(has_node_title(dog, "Mixin"), "Unrelated co-base Mixin excluded");
	rz_graph_free(dog);

	RzGraph *isolated = rz_analysis_class_get_inheritance_graph_by_name(
		core->analysis, "Isolated");
	mu_assert_notnull(isolated, "Isolated class graph");
	mu_assert_eq(rz_graph_count_nodes(isolated), 1, "Isolated has 1 node");
	mu_assert_true(has_node_title(isolated, "Isolated"), "Isolated node present");
	rz_graph_free(isolated);

	RzGraph *missing = rz_analysis_class_get_inheritance_graph_by_name(
		core->analysis, "DoesNotExist");
	mu_assert_null(missing, "Nonexistent class returns NULL");

	rz_core_cmd0(core, "ac CycA");
	rz_core_cmd0(core, "ac CycB");
	rz_core_cmd0(core, "ac CycChild");
	rz_core_cmd0(core, "acb CycA CycB");
	rz_core_cmd0(core, "acb CycB CycA");
	rz_core_cmd0(core, "acb CycChild CycA");
	RzGraph *cyc = rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "CycA");
	mu_assert_notnull(cyc, "Cyclic class graph terminates cleanly");
	mu_assert_eq(rz_graph_count_nodes(cyc), 3, "CycA, CycB, CycChild");
	rz_graph_free(cyc);

	rz_core_free(core);
	mu_end;
}

bool test_inherit_graph_by_name_empty_and_invalid() {
	RzCore *core = rz_core_new();

	RzGraph *empty_full = rz_analysis_class_get_inheritance_graph(core->analysis);
	mu_assert_notnull(empty_full, "Empty inheritance graph should succeed");
	mu_assert_eq(rz_graph_count_nodes(empty_full), 0, "Empty graph has 0 nodes");
	rz_graph_free(empty_full);

	mu_assert_null(
		rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "Missing"),
		"Lookup on empty class db returns NULL");
	mu_assert_null(
		rz_analysis_class_get_inheritance_graph_by_name(core->analysis, ""),
		"Empty class name returns NULL on empty db");

	rz_core_cmd0(core, "ac OnlyClass");
	mu_assert_null(
		rz_analysis_class_get_inheritance_graph_by_name(core->analysis, ""),
		"Empty class name returns NULL on populated db");
	mu_assert_null(
		rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "OtherClass"),
		"Unknown class name returns NULL on populated db");

	RzGraph *only = rz_analysis_class_get_inheritance_graph_by_name(
		core->analysis, "OnlyClass");
	mu_assert_notnull(only, "Single class graph succeeds");
	mu_assert_eq(rz_graph_count_nodes(only), 1, "Single class graph has 1 node");
	mu_assert_eq(rz_graph_count_edges(only), 0, "Single class graph has 0 edges");
	mu_assert_true(has_node_title(only, "OnlyClass"), "OnlyClass node present");
	rz_graph_free(only);

	rz_core_free(core);
	mu_end;
}

bool test_inherit_graph_by_name_deep_chain_and_multi_inherit() {
	RzCore *core = rz_core_new();
	rz_core_cmd0(core, "ac Root");
	rz_core_cmd0(core, "ac L1");
	rz_core_cmd0(core, "ac L2");
	rz_core_cmd0(core, "ac L3");
	rz_core_cmd0(core, "ac Leaf");
	rz_core_cmd0(core, "ac Side1");
	rz_core_cmd0(core, "ac Side2");
	rz_core_cmd0(core, "ac ExtraBase");
	rz_core_cmd0(core, "ac MultiChild");
	rz_core_cmd0(core, "ac MultiGrandChild");
	rz_core_cmd0(core, "ac OtherRoot");
	rz_core_cmd0(core, "ac OtherChild");
	rz_core_cmd0(core, "acb L1 Root");
	rz_core_cmd0(core, "acb L2 L1");
	rz_core_cmd0(core, "acb L3 L2");
	rz_core_cmd0(core, "acb Leaf L3");
	rz_core_cmd0(core, "acb Side1 Root");
	rz_core_cmd0(core, "acb Side2 Side1");
	rz_core_cmd0(core, "acb MultiChild L2");
	rz_core_cmd0(core, "acb MultiChild ExtraBase");
	rz_core_cmd0(core, "acb MultiGrandChild MultiChild");
	rz_core_cmd0(core, "acb OtherChild OtherRoot");

	RzGraph *mid = rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "L2");
	mu_assert_notnull(mid, "Filtered graph for L2");
	mu_assert_eq(rz_graph_count_nodes(mid), 7, "L2 keeps ancestors and descendants only");
	mu_assert_eq(rz_graph_count_edges(mid), 6, "L2 subgraph has 6 edges");
	mu_assert_true(has_node_title(mid, "Root"), "Root ancestor included");
	mu_assert_true(has_node_title(mid, "L1"), "L1 ancestor included");
	mu_assert_true(has_node_title(mid, "L2"), "L2 target included");
	mu_assert_true(has_node_title(mid, "L3"), "L3 descendant included");
	mu_assert_true(has_node_title(mid, "Leaf"), "Leaf descendant included");
	mu_assert_true(has_node_title(mid, "MultiChild"), "MultiChild descendant included");
	mu_assert_true(has_node_title(mid, "MultiGrandChild"), "MultiGrandChild included");
	mu_assert_false(has_node_title(mid, "Side1"), "Side1 sibling branch excluded");
	mu_assert_false(has_node_title(mid, "Side2"), "Side2 sibling branch excluded");
	mu_assert_false(has_node_title(mid, "ExtraBase"), "ExtraBase co-base excluded");
	mu_assert_false(has_node_title(mid, "OtherRoot"), "OtherRoot component excluded");
	mu_assert_false(has_node_title(mid, "OtherChild"), "OtherChild component excluded");
	rz_graph_free(mid);

	RzGraph *leaf = rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "Leaf");
	mu_assert_notnull(leaf, "Filtered graph for Leaf");
	mu_assert_eq(rz_graph_count_nodes(leaf), 5, "Leaf keeps 4 ancestors plus itself");
	mu_assert_eq(rz_graph_count_edges(leaf), 4, "Leaf chain has 4 edges");
	mu_assert_true(has_node_title(leaf, "Root"), "Root included for Leaf");
	mu_assert_true(has_node_title(leaf, "Leaf"), "Leaf included");
	mu_assert_false(has_node_title(leaf, "MultiChild"), "MultiChild excluded for Leaf");
	rz_graph_free(leaf);

	RzGraph *root = rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "Root");
	mu_assert_notnull(root, "Filtered graph for Root");
	mu_assert_eq(rz_graph_count_nodes(root), 9, "Root keeps full component");
	mu_assert_eq(rz_graph_count_edges(root), 8, "Root component has 8 edges");
	mu_assert_false(has_node_title(root, "ExtraBase"), "ExtraBase excluded for Root");
	mu_assert_false(has_node_title(root, "OtherRoot"), "OtherRoot excluded for Root");
	rz_graph_free(root);

	rz_core_free(core);
	mu_end;
}

bool test_inherit_graph_by_name_sanitized_and_cycles() {
	RzCore *core = rz_core_new();
	rz_analysis_class_create(core->analysis, "ns.Base");
	rz_analysis_class_create(core->analysis, "ns.Child");
	rz_analysis_class_create(core->analysis, "ns.Other");
	RzAnalysisBaseClass base = { .id = NULL, .class_name = "ns.Base", .offset = 0 };
	mu_assert_eq(
		rz_analysis_class_base_set(core->analysis, "ns.Child", &base),
		RZ_ANALYSIS_CLASS_ERR_SUCCESS,
		"Set sanitized base");
	free(base.id);

	RzGraph *san = rz_analysis_class_get_inheritance_graph_by_name(
		core->analysis, "ns.Child");
	mu_assert_notnull(san, "Sanitized class name lookup succeeds");
	mu_assert_eq(rz_graph_count_nodes(san), 2, "ns_Base and ns_Child");
	mu_assert_eq(rz_graph_count_edges(san), 1, "Single inheritance edge");
	mu_assert_true(has_node_title(san, "ns_Base"), "ns_Base included");
	mu_assert_true(has_node_title(san, "ns_Child"), "ns_Child included");
	mu_assert_false(has_node_title(san, "ns_Other"), "ns_Other excluded");
	rz_graph_free(san);

	// Reverse alphabetical order: AChild inherits from ZBase
	rz_core_cmd0(core, "ac AChild");
	rz_core_cmd0(core, "ac BChild");
	rz_core_cmd0(core, "ac ZBase");
	rz_core_cmd0(core, "acb AChild ZBase");
	rz_core_cmd0(core, "acb BChild ZBase");
	RzGraph *rev = rz_analysis_class_get_inheritance_graph_by_name(
		core->analysis, "AChild");
	mu_assert_notnull(rev, "Reverse alphabetical base lookup");
	mu_assert_eq(rz_graph_count_nodes(rev), 2, "AChild and ZBase");
	mu_assert_eq(rz_graph_count_edges(rev), 1, "Single edge ZBase -> AChild");
	mu_assert_true(has_node_title(rev, "AChild"), "AChild included");
	mu_assert_true(has_node_title(rev, "ZBase"), "ZBase included");
	mu_assert_false(has_node_title(rev, "BChild"), "BChild sibling excluded");
	rz_graph_free(rev);

	// Self-loops and 3-node cycle with entry/exit branches
	rz_core_cmd0(core, "ac Self");
	rz_core_cmd0(core, "ac OtherSelf");
	rz_core_cmd0(core, "acb Self Self");
	rz_core_cmd0(core, "acb OtherSelf OtherSelf");
	RzGraph *self_g = rz_analysis_class_get_inheritance_graph_by_name(
		core->analysis, "Self");
	mu_assert_notnull(self_g, "Self-loop class graph succeeds");
	mu_assert_eq(rz_graph_count_nodes(self_g), 1, "Self-loop keeps only Self");
	mu_assert_eq(rz_graph_count_edges(self_g), 1, "Self-loop edge preserved");
	mu_assert_true(has_node_title(self_g, "Self"), "Self included");
	mu_assert_false(has_node_title(self_g, "OtherSelf"), "OtherSelf pruned");
	rz_graph_free(self_g);

	rz_core_cmd0(core, "ac Pre");
	rz_core_cmd0(core, "ac C1");
	rz_core_cmd0(core, "ac C2");
	rz_core_cmd0(core, "ac C3");
	rz_core_cmd0(core, "ac Post");
	rz_core_cmd0(core, "acb C1 Pre");
	rz_core_cmd0(core, "acb C2 C1");
	rz_core_cmd0(core, "acb C3 C2");
	rz_core_cmd0(core, "acb C1 C3");
	rz_core_cmd0(core, "acb Post C3");
	RzGraph *tri = rz_analysis_class_get_inheritance_graph_by_name(core->analysis, "C2");
	mu_assert_notnull(tri, "3-node cycle graph succeeds");
	mu_assert_eq(rz_graph_count_nodes(tri), 5, "Pre, C1, C2, C3, Post");
	mu_assert_eq(rz_graph_count_edges(tri), 5, "All 5 edges in cyclic subgraph");
	mu_assert_true(has_node_title(tri, "Pre"), "Pre ancestor included");
	mu_assert_true(has_node_title(tri, "C1"), "C1 included");
	mu_assert_true(has_node_title(tri, "C2"), "C2 included");
	mu_assert_true(has_node_title(tri, "C3"), "C3 included");
	mu_assert_true(has_node_title(tri, "Post"), "Post descendant included");
	mu_assert_false(has_node_title(tri, "Self"), "Unrelated Self excluded");
	rz_graph_free(tri);

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_inherit_graph_creation);
	mu_run_test(test_inherit_graph_by_name_diamond);
	mu_run_test(test_inherit_graph_by_name_filtering_and_cycle);
	mu_run_test(test_inherit_graph_by_name_empty_and_invalid);
	mu_run_test(test_inherit_graph_by_name_deep_chain_and_multi_inherit);
	mu_run_test(test_inherit_graph_by_name_sanitized_and_cycles);
	return tests_passed != tests_run;
}

mu_main(all_tests)
