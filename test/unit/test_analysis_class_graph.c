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

int all_tests() {
	mu_run_test(test_inherit_graph_creation);
	mu_run_test(test_inherit_graph_by_name_diamond);
	mu_run_test(test_inherit_graph_by_name_filtering_and_cycle);
	return tests_passed != tests_run;
}

mu_main(all_tests)
