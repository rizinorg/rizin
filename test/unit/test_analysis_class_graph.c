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

	RzIterator *iter = rz_graph_get_nodes(graph);
	mu_assert_notnull(iter, "get_nodes iterator");
	RzGraphNode *node;
	int i = 0;
	rz_iterator_foreach(iter, node) {
		const RzGraphNodeInfo *info = rz_graph_node_get_data(node);
		switch (i++) {
		case 0:
			mu_assert_streq(info->def.title, "A", "Wrong node name");
			mu_assert_eq(rz_graph_out_degree(graph, node), 2, "Wrong node out-nodes");
			{
				RzIterator *out_iter = rz_graph_out_neighbors(graph, node);
				mu_assert_notnull(out_iter, "out_neighbors iter A");
				RzGraphNode *out_node;
				int j = 0;
				rz_iterator_foreach(out_iter, out_node) {
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
				rz_iterator_free(out_iter);
			}
			break;
		case 1:
			mu_assert_streq(info->def.title, "B", "Wrong node name");
			mu_assert_eq(rz_graph_out_degree(graph, node), 1, "Wrong node out-nodes");
			mu_assert_eq(rz_graph_in_degree(graph, node), 1, "Wrong node in-nodes");
			{
				RzIterator *out_iter = rz_graph_out_neighbors(graph, node);
				mu_assert_notnull(out_iter, "out_neighbors iter B");
				RzGraphNode *out_node;
				int j = 0;
				rz_iterator_foreach(out_iter, out_node) {
					const RzGraphNodeInfo *out_info = rz_graph_node_get_data(out_node);
					switch (j++) {
					case 0:
						mu_assert_streq(out_info->def.title, "D", "Wrong node name");
						break;
					}
				}
				rz_iterator_free(out_iter);
			}
			break;
		case 2:
			mu_assert_streq(info->def.title, "C", "Wrong node name");
			mu_assert_eq(rz_graph_out_degree(graph, node), 1, "Wrong node out-nodes");
			mu_assert_eq(rz_graph_in_degree(graph, node), 1, "Wrong node in-nodes");
			{
				RzIterator *out_iter = rz_graph_out_neighbors(graph, node);
				mu_assert_notnull(out_iter, "out_neighbors iter C");
				RzGraphNode *out_node;
				int j = 0;
				rz_iterator_foreach(out_iter, out_node) {
					const RzGraphNodeInfo *out_info = rz_graph_node_get_data(out_node);
					switch (j++) {
					case 0:
						mu_assert_streq(out_info->def.title, "D", "Wrong node name");
						break;
					}
				}
				rz_iterator_free(out_iter);
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
	rz_iterator_free(iter);
	rz_core_free(core);
	rz_graph_free(graph);
	mu_end;
}

int all_tests() {
	mu_run_test(test_inherit_graph_creation);
	return tests_passed != tests_run;
}

mu_main(all_tests)
