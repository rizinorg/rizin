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
	mu_assert_eq(graph->nodes->length, 4, "Wrong node count");

	RzListIter *iter;
	RzGraphNode *node;
	int i = 0;
	ls_foreach (graph->nodes, iter, node) {
		RzGraphNodeInfo *info = node->data;
		switch (i++) {
		case 0:
			mu_assert_streq(info->title, "A", "Wrong node name");
			mu_assert_eq(node->out_nodes->length, 2, "Wrong node out-nodes");
			{
				RzListIter *iter;
				RzGraphNode *out_node;
				int i = 0;
				ls_foreach (node->out_nodes, iter, out_node) {
					RzGraphNodeInfo *info = out_node->data;
					switch (i++) {
					case 0:
						mu_assert_streq(info->title, "B", "Wrong node name");
						break;
					case 1:
						mu_assert_streq(info->title, "C", "Wrong node name");
						break;
					}
				}
			}
			break;
		case 1:
			mu_assert_streq(info->title, "B", "Wrong node name");
			mu_assert_eq(node->out_nodes->length, 1, "Wrong node out-nodes");
			mu_assert_eq(node->in_nodes->length, 1, "Wrong node in-nodes");
			{
				RzListIter *iter;
				RzGraphNode *out_node;
				int i = 0;
				ls_foreach (node->out_nodes, iter, out_node) {
					RzGraphNodeInfo *info = out_node->data;
					switch (i++) {
					case 0:
						mu_assert_streq(info->title, "D", "Wrong node name");
						break;
					}
				}
			}
			break;
		case 2:
			mu_assert_streq(info->title, "C", "Wrong node name");
			mu_assert_eq(node->out_nodes->length, 1, "Wrong node out-nodes");
			mu_assert_eq(node->in_nodes->length, 1, "Wrong node in-nodes");
			{
				RzListIter *iter;
				RzGraphNode *out_node;
				int i = 0;
				ls_foreach (node->out_nodes, iter, out_node) {
					RzGraphNodeInfo *info = out_node->data;
					switch (i++) {
					case 0:
						mu_assert_streq(info->title, "D", "Wrong node name");
						break;
					}
				}
			}
			break;
		case 3:
			mu_assert_streq(info->title, "D", "Wrong node name");
			mu_assert_eq(node->in_nodes->length, 2, "Wrong node in-nodes");
			break;
		default:
			break;
		}
	}
	rz_core_free(core);
	rz_graph_free(graph);
	mu_end;
}

int all_tests() {
	mu_run_test(test_inherit_graph_creation);
	return tests_passed != tests_run;
}

mu_main(all_tests)