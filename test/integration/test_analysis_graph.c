// SPDX-FileCopyrightText: 2022 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_project.h>

#include "../unit/minunit.h"
#include <rz_util/rz_graph_drawable.h>

static inline RzGraph *graph_by_function_name(RzCore *core, RzCoreGraphType t, const char *name) {
	RzAnalysisFunction *f = rz_analysis_get_function_byname(core->analysis, name);
	char *msg = rz_str_newf("find function %s", name);
	mu_assert_notnull(f, msg);
	RZ_FREE(msg);

	RzGraph *g = rz_core_graph(core, t, f->addr);
	msg = rz_str_newf("create graph %s", name);
	mu_assert_notnull(g, msg);
	free(msg);
	return g;
}

bool test_analysis_graph() {
	// 1. Open the file
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	ut64 loadaddr = 0;
	const char *fpath = "bins/elf/ls";
	RzCoreFile *file = rz_core_file_open(core, fpath, RZ_PERM_R, loadaddr);
	mu_assert_notnull(file, "open file");
	rz_core_bin_load(core, fpath, loadaddr);

	// 2. Analyse the file
	rz_core_analysis_all(core);
	rz_core_analysis_everything(core, false, "esil");

	// 3 dataref graph
	RzGraph *g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_DATAREF, "entry0");
	mu_assert_notnull(g, "Graph was NULL");
	mu_assert_eq(g->n_nodes, 1, "data graph node count");
	mu_assert_eq(g->n_edges, 0, "data graph edge count");
	mu_assert_streq_free(rz_graph_drawable_to_json_str(g, true),
		"{\"nodes\":[{\"id\":0,\"title\":\"entry0\",\"offset\":23264,\"out_nodes\":[]}]}\n",
		"graph json");
	rz_graph_free(g);

	RzGraph *g_main_dataref = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_DATAREF, "main");
	mu_assert_eq(g_main_dataref->n_nodes, 135, "data graph node count");
	mu_assert_eq(g_main_dataref->n_edges, 134, "data graph edge count");

	// 4. Save into the project
	char *tmpdir = rz_file_tmpdir();
	char *project_file = rz_file_path_join(tmpdir, "test_analysis_graph.rzdb");
	RzProjectErr err = rz_project_save_file(core, project_file, true);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project save err");
	free(project_file);

	// 5. Close the file
	rz_core_file_close(file);
	rz_core_free(core);

	// 6. Create a new core
	core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");

	// 7. Load the previously saved project
	RzSerializeResultInfo *res = rz_serialize_result_info_new();
	mu_assert_notnull(res, "result info new");
	project_file = rz_file_path_join(tmpdir, "test_analysis_graph.rzdb");
	err = rz_project_load_file(core, project_file, true, res);
	mu_assert_eq(err, RZ_PROJECT_ERR_SUCCESS, "project load err");
	free(project_file);

	// 8. Compare with the previously saved one
	g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_DATAREF, "main");
	mu_assert_eq(g->n_nodes, g_main_dataref->n_nodes, "compare node count");
	mu_assert_eq(g->n_edges, g_main_dataref->n_edges, "compare edge count");
	rz_graph_free(g);
	rz_graph_free(g_main_dataref);

	// 10. Exit
	free(tmpdir);
	rz_serialize_result_info_free(res);
	rz_core_free(core);
	mu_end;
}

bool test_analysis_graph_more() {
	// 1. Open the file
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	const char *fpath = "bins/elf/lab1B";
	mu_assert_true(rz_core_file_open_load(core, fpath, 0, RZ_PERM_R, false), "load file");

	// 2. Analyse the file
	rz_core_analysis_all(core);
	rz_core_analysis_everything(core, false, "esil");
	rz_core_analysis_flag_every_function(core);

	// 3.1 dataref graph
	RzGraph *g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_DATAREF, "main");
	mu_assert_notnull(g, "Graph was NULL");
	mu_assert_eq(g->n_nodes, 6, "data graph node count");
	mu_assert_eq(g->n_edges, 5, "data graph edge count");
	mu_assert_streq_free(rz_graph_drawable_to_json_str(g, true),
		"{\"nodes\":["
		"{\"id\":0,\"title\":\"main\",\"offset\":134515684,\"out_nodes\":[1,2,3,4,5]},"
		"{\"id\":1,\"title\":\"data.08048d88\",\"offset\":134516104,\"out_nodes\":[]},"
		"{\"id\":2,\"title\":\"str.RPISEC___CrackMe_v2.0\",\"offset\":134516134,\"out_nodes\":[]},"
		"{\"id\":3,\"title\":\"str.\",\"offset\":134516164,\"out_nodes\":[]},"
		"{\"id\":4,\"title\":\"str.Password:\",\"offset\":134516194,\"out_nodes\":[]},"
		"{\"id\":5,\"title\":\"data.08048dee\",\"offset\":134516206,\"out_nodes\":[]}"
		"]}\n",
		"graph json");
	rz_graph_free(g);

	// 3.2 function blocks graph
	g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_BLOCK_FUN, "main");
	mu_assert_eq(g->n_nodes, 3, "data graph node count");
	mu_assert_eq(g->n_edges, 3, "data graph edge count");

	RzGraphNode *n = rz_graph_get_node(g, 0);
	mu_assert_notnull(n, "graph node");

	RzGraphNodeInfo *ni = n->data;
	mu_assert_notnull(ni, "graph node info");
	mu_assert_streq(ni->def.title, "0x8048be4", "graph node");

	const RzList *list = rz_graph_get_neighbours(g, n);
	mu_assert_notnull(list, "node neighbours");
	mu_assert_eq(rz_list_length(list), 2, "node neighbours");
	rz_graph_free(g);

	// 3.3 function call graph
	g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_FUNCALL, "main");
	mu_assert_eq(g->n_nodes, 9, "data graph node count");
	mu_assert_eq(g->n_edges, 8, "data graph edge count");

	n = rz_graph_get_node(g, 0);
	mu_assert_notnull(n, "graph node");

	ni = n->data;
	mu_assert_notnull(ni, "graph node info");
	mu_assert_streq(ni->def.title, "main", "graph node");

	list = rz_graph_get_neighbours(g, n);
	mu_assert_notnull(list, "node neighbours");
	mu_assert_eq(rz_list_length(list), 8, "node neighbours");
	rz_graph_free(g);

	// 3.4 coderef graph
	g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_REF, "main");
	mu_assert_eq(g->n_nodes, 1, "data graph node count");
	mu_assert_eq(g->n_edges, 0, "data graph edge count");
	rz_graph_free(g);

	// 3.5 codexref graph
	g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_XREF, "main");
	mu_assert_eq(g->n_nodes, 2, "data graph node count");
	mu_assert_eq(g->n_edges, 1, "data graph edge count");

	n = rz_graph_get_node(g, 0);
	mu_assert_notnull(n, "graph node");

	ni = n->data;
	mu_assert_notnull(ni, "graph node info");
	mu_assert_streq(ni->def.title, "sym.main", "graph node");

	list = rz_graph_get_neighbours(g, n);
	mu_assert_notnull(list, "node neighbours");
	mu_assert_eq(rz_list_length(list), 0, "node neighbours");
	rz_graph_free(g);

	// 3.6 import graph
	g = rz_core_graph(core, RZ_CORE_GRAPH_TYPE_IMPORT, 0);
	mu_assert_eq(g->n_nodes, 35, "data graph node count");
	mu_assert_eq(g->n_edges, 18, "data graph edge count");

	n = rz_graph_get_node(g, 1);
	mu_assert_notnull(n, "graph node");

	ni = n->data;
	mu_assert_notnull(ni, "graph node info");
	mu_assert_streq(ni->def.title, "0x08048a3e", "graph node");

	list = rz_graph_get_neighbours(g, n);
	mu_assert_notnull(list, "node neighbours");
	mu_assert_eq(rz_list_length(list), 1, "node neighbours");
	rz_graph_free(g);

	// 5. Close the file
	rz_core_free(core);
	mu_end;
}

bool test_analysis_graph_icfg() {
	// Open the file
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	const char *fpath = "bins/elf/analysis/x86_icfg_malloc_test";
	mu_assert_true(rz_core_file_open_load(core, fpath, 0, RZ_PERM_R, false), "load file");

	// Analyse the file
	rz_core_analysis_all(core);
	rz_core_analysis_everything(core, false, "esil");
	rz_core_analysis_flag_every_function(core);

	RzGraph *g = rz_core_graph_icfg(core);
	mu_assert_notnull(g, "Graph was NULL");
	mu_assert_eq(g->n_nodes, 13, "data graph node count");
	mu_assert_eq(g->n_edges, 6, "data graph edge count");

	// Testing the node content is a little annoying. The nodes
	// are indexed by their position in the list.
	// Although in case of a CFG and iCFG it would be better to
	// have them indexed by their address in the binary.
	// But the current graph implementation (list and not hashmap based)
	// doesn't support this.
	// So, if this test breaks due to some changes in the analysis,
	// make sure the order of the nodes did not change
	// (because they might have been added in different order).
	RzGraphNodeInfo *info = rz_graph_get_node_info_data(rz_graph_get_node(g, 7)->data);
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_ICFG, "info type");
	mu_assert_eq(info->icfg.address, 0x1159, "info address");
	mu_assert_false(info->icfg.is_malloc, "info address");

	info = rz_graph_get_node_info_data(rz_graph_get_node(g, 8)->data);
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_ICFG, "info type");
	mu_assert_eq(info->icfg.address, 0x1040, "info address");
	mu_assert_true(info->icfg.is_malloc, "info is_malloc");

	info = rz_graph_get_node_info_data(rz_graph_get_node(g, 9)->data);
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_ICFG, "info type");
	mu_assert_eq(info->icfg.address, 0x1030, "info address");
	mu_assert_true(info->icfg.is_malloc, "info is_malloc");

	info = rz_graph_get_node_info_data(rz_graph_get_node(g, 10)->data);
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_ICFG, "info type");
	mu_assert_eq(info->icfg.address, 0x1050, "info address");
	mu_assert_true(info->icfg.is_malloc, "info is_malloc");

	rz_graph_free(g);

	// Close the file
	rz_core_free(core);
	mu_end;
}

bool test_analysis_graph_cfg() {
	// Open the file
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	const char *fpath = "bins/elf/analysis/x86_cfg_node_details_test";
	mu_assert_true(rz_core_file_open_load(core, fpath, 0, RZ_PERM_R, false), "load file");

	// Analyse the file
	rz_core_analysis_all(core);
	rz_core_analysis_everything(core, false, "esil");
	rz_core_analysis_flag_every_function(core);

	RzGraph *g = rz_core_graph_cfg(core, 0x117a, true); // main()
	mu_assert_notnull(g, "Graph was NULL");
	mu_assert_eq(g->n_nodes, 24, "data graph node count");
	mu_assert_eq(g->n_edges, 25, "data graph edge count");

	// Testing the node content is a little annoying. The nodes
	// are indexed by their position in the list.
	// Although in case of a CFG and iCFG it would be better to
	// have them indexed by their address in the binary.
	// But the current graph implementation (list and not hashmap based)
	// doesn't support this.
	// So, if this test breaks due to some changes in the analysis,
	// make sure the order of the nodes did not change
	// (because they might have been added in different order).
	RzGraphNodeInfo *info = rz_graph_get_node_info_data(rz_graph_get_node(g, 0)->data);
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->cfg.subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY, "info subtype");
	mu_assert_eq(info->cfg.address, 0x117a, "info address");
	mu_assert_eq(info->cfg.call_address, UT64_MAX, "info call address");

	info = rz_graph_get_node_info_data(rz_graph_get_node(g, 3)->data);
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->cfg.subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_CALL, "info subtype");
	mu_assert_eq(info->cfg.address, 0x1182, "info address");
	mu_assert_eq(info->cfg.call_address, 0x1050, "info call address");

	info = rz_graph_get_node_info_data(rz_graph_get_node(g, 10)->data);
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->cfg.subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_COND, "info subtype");
	mu_assert_eq(info->cfg.address, 0x11a7, "info address");
	mu_assert_eq(info->cfg.call_address, UT64_MAX, "info call address");

	info = rz_graph_get_node_info_data(rz_graph_get_node(g, 23)->data);
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->cfg.subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_CALL, "info subtype");
	mu_assert_eq(info->cfg.address, 0x11cd, "info address");
	mu_assert_eq(info->cfg.call_address, UT64_MAX, "info call address");

	info = rz_graph_get_node_info_data(rz_graph_get_node(g, 18)->data);
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->cfg.subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN, "info subtype");
	mu_assert_eq(info->cfg.address, 0x11d3, "info address");
	mu_assert_eq(info->cfg.call_address, UT64_MAX, "info call address");

	rz_graph_free(g);

	// Close the file
	rz_core_free(core);
	mu_end;
}
int all_tests() {
	mu_run_test(test_analysis_graph);
	mu_run_test(test_analysis_graph_more);
	mu_run_test(test_analysis_graph_icfg);
	mu_run_test(test_analysis_graph_cfg);
	return tests_passed != tests_run;
}

mu_main(all_tests)
