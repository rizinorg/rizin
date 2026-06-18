// SPDX-FileCopyrightText: 2022 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_project.h>

#include "../unit/minunit.h"
#include <rz_util/rz_graph_drawable.h>

/**
 * \brief DO NOT USE
 * Compatibility replacement for the removed rz_graph_get_node().
 * Safe indexed access into node_vec by insertion-order index. Returns NULL
 * if \p idx is out of bounds or the slot is a deleted hole (NULL left by
 * rz_graph_del_node). Callers must not assume the index is stable after
 * node deletions.
 *
 * \param g graph
 * \param idx insertion-order index (same as _vec_id at the time of node creation)
 * \return the node at that index (borrowed), or NULL
 */
static RZ_NULLABLE RZ_BORROW RzGraphNode *rz_graph_get_node_at(const RzGraph *g, ut64 idx) {
	rz_return_val_if_fail(g, NULL);
	const RzPVector *node_vec = rz_graph_get_node_vec(g);
	if (idx >= rz_pvector_len(node_vec)) {
		return NULL;
	}
	return (RzGraphNode *)rz_pvector_at(node_vec, idx);
}

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
	mu_assert_eq(rz_graph_get_n_nodes(g), 1, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g), 0, "data graph edge count");
	mu_assert_streq_free(rz_graph_drawable_to_json_str(g, true),
		"{\"nodes\":[{\"id\":0,\"title\":\"entry0\",\"offset\":23264,\"out_nodes\":[]}]}\n",
		"graph json");
	rz_graph_free(g);

	RzGraph *g_main_dataref = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_DATAREF, "main");
	mu_assert_eq(rz_graph_get_n_nodes(g_main_dataref), 130, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g_main_dataref), 129, "data graph edge count");

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
	mu_assert_eq(rz_graph_get_n_nodes(g), rz_graph_get_n_nodes(g_main_dataref), "compare node count");
	mu_assert_eq(rz_graph_get_n_edges(g), rz_graph_get_n_edges(g_main_dataref), "compare edge count");
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
	mu_assert_eq(rz_graph_get_n_nodes(g), 6, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g), 5, "data graph edge count");
	mu_assert_streq_free(rz_graph_drawable_to_json_str(g, true),
		"{\"nodes\":["
		"{\"id\":0,\"title\":\"main\",\"offset\":134515684,\"out_nodes\":[1,2,3,4,5]},"
		"{\"id\":1,\"title\":\"data.08048d88\",\"offset\":134516104,\"out_nodes\":[]},"
		"{\"id\":2,\"title\":\"str.RPISEC___CrackMe_v2.0\",\"offset\":134516134,\"out_nodes\":[]},"
		"{\"id\":3,\"title\":\"str.\",\"offset\":134516164,\"out_nodes\":[]},"
		"{\"id\":4,\"title\":\"str.Password:\",\"offset\":134516194,\"out_nodes\":[]},"
		"{\"id\":5,\"title\":\"str.d\",\"offset\":134516206,\"out_nodes\":[]}"
		"]}\n",
		"graph json");
	rz_graph_free(g);

	// 3.2 function blocks graph
	g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_BLOCK_FUN, "main");
	mu_assert_eq(rz_graph_get_n_nodes(g), 3, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g), 3, "data graph edge count");

	RzGraphNode *n = rz_graph_get_node_at(g, 0);
	mu_assert_notnull(n, "graph node");

	const RzGraphNodeInfo *ni = rz_graph_node_get_data(n);
	mu_assert_notnull(ni, "graph node info");
	mu_assert_streq(ni->def.title, "0x8048be4", "graph node");

	mu_assert_eq(rz_graph_out_degree(g, n), 2, "node neighbours");
	rz_graph_free(g);

	// 3.3 function call graph
	g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_FUNCALL, "main");
	mu_assert_eq(rz_graph_get_n_nodes(g), 9, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g), 8, "data graph edge count");

	n = rz_graph_get_node_at(g, 0);
	mu_assert_notnull(n, "graph node");

	ni = rz_graph_node_get_data(n);
	mu_assert_notnull(ni, "graph node info");
	mu_assert_streq(ni->def.title, "main", "graph node");

	mu_assert_eq(rz_graph_out_degree(g, n), 8, "node neighbours");
	rz_graph_free(g);

	// 3.4 coderef graph
	g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_REF, "main");
	mu_assert_eq(rz_graph_get_n_nodes(g), 1, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g), 0, "data graph edge count");
	rz_graph_free(g);

	// 3.5 codexref graph
	g = graph_by_function_name(core, RZ_CORE_GRAPH_TYPE_XREF, "main");
	mu_assert_eq(rz_graph_get_n_nodes(g), 2, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g), 1, "data graph edge count");

	n = rz_graph_get_node_at(g, 0);
	mu_assert_notnull(n, "graph node");

	ni = rz_graph_node_get_data(n);
	mu_assert_notnull(ni, "graph node info");
	mu_assert_streq(ni->def.title, "sym.main", "graph node");

	mu_assert_eq(rz_graph_out_degree(g, n), 0, "node neighbours");
	rz_graph_free(g);

	// 3.6 import graph
	g = rz_core_graph(core, RZ_CORE_GRAPH_TYPE_IMPORT, 0);
	mu_assert_eq(rz_graph_get_n_nodes(g), 35, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g), 18, "data graph edge count");

	n = rz_graph_get_node_at(g, 1);
	mu_assert_notnull(n, "graph node");

	ni = rz_graph_node_get_data(n);
	mu_assert_notnull(ni, "graph node info");
	mu_assert_streq(ni->def.title, "0x08048a3e", "graph node");

	mu_assert_eq(rz_graph_out_degree(g, n), 1, "node neighbours");
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
	mu_assert_eq(rz_graph_get_n_nodes(g), 13, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g), 6, "data graph edge count");

	// Testing the node content is a little annoying. The nodes
	// are indexed by their position in the list.
	// Although in case of a CFG and iCFG it would be better to
	// have them indexed by their address in the binary.
	// But the current graph implementation (list and not hashmap based)
	// doesn't support this.
	// So, if this test breaks due to some changes in the analysis,
	// make sure the order of the nodes did not change
	// (because they might have been added in different order).
	RzGraphNodeInfo *info = rz_graph_get_node_info_data(rz_graph_node_get_data_mut(rz_graph_get_node_at(g, 7)));
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_ICFG, "info type");
	mu_assert_eq(info->icfg.address, 0x1159, "info address");
	mu_assert_false(info->icfg.is_malloc, "info address");

	info = rz_graph_get_node_info_data(rz_graph_node_get_data_mut(rz_graph_get_node_at(g, 8)));
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_ICFG, "info type");
	mu_assert_eq(info->icfg.address, 0x1040, "info address");
	mu_assert_true(info->icfg.is_malloc, "info is_malloc");

	info = rz_graph_get_node_info_data(rz_graph_node_get_data_mut(rz_graph_get_node_at(g, 9)));
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_ICFG, "info type");
	mu_assert_eq(info->icfg.address, 0x1030, "info address");
	mu_assert_true(info->icfg.is_malloc, "info is_malloc");

	info = rz_graph_get_node_info_data(rz_graph_node_get_data_mut(rz_graph_get_node_at(g, 10)));
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

	RzGraph *g = rz_core_graph_cfg(core, 0x117a); // main()
	mu_assert_notnull(g, "Graph was NULL");
	mu_assert_eq(rz_graph_get_n_nodes(g), 24, "data graph node count");
	mu_assert_eq(rz_graph_get_n_edges(g), 25, "data graph edge count");

	// Testing the node content is a little annoying. The nodes
	// are indexed by their position in the list.
	// Although in case of a CFG and iCFG it would be better to
	// have them indexed by their address in the binary.
	// But the current graph implementation (list and not hashmap based)
	// doesn't support this.
	// So, if this test breaks due to some changes in the analysis,
	// make sure the order of the nodes did not change
	// (because they might have been added in different order).
	RzGraphNodeInfo *info = rz_graph_get_node_info_data(rz_graph_node_get_data_mut(rz_graph_get_node_at(g, 0)));
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY, "info subtype");
	mu_assert_eq(info->cfg.address, 0x117a, "info address");
	mu_assert_eq(info->cfg.call_address, UT64_MAX, "info call address");

	info = rz_graph_get_node_info_data(rz_graph_node_get_data_mut(rz_graph_get_node_at(g, 3)));
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_CALL, "info subtype");
	mu_assert_eq(info->cfg.address, 0x1182, "info address");
	mu_assert_eq(info->cfg.call_address, 0x1050, "info call address");

	info = rz_graph_get_node_info_data(rz_graph_node_get_data_mut(rz_graph_get_node_at(g, 10)));
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_COND, "info subtype");
	mu_assert_eq(info->cfg.address, 0x11a7, "info address");
	mu_assert_eq(info->cfg.call_address, UT64_MAX, "info call address");

	info = rz_graph_get_node_info_data(rz_graph_node_get_data_mut(rz_graph_get_node_at(g, 23)));
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_CALL, "info subtype");
	mu_assert_eq(info->cfg.address, 0x11cd, "info address");
	mu_assert_eq(info->cfg.call_address, UT64_MAX, "info call address");

	info = rz_graph_get_node_info_data(rz_graph_node_get_data_mut(rz_graph_get_node_at(g, 18)));
	mu_assert_eq(info->type, RZ_GRAPH_NODE_TYPE_CFG, "info type");
	mu_assert_eq(info->subtype, RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN, "info subtype");
	mu_assert_eq(info->cfg.address, 0x11d3, "info address");
	mu_assert_eq(info->cfg.call_address, UT64_MAX, "info call address");

	rz_graph_free(g);

	// Close the file
	rz_core_free(core);
	mu_end;
}

bool test_analysis_graph_entrypoints() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	const char *fpath = "bins/elf/lab1B";
	mu_assert_true(rz_core_file_open_load(core, fpath, 0, RZ_PERM_R, false), "load file");

	rz_core_analysis_all(core);
	rz_core_analysis_everything(core, false, "esil");
	rz_core_analysis_flag_every_function(core);

	RzAnalysisFunction *f = rz_analysis_get_function_byname(core->analysis, "main");
	mu_assert_notnull(f, "find main");

	// callgraph: direct call must match the dispatcher (FUNCALL).
	RzGraph *direct = rz_core_graph_callgraph(core, f->addr);
	mu_assert_notnull(direct, "callgraph direct");
	RzGraph *via = rz_core_graph(core, RZ_CORE_GRAPH_TYPE_FUNCALL, f->addr);
	mu_assert_notnull(via, "callgraph via dispatcher");
	mu_assert_eq(rz_graph_get_n_nodes(direct), rz_graph_get_n_nodes(via), "callgraph nodes match");
	mu_assert_eq(rz_graph_get_n_edges(direct), rz_graph_get_n_edges(via), "callgraph edges match");
	rz_graph_free(direct);
	rz_graph_free(via);

	// datarefs: direct call must match the dispatcher (DATAREF).
	direct = rz_core_graph_datarefs(core, f->addr);
	mu_assert_notnull(direct, "datarefs direct");
	via = rz_core_graph(core, RZ_CORE_GRAPH_TYPE_DATAREF, f->addr);
	mu_assert_notnull(via, "datarefs via dispatcher");
	mu_assert_eq(rz_graph_get_n_nodes(direct), rz_graph_get_n_nodes(via), "datarefs nodes match");
	mu_assert_eq(rz_graph_get_n_edges(direct), rz_graph_get_n_edges(via), "datarefs edges match");
	rz_graph_free(direct);
	rz_graph_free(via);

	// coderefs: direct call must match the dispatcher (REF).
	direct = rz_core_graph_coderefs(core, f->addr);
	mu_assert_notnull(direct, "coderefs direct");
	via = rz_core_graph(core, RZ_CORE_GRAPH_TYPE_REF, f->addr);
	mu_assert_notnull(via, "coderefs via dispatcher");
	mu_assert_eq(rz_graph_get_n_nodes(direct), rz_graph_get_n_nodes(via), "coderefs nodes match");
	mu_assert_eq(rz_graph_get_n_edges(direct), rz_graph_get_n_edges(via), "coderefs edges match");
	rz_graph_free(direct);
	rz_graph_free(via);

	// importxrefs: takes no address, must match the dispatcher (IMPORT).
	direct = rz_core_graph_importxrefs(core);
	mu_assert_notnull(direct, "importxrefs direct");
	via = rz_core_graph(core, RZ_CORE_GRAPH_TYPE_IMPORT, 0);
	mu_assert_notnull(via, "importxrefs via dispatcher");
	mu_assert_eq(rz_graph_get_n_nodes(direct), rz_graph_get_n_nodes(via), "importxrefs nodes match");
	mu_assert_eq(rz_graph_get_n_edges(direct), rz_graph_get_n_edges(via), "importxrefs edges match");
	rz_graph_free(direct);
	rz_graph_free(via);

	rz_core_free(core);
	mu_end;
}

/**
 * rz_core_graph_to_dot_str() and rz_core_graph_to_sdb_str() turn an RzGraph
 * into the textual representations used by the `agd`/`agk`-style commands.
 * We assert they produce non-empty output for a real function graph.
 */
bool test_analysis_graph_serialize() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	const char *fpath = "bins/elf/lab1B";
	mu_assert_true(rz_core_file_open_load(core, fpath, 0, RZ_PERM_R, false), "load file");

	rz_core_analysis_all(core);
	rz_core_analysis_everything(core, false, "esil");
	rz_core_analysis_flag_every_function(core);

	RzAnalysisFunction *f = rz_analysis_get_function_byname(core->analysis, "main");
	mu_assert_notnull(f, "find main");

	RzGraph *g = rz_core_graph_callgraph(core, f->addr);
	mu_assert_notnull(g, "callgraph");

	char *dot = rz_core_graph_to_dot_str(core, g);
	mu_assert_notnull(dot, "dot string");
	mu_assert_true(strstr(dot, "digraph") != NULL, "dot has digraph header");
	free(dot);

	char *sdb = rz_core_graph_to_sdb_str(core, g);
	mu_assert_notnull(sdb, "sdb string");
	mu_assert_true(strlen(sdb) > 0, "sdb non-empty");
	free(sdb);

	rz_graph_free(g);
	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_analysis_graph);
	mu_run_test(test_analysis_graph_more);
	mu_run_test(test_analysis_graph_icfg);
	mu_run_test(test_analysis_graph_cfg);
	mu_run_test(test_analysis_graph_entrypoints);
	mu_run_test(test_analysis_graph_serialize);
	return tests_passed != tests_run;
}

mu_main(all_tests)
