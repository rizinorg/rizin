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
		"{\"id\":5,\"title\":\"data.08048dee\",\"offset\":134516206,\"out_nodes\":[]}"
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

/*
 * Real-CFG render golden.
 *
 * The synthetic-graph goldens in test/unit/test_agraph.c pin coordinates for
 * small graphs with fixed node dimensions. They do not cover the rendered
 * output of a real binary's control-flow graph, where node bodies hold actual
 * instruction text and node width/height come from rz_str_bounds() on that
 * text. This test loads bins/elf/lab1B, computes the main function's CFG, and
 * asserts that the full ASCII render is byte-for-byte identical to a known-good
 * fixture (2791 bytes). Any change to layout, dummy-edge routing, node
 * rendering, or text measurement that affects the visible output will fail this
 * test with a diff that points at the exact change.
 *
 * The fixture was captured from the algorithm as it stands when this test was
 * written; the md5 (671d659a9ec3725794c5fbcd1b74f0d3) has been stable across
 * every layout refactor in this series (rizinorg/rizin#992).
 */
/*
 * Helper: load \p binary, seek to \p seek_target, render the function CFG via
 * the agf command, and assert it equals \p expected byte-for-byte. Used by the
 * real-CFG render goldens below.
 */
static bool assert_agf_render(const char *binary, const char *seek_target,
	const char *expected) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "new RzCore instance");
	mu_assert_true(rz_core_file_open_load(core, binary, 0, RZ_PERM_R, false), "load file");

	/* Pin the rendering knobs so the fixture is reproducible. */
	rz_config_set(core->config, "scr.utf8", "false");
	rz_config_set(core->config, "scr.color", "0");

	rz_core_cmd0(core, "aa");
	rz_core_cmd0(core, seek_target);
	char *out = rz_core_cmd_str(core, "agf");
	mu_assert_notnull(out, "agf produced output");
	mu_assert_streq(out, expected, "agf render byte-identical to fixture");

	free(out);
	rz_core_free(core);
	return true;
}

/*
 * Real-CFG render golden #1: lab1B main (small, ~4 blocks).
 *
 * Loads bins/elf/lab1B, computes main's CFG, runs the full agf pipeline
 * in-process via rz_core_cmd_str(), and asserts the 2791-byte ASCII render is
 * byte-for-byte identical to a stored fixture. Catches anything the
 * coordinate goldens in test_agraph.c miss: text measurement on real
 * instruction bodies, dummy-edge routing, canvas drawing, spacing. Any
 * visible change in the picture fails the test with a diff that points at
 * the exact byte. The fixture's md5
 * (671d659a9ec3725794c5fbcd1b74f0d3) has been stable across every layout
 * refactor in this series (rizinorg/rizin#992).
 */
bool test_analysis_graph_render_real_cfg() {
	const char *expected =
		"  .----------------------------------------.\n"
		"  |  0x8048be4                             |\n"
		"  |   ; DATA XREF from entry0 @ 0x8048867  |\n"
		"  | main();                                |\n"
		"  | ; var unknown_t var_20h @ stack - 0x20 |\n"
		"  | ; var unknown_t var_1ch @ stack - 0x1c |\n"
		"  | ; var unknown_t var_8h @ stack - 0x8   |\n"
		"  | ; var unknown_t var_4h @ stack - 0x4   |\n"
		"  | push ebp                               |\n"
		"  | mov ebp, esp                           |\n"
		"  | and esp, 0xfffffff0                    |\n"
		"  | sub esp, 0x20                          |\n"
		"  | push eax                               |\n"
		"  | xor eax, eax                           |\n"
		"  | jz 0x8048bf5                           |\n"
		"  `----------------------------------------'\n"
		"          f t\n"
		"          | |\n"
		"          | '----------------.\n"
		"          '--.               |\n"
		"             |               |\n"
		"         .---------------.   |\n"
		"         |  0x8048bf2    |   |\n"
		"         | add esp, 0x04 |   |\n"
		"         `---------------'   |\n"
		"             v               |\n"
		"             |               |\n"
		"      .------'               |\n"
		"      | .--------------------'\n"
		"      | |\n"
		".--------------------------------------------.\n"
		"|  0x8048bf5                                 |\n"
		"| pop eax                                    |\n"
		"| mov dword [esp], 0x00                      |\n"
		"| call sym.imp.time                          |\n"
		"| mov dword [esp], eax                       |\n"
		"| call sym.imp.srand                         |\n"
		"| ; [0x8048d88:4]=0x2d2d2d2e                 |\n"
		"| mov dword [esp], 0x8048d88                 |\n"
		"| call sym.imp.puts                          |\n"
		"| ; [0x8048da6:4]=0x202d2d7c                 |\n"
		"| ; \"|-- RPISEC - CrackMe v2.0 --|\"          |\n"
		"| mov dword [esp], str.RPISEC___CrackMe_v2.0 |\n"
		"| call sym.imp.puts                          |\n"
		"| ; [0x8048dc4:4]=0x2d2d2d27                 |\n"
		"| ; \"'---------------------------'\"          |\n"
		"| mov dword [esp], str.                      |\n"
		"| call sym.imp.puts                          |\n"
		"| ; [0x8048de2:4]=0x7361500a                 |\n"
		"| ; \"\\nPassword: \"                           |\n"
		"| mov dword [esp], str.Password:             |\n"
		"| call sym.imp.printf                        |\n"
		"| lea eax, dword [var_8h]                    |\n"
		"| mov dword [var_20h], eax                   |\n"
		"| ; [0x8048dee:4]=0x6425                     |\n"
		"| mov dword [esp], 0x8048dee                 |\n"
		"| call sym.imp.__isoc99_scanf                |\n"
		"| mov eax, dword [var_8h]                    |\n"
		"| ; [0x1337d00d:4]=-1                        |\n"
		"| mov dword [var_20h], 0x1337d00d            |\n"
		"| mov dword [esp], eax                       |\n"
		"| call sym.test                              |\n"
		"| mov eax, 0x00                              |\n"
		"| leave                                      |\n"
		"| ret                                        |\n"
		"`--------------------------------------------'\n";
	if (!assert_agf_render("bins/elf/lab1B", "s main", expected)) {
		return MU_ERR;
	}
	mu_end;
}

/*
 * Real-CFG render golden #2: lab1B sym.decrypt (~11 blocks, multi-layer with
 * long edges that exercise dummy-node insertion and crossing reduction on a
 * real CFG). Materially broader coverage than the main fixture: deeper
 * layering, more edge routing, wider mix of comment/data references in node
 * bodies. Fixture md5: 3db46f6070ef4f0b16bd8013d2dec3c6.
 */
bool test_analysis_graph_render_real_cfg_decrypt() {
	const char *expected =
		"                  .-----------------------------------------.\n"
		"                  |  0x80489b7                              |\n"
		"                  |   ; CALL XREF from sym.test @ 0x8048bdd |\n"
		"                  | sym.decrypt(unknown_t arg_4h);          |\n"
		"                  | ; var unknown_t var_38h @ stack - 0x38  |\n"
		"                  | ; var unknown_t var_2ch @ stack - 0x2c  |\n"
		"                  | ; var unknown_t var_28h @ stack - 0x28  |\n"
		"                  | ; var unknown_t var_21h @ stack - 0x21  |\n"
		"                  | ; var unknown_t var_1dh @ stack - 0x1d  |\n"
		"                  | ; var unknown_t var_19h @ stack - 0x19  |\n"
		"                  | ; var unknown_t var_15h @ stack - 0x15  |\n"
		"                  | ; var unknown_t var_11h @ stack - 0x11  |\n"
		"                  | ; var unknown_t var_10h @ stack - 0x10  |\n"
		"                  | ; arg unknown_t arg_4h @ stack + 0x4    |\n"
		"                  | push ebp                                |\n"
		"                  | mov ebp, esp                            |\n"
		"                  | sub esp, 0x38                           |\n"
		"                  | mov eax, dword gs:[0x14]                |\n"
		"                  | mov dword [var_10h], eax                |\n"
		"                  | xor eax, eax                            |\n"
		"                  | ; 'Q}|u'                                |\n"
		"                  | mov dword [var_21h], 0x757c7d51         |\n"
		"                  | ; '`sfg'                                |\n"
		"                  | mov dword [var_1dh], 0x67667360         |\n"
		"                  | ; '~sf{'                                |\n"
		"                  | mov dword [var_19h], 0x7b66737e         |\n"
		"                  | ; '}|a3'                                |\n"
		"                  | mov dword [var_15h], 0x33617c7d         |\n"
		"                  | mov byte [var_11h], 0x00                |\n"
		"                  | push eax                                |\n"
		"                  | xor eax, eax                            |\n"
		"                  | jz 0x80489f0                            |\n"
		"                  `-----------------------------------------'\n"
		"                          f t\n"
		"                          | |\n"
		"                          | '----------------.\n"
		"                          '--.               |\n"
		"                             |               |\n"
		"                         .---------------.   |\n"
		"                         |  0x80489ed    |   |\n"
		"                         | add esp, 0x04 |   |\n"
		"                         `---------------'   |\n"
		"                             v               |\n"
		"                             |               |\n"
		"                           .-'               |\n"
		"                           | .---------------'\n"
		"                           | |\n"
		"                     .---------------------------.\n"
		"                     |  0x80489f0                |\n"
		"                     | pop eax                   |\n"
		"                     | lea eax, dword [var_21h]  |\n"
		"                     | mov dword [esp], eax      |\n"
		"                     | call sym.imp.strlen       |\n"
		"                     | mov dword [var_28h], eax  |\n"
		"                     | mov dword [var_2ch], 0x00 |\n"
		"                     | jmp 0x8048a28             |\n"
		"                     `---------------------------'\n"
		"                         v\n"
		"                         |\n"
		"                   .-----'\n"
		".--------------------.\n"
		"|                  | |\n"
		"|            .------------------------------------------.\n"
		"|            |  0x8048a28                               |\n"
		"|            | ; CODE XREF from sym.decrypt @ 0x8048a06 |\n"
		"|            | mov eax, dword [var_2ch]                 |\n"
		"|            | cmp eax, dword [var_28h]                 |\n"
		"|            | jb 0x8048a08                             |\n"
		"|            `------------------------------------------'\n"
		"|                  t f\n"
		"|                  | |\n"
		"|    .-------------' |\n"
		"|    |               '---------------.\n"
		"|    |                               |\n"
		"|.---------------------------.   .------------------------------------------.\n"
		"||  0x8048a08                |   |  0x8048a30                               |\n"
		"|| lea edx, dword [var_21h]  |   | ; [0x8048d03:4]=0x676e6f43               |\n"
		"|| mov eax, dword [var_2ch]  |   | ; \"Congratulations!\"                     |\n"
		"|| add eax, edx              |   | mov dword [var_38h], str.Congratulations |\n"
		"|| movzx eax, byte [eax]     |   | lea eax, dword [var_21h]                 |\n"
		"|| mov edx, eax              |   | mov dword [esp], eax                     |\n"
		"|| mov eax, dword [arg_4h]   |   | call sym.imp.strcmp                      |\n"
		"|| xor eax, edx              |   | test eax, eax                            |\n"
		"|| lea ecx, dword [var_21h]  |   | jnz 0x8048a55                            |\n"
		"|| mov edx, dword [var_2ch]  |   `------------------------------------------'\n"
		"|| add edx, ecx              |         t f\n"
		"|| mov byte [edx], al        |         | |\n"
		"|| add dword [var_2ch], 0x01 |         | |\n"
		"|`---------------------------'         | |\n"
		"|    v                                 | |\n"
		"|    |                                 | |\n"
		"`----'                                 | |\n"
		"    .----------------------------------' |\n"
		"    |                                    '------.\n"
		"    |                                           |\n"
		".---------------------------------------.   .-----------------------------.\n"
		"|  0x8048a55                            |   |  0x8048a47                  |\n"
		"| ; [0x8048d1c:4]=0x766e490a            |   | ; [0x8048d14:4]=0x6e69622f  |\n"
		"| ; \"\\nInvalid Password!\"               |   | ; \"/bin/sh\"                 |\n"
		"| mov dword [esp], str.Invalid_Password |   | mov dword [esp], str.bin_sh |\n"
		"| call sym.imp.puts                     |   | call sym.imp.system         |\n"
		"`---------------------------------------'   | jmp 0x8048a61               |\n"
		"    v                                       `-----------------------------'\n"
		"    |                                           v\n"
		"    |                                           |\n"
		"    '------------------.                        |\n"
		"                       | .----------------------'\n"
		"                       | |\n"
		"                 .------------------------------------------.\n"
		"                 |  0x8048a61                               |\n"
		"                 | ; CODE XREF from sym.decrypt @ 0x8048a53 |\n"
		"                 | mov eax, dword [var_10h]                 |\n"
		"                 | xor eax, dword gs:[0x14]                 |\n"
		"                 | jz 0x8048a72                             |\n"
		"                 `------------------------------------------'\n"
		"                         f t\n"
		"                         | |\n"
		"                         | '---------------------.\n"
		"                 .-------'                       |\n"
		"                 |                               |\n"
		"             .-------------------------------.   |\n"
		"             |  0x8048a6d                    |   |\n"
		"             | call sym.imp.__stack_chk_fail |   |\n"
		"             `-------------------------------'   |\n"
		"                 v                               |\n"
		"                 |                               |\n"
		"                 '--------------------.          |\n"
		"                                      | .--------'\n"
		"                                      | |\n"
		"                                .-------------.\n"
		"                                |  0x8048a72  |\n"
		"                                | leave       |\n"
		"                                | ret         |\n"
		"                                `-------------'\n";
	if (!assert_agf_render("bins/elf/lab1B", "s sym.decrypt", expected)) {
		return MU_ERR;
	}
	mu_end;
}

int all_tests() {
	mu_run_test(test_analysis_graph);
	mu_run_test(test_analysis_graph_more);
	mu_run_test(test_analysis_graph_icfg);
	mu_run_test(test_analysis_graph_cfg);
	mu_run_test(test_analysis_graph_entrypoints);
	mu_run_test(test_analysis_graph_serialize);
	mu_run_test(test_analysis_graph_render_real_cfg);
	mu_run_test(test_analysis_graph_render_real_cfg_decrypt);
	return tests_passed != tests_run;
}

mu_main(all_tests)
