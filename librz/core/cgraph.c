// SPDX-FileCopyrightText: 2022 imbillow <billow.fun@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_list.h>
#include <rz_core.h>
#include <rz_util/rz_graph_drawable.h>
#include "core_private.h"

static inline bool is_between(ut64 a, ut64 x, ut64 b) {
	return (a == UT64_MAX && b == UT64_MAX) || RZ_BETWEEN(a, x, b);
}

static inline char *core_flag_name(const RzCore *core, ut64 addr) {
	RzFlagItem *item = rz_flag_get_i(core->flags, addr);
	return item ? strdup(item->name) : rz_str_newf("0x%08" PFMT64x, addr);
}

static inline void core_graph_dataref(RzCore *core, RzAnalysisFunction *fcn, RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	if (!fcn) {
		return;
	}

	char *me = rz_core_analysis_fcn_name(core, fcn);
	RzGraphNode *curr_node = rz_graph_add_node_info(graph, me, NULL, fcn->addr);
	RZ_FREE(me);
	if (!curr_node) {
		return;
	}

	RzBinObject *obj = rz_bin_cur_object(core->bin);
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	RzListIter *iter;
	RzAnalysisXRef *xref;
	rz_list_foreach (xrefs, iter, xref) {
		RzBinSection *binsec = rz_bin_get_section_at(obj, xref->to, true);
		if (binsec && binsec->is_data) {
			char *dst = core_flag_name(core, xref->to);
			RzGraphNode *node = rz_graph_add_node_info(graph, dst, NULL, xref->to);
			free(dst);
			rz_graph_add_edge(graph, curr_node, node);
		}
	}
	rz_list_free(xrefs);
}

/**
 * \brief Get the graph of the data references from \p addr (UT64_MAX for all).
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_datarefs(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core && core->analysis, NULL);
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}
	if (addr == UT64_MAX) {
		ut64 from = rz_config_get_i(core->config, "graph.from");
		ut64 to = rz_config_get_i(core->config, "graph.to");
		RzListIter *it;
		RzAnalysisFunction *fcn;
		rz_list_foreach (core->analysis->fcns, it, fcn) {
			if (!is_between(from, fcn->addr, to)) {
				continue;
			}
			core_graph_dataref(core, fcn, graph);
		}
	} else {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, -1);
		core_graph_dataref(core, fcn, graph);
	}
	return graph;
}

static void core_graph_coderef(RzCore *core, RzAnalysisFunction *fcn, RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	if (!fcn) {
		return;
	}

	char *me = rz_core_analysis_fcn_name(core, fcn);
	RzGraphNode *curr_node = rz_graph_add_node_info(graph, me, NULL, fcn->addr);
	RZ_FREE(me);
	if (!curr_node) {
		return;
	}

	RzList *xrefs = rz_analysis_xrefs_get_from(core->analysis, fcn->addr);
	RzListIter *it;
	RzAnalysisXRef *xref;
	rz_list_foreach (xrefs, it, xref) {
		char *dst = core_flag_name(core, xref->to);
		RzGraphNode *node = rz_graph_add_node_info(graph, dst, NULL, xref->to);
		free(dst);
		rz_graph_add_edge(graph, curr_node, node);
	}
	rz_list_free(xrefs);
}

/**
 * \brief Get the graph of the function references from \p addr (UT64_MAX for all).
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_coderefs(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core && core->analysis, NULL);
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}
	if (addr == UT64_MAX) {
		ut64 from = rz_config_get_i(core->config, "graph.from");
		ut64 to = rz_config_get_i(core->config, "graph.to");
		RzListIter *it;
		RzAnalysisFunction *fcn;
		rz_list_foreach (core->analysis->fcns, it, fcn) {
			if (!is_between(from, fcn->addr, to)) {
				continue;
			}
			core_graph_coderef(core, fcn, graph);
		}
	} else {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, -1);
		core_graph_coderef(core, fcn, graph);
	}
	return graph;
}

static void add_single_addr_xrefs(RzCore *core, ut64 addr, RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	char *me = core_flag_name(core, addr);
	RzGraphNode *curr_node = rz_graph_add_node_info(graph, me, NULL, addr);
	RZ_FREE(me);
	if (!curr_node) {
		return;
	}
	RzListIter *iter;
	RzAnalysisXRef *xref;
	RzList *list = rz_analysis_xrefs_get_to(core->analysis, addr);
	rz_list_foreach (list, iter, xref) {
		char *src = core_flag_name(core, xref->from);
		RzGraphNode *reference_from = rz_graph_add_node_info(graph, src, NULL, xref->from);
		free(src);
		rz_graph_add_edge(graph, reference_from, curr_node);
	}
	rz_list_free(list);
}

/**
 * \brief Get the graph of all import symbols references.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_importxrefs(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core && core->analysis, NULL);
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	if (!obj) {
		return NULL;
	}
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}

	bool va = core->io->va || core->bin->is_debugger;
	RzListIter *iter;
	RzBinImport *imp;
	rz_list_foreach (obj->imports, iter, imp) {
		RzBinSymbol *sym = rz_bin_object_get_symbol_of_import(obj, imp);
		ut64 addr = sym ? (va ? rz_bin_object_get_vaddr(obj, sym->paddr, sym->vaddr) : sym->paddr) : UT64_MAX;
		if (addr && addr != UT64_MAX) {
			add_single_addr_xrefs(core, addr, graph);
		} else {
			rz_graph_add_node_info(graph, imp->name, NULL, 0);
		}
	}
	return graph;
}

/**
 * \brief Get the graph of code cross references to \p addr.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_codexrefs(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core && core->analysis, NULL);
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}
	add_single_addr_xrefs(core, addr, graph);
	return graph;
}

static void core_graph_fn_call(RzCore *core, RzAnalysisFunction *fcn, RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	if (!fcn) {
		return;
	}

	char *me = rz_core_analysis_fcn_name(core, fcn);
	RzGraphNode *curr_node = rz_graph_add_node_info(graph, me, NULL, fcn->addr);
	RZ_FREE(me);
	if (!curr_node) {
		return;
	}

	RzList *calls = rz_core_analysis_fcn_get_calls(core, fcn);
	RzListIter *it;
	RzAnalysisXRef *xref;
	rz_list_foreach (calls, it, xref) {
		char *src = core_flag_name(core, xref->to);
		RzGraphNode *node = rz_graph_add_node_info(graph, src, NULL, xref->to);
		free(src);
		rz_graph_add_edge(graph, curr_node, node);
	}
	rz_list_free(calls);
}

/**
 * \brief Get the graph of the function call references from \p addr (UT64_MAX for all).
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_callgraph(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core && core->analysis, NULL);
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}
	if (addr == UT64_MAX) {
		ut64 from = rz_config_get_i(core->config, "graph.from");
		ut64 to = rz_config_get_i(core->config, "graph.to");
		RzListIter *it;
		RzAnalysisFunction *fcn;
		rz_list_foreach (core->analysis->fcns, it, fcn) {
			if (!is_between(from, fcn->addr, to)) {
				continue;
			}
			core_graph_fn_call(core, fcn, graph);
		}
	} else {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, -1);
		core_graph_fn_call(core, fcn, graph);
	}
	return graph;
}

typedef char *(*GraphBodyFn)(RzCore *core, ut64 addr, RzAnalysisBlock *bb);

static inline char *block_disasm(RzCore *core, ut64 addr, RzAnalysisBlock *bb) {
	return rz_core_cmd_strf(core, "pdb @ 0x%" PFMT64x, addr);
}

static inline RzGraphNode *graph_add_cached(RzCore *core, HtUP *cache, RzAnalysisBlock *bb, ut64 offset, RzGraph /*<RzGraphNodeInfo *>*/ *graph, GraphBodyFn body_fn) {
	RzGraphNode *node = (RzGraphNode *)ht_up_find(cache, offset, NULL);
	if (node) {
		return node;
	}

	char *title = rz_str_newf("0x%" PFMT64x, offset);
	char *body = body_fn ? body_fn(core, offset, bb) : NULL;
	node = rz_graph_add_node_info(graph, title, body, offset);
	ht_up_insert(cache, offset, node);
	free(title);
	free(body);
	return node;
}

static void core_graph_fn_bbs(RzCore *core, RzAnalysisFunction *fcn, RzGraph /*<RzGraphNodeInfo *>*/ *graph, HtUP *cache, GraphBodyFn body_fn) {
	if (!(fcn && fcn->bbs)) {
		return;
	}

	RzListIter *iter;
	RzAnalysisBlock *bbi;
	rz_list_foreach (fcn->bbs, iter, bbi) {
		if (bbi->addr == UT64_MAX) {
			continue;
		}

		RzGraphNode *bb_node = graph_add_cached(core, cache, bbi, bbi->addr, graph, body_fn);
		if (!bb_node) {
			continue;
		}

		if (bbi->jump != UT64_MAX) {
			RzGraphNode *node = graph_add_cached(core, cache, NULL, bbi->jump, graph, body_fn);
			if (node) {
				rz_graph_add_edge(graph, bb_node, node);
			}
		}

		if (bbi->fail != UT64_MAX) {
			RzGraphNode *node = graph_add_cached(core, cache, NULL, bbi->fail, graph, body_fn);
			if (node) {
				rz_graph_add_edge(graph, bb_node, node);
			}
		}

		if (!bbi->switch_op) {
			continue;
		}
		RzAnalysisCaseOp *case_op;
		RzListIter *iter_case;
		rz_list_foreach (bbi->switch_op->cases, iter_case, case_op) {
			RzGraphNode *case_node = graph_add_cached(core, cache, NULL, case_op->addr, graph, body_fn);
			if (case_node) {
				rz_graph_add_edge(graph, bb_node, case_node);
			}

			RzGraphNode *case_jump_node = graph_add_cached(core, cache, NULL, case_op->jump, graph, body_fn);
			if (case_jump_node) {
				rz_graph_add_edge(graph, case_node, case_jump_node);
			}
		}
	}
}

/**
 * \brief Create a graph of the function blocks.
 * \param core RzCore instance
 * \param addr Address to analyze
 * \param body_fn Callback Function to use to get the body from RzAnalysisBlock or address
 * \return RzGraph*
 */
static RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_function_bbs(RZ_NONNULL RzCore *core, ut64 addr, RZ_NULLABLE GraphBodyFn body_fn) {
	rz_return_val_if_fail(core && core->analysis, NULL);

	if (rz_list_empty(core->analysis->fcns)) {
		return NULL;
	}
	HtUP *cache = NULL;
	RzConfigHold *hc = NULL;
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}
	hc = rz_config_hold_new(core->config);
	if (!hc) {
		goto fail;
	}
	cache = ht_up_new0();
	if (!cache) {
		goto fail;
	}

	rz_config_hold_i(hc, "asm.lines", "asm.lines.fcn", "asm.bytes", "asm.dwarf", "asm.offset", "asm.marks",
		"asm.cmt.right", "asm.cmt.col", "asm.bb.middle", NULL);
	rz_config_set_i(core->config, "asm.lines", 0);
	rz_config_set_i(core->config, "asm.lines.fcn", 0);
	rz_config_set_i(core->config, "asm.bytes", 0);
	rz_config_set_i(core->config, "asm.dwarf", 0);
	rz_config_set_i(core->config, "asm.offset", 0);
	rz_config_set_i(core->config, "asm.marks", 0);
	rz_config_set_i(core->config, "asm.cmt.right", 0);
	rz_config_set_i(core->config, "asm.cmt.col", 0);
	rz_config_set_i(core->config, "asm.bb.middle", 0);

	if (addr == UT64_MAX) {
		ut64 from = rz_config_get_i(core->config, "graph.from");
		ut64 to = rz_config_get_i(core->config, "graph.to");
		RzListIter *it;
		RzAnalysisFunction *fcn;
		rz_list_foreach (core->analysis->fcns, it, fcn) {
			if (!(is_between(from, fcn->addr, to) && fcn->type & (RZ_ANALYSIS_FCN_TYPE_SYM | RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_LOC))) {
				continue;
			}
			core_graph_fn_bbs(core, fcn, graph, cache, body_fn);
		}
	} else {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, -1);
		core_graph_fn_bbs(core, fcn, graph, cache, body_fn);
	}

ret:
	ht_up_free(cache);
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return graph;
fail:
	rz_graph_free(graph);
	graph = NULL;
	goto ret;
}

/**
 * \brief Get a graph of the function blocks at \p addr.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_function(RzCore *core, ut64 addr) {
	return rz_core_graph_function_bbs(core, addr, block_disasm);
}

static char *block_line(RzCore *core, ut64 addr, RzAnalysisBlock *bb) {
	if (!bb) {
		bb = rz_analysis_get_block_at(core->analysis, addr);
		if (!bb) {
			return NULL;
		}
	}
	char file[1024], *cmd_str = NULL, *file_str = NULL, *str = NULL;
	int line = 0, oline = 0, idx = 0;
	int is_html = rz_cons_singleton()->is_html;
	ut64 end = bb->addr + bb->size - 2;
	for (ut64 at = bb->addr; at < end; at += 2) {
		rz_bin_addr2line(core->bin, at, file, sizeof(file) - 1, &line);
		if (line != 0 && line != oline && strcmp(file, "??") != 0) {
			file_str = rz_file_slurp_line(file, line, 0);
			if (file_str) {
				ut32 len = strlen(file_str);
				cmd_str = realloc(cmd_str, idx + len + 8);
				memcpy(cmd_str + idx, file_str, len);
				idx += len;
				if (is_html) {
					strcpy(cmd_str + idx, "<br />");
					idx += 6;
				} else {
					strcpy(cmd_str + idx, "\\l");
					idx += 2;
				}
				free(file_str);
			}
		}
		oline = line;
	}
	if (cmd_str) {
		str = rz_str_escape_dot(cmd_str);
		free(cmd_str);
	}
	return str;
}

/**
 * \brief Get a line graph of the function blocks at \p addr.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_line(RzCore *core, ut64 addr) {
	return rz_core_graph_function_bbs(core, addr, block_line);
}

/**
 * \brief Get a normal graph of the function blocks at \p addr.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_normal(RzCore *core, ut64 addr) {
	return rz_core_graph_function_bbs(core, addr, NULL);
}

/**
 * \brief Get a graph of specific type (\p type) at \p addr.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph(RzCore *core, RzCoreGraphType type, ut64 addr) {
	rz_return_val_if_fail(core && core->analysis, NULL);
	RzGraph *graph = NULL;
	switch (type) {
	case RZ_CORE_GRAPH_TYPE_DATAREF:
		graph = rz_core_graph_datarefs(core, addr);
		break;
	case RZ_CORE_GRAPH_TYPE_FUNCALL:
		graph = rz_core_graph_callgraph(core, addr);
		break;
	case RZ_CORE_GRAPH_TYPE_BLOCK_FUN:
		graph = rz_core_graph_function(core, addr);
		break;
	case RZ_CORE_GRAPH_TYPE_IMPORT:
		graph = rz_core_graph_importxrefs(core);
		break;
	case RZ_CORE_GRAPH_TYPE_REF:
		graph = rz_core_graph_coderefs(core, addr);
		break;
	case RZ_CORE_GRAPH_TYPE_XREF:
		graph = rz_core_graph_codexrefs(core, addr);
		break;
	case RZ_CORE_GRAPH_TYPE_LINE:
		graph = rz_core_graph_line(core, addr);
		break;
	case RZ_CORE_GRAPH_TYPE_NORMAL:
		graph = rz_core_graph_normal(core, addr);
		break;
	case RZ_CORE_GRAPH_TYPE_DIFF:
	default:
		rz_warn_if_reached();
		break;
	}
	return graph;
}

/**
 * \brief Convert a string to RzCoreGraphFormat.
 */
RZ_API RzCoreGraphFormat rz_core_graph_format_from_string(RZ_NULLABLE const char *x) {
	const char short_opt = (char)(x && strlen(x) == 1 ? x[0] : 0);

	if (strcmp(x, "ascii") == 0 || RZ_STR_ISEMPTY(x) || short_opt == ' ') {
		return RZ_CORE_GRAPH_FORMAT_ASCII_ART;
	} else if (strcmp(x, "cmd") == 0 || short_opt == '*') {
		return RZ_CORE_GRAPH_FORMAT_CMD;
	} else if (strcmp(x, "dot") == 0 || short_opt == 'd') {
		return RZ_CORE_GRAPH_FORMAT_DOT;
	} else if (strcmp(x, "gml") == 0 || short_opt == 'g') {
		return RZ_CORE_GRAPH_FORMAT_GML;
	} else if (strcmp(x, "json_disasm") == 0 || short_opt == 'J') {
		return RZ_CORE_GRAPH_FORMAT_JSON_DISASM;
	} else if (strcmp(x, "json") == 0 || short_opt == 'j') {
		return RZ_CORE_GRAPH_FORMAT_JSON;
	} else if (strcmp(x, "sdb") == 0 || short_opt == 'k') {
		return RZ_CORE_GRAPH_FORMAT_SDB;
	} else if (strcmp(x, "tiny") == 0 || short_opt == 't') {
		return RZ_CORE_GRAPH_FORMAT_TINY;
	} else if (strcmp(x, "interactive") == 0 || short_opt == 'v') {
		return RZ_CORE_GRAPH_FORMAT_VISUAL;
	}

	RZ_LOG_ERROR("invalid graph format: %s\n", x);
	return RZ_CORE_GRAPH_FORMAT_UNK;
}

/**
 * \brief Convert a string to RzCoreGraphType.
 */
RZ_API RzCoreGraphType rz_core_graph_type_from_string(RZ_NULLABLE const char *x) {
	if (!x) {
		return RZ_CORE_GRAPH_TYPE_UNK;
	}
	if (strcmp(x, "dataref") == 0) {
		return RZ_CORE_GRAPH_TYPE_DATAREF;
	} else if (strcmp(x, "funcall") == 0) {
		return RZ_CORE_GRAPH_TYPE_FUNCALL;
	} else if (strcmp(x, "diff") == 0) {
		return RZ_CORE_GRAPH_TYPE_DIFF;
	} else if (strcmp(x, "funblock") == 0) {
		return RZ_CORE_GRAPH_TYPE_BLOCK_FUN;
	} else if (strcmp(x, "import") == 0) {
		return RZ_CORE_GRAPH_TYPE_IMPORT;
	} else if (strcmp(x, "ref") == 0) {
		return RZ_CORE_GRAPH_TYPE_REF;
	} else if (strcmp(x, "line") == 0) {
		return RZ_CORE_GRAPH_TYPE_LINE;
	} else if (strcmp(x, "xref") == 0) {
		return RZ_CORE_GRAPH_TYPE_XREF;
	} else if (strcmp(x, "custom") == 0) {
		return RZ_CORE_GRAPH_TYPE_CUSTOM;
	}

	RZ_LOG_ERROR("invalid graph type: %s\n", x);
	return RZ_CORE_GRAPH_TYPE_UNK;
}

RZ_IPI bool rz_core_graph_print_graph(RZ_NONNULL RzCore *core, RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph, RzCoreGraphFormat format, bool use_offset) {
	rz_return_val_if_fail(core && graph, false);
	char *string = NULL;
	switch (format) {
	case RZ_CORE_GRAPH_FORMAT_ASCII_ART:
	case RZ_CORE_GRAPH_FORMAT_TINY:
	case RZ_CORE_GRAPH_FORMAT_VISUAL:
	case RZ_CORE_GRAPH_FORMAT_SDB: {
		rz_core_agraph_reset(core);
		core->graph->is_interactive = (format == RZ_CORE_GRAPH_FORMAT_VISUAL);
		rz_core_agraph_apply(core, graph);
		rz_core_agraph_print(core, format);
		break;
	}
	case RZ_CORE_GRAPH_FORMAT_CMD: {
		string = rz_graph_drawable_to_cmd(graph);
		break;
	}
	case RZ_CORE_GRAPH_FORMAT_DOT: {
		string = rz_core_graph_to_dot_str(core, graph);
		break;
	}
	case RZ_CORE_GRAPH_FORMAT_JSON:
		/* fall-thru */
	case RZ_CORE_GRAPH_FORMAT_JSON_DISASM: {
		string = rz_graph_drawable_to_json_str(graph, use_offset);
		break;
	}
	case RZ_CORE_GRAPH_FORMAT_GML: {
		string = rz_graph_drawable_to_gml(graph);
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
	if (!string) {
		return false;
	}
	rz_cons_print(string);
	free(string);
	return true;
}

RZ_IPI bool rz_core_graph_print(RzCore *core, ut64 addr, RzCoreGraphType type, RzCoreGraphFormat format) {
	RzGraph *g = rz_core_graph(core, type, addr);
	if (!g) {
		return false;
	}
	core->graph->is_callgraph = type == RZ_CORE_GRAPH_TYPE_FUNCALL;
	rz_core_graph_print_graph(core, g, format, true);
	rz_graph_free(g);
	return true;
}

static char *dot_executable_path(void) {
	const char *dot = "dot";
	char *dotPath = rz_file_path(dot);
	if (!strcmp(dotPath, dot)) {
		free(dotPath);
		dot = "xdot";
		dotPath = rz_file_path(dot);
		if (!strcmp(dotPath, dot)) {
			free(dotPath);
			return NULL;
		}
	}
	RzList *list = rz_str_split_duplist(dotPath, RZ_SYS_DIR, true);
	if (!list) {
		free(dotPath);
		return NULL;
	}
	char *path = rz_list_pop(list);
	rz_list_free(list);
	free(dotPath);
	return path;
}

static char *viewer_path(void) {
	int i;
	const char *viewers[] = {
#if __WINDOWS__
		"explorer",
#else
		"open",
		"geeqie",
		"gqview",
		"eog",
		"xdg-open",
#endif
		NULL
	};
	for (i = 0; viewers[i]; i++) {
		char *path = rz_file_path(viewers[i]);
		if (RZ_STR_ISNOTEMPTY(path)) {
			return path;
		}
		free(path);
	}
	return NULL;
}

static bool convert_dot_to_image(RzCore *core, const char *dot_file, const char *save_path) {
	char *dot = dot_executable_path();
	bool result = false;
	if (!dot) {
		eprintf("Graphviz not found\n");
		return false;
	}
	const char *ext = rz_config_get(core->config, "graph.gv.format");

	char *cmd = NULL;
	if (save_path && *save_path) {
		cmd = rz_str_newf("!%s -T%s -o%s a.dot;", dot, ext, save_path);
	} else {
		char *viewer = viewer_path();
		if (viewer) {
			cmd = rz_str_newf("!%s -T%s -oa.%s a.dot;!%s a.%s",
				dot, ext, ext, viewer, ext);
			free(viewer);
		} else {
			eprintf("Cannot find a valid picture viewer\n");
			goto end;
		}
	}
	RZ_LOG_VERBOSE("%s\n", cmd);
	rz_core_cmd0(core, cmd);
	result = true;
end:
	free(cmd);
	free(dot);
	return result;
}

static bool convert_dot_str_to_image(RzCore *core, char *str, const char *save_path) {
	if (save_path && *save_path) {
		rz_cons_printf("Saving to file '%s'...\n", save_path);
		rz_cons_flush();
	}
	if (!rz_file_dump("a.dot", (const unsigned char *)str, -1, false)) {
		return false;
	}
	return convert_dot_to_image(core, "a.dot", save_path);
}

/**
 * \brief Convert \p graph to Graphviz dot string.
 */
RZ_API RZ_OWN char *rz_core_graph_to_dot_str(RZ_NONNULL RzCore *core, RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	rz_return_val_if_fail(core && graph, NULL);
	const char *font = rz_config_get(core->config, "graph.font");
	char *node_properties = rz_str_newf("fontname=\"%s\"", font);
	char *result = rz_graph_drawable_to_dot(graph, node_properties, NULL);
	free(node_properties);
	return result;
}

/**
 * \brief Convert \p graph to sdb string.
 */
RZ_API RZ_OWN char *rz_core_graph_to_sdb_str(RZ_NONNULL RzCore *core, RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	rz_return_val_if_fail(core && graph, NULL);
	rz_core_agraph_reset(core);
	rz_core_agraph_apply(core, graph);
	Sdb *db = rz_agraph_get_sdb(core->graph);
	return sdb_querys(db, "null", 0, "*");
}

/**
 * \brief Convert \p graph to an image, and write it to \p filename.
 */
RZ_API bool rz_core_graph_write_graph(RZ_NONNULL RzCore *core, RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph, RZ_NONNULL const char *filename) {
	rz_return_val_if_fail(core && graph && filename, NULL);
	char *dot_text = rz_core_graph_to_dot_str(core, graph);
	if (!dot_text) {
		return false;
	}
	bool ret = convert_dot_str_to_image(core, dot_text, filename);
	free(dot_text);
	return ret;
}

/**
 * \brief Convert RzGraph of \p type at \p addr to an image, and write it to \p filename.
 */
RZ_API bool rz_core_graph_write(RZ_NONNULL RzCore *core, ut64 addr, RzCoreGraphType type, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(core && path, false);
	RzGraph *graph = rz_core_graph(core, type, addr);
	if (!graph) {
		return false;
	}
	rz_core_graph_write_graph(core, graph, path);
	rz_graph_free(graph);
	return true;
}
