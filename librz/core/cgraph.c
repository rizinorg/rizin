// SPDX-FileCopyrightText: 2022 imbillow <billow.fun@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_list.h>
#include <rz_core.h>
#include <rz_util/rz_graph_drawable.h>
#include "core_private.h"
#include <rz_util/rz_iterator.h>
#include <rz_util/rz_set.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_str.h>
#include <rz_util/ht_uu.h>
#include <rz_util/ht_up.h>
#include <rz_util/rz_graph.h>
#include <rz_util/rz_th_ht.h>

static inline bool is_between(ut64 a, ut64 x, ut64 b) {
	return (a == UT64_MAX && b == UT64_MAX) || RZ_BETWEEN(a, x, b);
}

static inline char *core_flag_name(const RzCore *core, ut64 addr) {
	RzFlagItem *item = rz_flag_get_i(core->flags, addr);
	return item ? rz_str_dup(item->name) : rz_str_newf("0x%08" PFMT64x, addr);
}

static inline void core_graph_dataref(RzCore *core, RzAnalysisFunction *fcn, RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	if (!fcn) {
		return;
	}

	RzGraphNode *curr_node = rz_graph_add_node_info(graph, fcn->name, NULL, fcn->addr);
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

	RzGraphNode *curr_node = rz_graph_add_node_info(graph, fcn->name, NULL, fcn->addr);
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
	void **iter;
	RzBinImport *imp;
	rz_pvector_foreach (obj->imports, iter) {
		imp = *iter;
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

	RzGraphNode *curr_node = rz_graph_add_node_info(graph, fcn->name, NULL, fcn->addr);
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
	RzAnalysisBlock *b = rz_analysis_find_most_relevant_block_in(core->analysis, addr);
	if (!b) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", addr);
		return NULL;
	}
	ut8 *block = malloc(b->size + 1);
	if (!block) {
		RZ_LOG_ERROR("Cannot allocate buffer\n");
		return NULL;
	}
	rz_cons_push();
	rz_io_read_at(core->io, b->addr, block, b->size);
	RzCoreDisasmOptions disasm_options = {
		.cbytes = 2,
	};
	rz_core_print_disasm(core, b->addr, block, b->size, 9999, NULL, &disasm_options);
	rz_cons_filter();
	const char *retstr = rz_str_get(rz_cons_get_buffer());
	char *opcodes = rz_str_dup(retstr);
	rz_cons_pop();
	rz_cons_echo(NULL);
	free(block);
	return opcodes;
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

	RzAnalysisBlock *bbi;
	void **iter;
	rz_pvector_foreach (fcn->bbs, iter) {
		bbi = (RzAnalysisBlock *)*iter;
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
	cache = ht_up_new(NULL, NULL);
	if (!cache) {
		goto fail;
	}

	rz_config_hold_i(hc, "asm.xrefs.max", "asm.lines", "asm.lines.fcn", "asm.bytes", "asm.debuginfo", "asm.offset", "asm.marks",
		"asm.cmt.right", "asm.cmt.col", "asm.bb.middle", NULL);
	rz_config_set_i(core->config, "asm.xrefs.max", 3);
	rz_config_set_i(core->config, "asm.lines", 0);
	rz_config_set_i(core->config, "asm.lines.fcn", 0);
	rz_config_set_i(core->config, "asm.bytes", 0);
	rz_config_set_i(core->config, "asm.debuginfo", 0);
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
	RzBinObject *o = rz_bin_cur_object(core->bin);
	RzBinSourceLineInfo *sl = o ? o->lines : NULL;
	for (ut64 at = bb->addr; at < end; at += 2) {
		if (sl) {
			rz_bin_source_line_addr2line(sl, at, file, sizeof(file) - 1, &line);
		}
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
	case RZ_CORE_GRAPH_TYPE_IL:
		graph = rz_core_graph_il(core, addr);
		break;
	case RZ_CORE_GRAPH_TYPE_ICFG:
		graph = rz_core_graph_icfg(core);
		break;
	case RZ_CORE_GRAPH_TYPE_CFG:
		if (core->analysis->cur && core->analysis->cur->decode_iword) {
			// Build the instruction word graph.
			graph = rz_core_graph_cfg_iwords(core, addr, false);
		} else {
			graph = rz_core_graph_cfg(core, addr, false);
		}
		break;
	case RZ_CORE_GRAPH_TYPE_CFG_FCN:
		if (core->analysis->cur && core->analysis->cur->decode_iword) {
			// Build the instruction word graph.
			graph = rz_core_graph_cfg_iwords(core, addr, true);
		} else {
			graph = rz_core_graph_cfg(core, addr, true);
		}
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
	bool is_il = type == RZ_CORE_GRAPH_TYPE_IL;
	core->graph->is_callgraph = (type == RZ_CORE_GRAPH_TYPE_FUNCALL || type == RZ_CORE_GRAPH_TYPE_ICFG);
	core->graph->is_il = is_il;
	rz_core_graph_print_graph(core, g, format, !is_il);
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
	rz_return_val_if_fail(core && graph && filename, false);
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

/**
 * \brief Get the graph of the function references from \p addr (UT64_MAX for all).
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_il(RZ_NONNULL RzCore *core, ut64 addr) {
	rz_return_val_if_fail(core && core->analysis, NULL);

	RzAnalysisOp op = { 0 };
	RzGraph *graph = NULL;
	ut64 old_offset = core->offset;
	RzAnalysisOpMask flags = RZ_ANALYSIS_OP_MASK_DISASM | RZ_ANALYSIS_OP_MASK_IL;
	if (addr != old_offset) {
		rz_core_seek(core, addr, true);
	}

	rz_analysis_op_init(&op);
	if (rz_analysis_op(core->analysis, &op, core->offset, core->block, core->blocksize, flags) > 0) {
		graph = rz_il_op_effect_graph(op.il_op, op.mnemonic);
	}
	rz_analysis_op_fini(&op);

	if (addr != old_offset) {
		rz_core_seek(core, old_offset, true);
	}
	return graph;
}

static RzGraphNode *rz_graph_add_node_info_icfg(RzGraph /*<RzGraphNodeInfo *>*/ *graph, const RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(graph, NULL);
	RzGraphNodeInfo *data = NULL;
	if (rz_analysis_function_is_malloc(fcn)) {
		data = rz_graph_create_node_info_icfg(fcn->addr, RZ_GRAPH_NODE_SUBTYPE_ICFG_MALLOC);
	} else {
		data = rz_graph_create_node_info_icfg(fcn->addr, RZ_GRAPH_NODE_SUBTYPE_ICFG_NONE);
	}
	if (!data) {
		rz_warn_if_reached();
		return NULL;
	}
	RzGraphNode *node = rz_graph_add_nodef(graph, data, rz_graph_free_node_info);
	if (!node) {
		rz_graph_free_node_info(data);
	}
	return node;
}

/**
 * \brief Returns the graph node of a given \p fcn. If the function
 * is not yet added as node to the graph, it adds it to the graph and returns its reference.
 *
 * \param icfg The iCFG to fill.
 * \param graph_idx Hash table to track the graph indices of each function address.
 * \param fcn The function to add.
 * \param existed Is set to true if the node was already in the graph.
 *
 * \return The GraphNode.
 */
static RZ_OWN RzGraphNode *get_graph_node_of_fcn(RZ_BORROW RzGraph /*<RzGraphNodeInfo *>*/ *icfg, RZ_BORROW HtUU *graph_idx, const RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(icfg && graph_idx && fcn, NULL);
	bool found = false;
	ut64 i = ht_uu_find(graph_idx, fcn->addr, &found);
	if (found) {
		// Node already added, get it.
		return rz_graph_get_node(icfg, i);
	}
	ht_uu_insert(graph_idx, fcn->addr, rz_list_length(rz_graph_get_nodes(icfg)));
	return rz_graph_add_node_info_icfg(icfg, fcn);
}

/**
 * \brief Adds all call xrefs from \p fcn as edges to the iCFG
 * and recurses into each of them.
 *
 * \param analysis The current RzAnalysis.
 * \param icfg The iCFG to fill.
 * \param graph_idx Hash table to track the graph node indices for each function address.
 * \param fcn The function to add.
 */
static void extend_icfg(const RzAnalysis *analysis, RZ_BORROW RzGraph /*<RzGraphNodeInfo *>*/ *icfg, RZ_BORROW HtUU *graph_idx, const RzAnalysisFunction *fcn) {
	rz_return_if_fail(analysis && icfg && graph_idx && fcn);
	RzGraphNode *from_node = get_graph_node_of_fcn(icfg, graph_idx, fcn);
	RzListIter *it;
	const RzAnalysisXRef *xref;
	RzList *fcn_xrefs = rz_analysis_function_get_xrefs_from(fcn);
	rz_list_foreach (fcn_xrefs, it, xref) {
		if (xref->type != RZ_ANALYSIS_XREF_TYPE_CALL) {
			continue;
		}
		const RzAnalysisFunction *called_fcn = rz_analysis_get_function_at(analysis, xref->to);
		if (!called_fcn) {
			// Either a faulty entry or a GOT entry
			continue;
		}
		RzGraphNode *to_node = get_graph_node_of_fcn(icfg, graph_idx, called_fcn);
		assert(to_node && from_node);
		if (rz_graph_adjacent(icfg, from_node, to_node)) {
			// Edge already added and walked. Don't recurse.
			continue;
		}
		rz_graph_add_edge(icfg, from_node, to_node);
		// Recurse into called function.
		extend_icfg(analysis, icfg, graph_idx, called_fcn);
	}
	rz_list_free(fcn_xrefs);
}

/**
 * \brief Get the inter-procedual control flow graph of the binary.
 * It uses the already discovered functions and their xrefs.
 *
 * \param core The current core.
 *
 * \return The iCFG of the binary or NULL in case of failure.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_icfg(RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(core && core->analysis, NULL);
	const RzList *fcns = core->analysis->fcns;
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}
	if (rz_list_length(fcns) < 1) {
		RZ_LOG_WARN("Cannot build iCFG without discovered functions. Did you run 'aac' and 'aap'?\n");
		return NULL;
	}

	HtUU *graph_idx = ht_uu_new();
	RzListIter *it;
	const RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, it, fcn) {
		extend_icfg(core->analysis, graph, graph_idx, fcn);
	}
	ht_uu_free(graph_idx);
	return graph;
}

static inline bool is_call(const RzAnalysisOp *op) {
	_RzAnalysisOpType type = (op->type & RZ_ANALYSIS_OP_TYPE_MASK);
	return type == RZ_ANALYSIS_OP_TYPE_CALL ||
		type == RZ_ANALYSIS_OP_TYPE_UCALL ||
		type == RZ_ANALYSIS_OP_TYPE_RCALL ||
		type == RZ_ANALYSIS_OP_TYPE_ICALL ||
		type == RZ_ANALYSIS_OP_TYPE_IRCALL ||
		type == RZ_ANALYSIS_OP_TYPE_CCALL ||
		type == RZ_ANALYSIS_OP_TYPE_UCCALL;
}

static inline bool is_tail(const RzAnalysisOp *op) {
	return op->type & RZ_ANALYSIS_OP_TYPE_TAIL;
}

static inline bool is_jump(const RzAnalysisOp *op) {
	_RzAnalysisOpType type = (op->type & RZ_ANALYSIS_OP_TYPE_MASK);
	return type == RZ_ANALYSIS_OP_TYPE_JMP ||
		type == RZ_ANALYSIS_OP_TYPE_UJMP ||
		type == RZ_ANALYSIS_OP_TYPE_RJMP ||
		type == RZ_ANALYSIS_OP_TYPE_IJMP ||
		type == RZ_ANALYSIS_OP_TYPE_IRJMP ||
		type == RZ_ANALYSIS_OP_TYPE_CJMP ||
		type == RZ_ANALYSIS_OP_TYPE_RCJMP ||
		type == RZ_ANALYSIS_OP_TYPE_MJMP ||
		type == RZ_ANALYSIS_OP_TYPE_MCJMP ||
		type == RZ_ANALYSIS_OP_TYPE_UCJMP;
}

static inline bool is_uncond_jump(const RzAnalysisOp *op) {
	ut32 op_type = op->type & RZ_ANALYSIS_OP_TYPE_MASK;
	return (op_type == RZ_ANALYSIS_OP_TYPE_JMP || op_type == RZ_ANALYSIS_OP_TYPE_UJMP) &&
		!((op->type & RZ_ANALYSIS_OP_HINT_MASK) & RZ_ANALYSIS_OP_TYPE_COND);
}

static inline bool is_invalid(const RzAnalysisOp *op) {
	return (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_ILL;
}

static inline bool is_return(const RzAnalysisOp *op) {
	return (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_RET;
}

static inline bool is_cond(const RzAnalysisOp *op) {
	return (op->type & RZ_ANALYSIS_OP_HINT_MASK) == RZ_ANALYSIS_OP_TYPE_COND;
}

static inline bool is_exit(const RzAnalysisOp *op) {
	return (op->type & RZ_ANALYSIS_OP_TYPE_MASK) == RZ_ANALYSIS_OP_TYPE_ILL;
}

static inline bool is_leaf_op(const RzAnalysisOp *op) {
	return is_return(op) || is_exit(op);
}


static inline bool ignore_next_instr(const RzAnalysisOp *op) {
	// Ignore if:
	return is_uncond_jump(op) || (op->fail != UT64_MAX && !is_call(op)) || is_invalid(op); // Except calls, everything which has set fail
}

static RzGraphNodeCFGSubType get_cfg_node_flags(const RzAnalysisOp *op, bool is_entry) {
	rz_return_val_if_fail(op, RZ_GRAPH_NODE_SUBTYPE_CFG_NONE);
	RzGraphNodeCFGSubType subtype = RZ_GRAPH_NODE_SUBTYPE_CFG_NONE;
	if (is_entry) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY;
	}
	if (is_call(op)) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_CALL;
	}
	if (is_tail(op)) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_TAIL;
	}
	if (is_jump(op)) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_JUMP;
	}
	if (is_return(op)) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN;
	}
	if (is_cond(op)) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_COND;
	}
	if (is_exit(op)) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT;
	}
	return subtype;
}

static RzGraphNodeCFGIWordSubType get_cfg_iword_node_flags(const RzAnalysisInsnWord *iword) {
	rz_return_val_if_fail(iword, RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_NONE);
	RzGraphNodeCFGIWordSubType subtype = RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_NONE;
	if (iword->props & RZ_ANALYSIS_IWORD_RET) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_RETURN;
	}
	if (iword->props & RZ_ANALYSIS_IWORD_COND) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_COND;
	}
	if (iword->props & RZ_ANALYSIS_IWORD_TAIL) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_TAIL;
	}
	return subtype;
}

/**
 * \brief Initializes a instruction word node info struct of a CFG node.
 *
 * \param iword The instructoin word to build the node from.
 * \param subtype The sub types of the node.
 *
 * \return The initialized RzGraphNodeInfo or NULL in case of failure.
 */
static RzGraphNodeInfo *rz_graph_create_node_info_cfg_iword(const RzAnalysisInsnWord *iword, RzGraphNodeCFGIWordSubType subtype) {
	RzGraphNodeInfo *data = RZ_NEW0(RzGraphNodeInfo);
	rz_graph_node_info_data_cfg_iword_init(&data->cfg_iword);
	data->type = RZ_GRAPH_NODE_TYPE_CFG_IWORD;
	data->cfg_iword.subtype = subtype;
	data->cfg_iword.address = iword->addr;
	bool is_entry = subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_ENTRY;
	void **it;
	rz_pvector_foreach (iword->insns, it) {
		const RzAnalysisOp *op = *it;
		RzGraphNodeInfoDataCFG *info = RZ_NEW0(RzGraphNodeInfoDataCFG);
		info->address = op->addr;
		info->call_address = (rz_analysis_op_is_call(op) || rz_analysis_op_is_ccall(op)) ? op->jump : UT64_MAX;
		info->jump_address = is_jump(op) ? op->jump : UT64_MAX;
		info->next = is_return(op) || is_uncond_jump(op) || is_tail(op) ? UT64_MAX : op->addr + op->size;
		info->subtype = get_cfg_node_flags(op, is_entry);
		rz_pvector_push(data->cfg_iword.insn, info);
		is_entry = false;
	}
	return data;
}

static RzGraphNode *add_node_info_cfg(RzGraph /*<RzGraphNodeInfo *>*/ *cfg, const RzAnalysisOp *op, bool is_entry) {
	rz_return_val_if_fail(cfg, NULL);
	RzGraphNodeCFGSubType subtype = get_cfg_node_flags(op, is_entry);
	ut64 call_target = is_call(op) ? op->jump : UT64_MAX;
	ut64 jump_target = rz_analysis_op_is_jump(op) ? op->jump : UT64_MAX;
	ut64 next = is_return(op) || is_uncond_jump(op) ? UT64_MAX : op->addr + op->size;
	RzGraphNodeInfo *data = rz_graph_create_node_info_cfg(op->addr, call_target, jump_target, next, subtype);
	if (!data) {
		return NULL;
	}
	RzGraphNode *node = rz_graph_add_nodef(cfg, data, rz_graph_free_node_info);
	if (!node) {
		rz_graph_free_node_info(data);
	}
	return node;
}

/**
 * \brief Add an edge to the graph and update \p to_visit vector and the \p nodes_visited hash table.
 *
 * \param graph The graph to work on.
 * \param to_visit The vector with addresses to visit.
 * \param nodes_visited The hash table holding already visited addresses and their node indices in the graph.
 * \param op_from The RzAnalysisOp the edge originates from.
 * \param op_to The RzAnalysisOp the edge goes to.
 * \param fcn Check the function if it contains \p op_to. \p op_to will not be added to \p to_visit, if it is not within the function.
 * If \p fcn is NULL it assumes \p op_to is always added, if it wasn't before.
 *
 * \return true On success.
 * \return false On failure.
 */
static bool add_edge_to_cfg(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph,
	RZ_NONNULL RzVector /*<ut64>*/ *to_visit,
	RZ_NONNULL HtUU *nodes_visited,
	const RzAnalysisOp *op_from,
	const RzAnalysisOp *op_to,
	bool to_node_within_fcn) {
	rz_return_val_if_fail(graph && to_visit && nodes_visited && op_from && op_to, -1);
	ut64 from = op_from->addr;
	ut64 to = op_to->addr;
	if (!to_node_within_fcn) {
		return true;
	}
	bool visited = false;
	ut64 from_idx = ht_uu_find(nodes_visited, from, &visited);
	if (!visited && from != to) {
		RZ_LOG_ERROR("'from' node should have been added before. 0x%" PFMT64x " -> 0x%" PFMT64x "\n", from, to);
		return false;
	}

	RzGraphNode *to_node = NULL;
	bool found = false;
	ut64 to_idx = ht_uu_find(nodes_visited, to, &found);
	if (found) {
		to_node = rz_graph_get_node(graph, to_idx);
	} else {
		to_node = add_node_info_cfg(graph, op_to, false);
	}
	if (!to_node) {
		RZ_LOG_ERROR("Could not add node at 0x%" PFMT64x "\n", to);
		return false;
	}
	to_idx = to_node->idx;
	if (from == to) {
		from_idx = to_idx;
	}
	to_idx = ht_uu_find(nodes_visited, to, &visited);

	if (from != to && !visited) {
		// The target node wasn't visited before. Otherwise this is a back-edge.
		rz_vector_push(to_visit, &to);
	}

	ht_uu_insert(nodes_visited, to, to_node->idx);
	rz_graph_add_edge(graph, rz_graph_get_node(graph, from_idx), to_node);
	return true;
}

static bool read_aligned_to_mapped(RzIO *io, ut64 addr, ut8 *buf, size_t *buf_len, size_t leading_bytes) {
	if (!rz_io_addr_is_mapped(io, addr)) {
		// Invalid read, but it will fill the buffer with invalid data.
		rz_io_read_at_mapped(io, addr - leading_bytes, buf, *buf_len);
		return false;
	}
	// Align the address for decoding start to a mapped region.
	while (!rz_io_addr_is_mapped(io, addr - leading_bytes) && addr - leading_bytes < addr) {
		leading_bytes -= 1;
	}
	// Align the end of the buffer read to a mapped region.
	while (!rz_io_addr_is_mapped(io, addr + *buf_len) && addr + *buf_len > addr) {
		*buf_len -= 1;
	}
	rz_io_read_at_mapped(io, addr - leading_bytes, buf, *buf_len);
	return true;
}

static st32 decode_op_at(RZ_BORROW RzCore *core,
	ut64 addr,
	RZ_BORROW ut8 *buf,
	size_t buf_len,
	RZ_OUT RzAnalysisOp *target_op) {
	rz_return_val_if_fail(core && core->analysis && core->io && buf, -1);
	size_t bl = buf_len;
	if (!read_aligned_to_mapped(core->io, addr, buf, &bl, 0)) {
		RZ_LOG_ERROR("read_aligned_to_mapped() read from unmapped region at 0x%" PFMT64x ".\n", addr);
	}
	int disas_bytes = rz_analysis_op(core->analysis, target_op, addr, buf, bl, RZ_ANALYSIS_OP_MASK_DISASM);
	if (disas_bytes <= 0 && target_op->type == RZ_ANALYSIS_OP_TYPE_ILL) {
		// Illegal instruction, return something positive
		return 1;
	}
	return disas_bytes;
}

static void assign_tails_exits(RZ_BORROW RzGraph *graph, HtUU *nodes_visited, const RzAnalysisOp *ana_op) {
	rz_return_if_fail(graph && ana_op);
	bool found = false;
	ut64 addr = ana_op->addr;
	ut64 node_idx = ht_uu_find(nodes_visited, addr, &found);
	RzGraphNode *node = rz_graph_get_node(graph, node_idx);
	rz_return_if_fail(node && found);
	RzGraphNodeInfo *data = node->data;
	if (is_call(ana_op)) {
		// Calls an exit procedure like abort, stack_chk_fail etc.
		data->cfg.subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT;
	} else if (is_jump(ana_op)) {
		// tail call
		data->cfg.subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_TAIL;
	}
}

static inline bool tail_exit_candidate(bool to_node_within_fcn, bool next_within_fcn, const RzAnalysisOp *curr_op) {
	return (is_call(curr_op) && !next_within_fcn) || (!to_node_within_fcn && is_jump(curr_op) && !is_cond(curr_op));
}

/**
 * \brief Get the procedual control flow graph (CFG) at an address.
 * Calls are not followed.
 *
 * \param core The current core.
 * \param addr The CFG entry point.
 * \param within_fcn If true, only nodes within the function at \p addr are added to the CFG.
 *
 * \return The CFG at address \p addr or NULL in case of failure.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_cfg(RZ_NONNULL RzCore *core, ut64 addr, bool within_fcn) {
	rz_return_val_if_fail(core && core->analysis && core->io, NULL);
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}
	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, addr);
	if (within_fcn && !fcn) {
		RZ_LOG_WARN("Cannot generate CFG for 0x%" PFMT64x ". addr doesn't point to a function entrypoint.", addr);
		return NULL;
	} else if (!within_fcn) {
		fcn = NULL;
	}

	// Visited instructions. Indexed by instruction address, value is index in graph.
	HtUU *nodes_visited = ht_uu_new();
	// Addresses to visit.
	RzVector *to_visit = rz_vector_new(sizeof(ut64), NULL, NULL);

	// Add entry node
	ut8 buf[64] = { 0 };
	RzAnalysisOp curr_op = { 0 };
	RzAnalysisOp target_op = { 0 };
	st32 disas_bytes = decode_op_at(core, addr, buf, sizeof(buf), &curr_op);
	RzGraphNode *entry = add_node_info_cfg(graph, &curr_op, true);
	if (disas_bytes <= 0) {
		goto fini;
	}
	ht_uu_insert(nodes_visited, addr, entry->idx);
	rz_vector_push(to_visit, &addr);

	while (rz_vector_len(to_visit) > 0) {
		ut64 cur_addr = 0;
		rz_vector_pop(to_visit, &cur_addr);

		disas_bytes = decode_op_at(core, cur_addr, buf, sizeof(buf), &curr_op);
		if (disas_bytes <= 0 || is_leaf_op(&curr_op)) {
			// A leaf. It was added before to the graph by the parent node.
			rz_analysis_op_fini(&curr_op);
			continue;
		}

		bool to_node_within_fcn = true;
		bool add_jump = curr_op.jump != UT64_MAX && !is_call(&curr_op);
		bool add_fail = curr_op.fail != UT64_MAX && !is_call(&curr_op);
		if (add_jump) {
			if (decode_op_at(core, curr_op.jump, buf, sizeof(buf), &target_op) <= 0) {
				rz_analysis_op_fini(&target_op);
				goto error;
			}
			to_node_within_fcn = fcn ? rz_analysis_function_contains(fcn, target_op.addr) : true;
			if (!add_edge_to_cfg(graph, to_visit, nodes_visited, &curr_op, &target_op, to_node_within_fcn)) {
				goto error;
			}
			rz_analysis_op_fini(&target_op);
		}
		if (add_fail) {
			if (decode_op_at(core, curr_op.fail, buf, sizeof(buf), &target_op) <= 0) {
				rz_analysis_op_fini(&target_op);
				goto error;
			}
			to_node_within_fcn = fcn ? rz_analysis_function_contains(fcn, target_op.addr) : true;
			if (!add_edge_to_cfg(graph, to_visit, nodes_visited, &curr_op, &target_op, to_node_within_fcn)) {
				goto error;
			}
			rz_analysis_op_fini(&target_op);
		}

		ut64 next_addr = cur_addr + disas_bytes;
		bool next_within_fcn = fcn ? rz_analysis_function_contains(fcn, next_addr) : true;
		if (within_fcn && !next_within_fcn && tail_exit_candidate(to_node_within_fcn && add_jump, next_within_fcn, &curr_op)) {
			assign_tails_exits(graph, nodes_visited, &curr_op);
			rz_analysis_op_fini(&curr_op);
			continue;
		}

		if (ignore_next_instr(&curr_op)) {
			rz_analysis_op_fini(&curr_op);
			continue;
		}

		// Add next instruction
		if (decode_op_at(core, next_addr, buf, sizeof(buf), &target_op) <= 0) {
			rz_analysis_op_fini(&target_op);
			goto error;
		}
		if (!add_edge_to_cfg(graph, to_visit, nodes_visited, &curr_op, &target_op, to_node_within_fcn)) {
			goto error;
		}
		rz_analysis_op_fini(&target_op);
		rz_analysis_op_fini(&curr_op);
	}

fini:
	rz_vector_free(to_visit);
	ht_uu_free(nodes_visited);
	return graph;

error:
	rz_warn_if_reached();
	rz_graph_free(graph);
	graph = NULL;
	goto fini;
}

static RzGraphNode *add_iword_to_cfg(RzGraph /*<RzGraphNodeInfo *>*/ *cfg, const RzAnalysisInsnWord *iword, bool is_entry) {
	rz_return_val_if_fail(cfg, NULL);
	RzGraphNodeCFGIWordSubType subtype = get_cfg_iword_node_flags(iword);
	if (is_entry) {
		subtype |= RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_ENTRY;
	}
	RzGraphNodeInfo *data = rz_graph_create_node_info_cfg_iword(iword, subtype);
	if (!data) {
		return NULL;
	}
	RzGraphNode *node = rz_graph_add_nodef(cfg, data, rz_graph_free_node_info);
	if (!node) {
		rz_graph_free_node_info(data);
	}
	return node;
}

static bool add_iword_edge_to_cfg(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph,
	RZ_NONNULL RzVector /*<ut64>*/ *to_visit,
	RZ_NONNULL HtUU *nodes_visited,
	const RzAnalysisInsnWord *irowrd_from,
	const RzAnalysisInsnWord *iword_to,
	bool to_node_in_fcn) {
	if (!to_node_in_fcn) {
		return true;
	}
	rz_return_val_if_fail(graph && to_visit && nodes_visited && irowrd_from && iword_to, -1);
	ut64 from = irowrd_from->addr;
	ut64 to = iword_to->addr;
	bool visited = false;
	ut64 from_idx = ht_uu_find(nodes_visited, from, &visited);
	if (!visited && from != to) {
		RZ_LOG_ERROR("'from' node should have been added before. 0x%" PFMT64x " -> 0x%" PFMT64x "\n", from, to);
		return false;
	}
	ut64 to_idx = ht_uu_find(nodes_visited, to, &visited);

	RzGraphNode *to_node = NULL;
	if (visited) {
		to_node = rz_graph_get_node(graph, to_idx);
	} else {
		to_node = add_iword_to_cfg(graph, iword_to, false);
	}
	if (!to_node) {
		RZ_LOG_ERROR("Could not add node at 0x%" PFMT64x "\n", to);
		return false;
	}
	to_idx = to_node->idx;
	if (from == to) {
		from_idx = to_idx;
	}

	if (from != to && !visited) {
		// The target node wasn't visited before. Otherwise this is a back-edge.
		rz_vector_push(to_visit, &to);
	}

	ht_uu_insert(nodes_visited, to, to_node->idx);
	if (!rz_graph_adjacent(graph, rz_graph_get_node(graph, from_idx), to_node)) {
		rz_graph_add_edge(graph, rz_graph_get_node(graph, from_idx), to_node);
	}
	return true;
}

static st32 decode_iword_at(RZ_BORROW RzCore *core,
	ut64 addr,
	RZ_BORROW ut8 *buf,
	size_t buf_len,
	RZ_OUT RzAnalysisInsnWord *target_iword) {
	rz_return_val_if_fail(core && core->analysis && core->io && buf && core->analysis->cur && core->analysis->cur->decode_iword, -1);
	size_t leading_bytes = addr < 8 ? addr : 8;
	size_t bl = buf_len;
	if (!read_aligned_to_mapped(core->io, addr, buf, &bl, leading_bytes)) {
		RZ_LOG_ERROR("read_aligned_to_mapped() read from unmapped region at 0x%" PFMT64x ".\n", addr);
		return -1;
	}
	bool success = core->analysis->cur->decode_iword(core->analysis, target_iword, addr, buf, bl, leading_bytes);
	return success ? target_iword->size_bytes : -1;
}

/**
 * \brief Get the procedual control flow graph (CFG) of instruction words at an address.
 * Calls are not followed.
 *
 * \param core The current core.
 * \param addr The CFG entry point.
 * \param within_fcn If true, only nodes within the function at \p addr are added to the CFG.
 *
 * \return The CFG at address \p addr or NULL in case of failure.
 */
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_core_graph_cfg_iwords(RZ_NONNULL RzCore *core, ut64 addr, bool within_fcn) {
	rz_return_val_if_fail(core && core->analysis && core->io, NULL);
	RzGraph *graph = rz_graph_new();
	if (!graph) {
		return NULL;
	}

	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, addr);
	if (within_fcn && !fcn) {
		RZ_LOG_WARN("Cannot generate CFG for 0x%" PFMT64x ". addr doesn't point to a function entrypoint.", addr);
		return NULL;
	} else if (!within_fcn) {
		fcn = NULL;
	}

	// Visited instructions. Indexed by instruction address, value is index in graph.
	HtUU *nodes_visited = ht_uu_new();
	// Addresses to visit.
	RzVector *to_visit = rz_vector_new(sizeof(ut64), NULL, NULL);

	// Add entry node
	ut8 buf[64] = { 0 };
	RzAnalysisInsnWord cur_iword = { 0 };
	rz_analysis_insn_word_setup(&cur_iword);

	st32 disas_bytes = decode_iword_at(core, addr, buf, sizeof(buf), &cur_iword);
	RzGraphNode *entry = add_iword_to_cfg(graph, &cur_iword, true);
	if (disas_bytes <= 0) {
		goto fini;
	}
	ht_uu_insert(nodes_visited, addr, entry->idx);
	rz_vector_push(to_visit, &addr);

	while (rz_vector_len(to_visit) > 0) {
		ut64 cur_addr = 0;
		rz_vector_pop(to_visit, &cur_addr);
		rz_analysis_insn_word_setup(&cur_iword);

		disas_bytes = decode_iword_at(core, cur_addr, buf, sizeof(buf), &cur_iword);
		if (disas_bytes <= 0) {
			// If the decoding was invalid we do not add it to the graph.
			rz_analysis_insn_word_fini(&cur_iword);
			continue;
		}
		// Add all neighbors to graph
		RzAnalysisInsnWord target_iword = { 0 };
		RzIterator *iter = rz_set_u_as_iter(cur_iword.jump_targets);
		ut64 *target;
		rz_iterator_foreach(iter, target) {
			rz_analysis_insn_word_setup(&target_iword);
			if (decode_iword_at(core, *target, buf, sizeof(buf), &target_iword) <= 0) {
				rz_analysis_insn_word_fini(&target_iword);
				continue;
			}
			bool target_within_fcn = fcn ? rz_analysis_function_contains(fcn, *target) : true;
			bool found = false;
			ht_uu_find(nodes_visited, *target, &found);
			if (!found && target_within_fcn) {
				rz_vector_push(to_visit, &target);
			}
			if (!add_iword_edge_to_cfg(graph, to_visit, nodes_visited, &cur_iword, &target_iword, target_within_fcn)) {
				rz_analysis_insn_word_fini(&target_iword);
				goto error;
			}
			rz_analysis_insn_word_fini(&target_iword);
		}
	}

fini:
	rz_analysis_insn_word_fini(&cur_iword);
	rz_vector_free(to_visit);
	ht_uu_free(nodes_visited);
	return graph;

error:
	rz_analysis_insn_word_fini(&cur_iword);
	rz_warn_if_reached();
	rz_graph_free(graph);
	graph = NULL;
	goto fini;
}
