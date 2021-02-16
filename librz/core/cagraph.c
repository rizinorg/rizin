// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "core_private.h"

RZ_IPI void rz_core_agraph_reset(RzCore *core) {
	rz_agraph_reset(core->graph);
}

RZ_IPI void rz_core_agraph_add_node(RzCore *core, const char *title, const char *body, int color) {
	char *b = strdup(body ? body : "");
	if (rz_str_startswith(b, "base64:")) {
		char *newbody = strdup(b);
		if (!newbody) {
			free(b);
			return;
		}
		b = rz_str_replace(newbody, "\\n", "", true);
		newbody = (char *)rz_base64_decode_dyn(b + strlen("base64:"), -1);
		free(b);
		if (!newbody) {
			return;
		}
		b = newbody;
	}
	if (!RZ_STR_ISEMPTY(b)) {
		b = rz_str_append(b, "\n");
	}
	rz_agraph_add_node_with_color(core->graph, title, b, color);
	free(b);
}

RZ_IPI void rz_core_agraph_del_node(RzCore *core, const char *title) {
	rz_agraph_del_node(core->graph, title);
}

RZ_IPI void rz_core_agraph_add_edge(RzCore *core, const char *un, const char *vn) {
	RzANode *u = rz_agraph_get_node(core->graph, un);
	RzANode *v = rz_agraph_get_node(core->graph, vn);
	if (!u) {
		rz_cons_printf("Node %s not found!\n", un);
		return;
	} else if (!v) {
		rz_cons_printf("Node %s not found!\n", vn);
		return;
	}
	rz_agraph_add_edge(core->graph, u, v);
}

RZ_IPI void rz_core_agraph_del_edge(RzCore *core, const char *un, const char *vn) {
	RzANode *u = rz_agraph_get_node(core->graph, un);
	RzANode *v = rz_agraph_get_node(core->graph, vn);
	if (!u) {
		rz_cons_printf("Node %s not found!\n", un);
		return;
	} else if (!v) {
		rz_cons_printf("Node %s not found!\n", vn);
		return;
	}
	rz_agraph_del_edge(core->graph, u, v);
}

RZ_IPI void rz_core_agraph_print_ascii(RzCore *core) {
	core->graph->can->linemode = rz_config_get_i(core->config, "graph.linemode");
	core->graph->can->color = rz_config_get_i(core->config, "scr.color");
	rz_agraph_set_title(core->graph, rz_config_get(core->config, "graph.title"));
	rz_agraph_print(core->graph);
}

RZ_IPI void rz_core_agraph_print_tiny(RzCore *core) {
	core->graph->is_tiny = true;
	int e = rz_config_get_i(core->config, "graph.edges");
	rz_config_set_i(core->config, "graph.edges", 0);
	rz_core_visual_graph(core, core->graph, NULL, false);
	rz_config_set_i(core->config, "graph.edges", e);
	core->graph->is_tiny = false;
}

RZ_IPI void rz_core_agraph_print_sdb(RzCore *core) {
	Sdb *db = rz_agraph_get_sdb(core->graph);
	char *o = sdb_querys(db, "null", 0, "*");
	rz_cons_print(o);
	free(o);
}

RZ_IPI void rz_core_agraph_print_interactive(RzCore *core) {
	RzANode *ran = rz_agraph_get_first_node(core->graph);
	if (!ran) {
		eprintf("This graph contains no nodes\n");
		return;
	}

	ut64 oseek = core->offset;
	rz_agraph_set_title(core->graph, rz_config_get(core->config, "graph.title"));
	rz_agraph_set_curnode(core->graph, ran);
	core->graph->force_update_seek = true;
	core->graph->need_set_layout = true;
	core->graph->layout = rz_config_get_i(core->config, "graph.layout");
	bool ov = rz_cons_is_interactive();
	core->graph->need_update_dim = true;
	int update_seek = rz_core_visual_graph(core, core->graph, NULL, true);
	rz_config_set_i(core->config, "scr.interactive", ov);
	rz_cons_show_cursor(true);
	rz_cons_enable_mouse(false);
	if (update_seek != -1) {
		rz_core_seek(core, oseek, false);
	}
}

RZ_IPI void rz_core_agraph_print_write(RzCore *core, const char *filename) {
	rz_convert_dotcmd_to_image(core, "aggd", filename);
}

static void agraph_print_node_dot(RzANode *n, void *user) {
	char *label = strdup(n->body);
	//label = rz_str_replace (label, "\n", "\\l", 1);
	if (!label || !*label) {
		rz_cons_printf("\"%s\" [URL=\"%s\", color=\"lightgray\", label=\"%s\"]\n",
			n->title, n->title, n->title);
	} else {
		rz_cons_printf("\"%s\" [URL=\"%s\", color=\"lightgray\", label=\"%s\\n%s\"]\n",
			n->title, n->title, n->title, label);
	}
	free(label);
}

static void agraph_print_edge_dot(RzANode *from, RzANode *to, void *user) {
	rz_cons_printf("\"%s\" -> \"%s\"\n", from->title, to->title);
}

static void agraph_print_edge(RzANode *from, RzANode *to, void *user) {
	rz_cons_printf("age \"%s\" \"%s\"\n", from->title, to->title);
}

static void agraph_print_node(RzANode *n, void *user) {
	char *encbody, *cmd;
	int len = strlen(n->body);

	if (len > 0 && n->body[len - 1] == '\n') {
		len--;
	}
	encbody = rz_base64_encode_dyn((const ut8 *)n->body, len);
	cmd = rz_str_newf("agn \"%s\" base64:%s\n", n->title, encbody);
	rz_cons_print(cmd);
	free(cmd);
	free(encbody);
}

RZ_IPI void rz_core_agraph_print_dot(RzCore *core) {
	const char *font = rz_config_get(core->config, "graph.font");
	rz_cons_printf("digraph code {\nrankdir=LR;\noutputorder=edgesfirst\ngraph [bgcolor=azure];\n"
		       "edge [arrowhead=normal, color=\"#3030c0\" style=bold weight=2];\n"
		       "node [fillcolor=white, style=filled shape=box "
		       "fontname=\"%s\" fontsize=\"8\"];\n",
		font);
	rz_agraph_foreach(core->graph, agraph_print_node_dot, NULL);
	rz_agraph_foreach_edge(core->graph, agraph_print_edge_dot, NULL);
	rz_cons_printf("}\n");
}

RZ_IPI void rz_core_agraph_print_rizin(RzCore *core) {
	rz_agraph_foreach(core->graph, agraph_print_node, NULL);
	rz_agraph_foreach_edge(core->graph, agraph_print_edge, NULL);
}

RZ_IPI void rz_core_agraph_print_json(RzCore *core) {
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_k(pj, "nodes");
	pj_a(pj);
	rz_agraph_print_json(core->graph, pj);
	pj_end(pj);
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
}

static void agraph_print_node_gml(RzANode *n, void *user) {
	rz_cons_printf("  node [\n"
		       "    id  %d\n"
		       "    label  \"%s\"\n"
		       "  ]\n",
		n->gnode->idx, n->title);
}

static void agraph_print_edge_gml(RzANode *from, RzANode *to, void *user) {
	rz_cons_printf("  edge [\n"
		       "    source  %d\n"
		       "    target  %d\n"
		       "  ]\n",
		from->gnode->idx, to->gnode->idx);
}

RZ_IPI void rz_core_agraph_print_gml(RzCore *core) {
	rz_cons_printf("graph\n[\n"
		       "hierarchic 1\n"
		       "label \"\"\n"
		       "directed 1\n");
	rz_agraph_foreach(core->graph, agraph_print_node_gml, NULL);
	rz_agraph_foreach_edge(core->graph, agraph_print_edge_gml, NULL);
	rz_cons_print("]\n");
}

RZ_IPI void rz_core_agraph_data_create(RzCore *core, ut64 addr) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, -1);
	if (!fcn) {
		eprintf("Not in a function.\n");
		return;
	}
	bool found = false;
	const char *me = fcn->name;
	RzListIter *iter;
	RzAnalysisRef *ref;
	RzList *refs = rz_analysis_function_get_refs(fcn);
	rz_list_foreach (refs, iter, ref) {
		RzBinObject *obj = rz_bin_cur_object(core->bin);
		RzBinSection *binsec = rz_bin_get_section_at(obj, ref->addr, true);
		if (binsec && binsec->is_data) {
			if (!found) {
				rz_core_agraph_add_node(core, me, NULL, -1);
				found = true;
			}
			RzFlagItem *item = rz_flag_get_i(core->flags, ref->addr);
			const char *dst = item ? item->name : sdb_fmt("0x%08" PFMT64x, ref->addr);
			rz_core_agraph_add_node(core, dst, NULL, -1);
			rz_core_agraph_add_edge(core, me, dst);
		}
	}
	rz_list_free(refs);
}

RZ_IPI void rz_core_agraph_globdata_create(RzCore *core) {
	ut64 from = rz_config_get_i(core->config, "graph.from");
	ut64 to = rz_config_get_i(core->config, "graph.to");
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, it, fcn) {
		if ((from == UT64_MAX && to == UT64_MAX) || RZ_BETWEEN(from, fcn->addr, to)) {
			rz_core_agraph_data_create(core, fcn->addr);
		}
	}
}

static int funccall_analysis_ref_cmp(const RzAnalysisRef *ref1, const RzAnalysisRef *ref2) {
	return ref1->addr != ref2->addr;
}

static void funccall_create_graph(RzCore *core, RzAnalysisFunction *fcn) {
	bool refgraph = rz_config_get_i(core->config, "graph.refs");
	RzList *refs = rz_analysis_function_get_refs(fcn);
	RzList *calls = rz_list_new();
	RzListIter *iter2;
	RzAnalysisRef *fcnr;

	rz_list_foreach (refs, iter2, fcnr) {
		if (fcnr->type == 'C' && rz_list_find(calls, fcnr, (RzListComparator)funccall_analysis_ref_cmp) == NULL) {
			rz_list_append(calls, fcnr);
		}
	}
	if (rz_list_empty(calls)) {
		rz_list_free(refs);
		rz_list_free(calls);
		return;
	}

	rz_list_foreach (calls, iter2, fcnr) {
		RzFlagItem *flag = rz_flag_get_i(core->flags, fcnr->addr);
		char *fcnr_name = (flag && flag->name) ? flag->name : rz_str_newf("unk.0x%" PFMT64x, fcnr->addr);
		if (refgraph || fcnr->type == RZ_ANALYSIS_REF_TYPE_CALL) {
			rz_core_agraph_add_node(core, fcn->name, NULL, -1);
			rz_core_agraph_add_node(core, fcnr_name, NULL, -1);
			rz_core_agraph_add_edge(core, fcn->name, fcnr_name);
		}
		if (!(flag && flag->name)) {
			free(fcnr_name);
		}
	}
	rz_list_free(refs);
	rz_list_free(calls);
}

RZ_IPI void rz_core_agraph_funccall_create(RzCore *core, ut64 addr) {
	RzList *fcns = rz_analysis_get_functions_in(core->analysis, addr);
	if (rz_list_empty(fcns)) {
		return;
	}

	RzAnalysisFunction *fcn = rz_list_get_n(fcns, 0);
	funccall_create_graph(core, fcn);
}

RZ_IPI void rz_core_agraph_globcall_create(RzCore *core) {
	ut64 from = rz_config_get_i(core->config, "graph.from");
	ut64 to = rz_config_get_i(core->config, "graph.to");
	RzAnalysisFunction *fcni;
	RzListIter *iter;

	rz_list_foreach (core->analysis->fcns, iter, fcni) {
		if (from != UT64_MAX && fcni->addr < from) {
			continue;
		}
		if (to != UT64_MAX && fcni->addr > to) {
			continue;
		}
		funccall_create_graph(core, fcni);
	}
}

RZ_IPI void rz_core_agraph_imports_create(RzCore *core) {
	RzBinInfo *info = rz_bin_get_info(core->bin);
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	if (!obj) {
		return;
	}

	bool lit = info ? info->has_lit : false;
	bool va = core->io->va || core->bin->is_debugger;

	RzListIter *iter;
	RzBinImport *imp;
	rz_list_foreach (obj->imports, iter, imp) {
		ut64 addr = lit ? rz_core_bin_impaddr(core->bin, va, imp->name) : 0;
		RzFlagItem *f = rz_flag_get_at(core->flags, addr, false);
		if (addr) {
			char *me = (f && f->offset == addr)
				? rz_str_new(f->name)
				: rz_str_newf("0x%" PFMT64x, addr);
			rz_core_agraph_add_node(core, me, NULL, -1);

			RzList *list = rz_analysis_xrefs_get(core->analysis, addr);
			RzListIter *iter;
			RzAnalysisRef *ref;
			rz_list_foreach (list, iter, ref) {
				RzFlagItem *item = rz_flag_get_i(core->flags, ref->addr);
				char *src = item ? rz_str_new(item->name) : rz_str_newf("0x%08" PFMT64x, ref->addr);
				rz_core_agraph_add_node(core, src, NULL, -1);
				rz_core_agraph_add_edge(core, src, me);
				free(src);
			}
			rz_list_free(list);
		} else {
			rz_core_agraph_add_node(core, imp->name, NULL, -1);
		}
	}
}

RZ_IPI void rz_core_agraph_refs_create(RzCore *core, ut64 addr) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, -1);
	if (!fcn) {
		eprintf("Not in a function.\n");
	}

	const char *me = fcn->name;
	RzListIter *iter;
	RzAnalysisRef *ref;
	RzList *refs = rz_analysis_function_get_refs(fcn);
	rz_core_agraph_add_node(core, me, NULL, -1);
	rz_list_foreach (refs, iter, ref) {
		RzFlagItem *item = rz_flag_get_i(core->flags, ref->addr);
		const char *dst = item ? item->name : sdb_fmt("0x%08" PFMT64x, ref->addr);
		rz_core_agraph_add_node(core, dst, NULL, -1);
		rz_core_agraph_add_edge(core, me, dst);
	}
	rz_list_free(refs);
}

RZ_IPI void rz_core_agraph_globrefs_create(RzCore *core) {
	ut64 from = rz_config_get_i(core->config, "graph.from");
	ut64 to = rz_config_get_i(core->config, "graph.to");
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (core->analysis->fcns, it, fcn) {
		if ((from == UT64_MAX && to == UT64_MAX) || RZ_BETWEEN(from, fcn->addr, to)) {
			rz_core_agraph_refs_create(core, fcn->addr);
		}
	}
}

RZ_IPI void rz_core_agraph_xrefs_create(RzCore *core, ut64 addr) {
	RzFlagItem *f = rz_flag_get_at(core->flags, addr, false);
	char *me = (f && f->offset == addr)
		? rz_str_new(f->name)
		: rz_str_newf("0x%" PFMT64x, addr);

	rz_core_agraph_add_node(core, me, NULL, -1);
	RzList *list = rz_analysis_xrefs_get(core->analysis, addr);
	RzListIter *iter;
	RzAnalysisRef *ref;
	rz_list_foreach (list, iter, ref) {
		RzFlagItem *item = rz_flag_get_i(core->flags, ref->addr);
		char *src = item ? rz_str_new(item->name) : rz_str_newf("0x%08" PFMT64x, ref->addr);
		rz_core_agraph_add_node(core, src, NULL, -1);
		rz_core_agraph_add_edge(core, src, me);
		free(src);
	}
	rz_list_free(list);
}

RZ_IPI void rz_core_agraph_esil_create(RzCore *core, const char *expr) {
	RzAnalysisEsilDFG *edf = rz_analysis_esil_dfg_expr(core->analysis, NULL, expr);
	RzListIter *iter, *ator;
	RzGraphNode *node, *edon;
	RzStrBuf *buf = rz_strbuf_new("");
	rz_list_foreach (rz_graph_get_nodes(edf->flow), iter, node) {
		const RzAnalysisEsilDFGNode *enode = (RzAnalysisEsilDFGNode *)node->data;
		char *esc_str = rz_str_escape(rz_strbuf_get(enode->content));
		rz_strbuf_set(buf, esc_str);
		if (enode->type == RZ_ANALYSIS_ESIL_DFG_BLOCK_GENERATIVE) {
			rz_strbuf_prepend(buf, "generative:");
		}
		rz_strbuf_append(buf, "\n");
		char title[32];
		rz_agraph_add_node_with_color(core->graph, rz_strf(title, "%d", enode->idx), rz_strbuf_get(buf), -1);
		free(esc_str);
	}
	rz_strbuf_free(buf);

	rz_list_foreach (rz_graph_get_nodes(edf->flow), iter, node) {
		const RzAnalysisEsilDFGNode *enode = (RzAnalysisEsilDFGNode *)node->data;
		rz_list_foreach (rz_graph_get_neighbours(edf->flow, node), ator, edon) {
			const RzAnalysisEsilDFGNode *edone = (RzAnalysisEsilDFGNode *)edon->data;
			char u[32], v[32];
			rz_core_agraph_add_edge(core, rz_strf(u, "%d", enode->idx), rz_strf(v, "%d", edone->idx));
		}
	}

	rz_analysis_esil_dfg_free(edf);
}

RZ_IPI void rz_core_agraph_bb_create(RzCore *core, ut64 addr) {
	RzAnalysisBlock *bb;
	RzListIter *iter;
	RzList *fcns = rz_analysis_get_functions_in(core->analysis, addr);
	if (rz_list_empty(fcns)) {
		return;
	}
	RzAnalysisFunction *fcn = rz_list_get_n(fcns, 0);

	RzConfigHold *hc = rz_config_hold_new(core->config);
	rz_config_hold_i(hc, "scr.color", "scr.utf8", "asm.marks", "asm.offset", "asm.lines",
		"asm.cmt.right", "asm.cmt.col", "asm.lines.fcn", "asm.bytes", NULL);
	/*rz_config_set_i (core->config, "scr.color", 0);*/
	rz_config_set_i(core->config, "scr.utf8", 0);
	rz_config_set_i(core->config, "asm.marks", 0);
	rz_config_set_i(core->config, "asm.offset", 0);
	rz_config_set_i(core->config, "asm.lines", 0);
	rz_config_set_i(core->config, "asm.cmt.right", 0);
	rz_config_set_i(core->config, "asm.cmt.col", 0);
	rz_config_set_i(core->config, "asm.lines.fcn", 0);
	rz_config_set_i(core->config, "asm.bytes", 0);

	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char title[32];
		char *body = rz_core_cmd_strf(core, "pdb @ 0x%08" PFMT64x, bb->addr);
		if (!body) {
			free(body);
			goto err;
		}
		rz_agraph_add_node_with_color(core->graph, rz_strf(title, "0x%" PFMT64x, bb->addr), body, -1);
		free(body);
	}

	rz_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char u[32], v[32];
		rz_strf(u, "0x%" PFMT64x, bb->addr);
		if (bb->jump != UT64_MAX) {
			rz_core_agraph_add_edge(core, u, rz_strf(v, "0x%" PFMT64x, bb->jump));
		}
		if (bb->fail != UT64_MAX) {
			rz_core_agraph_add_edge(core, u, rz_strf(v, "0x%" PFMT64x, bb->fail));
		}
		if (bb->switch_op) {
			RzListIter *it;
			RzAnalysisCaseOp *cop;
			rz_list_foreach (bb->switch_op->cases, it, cop) {
				rz_core_agraph_add_edge(core, u, rz_strf(v, "0x%" PFMT64x, cop->addr));
			}
		}
	}

err:
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	rz_list_free(fcns);
}

static bool core_agraph_bb_handle(RzCore *core, RzAGraphOutputMode mode, const char *extra) {
	RzAnalysisFunction *fcn = NULL;
	RzConfigHold *hc = NULL;
	char *cmdargs = NULL;
	int e;

	// NOTE: special handling for agf for now, because agf contains a lot of information
	switch (mode) {
	case RZ_AGRAPH_OUTPUT_MODE_ASCII:
		if (!RZ_STR_ISEMPTY(extra)) {
			fcn = rz_analysis_get_fcn_in(core->analysis, rz_num_math(core->num, extra), 0);
		}
		rz_core_visual_graph(core, NULL, fcn, false);
		return false;
	case RZ_AGRAPH_OUTPUT_MODE_INTERACTIVE:
		fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ROOT);
		if (fcn) {
			rz_core_visual_graph(core, NULL, fcn, 1);
		}
		rz_cons_enable_mouse(false);
		rz_cons_show_cursor(true);
		return false;
	case RZ_AGRAPH_OUTPUT_MODE_TINY:
		e = rz_config_get_i(core->config, "graph.edges");
		rz_config_set_i(core->config, "graph.edges", 0);
		fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		rz_core_visual_graph(core, NULL, fcn, 2);
		rz_config_set_i(core->config, "graph.edges", e);
		return false;
	case RZ_AGRAPH_OUTPUT_MODE_DOT:
		rz_core_analysis_graph(core, rz_num_math(core->num, extra), RZ_CORE_ANALYSIS_GRAPHBODY);
		return false;
	case RZ_AGRAPH_OUTPUT_MODE_WRITE:
		cmdargs = rz_str_newf("agfd @ 0x%" PFMT64x, core->offset);
		rz_convert_dotcmd_to_image(core, cmdargs, extra);
		free(cmdargs);
		return false;
	case RZ_AGRAPH_OUTPUT_MODE_JSON:
		rz_core_analysis_graph(core, rz_num_math(core->num, extra), RZ_CORE_ANALYSIS_JSON);
		return false;
	case RZ_AGRAPH_OUTPUT_MODE_JSON_FORMAT:
		hc = rz_config_hold_new(core->config);
		rz_config_hold_i(hc, "asm.offset", NULL);
		const bool o_graph_offset = rz_config_get_i(core->config, "graph.offset");
		rz_config_set_i(core->config, "asm.offset", o_graph_offset);
		rz_core_analysis_graph(core, rz_num_math(core->num, extra),
			RZ_CORE_ANALYSIS_JSON | RZ_CORE_ANALYSIS_JSON_FORMAT_DISASM);
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		return false;
	default:
		rz_core_agraph_bb_create(core, core->offset);
		return true;
	}
}

RZ_IPI void rz_core_agraph_print_type(RzCore *core, RzAGraphType type, RzAGraphOutputMode mode, const char *extra) {
	core->graph->is_callgraph = false;
	switch (type) {
	case RZ_AGRAPH_TYPE_DATA:
		rz_core_agraph_reset(core);
		rz_core_agraph_data_create(core, core->offset);
		break;
	case RZ_AGRAPH_TYPE_GLOBDATA:
		rz_core_agraph_reset(core);
		rz_core_agraph_globdata_create(core);
		break;
	case RZ_AGRAPH_TYPE_FUNCCALL:
		core->graph->is_callgraph = true;
		rz_core_agraph_reset(core);
		rz_core_agraph_funccall_create(core, core->offset);
		break;
	case RZ_AGRAPH_TYPE_GLOBCALL:
		core->graph->is_callgraph = true;
		rz_core_agraph_reset(core);
		rz_core_agraph_globcall_create(core);
		break;
	case RZ_AGRAPH_TYPE_BB:
		rz_core_agraph_reset(core);
		if (!core_agraph_bb_handle(core, mode, extra)) {
			return;
		}
		break;
	case RZ_AGRAPH_TYPE_IMPORTS:
		rz_core_agraph_reset(core);
		rz_core_agraph_imports_create(core);
		break;
	case RZ_AGRAPH_TYPE_REFS:
		rz_core_agraph_reset(core);
		rz_core_agraph_refs_create(core, core->offset);
		break;
	case RZ_AGRAPH_TYPE_GLOBREFS:
		rz_core_agraph_reset(core);
		rz_core_agraph_globrefs_create(core);
		break;
	case RZ_AGRAPH_TYPE_XREFS:
		rz_core_agraph_reset(core);
		rz_core_agraph_xrefs_create(core, core->offset);
		break;
	case RZ_AGRAPH_TYPE_CUSTOM:
		break;
	case RZ_AGRAPH_TYPE_ESIL:
		rz_core_agraph_reset(core);
		if (RZ_STR_ISEMPTY(extra)) {
			RzAnalysisOp *aop = rz_core_analysis_op(core, core->offset, RZ_ANALYSIS_OP_MASK_ESIL);
			if (!aop) {
				return;
			}
			const char *esilstr = rz_strbuf_get(&aop->esil);
			rz_core_agraph_esil_create(core, esilstr);
		} else {
			rz_core_agraph_esil_create(core, extra);
		}
		break;
	}

	switch (mode) {
	case RZ_AGRAPH_OUTPUT_MODE_ASCII:
		rz_core_agraph_print_ascii(core);
		break;
	case RZ_AGRAPH_OUTPUT_MODE_RIZIN:
		rz_core_agraph_print_rizin(core);
		break;
	case RZ_AGRAPH_OUTPUT_MODE_DOT:
		rz_core_agraph_print_dot(core);
		break;
	case RZ_AGRAPH_OUTPUT_MODE_GML:
		rz_core_agraph_print_gml(core);
		break;
	case RZ_AGRAPH_OUTPUT_MODE_JSON:
	case RZ_AGRAPH_OUTPUT_MODE_JSON_FORMAT:
		rz_core_agraph_print_json(core);
		break;
	case RZ_AGRAPH_OUTPUT_MODE_SDB:
		rz_core_agraph_print_sdb(core);
		break;
	case RZ_AGRAPH_OUTPUT_MODE_TINY:
		rz_core_agraph_print_tiny(core);
		break;
	case RZ_AGRAPH_OUTPUT_MODE_INTERACTIVE:
		rz_core_agraph_print_interactive(core);
		break;
	case RZ_AGRAPH_OUTPUT_MODE_WRITE:
		rz_core_agraph_print_write(core, extra);
		break;
	}
}