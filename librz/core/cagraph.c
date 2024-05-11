// SPDX-FileCopyrightText: 2014-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014-2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "core_private.h"

RZ_IPI void rz_core_agraph_reset(RzCore *core) {
	rz_agraph_reset(core->graph);
}

RZ_IPI void rz_core_agraph_add_node(RzCore *core, const char *title, const char *body) {
	char *b = strdup(body);
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
	rz_agraph_add_node(core->graph, title, b);
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

RZ_IPI void rz_core_agraph_print_sdb(RzCore *core) {
	Sdb *db = rz_agraph_get_sdb(core->graph);
	char *o = sdb_querys(db, "null", 0, "*");
	rz_cons_print(o);
	free(o);
}

RZ_IPI void rz_core_agraph_print_interactive(RzCore *core) {
	RzANode *ran = rz_agraph_get_first_node(core->graph);
	if (!ran) {
		RZ_LOG_ERROR("core: this graph contains no nodes\n");
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

static void agraph_print_node_dot(RzANode *n, void *user) {
	char *label = strdup(n->body);
	// label = rz_str_replace (label, "\n", "\\l", 1);

	if (!label || !*label) {
		rz_cons_printf("\"%s\" [URL=\"%s\", color=\"lightgray\", label=\"%s\"]\n",
			n->title, n->title, n->title);
	} else {
		rz_str_replace_ch(label, '\"', '\'', true);
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
	char *cmd;
	int len = strlen(n->body);

	if (len > 0 && n->body[len - 1] == '\n') {
		len--;
	}
	if (RZ_STR_ISEMPTY(n->body)) {
		cmd = rz_str_newf("agn \"%s\"\n", n->title);
	} else {
		char *encbody = rz_base64_encode_dyn((const ut8 *)n->body, len);
		cmd = rz_str_newf("agn \"%s\" base64:%s\n", n->title, encbody);
		free(encbody);
	}
	rz_cons_print(cmd);
	free(cmd);
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

RZ_IPI bool rz_core_agraph_print(RzCore *core, RzCoreGraphFormat format) {
	switch (format) {
	case RZ_CORE_GRAPH_FORMAT_ASCII_ART:
		rz_core_agraph_print_ascii(core);
		break;
		break;
	case RZ_CORE_GRAPH_FORMAT_SDB:
		rz_core_agraph_print_sdb(core);
		break;
	case RZ_CORE_GRAPH_FORMAT_VISUAL:
		rz_core_agraph_print_interactive(core);
		break;
	case RZ_CORE_GRAPH_FORMAT_DOT:
		rz_core_agraph_print_dot(core);
		break;
	case RZ_CORE_GRAPH_FORMAT_CMD:
		rz_core_agraph_print_rizin(core);
		break;
	case RZ_CORE_GRAPH_FORMAT_JSON:
		/* fall-thru */
	case RZ_CORE_GRAPH_FORMAT_JSON_DISASM:
		rz_core_agraph_print_json(core);
		break;
	case RZ_CORE_GRAPH_FORMAT_GML:
		rz_core_agraph_print_gml(core);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	return true;
}

RZ_IPI bool rz_core_agraph_is_shortcuts(RzCore *core, RzAGraph *g) {
	rz_return_val_if_fail(g && core, false);
	return g->is_interactive && rz_config_get_i(core->config, "graph.nodejmps");
}

RZ_IPI bool rz_core_agraph_add_shortcut(RzCore *core, RzAGraph *g, RzANode *an, ut64 addr, char *title) {
	rz_return_val_if_fail(core && g && an && title, false);
	char *shortcut = rz_core_add_asmqjmp(core, addr);
	if (!shortcut) {
		return false;
	}
	char *key = rz_str_newf("agraph.nodes.%s.shortcut", title);
	sdb_set(g->db, key, shortcut);
	free(key);
	// title + "[o{shortcut}]", so w + 3 ?
	an->shortcut_w = strlen(shortcut) + 3;
	free(shortcut);
	return true;
}

RZ_IPI bool rz_core_add_shortcuts(RzCore *core, RzAGraph *ag) {
	rz_return_val_if_fail(core && ag, false);
	const RzList *nodes = rz_graph_get_nodes(ag->graph);
	RzGraphNode *gn;
	RzListIter *it;
	rz_list_foreach (nodes, it, gn) {
		RzANode *an = gn->data;
		rz_core_agraph_add_shortcut(core, ag, an, an->offset, an->title);
	}
	return true;
}

RZ_IPI bool rz_core_agraph_apply(RzCore *core, RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	if (!(core && core->graph && graph)) {
		return false;
	}
	if (!create_agraph_from_graph_at(core->graph, graph, false, rz_config_get_b(core->config, "scr.utf8"))) {
		return false;
	}
	if (rz_core_agraph_is_shortcuts(core, core->graph)) {
		rz_core_add_shortcuts(core, core->graph);
	}
	return true;
}
