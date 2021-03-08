// SPDX-FileCopyrightText: 2014-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014-2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "core_private.h"

RZ_IPI void rz_core_agraph_reset(RzCore *core) {
	rz_agraph_reset(core->graph);
}

RZ_IPI void rz_core_agraph_add_node(RzCore *core, const char *title, const char *body, int color) {
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
