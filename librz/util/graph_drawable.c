// SPDX-FileCopyrightText: 2020 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2020 karliss <karlis3p70l1ij@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util/rz_graph_drawable.h>

RZ_API void rz_graph_free_node_info(void *ptr) {
	if (!ptr) {
		return;
	}
	RzGraphNodeInfo *info = ptr;
	free(info->body);
	free(info->title);
	free(info);
}

RZ_API RzGraphNodeInfo *rz_graph_create_node_info(const char *title, const char *body, ut64 offset) {
	RzGraphNodeInfo *data = RZ_NEW0(RzGraphNodeInfo);
	if (data) {
		data->title = RZ_STR_DUP(title);
		data->body = RZ_STR_DUP(body);
		data->offset = offset;
	}
	return data;
}

RZ_API RzGraphNode *rz_graph_add_node_info(RzGraph *graph, const char *title, const char *body, ut64 offset) {
	rz_return_val_if_fail(graph, NULL);
	RzGraphNodeInfo *data = rz_graph_create_node_info(title, body, offset);
	if (!data) {
		return NULL;
	}
	RzGraphNode *node = rz_graph_add_nodef(graph, data, rz_graph_free_node_info);
	if (!node) {
		rz_graph_free_node_info(data);
	}
	return node;
}

RZ_API char *rz_graph_drawable_to_dot(RzGraph /*RzGraphNodeInfo*/ *graph, const char *node_properties, const char *edge_properties) {
	RzList *nodes = graph->nodes;
	RzListIter *it, *itt;
	RzGraphNode *node = NULL, *target = NULL;
	RzStrBuf buf;
	rz_strbuf_init(&buf);
	rz_strbuf_appendf(&buf,
		"digraph code {\nrankdir=LR;\noutputorder=edgesfirst\ngraph [bgcolor=azure];\n"
		"edge [arrowhead=normal, color=\"#3030c0\" style=bold weight=2 %s];\n"
		"node [fillcolor=white, style=filled shape=box "
		"fontsize=\"8\" %s];\n",
		edge_properties ? edge_properties : "",
		node_properties ? node_properties : "");

	rz_list_foreach (nodes, it, node) {
		RzGraphNodeInfo *print_node = (RzGraphNodeInfo *)node->data;
		const char *body = print_node->body;
		if (!body || !*body) {
			rz_strbuf_appendf(&buf, "%d [URL=\"%s\", color=\"lightgray\", label=\"%s\"]\n",
				node->idx, print_node->title, print_node->title);
		} else {
			rz_strbuf_appendf(&buf, "%d [URL=\"%s\", color=\"lightgray\", label=\"%s\\n%s\"]\n",
				node->idx, print_node->title, print_node->title, body);
		}
		rz_list_foreach (node->out_nodes, itt, target) {
			rz_strbuf_appendf(&buf, "%d -> %d\n", node->idx, target->idx);
		}
	}
	rz_strbuf_append(&buf, "}\n");
	return rz_strbuf_drain_nofree(&buf);
}

RZ_API void rz_graph_drawable_to_json(RzGraph /*RzGraphNodeInfo*/ *graph, PJ *pj, bool use_offset) {
	RzList *nodes = graph->nodes, *neighbours = NULL;
	RzListIter *it, *itt;
	RzGraphNode *node = NULL, *neighbour = NULL;
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_k(pj, "nodes");
	pj_a(pj);

	rz_list_foreach (nodes, it, node) {
		RzGraphNodeInfo *print_node = (RzGraphNodeInfo *)node->data;
		pj_o(pj);
		pj_ki(pj, "id", node->idx);
		if (print_node->title) {
			pj_ks(pj, "title", print_node->title);
		}
		if (print_node->body) {
			pj_ks(pj, "body", print_node->body);
		}
		if (use_offset) {
			pj_kn(pj, "offset", print_node->offset);
		}
		pj_k(pj, "out_nodes");
		pj_a(pj);
		neighbours = node->out_nodes;
		rz_list_foreach (neighbours, itt, neighbour) {
			pj_i(pj, neighbour->idx);
		}
		pj_end(pj);
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);
}
