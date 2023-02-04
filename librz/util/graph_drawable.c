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

RZ_API RzGraphNode *rz_graph_add_node_info(RzGraph /*<RzGraphNodeInfo *>*/ *graph, const char *title, const char *body, ut64 offset) {
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

RZ_API RZ_OWN char *rz_graph_drawable_to_dot(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph,
	RZ_NULLABLE const char *node_properties, RZ_NULLABLE const char *edge_properties) {
	rz_return_val_if_fail(graph, NULL);
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
		char *body = print_node->body;

		if (!body || !*body) {
			rz_strbuf_appendf(&buf, "%d [URL=\"%s\", color=\"lightgray\", label=\"%s\"]\n",
				node->idx, print_node->title, print_node->title);
		} else {
			rz_str_replace_ch(body, '\"', '\'', true);
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

/**
 * \brief Convert \p graph to json to \p pj.
 * \param use_offset use offset in json ?
 */
RZ_API void rz_graph_drawable_to_json(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph, RZ_NONNULL PJ *pj, bool use_offset) {
	rz_return_if_fail(graph && pj);
	RzList *nodes = graph->nodes, *neighbours = NULL;
	RzListIter *it, *itt;
	RzGraphNode *node = NULL, *neighbour = NULL;
	pj_o(pj);
	pj_k(pj, "nodes");
	pj_a(pj);

	rz_list_foreach (nodes, it, node) {
		RzGraphNodeInfo *print_node = (RzGraphNodeInfo *)node->data;
		pj_o(pj);
		pj_kn(pj, "id", node->idx);
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
			pj_n(pj, neighbour->idx);
		}
		pj_end(pj);
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);
}

/**
 * \brief Convert \p graph to json string.
 * \param use_offset use offset in json ?
 */
RZ_API RZ_OWN char *rz_graph_drawable_to_json_str(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph, bool use_offset) {
	rz_return_val_if_fail(graph, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	PJ *pj = pj_new();
	if (!pj) {
		rz_strbuf_free(sb);
		return NULL;
	}

	rz_graph_drawable_to_json(graph, pj, use_offset);
	char *pj_str = pj_drain(pj);
	rz_strbuf_append(sb, pj_str);
	rz_strbuf_append(sb, "\n");
	free(pj_str);
	return rz_strbuf_drain(sb);
}

/**
 * \brief Convert \p graph to rizin cmd string.
 */
RZ_API RZ_OWN char *rz_graph_drawable_to_cmd(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	rz_return_val_if_fail(graph, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}

	RzGraphNode *node, *target;
	RzListIter *it, *edge_it;
	rz_list_foreach (graph->nodes, it, node) {
		RzGraphNodeInfo *print_node = node->data;
		if (RZ_STR_ISNOTEMPTY(print_node->body)) {
			ut32 len = strlen(print_node->body);
			if (len > 0 && print_node->body[len - 1] == '\n') {
				len--;
			}
			char *body = rz_base64_encode_dyn((const ut8 *)print_node->body, len);
			rz_strbuf_appendf(sb, "agn \"%s\" base64:%s\n", print_node->title, body);
			free(body);
		} else {
			rz_strbuf_appendf(sb, "agn \"%s\"\n", print_node->title);
		}
	}
	rz_list_foreach (graph->nodes, it, node) {
		RzGraphNodeInfo *print_node = node->data;
		rz_list_foreach (node->out_nodes, edge_it, target) {
			RzGraphNodeInfo *to = target->data;
			rz_strbuf_appendf(sb, "age \"%s\" \"%s\"\n", print_node->title, to->title);
		}
	}
	return rz_strbuf_drain(sb);
}

/**
 * \brief Convert \p graph to GML (Graph Modelling Language) string.
 */
RZ_API RZ_OWN char *rz_graph_drawable_to_gml(RZ_NONNULL RzGraph /*<RzGraphNodeInfo *>*/ *graph) {
	rz_return_val_if_fail(graph, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}

	rz_strbuf_appendf(sb, "graph\n[\n"
			      "hierarchic 1\n"
			      "label \"\"\n"
			      "directed 1\n");
	RzListIter *it;
	RzGraphNode *graphNode, *target;
	rz_list_foreach (graph->nodes, it, graphNode) {
		RzGraphNodeInfo *print_node = graphNode->data;
		rz_strbuf_appendf(sb, "  node [\n"
				      "    id  %d\n"
				      "    label  \"%s\"\n"
				      "  ]\n",
			graphNode->idx, print_node->title);
	}
	RzListIter *edge_it;
	rz_list_foreach (graph->nodes, it, graphNode) {
		rz_list_foreach (graphNode->out_nodes, edge_it, target) {
			rz_strbuf_appendf(sb, "  edge [\n"
					      "    source  %d\n"
					      "    target  %d\n"
					      "  ]\n",
				graphNode->idx, target->idx);
		}
	}
	rz_strbuf_appendf(sb, "]\n");
	return rz_strbuf_drain(sb);
}
