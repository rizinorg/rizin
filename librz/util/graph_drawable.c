// SPDX-FileCopyrightText: 2020 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2020 karliss <karlis3p70l1ij@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_util/rz_graph_drawable.h>

/**
 * \brief Translates the \p subtype flags of a node to its annotation symbols.
 *
 * \param subtype The sub-type flags of the node.
 * \param utf8 If true, the symbols will be UTF-8 characters. If false, they are in ASCII.
 *
 * \return A string with all symbols.
 */
RZ_API RZ_OWN char *rz_graph_get_node_subtype_annotation(RzGraphNodeSubType subtype, bool utf8) {
	char *annotation = rz_str_newf(" ");
	if (!utf8) {
		annotation = rz_str_append(annotation, "(");
	}
	if (subtype == RZ_GRAPH_NODE_SUBTYPE_NONE) {
		annotation = rz_str_append(annotation, utf8 ? "○" : ".");
		if (!utf8) {
			annotation = rz_str_append(annotation, ")");
		}
		return annotation;
	}
	if (subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY) {
		annotation = rz_str_append(annotation, utf8 ? "↓" : "e");
	}
	if (subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_CALL) {
		annotation = rz_str_append(annotation, utf8 ? "⇢" : "C");
	}
	if (subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN) {
		annotation = rz_str_append(annotation, utf8 ? "↑" : "r");
	}
	if (subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_COND) {
		annotation = rz_str_append(annotation, utf8 ? "⤹" : "c");
	}
	if (subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT) {
		annotation = rz_str_append(annotation, utf8 ? "⭳" : "E");
	}
	if (!utf8) {
		annotation = rz_str_append(annotation, ")");
	}
	return annotation;
}

/**
 * \brief Casts the given graph node data pointer to a
 * RzGraphNodeInfo pointer and makes some plausibility tests on the data.
 *
 * \param data The data pointer from a graph node.
 *
 * \return A pointer to the graph node info struct or NULL in case of failure.
 */
RZ_API RZ_OWN RzGraphNodeInfo *rz_graph_get_node_info_data(RZ_BORROW void *data) {
	rz_return_val_if_fail(data, NULL);
	RzGraphNodeInfo *info = data;
	switch (info->type) {
	default:
		RZ_LOG_ERROR("Unhandled graph node info type %" PFMT32d "\n", info->type);
		return NULL;
	case RZ_GRAPH_NODE_TYPE_DEFAULT:
	case RZ_GRAPH_NODE_TYPE_CFG:
	case RZ_GRAPH_NODE_TYPE_ICFG:
		break;
	}
	return info;
}

RZ_API void rz_graph_free_node_info(RZ_NULLABLE void *ptr) {
	if (!ptr) {
		return;
	}
	RzGraphNodeInfo *info = ptr;
	switch (info->type) {
	default:
		RZ_LOG_WARN("Not handled RzGraphNodeInfoType\n");
		break;
	case RZ_GRAPH_NODE_TYPE_CFG:
	case RZ_GRAPH_NODE_TYPE_ICFG:
		break;
	case RZ_GRAPH_NODE_TYPE_DEFAULT:
		free(info->def.body);
		free(info->def.title);
		break;
	}
	free(info);
}

/**
 * \brief Initializes a node info struct of a CFG node.
 *
 * \param title The title describing the node.
 * \param body The body text describing the node.
 * \param offset A numeric offset of this node. 0 if invalid.
 *
 * \return The initialized RzGraphNodeInfo or NULL in case of failure.
 */
RZ_API RzGraphNodeInfo *rz_graph_create_node_info_default(const char *title, const char *body, ut64 offset) {
	RzGraphNodeInfo *data = RZ_NEW0(RzGraphNodeInfo);
	if (!data) {
		return NULL;
	}
	data->type = RZ_GRAPH_NODE_TYPE_DEFAULT;
	data->subtype = RZ_GRAPH_NODE_SUBTYPE_NONE;
	data->def.title = RZ_STR_DUP(title);
	data->def.body = RZ_STR_DUP(body);
	data->def.offset = offset;
	return data;
}

/**
 * \brief Initializes a node info struct of a CFG node.
 *
 * \param address The address of the instruction this node represents.
 * \param call_target_addr The address of the procedure called, if this node is a call.
 * \param flags Additional flags which describe the node.
 *
 * \return The initialized RzGraphNodeInfo or NULL in case of failure.
 */
RZ_API RzGraphNodeInfo *rz_graph_create_node_info_cfg(ut64 address, ut64 call_target_addr, RzGraphNodeType type, RzGraphNodeSubType subtype) {
	RzGraphNodeInfo *data = RZ_NEW0(RzGraphNodeInfo);
	if (!data) {
		return NULL;
	}
	data->type = RZ_GRAPH_NODE_TYPE_CFG;
	data->subtype = subtype;
	data->cfg.address = address;
	data->cfg.call_address = call_target_addr;
	return data;
}

/**
 * \brief Initializes a node info struct of an iCFG node.
 *
 * \param address The address of the procedure this node represents.
 * \param flags Additional flags which describe the node.
 *
 * \return The initialized RzGraphNodeInfo or NULL in case of failure.
 */
RZ_API RzGraphNodeInfo *rz_graph_create_node_info_icfg(ut64 address, RzGraphNodeType type, RzGraphNodeSubType subtype) {
	RzGraphNodeInfo *data = RZ_NEW0(RzGraphNodeInfo);
	if (!data) {
		return NULL;
	}
	data->type = RZ_GRAPH_NODE_TYPE_ICFG;
	data->subtype = subtype;
	data->icfg.address = address;
	data->icfg.is_malloc = subtype & RZ_GRAPH_NODE_SUBTYPE_ICFG_MALLOC;
	return data;
}

RZ_API RzGraphNode *rz_graph_add_node_info(RzGraph /*<RzGraphNodeInfo *>*/ *graph, const char *title, const char *body, ut64 offset) {
	rz_return_val_if_fail(graph, NULL);
	RzGraphNodeInfo *data = rz_graph_create_node_info_default(title, body, offset);
	if (!data) {
		return NULL;
	}
	RzGraphNode *node = rz_graph_add_nodef(graph, data, rz_graph_free_node_info);
	if (!node) {
		rz_graph_free_node_info(data);
	}
	return node;
}

/**
 * \brief Prints the given RzGraph as dot graph.
 *
 * \param graph The graph to print.
 * \param node_properties Edge property string, added to the dot graph header.
 * \param edge_properties Node property string, added to the dot graph header.
 */
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
		char *url;
		RzStrBuf *label = rz_strbuf_new("");

		switch (print_node->type) {
		default:
			RZ_LOG_ERROR("Unhandled node type. Graph node either doesn't support dot graph printing or it isn't implemented.\n");
			rz_strbuf_free(label);
			return NULL;
		case RZ_GRAPH_NODE_TYPE_CFG:
			rz_strbuf_appendf(label, "0x%" PFMT64x, print_node->cfg.address);
			if (print_node->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY) {
				rz_strbuf_append(label, " (entry)");
			}
			if (print_node->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_CALL) {
				rz_strbuf_append(label, " (call)");
			}
			if (print_node->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN) {
				rz_strbuf_append(label, " (ret)");
			}
			if (print_node->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_COND) {
				rz_strbuf_append(label, " (cond)");
			}
			if (print_node->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT) {
				rz_strbuf_append(label, " (exit)");
			}
			url = rz_strbuf_get(label);
			break;
		case RZ_GRAPH_NODE_TYPE_ICFG:
			rz_strbuf_appendf(label, "0x%" PFMT64x, print_node->icfg.address);
			if (print_node->subtype == RZ_GRAPH_NODE_SUBTYPE_ICFG_MALLOC) {
				rz_strbuf_append(label, " (alloc)");
			}
			url = rz_strbuf_get(label);
			break;
		case RZ_GRAPH_NODE_TYPE_DEFAULT:
			url = print_node->def.title;
			if (print_node->def.body && print_node->def.body[0]) {
				rz_str_replace_ch(print_node->def.body, '\"', '\'', true);
				rz_strbuf_appendf(label, "%s\\n%s", print_node->def.title, print_node->def.body);
			} else {
				rz_strbuf_append(label, print_node->def.title);
			}
		}

		rz_strbuf_appendf(&buf, "%d [URL=\"%s\", color=\"lightgray\", label=\"%s\"]\n",
			node->idx, url, rz_strbuf_get(label));
		rz_strbuf_free(label);
		// url sometimes is set to label above and shouldn't be used after label was freed.
		url = NULL;
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
		if (print_node->type == RZ_GRAPH_NODE_TYPE_DEFAULT) {
			if (print_node->def.title) {
				pj_ks(pj, "title", print_node->def.title);
			}
			if (print_node->def.body) {
				pj_ks(pj, "body", print_node->def.body);
			}
			if (use_offset) {
				pj_kn(pj, "offset", print_node->def.offset);
			}
		} else if (print_node->type == RZ_GRAPH_NODE_TYPE_ICFG) {
			pj_kn(pj, "address", print_node->icfg.address);
			pj_kb(pj, "is_malloc", print_node->type & RZ_GRAPH_NODE_SUBTYPE_ICFG_MALLOC);
		} else if (print_node->type == RZ_GRAPH_NODE_TYPE_CFG) {
			pj_kn(pj, "address", print_node->cfg.address);
			pj_kb(pj, "is_call", print_node->type & RZ_GRAPH_NODE_SUBTYPE_CFG_CALL);
			if (print_node->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_CALL && print_node->cfg.call_address != UT64_MAX) {
				pj_kn(pj, "call_address", print_node->cfg.call_address);
			}
			pj_kb(pj, "is_entry", print_node->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY);
			pj_kb(pj, "is_exit", print_node->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT);
			pj_kb(pj, "is_return", print_node->subtype & RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN);
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
		if (RZ_STR_ISNOTEMPTY(print_node->def.body)) {
			ut32 len = strlen(print_node->def.body);
			if (len > 0 && print_node->def.body[len - 1] == '\n') {
				len--;
			}
			char *body = rz_base64_encode_dyn((const ut8 *)print_node->def.body, len);
			rz_strbuf_appendf(sb, "agn \"%s\" base64:%s\n", print_node->def.title, body);
			free(body);
		} else {
			rz_strbuf_appendf(sb, "agn \"%s\"\n", print_node->def.title);
		}
	}
	rz_list_foreach (graph->nodes, it, node) {
		RzGraphNodeInfo *print_node = node->data;
		rz_list_foreach (node->out_nodes, edge_it, target) {
			RzGraphNodeInfo *to = target->data;
			rz_strbuf_appendf(sb, "age \"%s\" \"%s\"\n", print_node->def.title, to->def.title);
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
	char *label;
	char tmp[256] = { 0 };
	rz_list_foreach (graph->nodes, it, graphNode) {
		RzGraphNodeInfo *print_node = graphNode->data;

		switch (print_node->type) {
		default:
			RZ_LOG_ERROR("Unhandled node type. Graph node either doesn't support dot graph printing or it isn't implemented.\n");
			return NULL;
		case RZ_GRAPH_NODE_TYPE_CFG:
			label = rz_strf(tmp, "0x%" PFMT64x, print_node->cfg.address);
			break;
		case RZ_GRAPH_NODE_TYPE_ICFG:
			label = rz_strf(tmp, "0x%" PFMT64x, print_node->icfg.address);
			break;
		case RZ_GRAPH_NODE_TYPE_DEFAULT:
			label = print_node->def.title;
			break;
		}

		rz_strbuf_appendf(sb, "  node [\n"
				      "    id  %d\n"
				      "    label  \"%s\"\n"
				      "  ]\n",
			graphNode->idx, label);
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
