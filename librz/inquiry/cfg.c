// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_assert.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_log.h"
#include <rz_inquiry/rz_cfg.h>

struct rz_icfg_t {
	RzVector /* ICFGEdge */ prepared_edges;
	RzVector /* ut64 */ proc_entries; ///< Sorted vector of all procedure entry points in the icfg.
	RzGraph /*<RzCFGNode *, RzCFGEdgeType>*/ *graph;
};

typedef struct {
	ut64 from;
	ut64 to;
	RzCFGEdgeType type;
} ICFGEdge;

struct rz_icfg_node_t {
	ut64 addr; ///< Address of the corresponding block.
	size_t size; ///< Size the corresponding block covers in memorfromy (in bytes).
	/**
	 * \brief The offsets of the instructions (packets), from the block start address.
	 * Starting at the second instruction in the block (since first is always 0), offsets from the start of the block
	 */
	RzVector /*<ut16>*/ insn_offsets;
	/**
	 * \brief The procedures entry points this block can be reached from without walking a call edge.
	 */
	RzSetU *proc_memberships;
	/**
	 * \brief Block attributes. Kept in sync with the CFG.
	 * Used for accessing most important information, without the need to access the CFG edges.
	 */
	RzCFGNodeAttr attrs;
};

struct rz_cfg_t {
	ut64 entry;
	RzIterator *cfg_nodes; ///< An iterator over the sub-graph in the iCFG belonging to the function.
};

static void rz_icfg_node_free(RZ_NULLABLE RZ_OWN RzICFGNode *node) {
	rz_return_if_fail(node);
	if (!node) {
		return;
	}
	rz_vector_fini(&node->insn_offsets);
	free(node);
}

ut64 node_hash(RZ_NULLABLE const void *data) {
	if (!data) {
		rz_warn_if_reached();
		return 0;
	}
	const RzICFGNode *node = data;
	return node->addr;
}

RZ_API RZ_OWN RzICFG *rz_icfg_new() {
	RzICFG *m = RZ_NEW0(RzICFG);
	if (!m) {
		return NULL;
	}
	RzGraph *icfg = rz_graph_new(RZ_GRAPH_IMPL_LIST, (RzGraphIdentifierHash)node_hash, (RzGraphNodeDataFree)rz_icfg_node_free, NULL);
	if (!icfg) {
		free(m);
		return NULL;
	}
	m->graph = icfg;
	rz_vector_init(&m->prepared_edges, sizeof(ICFGEdge), NULL, NULL);
	rz_vector_init(&m->proc_entries, sizeof(ut64), NULL, NULL);
	return m;
}

RZ_API void rz_icfg_free(RZ_NULLABLE RZ_OWN RzICFG *map) {
	if (!map) {
		return;
	}
	rz_graph_free(map->graph);
	free(map);
}

static RZ_OWN RzICFGNode *icfg_node_new(ut64 addr, size_t size, RZ_NONNULL const RzVector *insn_offsets) {
	rz_return_val_if_fail(insn_offsets, NULL);
	RzICFGNode *node = RZ_NEW0(RzICFGNode);
	if (!node) {
		return NULL;
	}
	node->proc_memberships = rz_set_u_new();
	if (!node->proc_memberships) {
		free(node);
		return NULL;
	}
	node->addr = addr;
	node->size = size;
	rz_vector_clone_into(&node->insn_offsets, insn_offsets);
	return node;
}

static int uint_cmp(ut64 *a, ut64 *b, void *user) {
	if (*a > *b) {
		return 1;
	} else if (*a < *b) {
		return -1;
	}
	return 0;
}

RZ_API bool rz_icfg_add_node(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 addr, size_t size, RZ_NONNULL const RzVector *insn_offsets, ut64 proc_membership) {
	rz_return_val_if_fail(icfg && insn_offsets, false);

	RzICFGNode *node = NULL;
	RzGraphNode *gn = rz_graph_find_node(icfg->graph, addr);
	if (!gn) {
		node = icfg_node_new(addr, size, insn_offsets);
		if (!node) {
			rz_warn_if_reached();
			return false;
		}
		rz_set_u_add(node->proc_memberships, proc_membership);
		if (rz_graph_add_node(icfg->graph, node, NULL) != RZ_GRAPH_STATUS_OK) {
			rz_warn_if_reached();
			return false;
		}
		goto success;
	}
	node = rz_graph_node_get_data_mut(gn);

	// TODO: Remove these comparison checks after testing.
	if (node->addr != addr || node->size != size || rz_vector_len(&node->insn_offsets) != rz_vector_len(insn_offsets)) {
		RZ_LOG_ERROR("The node at 0x%" PFMT64x " doesn't match the existing one.\n", addr);
		return false;
	}
	for (size_t i = 0; i < rz_vector_len(&node->insn_offsets); ++i) {
		if (*((ut16 *)rz_vector_index_ptr(&node->insn_offsets, i)) != *((ut16 *)rz_vector_index_ptr(insn_offsets, i))) {
			RZ_LOG_ERROR("The node at 0x%" PFMT64x " has mismatching instruction offsets.\n", addr);
			return false;
		}
	}
	// END

	rz_set_u_add(node->proc_memberships, proc_membership);

success:
	if (rz_vector_find_sorted(&icfg->proc_entries, &addr, (RzVectorComparator)uint_cmp, NULL) == SZT_MAX) {
		rz_vector_insert_sorted(&icfg->proc_entries, &addr, (RzVectorComparator)uint_cmp, NULL);
	}
	return true;
}

/**
 * \brief Prepares an edge to be added to the ICFG.
 * The nodes for \p from and \p to don't have to exist.
 *
 * NOTE: After all edges were added, rz_icfg_apply() *must* be run to copy the edges to the graph.
 */
RZ_API bool rz_icfg_prepare_edge(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 from, ut64 to, RzCFGEdgeType type) {
	rz_return_val_if_fail(icfg, false);
	ICFGEdge edge = { .from = from, .to = to, .type = type };
	rz_vector_push(&icfg->prepared_edges, &edge);
	return true;
}

/**
 * \brief Applies all prepared edges to the iCFG.
 * This function will return the number of edges which miss a node.
 * Or SIZE_MAX in case of error.
 *
 * \param icfg The iCFG to update.
 */
RZ_API size_t rz_icfg_apply(RZ_NONNULL RZ_BORROW RzICFG *icfg) {
	rz_return_val_if_fail(icfg, SZT_MAX);

	size_t existed = 0; // TODO: Remove after debug
	size_t missing_node = 0;
	ICFGEdge *edge;
	rz_vector_foreach (&icfg->prepared_edges, edge) {
		RzGraphStatus status = rz_graph_add_edge_by_id(icfg->graph, edge->from, edge->to, RZ_GRAPH_INT_AS_DATA(edge->type));
		switch (status) {
		case RZ_GRAPH_STATUS_OK:
			break;
		case RZ_GRAPH_STATUS_EXISTED:
			existed++;
			break;
		case RZ_GRAPH_STATUS_MISSING_NODE:
			missing_node++;
			break;
		case RZ_GRAPH_STATUS_ERR:
		default:
			RZ_LOG_ERROR("icfg: Failed to add apply edge (0x%" PFMT64x ", 0x%" PFMT64x ", %" PFMT32d ") to iCFG.\n",
				edge->from,
				edge->to,
				edge->type);
			break;
		}
	}
	(void)existed;
	return missing_node;
}

RZ_API bool rz_icfg_get_cfg(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 entry_point, RZ_OUT RzCFG *cfg_out) {
	rz_return_val_if_fail(icfg, false);
	// TODO
	rz_warn_if_reached();
	return false;
}

RZ_API void rz_cfg_fini(RZ_NULLABLE RZ_BORROW RzCFG *cfg) {
	if (!cfg) {
		return;
	}
	rz_iterator_fini(cfg->cfg_nodes);
}
