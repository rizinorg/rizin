// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"
#include "rz_types_base.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_iterator.h"
#include "rz_vector.h"
#include <rz_inquiry/rz_bcfg.h>

static ut64 hash_node(const void *data) {
	const RzInquiryBlock *bb = data;
	return bb->addr;
}

static RZ_OWN char *node_formatter(const RzGraphNode *n) {
	const RzInquiryBlock *bb = rz_graph_node_get_data(n);
	return rz_str_newf("[label=\"0x%" PFMT64x ":%" PFMT64u "\"]",
		bb->addr, bb->size);
}

static RZ_OWN char *edge_formatter(const RzGraphEdge *e) {
	RzInquiryBCFGEdgeType type = (utptr)rz_graph_edge_get_data(e);
	switch (type) {
	case RZ_INQUIRY_BCFG_EDGE_TYPE_NONE:
		return rz_str_dup("[label=Unknown]");
	case RZ_INQUIRY_BCFG_EDGE_TYPE_JMP:
	case RZ_INQUIRY_BCFG_EDGE_TYPE_CF:
		return NULL;
	case RZ_INQUIRY_BCFG_EDGE_TYPE_CALL_RET:
		return rz_str_dup("[style=dotted label=npc]");
	case RZ_INQUIRY_BCFG_EDGE_TYPE_CALL:
		return rz_str_dup("[style=dotted label=call]");
	case RZ_INQUIRY_BCFG_EDGE_TYPE_RETURN:
		return rz_str_dup("[style=dotted label=ret]");
	}
	rz_warn_if_reached();
	return NULL;
}

RZ_IPI RZ_OWN char *rz_inquiry_bcfg_as_dot(const RzInquiryBCFG *bcfg, RZ_NULLABLE const char *name) {
	rz_return_val_if_fail(bcfg, NULL);
	return rz_graph_as_dot_str(bcfg->graph, name, node_formatter, edge_formatter);
}

RZ_IPI RZ_OWN RzInquiryBCFG *rz_inquiry_bcfg_new(RzGraphImplType impl_type) {
	RzInquiryBCFG *bcfg = RZ_NEW0(RzInquiryBCFG);
	if (!bcfg) {
		return NULL;
	}
	bcfg->graph = rz_graph_new(impl_type, hash_node, free, NULL);
	if (!bcfg->graph) {
		rz_inquiry_bcfg_free(bcfg);
		return NULL;
	}
	return bcfg;
}

RZ_IPI void rz_inquiry_bcfg_free(RZ_NULLABLE RZ_OWN RzInquiryBCFG *bcfg) {
	if (!bcfg) {
		return;
	}
	rz_graph_free(bcfg->graph);
	free(bcfg);
}

static bool edge_from(const RzGraphEdge *e, void *addr) {
	ut64 from_addr = (utptr)addr;
	return rz_graph_node_get_id(rz_graph_edge_get_from(e)) == from_addr;
}

RZ_IPI bool rz_inquiry_bcfg_del_out_edges(RzInquiryBCFG *cfg, ut64 bb_addr) {
	rz_return_val_if_fail(cfg, false);
	return rz_graph_del_edges(cfg->graph, edge_from, RZ_GRAPH_INT_AS_DATA(bb_addr)) != RZ_GRAPH_STATUS_ERR;
}

/**
 * \brief Adds an edge to the block CFG.
 *
 * \param cfg The block CFG to edit.
 * \param from_bb The address of the block with the branch.
 *                Not the address of the branch instruction!
 * \param to_bb The address of the block the branch leads to.
 * \param type The type of the edge.
 *
 * \return True if edge was added. False for error or if a node doesn't exist.
 */
RZ_IPI bool rz_inquiry_bcfg_add_edge(RzInquiryBCFG *cfg, ut64 from_bb, ut64 to_bb, RzInquiryBCFGEdgeType type) {
	RzGraphStatus s = rz_graph_add_edge_by_id(cfg->graph, from_bb, to_bb, RZ_GRAPH_INT_AS_DATA(type));
	if (s == RZ_GRAPH_STATUS_OK || s == RZ_GRAPH_STATUS_EXISTED) {
		return true;
	}
	return false;
}

RZ_IPI bool rz_inquiry_bcfg_del_edge(RzInquiryBCFG *cfg, ut64 from_bb, ut64 to_bb) {
	return rz_graph_del_edge_by_id(cfg->graph, from_bb, to_bb) != RZ_GRAPH_STATUS_ERR;
}

static bool is_cf_edge(const RzGraphEdge *e, void *unused) {
	RzInquiryBCFGEdgeType type = (utptr)rz_graph_edge_get_data(e);
	return type == RZ_INQUIRY_BCFG_EDGE_TYPE_CF || type == RZ_INQUIRY_BCFG_EDGE_TYPE_NONE;
}

/**
 * \brief Updates or adds an edge to the block CFG.
 * Only edges of type RZ_INQUIRY_BCFG_EDGE_TYPE_CF are updated to \p type.
 * Otherwise the edge is not updated.
 *
 * \param cfg The block CFG to edit.
 * \param from_bb The address of the block with the branch.
 *                Not the address of the branch instruction!
 * \param to_bb The address of the block the branch leads to.
 * \param type The type of the edge.
 *
 * \return True if edge was added. False in case of error.
 */
RZ_IPI bool rz_inquiry_bcfg_update_edge(RzInquiryBCFG *cfg, ut64 from_bb, ut64 to_bb, RzInquiryBCFGEdgeType type) {
	return rz_graph_update_edge_by_id(cfg->graph, from_bb, to_bb, RZ_GRAPH_INT_AS_DATA(type), is_cf_edge, NULL) != RZ_GRAPH_STATUS_ERR;
}

RZ_IPI bool rz_inquiry_bcfg_get_block(const RzInquiryBCFG *cfg, ut64 bb_addr, RZ_OUT RZ_NULLABLE RzInquiryBlock *bb) {
	rz_return_val_if_fail(cfg, false);
	const RzGraphNode *n = rz_graph_find_node(cfg->graph, bb_addr);
	if (!n) {
		RZ_LOG_WARN("Could not find BB at 0x%" PFMT64x "\n", bb_addr);
		return false;
	}
	if (bb) {
		const RzInquiryBlock *n_data = rz_graph_node_get_data(n);
		bb->addr = n_data->addr;
		bb->size = n_data->size;
	}
	return true;
}

/**
 * \brief Neighbors of outgoing edges.
 */
RZ_API RZ_OWN RzIterator /*<RzGraphEdge *>*/ *rz_inquiry_bcfg_get_outgoing_edges(const RzInquiryBCFG *cfg, ut64 bb_addr) {
	rz_return_val_if_fail(cfg, NULL);
	return rz_graph_out_edges_by_id(cfg->graph, bb_addr);
}

/**
 * \brief Neighbors of incoming edges.
 */
RZ_API RZ_OWN RzIterator /*<RzGraphNode *>*/ *rz_inquiry_bcfg_get_incoming_edges(const RzInquiryBCFG *cfg, ut64 bb_addr) {
	rz_return_val_if_fail(cfg, NULL);
	return rz_graph_in_edges_by_id(cfg->graph, bb_addr);
}

/**
 * \brief Does not update the BB if it is already present.
 * Returns false if it already exists.
 */
RZ_IPI bool rz_inquiry_bcfg_add_block(RzInquiryBCFG *cfg, ut64 addr, ut64 size) {
	RzInquiryBlock *bb = RZ_NEW(RzInquiryBlock);
	if (!bb) {
		return false;
	}
	bb->addr = addr;
	bb->size = size;
	rz_graph_add_node(cfg->graph, bb, NULL);
	// const RzInquiryBB *nbb = rz_graph_node_get_data(n);
	// if (nbb->size != size) {
	// 	rz_warn_if_reached();
	// }
	return true;
}

RZ_IPI bool rz_inquiry_bcfg_add_edge_xref(RzInquiryBCFG *cfg, const RzVector /*<RzAnalysisXRef>*/ *xrefs) {
	RzAnalysisXRef *xref;
	rz_vector_foreach (xrefs, xref) {
		switch (xref->type) {
		case RZ_ANALYSIS_XREF_TYPE_CODE:
			if (!rz_inquiry_bcfg_update_edge(cfg, xref->bb_addr, xref->to, RZ_INQUIRY_BCFG_EDGE_TYPE_JMP)) {
				RZ_LOG_DEBUG("Did not add JMP edge: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", xref->bb_addr, xref->to);
			}
			break;
		case RZ_ANALYSIS_XREF_TYPE_CALL:
			if (!rz_inquiry_bcfg_update_edge(cfg, xref->bb_addr, xref->to, RZ_INQUIRY_BCFG_EDGE_TYPE_CALL)) {
				RZ_LOG_DEBUG("Did not add CALL edge: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", xref->bb_addr, xref->to);
			}
			RzInquiryBlock bb = { 0 };
			if (!rz_inquiry_bcfg_get_block(cfg, xref->bb_addr, &bb)) {
				rz_warn_if_reached();
				break;
			}
			ut64 ret_addr = bb.addr + bb.size;
			if (!rz_inquiry_bcfg_update_edge(cfg, xref->bb_addr, ret_addr, RZ_INQUIRY_BCFG_EDGE_TYPE_CALL_RET)) {
				RZ_LOG_DEBUG("Did not add CALL_RET edge: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", xref->bb_addr, ret_addr);
			}
			break;
		case RZ_ANALYSIS_XREF_TYPE_RETURN:
			if (!rz_inquiry_bcfg_update_edge(cfg, xref->bb_addr, xref->to, RZ_INQUIRY_BCFG_EDGE_TYPE_RETURN)) {
				RZ_LOG_DEBUG("Did not add RETURN edge: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", xref->bb_addr, xref->to);
			}
			break;
		case RZ_ANALYSIS_XREF_TYPE_NULL:
		case RZ_ANALYSIS_XREF_TYPE_DATA:
		case RZ_ANALYSIS_XREF_TYPE_STRING:
		case RZ_ANALYSIS_XREF_TYPE_MEM_WRITE:
		case RZ_ANALYSIS_XREF_TYPE_CALL_RET:
			continue;
		}
	}
	return true;
}

static int cmp(const RzInquiryBlock *a, const RzInquiryBlock *b, void *user) {
	if (a->addr < b->addr) {
		return -1;
	} else if (a->addr > b->addr) {
		return 1;
	}
	return 0;
}

/**
 * \brief Reduces all blocks in the cfg to their minimum size.
 * Removing duplicates and split overlapping blocks to basic blocks.
 *
 * This function makes each block just have a single entry point.
 * So each becomes a basic block (one Entry/one Exit).
 *
 * Example:
 *
 * +-     0x1000
 * |
 * |
 * | +-   0x1058
 * | |
 * | | +- 0x105c
 * | | |
 * | | |
 * | | |
 * +-+-+- 0x1080
 *   |
 *   | JUMP
 *   v
 * +--    0x1084
 * |
 * |
 * | +-   0x108c
 * | |
 * | |
 * +-+-   0x10a0
 *
 * Gets converted to:
 *
 * +--   0x1000
 * |
 * +--
 *  | CTRL FLOW
 *  v
 * +--   0x1058
 * |
 * +--
 *  | CTRL FLOW
 *  v
 * +--   0x105c
 * |
 * |
 * |
 * +--   0x1080
 *   |
 *   | JUMP
 *   v
 * +--   0x1084
 * |
 * +--
 *  | CTRL FLOW
 *  v
 * +--   0x108c
 * |
 * |
 * +--   0x10a0
 */
RZ_IPI bool rz_inquiry_bcfg_reduce(RzInquiryBCFG *cfg) {
	RzPVector blocks = { 0 };
	rz_pvector_init(&blocks, NULL);
	rz_pvector_reserve(&blocks, rz_graph_get_n_nodes(cfg->graph));

	RzGraphNode *n;
	RzIterator *iter = rz_graph_get_nodes(cfg->graph);
	rz_iterator_foreach(iter, n) {
		RzInquiryBlock *b = rz_graph_node_get_data_mut(n);
		rz_pvector_push(&blocks, b); // Cast because API is not constified.
	}
	rz_iterator_free(iter);

	// Sorting by starting address.
	// Note that this means overlapping blocks (with the same end address)
	// will lie sequentially in this vector.
	rz_pvector_sort(&blocks, (RzPVectorComparator)cmp, NULL);

	RzVector outedges = { 0 };
	rz_vector_init(&outedges, sizeof(ut64), NULL, NULL);
	// It is unlikely any node will have more than 8 outgoing edges.
	rz_vector_reserve(&outedges, 8);

	size_t n_blocks = rz_pvector_len(&blocks);
	for (size_t i = 0; i < n_blocks - 1; ++i) {
		RzInquiryBlock *a = rz_pvector_at(&blocks, i);

		// Split of all blocks a overlaps with.
		for (; i < n_blocks - 1; ++i) {
			RzInquiryBlock *b = rz_pvector_at(&blocks, i + 1);
			if ((a->addr + a->size) != (b->addr + b->size)) {
				// End addresses don't match => b lies not within a.
				break;
			}
			// b and a have the same end address => b lies within a.
			// Shrink a.
			a->size = b->addr - a->addr;
			RzIterator *out_iter = rz_graph_out_edges_by_id(cfg->graph, a->addr);
			if (!out_iter) {
				// No edges to update.
				// Check for blocks b overlaps with.
				a = b;
				continue;
			}

			// Replace a's outgoing edges with a single edge to b,
			RzGraphEdge *e;
			rz_iterator_foreach(out_iter, e) {
				const RzGraphNode *to_node = rz_graph_edge_get_to(e);
				ut64 to = rz_graph_node_get_id(to_node);
				rz_vector_push(&outedges, &to);
			}
			rz_iterator_free(out_iter);

			ut64 *to;
			rz_vector_foreach (&outedges, to) {
				rz_graph_del_edge_by_id(cfg->graph, a->addr, *to);
			}
			rz_vector_purge(&outedges);
			rz_graph_add_edge_by_id(cfg->graph, a->addr, b->addr, RZ_GRAPH_INT_AS_DATA(RZ_INQUIRY_BCFG_EDGE_TYPE_CF));
			// Check for blocks b overlaps with.
			a = b;
		}
	}
	rz_vector_fini(&outedges);
	rz_pvector_fini(&blocks);

	return true;
}
