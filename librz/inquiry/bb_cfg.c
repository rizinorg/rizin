// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"
#include "rz_types_base.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_iterator.h"
#include <rz_inquiry/rz_bb_graph.h>

static ut64 hash_node(const void *data) {
	const RzInquiryBB *bb = data;
	return bb->addr;
}

RZ_IPI RZ_OWN RzInquiryBBCFG *rz_inquiry_bb_cfg_new(RzGraphImplType impl_type) {
	RzInquiryBBCFG *bb_cfg = RZ_NEW0(RzInquiryBBCFG);
	if (!bb_cfg) {
		return NULL;
	}
	bb_cfg->graph = rz_graph_new(impl_type, hash_node, free, NULL);
	if (!bb_cfg->graph) {
		rz_inquiry_bb_cfg_free(bb_cfg);
		return NULL;
	}
	return bb_cfg;
}

RZ_IPI void rz_inquiry_bb_cfg_free(RZ_NULLABLE RZ_OWN RzInquiryBBCFG *bb_cfg) {
	if (!bb_cfg) {
		return;
	}
	rz_graph_free(bb_cfg->graph);
	free(bb_cfg);
}

static bool edge_from(const RzGraphEdge *e, void *addr) {
	ut64 from_addr = (utptr)addr;
	return rz_graph_node_get_id(rz_graph_edge_get_from(e)) == from_addr;
}

RZ_IPI bool rz_inquiry_bb_cfg_del_out_edges(RzInquiryBBCFG *cfg, ut64 bb_addr) {
	return rz_graph_del_edges(cfg->graph, edge_from, RZ_GRAPH_INT_AS_DATA(bb_addr));
}

/**
 * \brief Adds an edge to the basic block CFG.
 *
 * \param cfg The basic block CFG to edit.
 * \param from_bb The address of the basic block with the branch.
 *                Not the address of the branch instruction!
 * \param to_bb The address of the basic block the branch leads to.
 *
 * \return True if edge was added. False for error or if a node doesn't exist.
 */
RZ_IPI bool rz_inquiry_bb_cfg_add_edge(RzInquiryBBCFG *cfg, ut64 from_bb, ut64 to_bb, RzInquiryBBCFGEdgeType type) {
	return rz_graph_add_edge_by_id(cfg->graph, from_bb, to_bb, RZ_GRAPH_INT_AS_DATA(type));
}

RZ_IPI bool rz_inquiry_bb_cfg_get_basic_block(const RzInquiryBBCFG *cfg, ut64 bb_addr, RZ_OUT RzInquiryBB *bb) {
	rz_return_val_if_fail(cfg && bb, false);
	const RzGraphNode *n = rz_graph_find_node(cfg->graph, bb_addr);
	if (!n) {
		RZ_LOG_WARN("Could not find BB at 0x%" PFMT64x "\n", bb_addr);
		return false;
	}
	const RzInquiryBB *n_data = rz_graph_node_get_data(n);
	bb->addr = n_data->addr;
	bb->size = n_data->size;
	return true;
}

/**
 * \brief Neighbors of outgoing edges.
 */
RZ_API RZ_OWN RzIterator /*<RzGraphEdge *>*/ *rz_inquiry_bb_cfg_get_outgoing_edges(const RzInquiryBBCFG *cfg, ut64 bb_addr) {
	rz_return_val_if_fail(cfg, NULL);
	return rz_graph_out_edges_by_id(cfg->graph, bb_addr);
}

/**
 * \brief Neighbors of incoming edges.
 */
RZ_API RZ_OWN RzIterator /*<RzGraphNode *>*/ *rz_inquiry_bb_cfg_get_incoming_edges(const RzInquiryBBCFG *cfg, ut64 bb_addr) {
	rz_return_val_if_fail(cfg, NULL);
	return rz_graph_in_edges_by_id(cfg->graph, bb_addr);
}

/**
 * \brief Does not update the BB if it is already present.
 * Returns false if it already exists.
 */
RZ_IPI bool rz_inquiry_bb_cfg_add_basic_block(RzInquiryBBCFG *cfg, ut64 addr, ut64 size) {
	RzInquiryBB *bb = RZ_NEW(RzInquiryBB);
	if (!bb) {
		return false;
	}
	bb->addr = addr;
	bb->size = size;
	bool existed;
	RzGraphNode *n = rz_graph_add_get_node(cfg->graph, bb, &existed);
	if (!n) {
		return false;
	}
	// const RzInquiryBB *nbb = rz_graph_node_get_data(n);
	// if (nbb->size != size) {
	// 	rz_warn_if_reached();
	// }
	if (existed) {
		free(bb);
	}
	return true;
}

RZ_IPI bool rz_inquiry_bb_cfg_add_xrefs(RzInquiryBBCFG *cfg, RzVector /*<RzAnalysisXRef>*/ *xrefs) {
	RzAnalysisXRef *xref;
	rz_vector_foreach (xrefs, xref) {
		switch (xref->type) {
		case RZ_ANALYSIS_XREF_TYPE_CODE:
			if (!rz_inquiry_bb_cfg_add_edge(cfg, xref->bb_addr, xref->to, RZ_INQUIRY_BB_CFG_EDGE_TYPE_JMP)) {
				RZ_LOG_DEBUG("Did not add JMP edge: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", xref->bb_addr, xref->to);
			}
			break;
		case RZ_ANALYSIS_XREF_TYPE_CALL:
			if (!rz_inquiry_bb_cfg_add_edge(cfg, xref->bb_addr, xref->to, RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL)) {
				RZ_LOG_DEBUG("Did not add CALL edge: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", xref->bb_addr, xref->to);
			}
			RzInquiryBB bb = { 0 };
			if (!rz_inquiry_bb_cfg_get_basic_block(cfg, xref->bb_addr, &bb)) {
				rz_warn_if_reached();
				break;
			}
			ut64 ret_addr = bb.addr + bb.size;
			if (!rz_inquiry_bb_cfg_add_edge(cfg, xref->bb_addr, ret_addr, RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL_RET)) {
				RZ_LOG_DEBUG("Did not add CALL_RET edge: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", xref->bb_addr, ret_addr);
			}
			break;
		case RZ_ANALYSIS_XREF_TYPE_RETURN:
			if (!rz_inquiry_bb_cfg_add_edge(cfg, xref->bb_addr, xref->to, RZ_INQUIRY_BB_CFG_EDGE_TYPE_RETURN)) {
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

static int cmp(const ut64 *a, const ut64 *b, void *user) {
	if (*a < *b) {
		return -1;
	} else if (*a > *b) {
		return 1;
	}
	return 0;
}

/**
 * \brief Reduces all basic blocks in the cfg to their minimum size.
 * Removing duplicates and overlapping basic blocks.
 * This function makes each basic block just have a single entry point.
 */
RZ_IPI bool rz_inquiry_bb_cfg_reduce(RzInquiryBBCFG *cfg) {
	// Index is end address of bb, values are starting address of bbs with that end address.
	HtUP *overlapping_bbs = ht_up_new(NULL, (HtUPFreeValue)rz_vector_free);

	RzGraphNode *n;
	RzIterator *iter = rz_graph_get_nodes(cfg->graph);
	rz_iterator_foreach(iter, n) {
		const RzInquiryBB *bb = rz_graph_node_get_data(n);
		ut64 end = bb->addr + bb->size;
		RzVector *start_addresses = ht_up_find(overlapping_bbs, end, NULL);
		if (!start_addresses) {
			start_addresses = rz_vector_new(sizeof(ut64), NULL, NULL);
			ht_up_insert(overlapping_bbs, end, start_addresses);
		}
		// Cast due to not constified vector API.
		rz_vector_push(start_addresses, (void *)&bb->addr);
	}
	rz_iterator_free(iter);

	void **it;
	iter = ht_up_as_iter(overlapping_bbs);
	rz_iterator_foreach(iter, it) {
		RzVector *addrs = *it;
		size_t i = rz_vector_len(addrs);
		if (i == 1) {
			continue;
		}
		// Sort start addresses.
		rz_vector_sort(addrs, (RzVectorComparator)cmp, false, NULL);
		for (i = i - 1; i > 0; i--) {
			ut64 small_bb_addr = *((ut64 *)rz_vector_index_ptr(addrs, i));
			ut64 big_bb_addr = *((ut64 *)rz_vector_index_ptr(addrs, i - 1));
			rz_goto_if_fail(small_bb_addr > big_bb_addr, fail);

			// Change size of big bb
			RzInquiryBB *big_bb = rz_graph_node_get_data_mut(rz_graph_find_node(cfg->graph, big_bb_addr));
			rz_goto_if_fail(big_bb, fail);
			big_bb->size = small_bb_addr - big_bb_addr;

			// add edge between big to small bb, move old edges to small_bb.
			RzGraphEdge *e;
			RzIterator *out_edges = rz_inquiry_bb_cfg_get_outgoing_edges(cfg, big_bb_addr);
			rz_iterator_foreach(out_edges, e) {
				ut64 to = rz_graph_node_get_id(rz_graph_edge_get_to(e));
				RzInquiryBBCFGEdgeType type = (utptr)rz_graph_edge_get_data(e);
				if (!rz_inquiry_bb_cfg_add_edge(cfg, small_bb_addr, to, type)) {
					RZ_LOG_DEBUG("Did not add edge: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", big_bb_addr, small_bb_addr);
					continue;
				}
			}
			rz_iterator_free(out_edges);

			rz_inquiry_bb_cfg_del_out_edges(cfg, big_bb_addr);
			if (!rz_inquiry_bb_cfg_add_edge(cfg, big_bb_addr, small_bb_addr, RZ_INQUIRY_BB_CFG_EDGE_TYPE_CF)) {
				RZ_LOG_DEBUG("Did not add edge: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", big_bb_addr, small_bb_addr);
				continue;
			}
		}
	}
	rz_iterator_free(iter);
	ht_up_free(overlapping_bbs);
	return true;

fail:
	rz_iterator_free(iter);
	ht_up_free(overlapping_bbs);
	rz_warn_if_reached();
	return false;
}
