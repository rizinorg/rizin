// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_list.h"
#include "rz_util/ht_up.h"
#include "rz_util/ht_uu.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_itv.h"
#include "rz_util/rz_log.h"
#include <rz_inquiry.h>

RZ_IPI RZ_OWN RzInquiryBBCFG *rz_inquiry_bb_cfg_new() {
	RzInquiryBBCFG *bb_cfg = RZ_NEW0(RzInquiryBBCFG);
	if (!bb_cfg) {
		return NULL;
	}
	bb_cfg->basic_blocks = ht_up_new(NULL, free);
	bb_cfg->bb_gnode_map = ht_up_new(NULL, NULL);
	bb_cfg->bb_gidx_map = ht_uu_new();
	bb_cfg->graph = rz_graph_new();
	if (!bb_cfg->basic_blocks ||
		!bb_cfg->bb_gnode_map ||
		!bb_cfg->bb_gidx_map ||
		!bb_cfg->graph) {
		rz_inquiry_bb_cfg_free(bb_cfg);
		return NULL;
	}
	return bb_cfg;
}

RZ_IPI void rz_inquiry_bb_cfg_free(RZ_NULLABLE RZ_OWN RzInquiryBBCFG *bb_cfg) {
	if (!bb_cfg) {
		return;
	}
	ht_uu_free(bb_cfg->bb_gidx_map);
	ht_up_free(bb_cfg->basic_blocks);
	ht_up_free(bb_cfg->bb_gnode_map);
	rz_graph_free(bb_cfg->graph);
	free(bb_cfg);
}

RZ_IPI bool rz_inquiry_bb_cfg_add_block(RzInquiryBBCFG *cfg, ut64 addr, ut64 size) {
	RzInterval *bb = ht_up_find(cfg->basic_blocks, addr, NULL);
	if (bb && bb->size == size) {
		return true;
	} else if (bb && bb->size != size) {
		RZ_LOG_ERROR("inquiry: Attempt to overwrite basic block size. Ignoring new version: "
			     "previous: (0x%" PFMT64x ", %" PFMT64d ") - new: (0x%" PFMT64x ", %" PFMT64d ")\n",
			bb->addr, bb->size, addr, size);
		return false;
	}
	bb = rz_itv_new(addr, size);
	ht_up_insert(cfg->basic_blocks, addr, bb);

	return true;
}

static /*const*/ RZ_BORROW RzGraphNode *get_node(RzInquiryBBCFG *cfg, ut64 bb_addr) {
	return ht_up_find(cfg->bb_gnode_map, bb_addr, NULL);
}

/**
 * \brief Adds new node or returns existing one.
 */
static /*const*/ RZ_BORROW RzGraphNode *get_add_node_to_cfg(RzInquiryBBCFG *cfg, ut64 bb_addr) {
	RzGraphNode *n = get_node(cfg, bb_addr);
	if (n) {
		return n;
	}
	n = rz_graph_add_node(cfg->graph, (void *)bb_addr);
	if (!n) {
		return NULL;
	}
	ht_uu_insert(cfg->bb_gidx_map, bb_addr, n->idx);
	ht_up_insert(cfg->bb_gnode_map, bb_addr, n);
	return n;
}

RZ_IPI bool rz_inquiry_bb_cfg_del_out_edges(RzInquiryBBCFG *cfg, ut64 bb_addr) {
	RzGraphNode *f = get_node(cfg, bb_addr);
	rz_return_val_if_fail(f, false);
	const RzList /*<RzGraphNode *>*/ *neighs = rz_inquiry_bb_cfg_get_neighbours_from(cfg, bb_addr);
	RzGraphNode *t;
	RzListIter *it;
	RzList *ptr_clones = rz_list_clone(neighs);
	rz_list_foreach (ptr_clones, it, t) {
		rz_graph_del_edge(cfg->graph, f, t);
	}
	rz_list_free(ptr_clones);
	return true;
}

/**
 * \brief Adds an edge to the basic block CFG.
 *
 * \param cfg The basic block CFG to edit.
 * \param from_bb The address of the basic block with the branch.
 *                Not the address of the branch instruction!
 * \param to_bb The address of the basic block the branch leads to.
 *
 * \return False if an error occurred. True otherwise.
 */
RZ_IPI bool rz_inquiry_bb_cfg_add_edge(RzInquiryBBCFG *cfg, ut64 from_bb, ut64 to_bb) {
	RzGraphNode *f = get_add_node_to_cfg(cfg, from_bb);
	RzGraphNode *t = get_add_node_to_cfg(cfg, to_bb);
	if (!f || !t) {
		rz_warn_if_reached();
		return false;
	}
	const RzList /*<RzGraphNode *>*/ *neighs = rz_inquiry_bb_cfg_get_neighbours_from(cfg, from_bb);
	if (rz_list_contains(neighs, t)) {
		// Edge already added.
		return true;
	}
	rz_graph_add_edge(cfg->graph, f, t);
	return true;
}

RZ_IPI bool rz_inquiry_bb_cfg_get_basic_block(const RzInquiryBBCFG *cfg, ut64 bb_addr, RZ_OUT RzInterval *bb) {
	rz_return_val_if_fail(cfg && bb, false);
	const RzInterval *itv = ht_up_find(cfg->basic_blocks, bb_addr, NULL);
	if (!itv) {
		RZ_LOG_WARN("Could not find BB at 0x%" PFMT64x "\n", bb_addr);
		return false;
	}
	bb->addr = itv->addr;
	bb->size = itv->size;
	return true;
}

RZ_API const RzList /*<RzGraphNode *>*/ *rz_inquiry_bb_cfg_get_neighbours_from(const RzInquiryBBCFG *cfg, ut64 bb_addr) {
	rz_return_val_if_fail(cfg, NULL);

	const RzGraphNode *n = ht_up_find(cfg->bb_gnode_map, bb_addr, NULL);
	if (!n) {
		rz_warn_if_reached();
		return NULL;
	}
	return rz_graph_get_neighbours(cfg->graph, n);
}

RZ_API const RzList /*<RzGraphNode *>*/ *rz_inquiry_bb_cfg_get_neighbours_to(const RzInquiryBBCFG *cfg, ut64 bb_addr) {
	rz_return_val_if_fail(cfg, NULL);

	const RzGraphNode *n = ht_up_find(cfg->bb_gnode_map, bb_addr, NULL);
	if (!n) {
		rz_warn_if_reached();
		return NULL;
	}
	return rz_graph_innodes(cfg->graph, n);
}

/**
 * \brief Add edges from iq->xrefs and the \p insn_to_insn_edges to the cfg.
 */
RZ_IPI bool rz_inquiry_bb_cfg_complement(RzInquiry *iq, RzVector /*<RzAnalysisXRef>*/ *insn_to_insn_edges) {
	// Add all edges discovered by the interpreter
	RzAnalysisXRef *xref;
	rz_vector_foreach (iq->xrefs, xref) {
		if (xref->type != RZ_ANALYSIS_XREF_TYPE_CODE) {
			continue;
		}
		void **it;
		RzIterator *bb_iter = ht_up_as_iter(iq->bb_cfg->basic_blocks);
		rz_iterator_foreach(bb_iter, it) {
			RzInterval *bb = *it;
			if (!rz_itv_contain(*bb, xref->from)) {
				continue;
			}
			rz_inquiry_bb_cfg_add_edge(iq->bb_cfg, bb->addr, xref->to);
		}
		rz_iterator_free(bb_iter);
	}

	// Add the instruction to instruction edges.
	RzAnalysisXRef *i2i_edge;
	rz_vector_foreach(insn_to_insn_edges, i2i_edge) {
		void **it;
		RzIterator *bb_iter = ht_up_as_iter(iq->bb_cfg->basic_blocks);
		rz_iterator_foreach(bb_iter, it) {
			RzInterval *bb = *it;
			if (!rz_itv_contain(*bb, i2i_edge->from)) {
				continue;
			}
			rz_inquiry_bb_cfg_add_edge(iq->bb_cfg, bb->addr, i2i_edge->to);
		}
		rz_iterator_free(bb_iter);
	}
	return true;
}

RZ_IPI bool rz_inquiry_bb_cfg_add_basic_block(RzInquiryBBCFG *cfg, ut64 addr, ut64 size) {
	if (ht_up_find(cfg->basic_blocks, addr, NULL)) {
		return true;
	}

	if (!get_add_node_to_cfg(cfg, addr)) {
		rz_warn_if_reached();
		return false;
	}
	RzInterval *bb = rz_itv_new(addr, size);
	if (!bb || !ht_up_insert(cfg->basic_blocks, addr, bb)) {
		rz_warn_if_reached();
		return false;
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

	RzIterator *iter = ht_up_as_iter(cfg->basic_blocks);
	void **it;
	rz_iterator_foreach(iter, it) {
		RzInterval *bb = *it;
		ut64 end = bb->addr + bb->size;
		RzVector *start_addresses = ht_up_find(overlapping_bbs, end, NULL);
		if (!start_addresses) {
			start_addresses = rz_vector_new(sizeof(ut64), NULL, NULL);
			ht_up_insert(overlapping_bbs, end, start_addresses);
		}
		rz_vector_push(start_addresses, &bb->addr);
	}
	rz_iterator_free(iter);

	iter = ht_up_as_iter(overlapping_bbs);
	rz_iterator_foreach(iter, it) {
		RzVector *addrs = *it;
		size_t i = rz_vector_len(addrs);
		if (i == 1) {
			continue;
		}
		rz_vector_sort(addrs, (RzVectorComparator)cmp, false, NULL);
		for (i = i - 1; i > 0; i--) {
			ut64 small_bb_addr = *((ut64 *)rz_vector_index_ptr(addrs, i));
			ut64 big_bb_addr = *((ut64 *)rz_vector_index_ptr(addrs, i - 1));
			rz_goto_if_fail(small_bb_addr > big_bb_addr, fail);

			// Change size of big bb
			RzInterval *big_bb = ht_up_find(cfg->basic_blocks, big_bb_addr, NULL);
			rz_goto_if_fail(big_bb, fail);
			big_bb->size = small_bb_addr - big_bb_addr;

			// add edge between big to small bb, remove old edges.
			rz_inquiry_bb_cfg_del_out_edges(cfg, big_bb_addr);
			if (!rz_inquiry_bb_cfg_add_edge(cfg, big_bb_addr, small_bb_addr)) {
				goto fail;
			}
		}
	}
	rz_iterator_free(iter);
	ht_up_free(overlapping_bbs);
	return true;

fail:
	ht_up_free(overlapping_bbs);
	rz_warn_if_reached();
	return false;
}
