// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/ht_up.h"
#include "rz_util/ht_uu.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_graph.h"
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

/**
 * \brief Adds new node or returns existing one.
 */
static /*const*/ RZ_BORROW RzGraphNode *get_add_node_to_cfg(RzInquiryBBCFG *cfg, ut64 bb_addr) {
	bool found = false;
	RzGraphNode *n = ht_up_find(cfg->bb_gnode_map, bb_addr, &found);
	if (found) {
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

static bool add_edge_to_cfg(RzInquiryBBCFG *cfg, ut64 from, ut64 to) {
	RzGraphNode *f = get_add_node_to_cfg(cfg, from);
	RzGraphNode *t = get_add_node_to_cfg(cfg, to);
	if (!f || !t) {
		rz_warn_if_reached();
		return false;
	}
	rz_graph_add_edge(cfg->graph, f, t);
	return true;
}

RZ_IPI bool rz_inquiry_fill_bb_cfg(RzInquiry *iq) {
	if (ht_up_size(iq->bb_cfg->basic_blocks) == 0) {
		RZ_LOG_WARN("No basic blocks present to fill CFG.\n");
		return false;
	}
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
			add_edge_to_cfg(iq->bb_cfg, bb->addr, xref->to);
		}
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
