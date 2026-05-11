// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This is the function detection algorithm inspired by
 * paper: "REV.NG: A Unified Binary Analysis Framework to Recover CFGs and Function Boundaries"
 * chapter: "4.2 Function boundaries recovery"
 * doi: 10.1145/3033019.3033028
 *
 * The actually algorithm is really simple.
 *
 * TERMS:
 *
 * Basic Block (BB): A sequence of instructions having exactly one entry point and
 * one jump/call/exit at the end.
 * Call candidate: RzAnalysisCallCandidate
 * Candidate function entry points (CFEP): Addresses of possible function entry point.
 * Return Addresses: Address after a call candidate BB, with an xref to it.
 * Basic Block CFG: Control Flow Graph with basic blocks as nodes.
 *
 * IN:
 *   - Call candidates.
 *   - CFEPs
 *   - Return Addresses
 *   - Basic Block CFG (bb_cfg)
 *
 * ALGO:
 *
 * It simply iterates over all CFEPs.
 * For each one it follows its edges in the bb_cfg.
 * If an edge belongs to a call, it is NOT taken.
 *
 * Every walked edge and the basic blocks are added to the function.
 *
 * Tail calls are not modelled.
 *
 * OUT:
 *  - List of functions
 *  - Each functions starts with one CFEP and is a sub-graph in the bb_cfg.
 */

#include "rz_analysis.h"
#include "rz_inquiry/rz_bb_graph.h"
#include "rz_types_base.h"
#include "rz_util/ht_up.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_iterator.h"
#include "rz_util/rz_log.h"
#include "rz_util/rz_set.h"
#include "rz_vector.h"
#include <rz_inquiry.h>
#include <rz_types.h>
#include <rz_util.h>

static int cmp(const void *a, const void *b, void *user) {
	if ((ut64)a > (ut64)b) {
		return 1;
	} else if ((ut64)a < (ut64)b) {
		return -1;
	}
	return 0;
}

static bool jumps_to_ignored_code(const RzVector *v, ut64 jump_target) {
	void *it;
	rz_vector_foreach (v, it) {
		RzInterval *itv = it;
		if (rz_itv_contain(*itv, jump_target)) {
			return true;
		}
	}
	return false;
}

static void recurse_into_fcn_bbs(
	RzInquiryFunction *fcn,
	ut64 predecessor_bb_addr,
	ut64 this_bb_addr,
	RzInquiryBBCFGEdgeType edge_type,
	RzSetU *visited_fcn_bbs,
	const RzVector /*<ut64>*/ *cfep_addresses,
	const HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates,
	const RzInquiryBBCFG *binary_bb_cfg,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code) {
	if (rz_set_u_contains(visited_fcn_bbs, this_bb_addr)) {
		return;
	}
	rz_set_u_add(visited_fcn_bbs, this_bb_addr);

	//
	// Add edge
	//
	RzInquiryBlock this_bb = { 0 };
	if (!rz_inquiry_bb_cfg_get_basic_block(binary_bb_cfg, this_bb_addr, &this_bb)) {
		rz_warn_if_reached();
		goto err_return;
	}
	if (!rz_inquiry_bb_cfg_add_block(fcn->bb_cfg, this_bb.addr, this_bb.size)) {
		rz_warn_if_reached();
		goto err_return;
	}

	if (edge_type != RZ_INQUIRY_BB_CFG_EDGE_TYPE_NONE) {
		RzInquiryBlock from_bb = { 0 };
		if (!rz_inquiry_bb_cfg_get_basic_block(binary_bb_cfg, predecessor_bb_addr, &from_bb)) {
			rz_warn_if_reached();
			goto err_return;
		}
		if (!rz_inquiry_bb_cfg_add_block(fcn->bb_cfg, from_bb.addr, from_bb.size)) {
			rz_warn_if_reached();
			goto err_return;
		}
		if (!rz_inquiry_bb_cfg_add_edge(fcn->bb_cfg, predecessor_bb_addr, this_bb_addr, edge_type)) {
			rz_warn_if_reached();
			goto err_return;
		}
	}

	//
	// Visit neighbors
	//
	RzIterator *successors = rz_inquiry_bb_cfg_get_outgoing_edges(binary_bb_cfg, this_bb_addr);
	if (!successors) {
		// Node has no successors.
		goto err_return;
	}

	const RzGraphEdge *e;
	rz_iterator_foreach(successors, e) {
		RzInquiryBBCFGEdgeType etype = (RzInquiryBBCFGEdgeType)(utptr)rz_graph_edge_get_data(e);
		ut64 succ_addr = rz_graph_node_get_id(rz_graph_edge_get_to(e));
		switch (etype) {
		case RZ_INQUIRY_BB_CFG_EDGE_TYPE_NONE:
		case RZ_INQUIRY_BB_CFG_EDGE_TYPE_CF:
		case RZ_INQUIRY_BB_CFG_EDGE_TYPE_JMP:
			// Just an edge between two basic blocks.
			break;
		case RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL_RET:
			// This is the next instruction packet after a call candidate.
			// It might be an non-existing edge which was only added as a guess.
			// In general all instructions after a call are added to the with
			// an edge, to increase coverage.
			// Even for call which never return (being a tail call or exit).
			//
			// The prototype doesn't handle tail calls. But to not loose too much
			// precission we can check here if the NPC after the call (this_bb address),
			// is a candidate function entry point.
			// If so, we can assume that the NPC is in fact not a return point of a procedure.
			// Hence, it shouldn't be added to the function CFG.
			if (rz_vector_contains(cfep_addresses, &succ_addr)) {
				continue;
			}
			break;
		case RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL:
		case RZ_INQUIRY_BB_CFG_EDGE_TYPE_RETURN:
			continue;
		}
		if (jumps_to_ignored_code(ignored_code, succ_addr)) {
			continue;
		}

		recurse_into_fcn_bbs(
			fcn,
			this_bb_addr,
			succ_addr,
			etype,
			visited_fcn_bbs,
			cfep_addresses,
			call_candidates,
			binary_bb_cfg,
			ignored_code);
	}
	rz_iterator_free(successors);

err_return:
	return;
}

static void fill_candidate_fcn_entry_points(
	const RzInquiryBBCFG *binary_bb_cfg,
	const HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates,
	RzVector *cfep_addresses) {
	void **it;
	RzIterator *iter = ht_up_as_iter(call_candidates);
	rz_iterator_foreach(iter, it) {
		RzAnalysisCallCandidate *cc = *it;
		RzIterator *predecessor = rz_inquiry_bb_cfg_get_outgoing_edges(binary_bb_cfg, cc->bb_addr);
		const RzGraphEdge *e;
		rz_iterator_foreach(predecessor, e) {
			RzInquiryBBCFGEdgeType type = (RzInquiryBBCFGEdgeType)(utptr)rz_graph_edge_get_data(e);
			if (type == RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL_RET) {
				// TODO: Remove this check
				const RzGraphNode *nr = rz_graph_edge_get_to(e);
				ut64 target = rz_graph_node_get_id(nr);
				rz_warn_if_fail(target == cc->npc);
			} else if (type == RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL) {
				const RzGraphNode *nc = rz_graph_edge_get_to(e);
				ut64 target = rz_graph_node_get_id(nc);
				rz_vector_push(cfep_addresses, &target);
				RZ_LOG_DEBUG("Add cfep at 0x%" PFMT64x " (call: 0x%" PFMT64x ") "
					     "based on BB 0x%" PFMT64x "\n",
					cc->bb_addr, cc->candidate_addr, target);
			}
		}
		rz_iterator_free(predecessor);
	}
	rz_iterator_free(iter);
	rz_vector_sort(cfep_addresses, cmp, false, NULL);
}

RZ_API bool rz_inquiry_algo_revng_fcn_detection(
	RzSetU *symbol_addresses,
	RZ_NONNULL const HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates,
	RZ_NONNULL const RzInquiryBBCFG *binary_bb_cfg,
	RZ_NONNULL RZ_OUT RzPVector /*<RzInquiryFunction *>*/ *fcns,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code) {
	rz_return_val_if_fail(call_candidates && binary_bb_cfg && fcns, false);

	// Candidate function entry points
	RzVector *cfep_addresses = rz_vector_new(sizeof(ut64), NULL, NULL);
	RzIterator *iter = rz_set_u_as_iter(symbol_addresses);
	ut64 *addr;
	rz_iterator_foreach(iter, addr) {
		rz_vector_push(cfep_addresses, addr);
	}
	rz_iterator_free(iter);
	fill_candidate_fcn_entry_points(binary_bb_cfg, call_candidates, cfep_addresses);

	// Set of handled cfep
	RzSetU *cfep_handled = rz_set_u_new();

	ut64 *elem;
	rz_vector_foreach (cfep_addresses, elem) {
		ut64 cfep_addr = *elem;
		if (rz_set_u_contains(cfep_handled, cfep_addr)) {
			continue;
		}

		RzSetU *visited_bbs = rz_set_u_new();
		RzInquiryFunction *fcn = rz_inquiry_function_new();
		rz_vector_push(fcn->entry_points, &cfep_addr);
		recurse_into_fcn_bbs(fcn,
			UT64_MAX,
			cfep_addr,
			RZ_INQUIRY_BB_CFG_EDGE_TYPE_NONE,
			visited_bbs,
			cfep_addresses,
			call_candidates,
			binary_bb_cfg,
			ignored_code);
		rz_set_u_free(visited_bbs);
		rz_set_u_add(cfep_handled, cfep_addr);
		rz_pvector_push(fcns, fcn);
	}

	rz_set_u_free(cfep_handled);
	rz_vector_free(cfep_addresses);
	return true;
}
