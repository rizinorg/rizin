// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This is the function detection algorithm inspired by
 * paper: "REV.NG: A Unified Binary Analysis Framework to Recover CFGs and Function Boundaries"
 * chapter: "4.2 Function boundaries recovery"
 * doi: 10.1145/3033019.3033028
 */

#include "rz_analysis.h"
#include "rz_list.h"
#include "rz_types_base.h"
#include "rz_util/ht_up.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_iterator.h"
#include "rz_util/rz_set.h"
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

static void recurse_into_fcn_bbs(
	RzInquiryFunction *fcn,
	ut64 predecessor_bb_addr,
	ut64 this_bb_addr,
	RzSetU *visited_fcn_bbs,
	const RzSetU *return_addresses,
	const RzVector /*<ut64>*/ *cfep_addresses,
	const HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates,
	const RzInquiryBBCFG *binary_bb_cfg) {
	if (rz_set_u_contains(visited_fcn_bbs, this_bb_addr)) {
		return;
	}
	rz_set_u_add(visited_fcn_bbs, this_bb_addr);

	//
	// Add edge
	//
	RzInterval this_bb = { 0 };
	if (!rz_inquiry_bb_cfg_get_basic_block(binary_bb_cfg, this_bb_addr, &this_bb)) {
		goto warn_return;
	}
	if (!rz_inquiry_bb_cfg_add_basic_block(fcn->bb_cfg, this_bb.addr, this_bb.size)) {
		goto warn_return;
	}

	if (predecessor_bb_addr != UT64_MAX) {
		RzInterval from_bb = { 0 };
		if (!rz_inquiry_bb_cfg_get_basic_block(binary_bb_cfg, predecessor_bb_addr, &from_bb)) {
			goto warn_return;
		}
		if (!rz_inquiry_bb_cfg_add_basic_block(fcn->bb_cfg, from_bb.addr, from_bb.size)) {
			goto warn_return;
		}
		if (!rz_inquiry_bb_cfg_add_edge(fcn->bb_cfg, predecessor_bb_addr, this_bb_addr)) {
			goto warn_return;
		}
	}

	//
	// Visit neighbors
	//
	const RzList *successors = rz_inquiry_bb_cfg_get_neighbours_from(binary_bb_cfg, this_bb_addr);
	if (!successors) {
		goto warn_return;
	}

	RzListIter *lit;
	const RzGraphNode *s;
	rz_list_foreach (successors, lit, s) {
		ut64 succ_addr = (ut64)s->data;
		if (rz_set_u_contains((RzSetU *)return_addresses, succ_addr)) {
			// Ignore tail called functions and return points
			// because they belong to a different function.
			continue;
		}
		if (rz_vector_contains(cfep_addresses, &succ_addr)) {
			// The successor is another function.
			// If address after the branch is a return point we choose it as
			// successor.
			// If it isn't, then the call at this basic block is likely a tail call.
			const RzAnalysisCallCandidate *cc = ht_up_find((HtUP *)call_candidates, this_bb_addr, NULL);
			if (cc && rz_set_u_contains((RzSetU *)return_addresses, cc->npc)) {
				succ_addr = cc->npc;
			} else {
				continue;
			}
		}

		recurse_into_fcn_bbs(
			fcn,
			this_bb_addr,
			succ_addr,
			visited_fcn_bbs,
			return_addresses,
			cfep_addresses,
			call_candidates,
			binary_bb_cfg);
	}
	return;

warn_return:
	rz_warn_if_reached();
	return;
}

static void fill_cfep_and_ret_addresses(
	const RzInquiryBBCFG *binary_bb_cfg,
	const HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates,
	RzSetU *return_addresses,
	RzVector *cfep_addresses) {
	void **it;
	RzIterator *iter = ht_up_as_iter(call_candidates);
	rz_iterator_foreach(iter, it) {
		RzAnalysisCallCandidate *cc = *it;
		ut64 ret_addr = cc->npc;
		const RzList *predecessor = rz_inquiry_bb_cfg_get_neighbours_to(binary_bb_cfg, ret_addr);
		if (rz_list_length(predecessor) > 0) {
			rz_set_u_add(return_addresses, ret_addr);
		}

		const RzList *successors = rz_inquiry_bb_cfg_get_neighbours_from(binary_bb_cfg, cc->bb_addr);
		RzGraphNode *gnode;
		RzListIter *lit;
		rz_list_foreach (successors, lit, gnode) {
			rz_vector_push(cfep_addresses, &gnode->data);
		}
	}
	rz_iterator_free(iter);
	rz_vector_sort(cfep_addresses, cmp, false, NULL);
}

RZ_API bool rz_inquiry_algo_revng_fcn_detection(
	RZ_NONNULL const HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates,
	RZ_NONNULL const RzInquiryBBCFG *binary_bb_cfg,
	RZ_NONNULL RZ_OUT RzPVector /*<RzInquiryFunction *>*/ *fcns) {
	rz_return_val_if_fail(call_candidates && binary_bb_cfg && fcns, false);

	// Candidate function entry points
	RzSetU *return_addresses = rz_set_u_new();
	RzVector *cfep_addresses = rz_vector_new(sizeof(ut64), NULL, NULL);
	fill_cfep_and_ret_addresses(binary_bb_cfg, call_candidates, return_addresses, cfep_addresses);

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
			visited_bbs,
			return_addresses,
			cfep_addresses,
			call_candidates,
			binary_bb_cfg);
		rz_set_u_free(visited_bbs);
		rz_set_u_add(cfep_handled, cfep_addr);
		rz_pvector_push(fcns, fcn);
	}

	rz_set_u_free(cfep_handled);
	rz_set_u_free(return_addresses);
	rz_vector_free(cfep_addresses);
	return true;
}
