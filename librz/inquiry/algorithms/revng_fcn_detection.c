// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This is the function detection algorithm from the
 * paper: "REV.NG: A Unified Binary Analysis Framework to Recover CFGs and Function Boundaries"
 * chapter: "4.2 Function boundaries recovery"
 * doi: 10.1145/3033019.3033028
 *
 * The algorithm here differs in a few ways to fit the assumptions Rizin makes
 * and simplify implementation.
 *
 * 1. Function Call: A branch instruction with any store of the next PC **in its basic block**.
 *   - That introduces somewhat more inaccuracy.
 *     But is easier to implement for a prototype.
 * 2. Return: Any branch instruction whose destination is a return address.
 *   - Remove requirement for indirect branch and don't treat unknown targets as return.
 *     Easier to implement.
 * 3. Syscalls are ignored. They are not supported by RzIL, yet.
 * 4. longjmps/killer basic blocks are ignored. - Easier to implement.
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
	RZ_OUT RzSetU *tail_called_addr,
	const RzSetU *return_addresses,
	const RzVector /*<ut64>*/ *cfep_addresses,
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
	const RzList *successors = rz_inquiry_bb_cfg_get_neighbours(binary_bb_cfg, this_bb_addr);
	if (!successors) {
		goto warn_return;
	}

	RzListIter *lit;
	const RzGraphNode *s;
	rz_list_foreach (successors, lit, s) {
		ut64 succ_addr = (ut64)s->data;
		if (rz_set_u_contains((RzSetU *)return_addresses, succ_addr) ||
			rz_vector_contains(cfep_addresses, &succ_addr) ||
			rz_set_u_contains(tail_called_addr, succ_addr)) {
			continue;
		}

		ut64 *val;
		rz_vector_foreach (cfep_addresses, val) {
			ut64 cfep_addr = *val;
			if (cfep_addr != this_bb_addr &&
				(RZ_BETWEEN_EXCL(this_bb_addr, cfep_addr, succ_addr) ||
					RZ_BETWEEN_EXCL(succ_addr, cfep_addr, this_bb_addr))) {
				// The jump goes over a cfep candidate.
				// Assume the succ_addr is a tail call target.
				// Log it and don't recurse.
				rz_set_u_add(tail_called_addr, succ_addr);
				continue;
			}

			// The jump goes not over cfep so it should be a
			// valid basic block of this function.
			recurse_into_fcn_bbs(
				fcn,
				this_bb_addr,
				succ_addr,
				visited_fcn_bbs,
				tail_called_addr,
				return_addresses,
				cfep_addresses,
				binary_bb_cfg);
		}
	}
	return;

warn_return:
	rz_warn_if_reached();
	return;
}

RZ_API bool rz_inquiry_algo_revng_fcn_detection(
	RZ_NONNULL const HtUP /*<RzAnalysisCallCandidate *>*/ *call_candidates,
	RZ_NONNULL const RzInquiryBBCFG *binary_bb_cfg,
	RZ_NONNULL RZ_OUT RzPVector /*<RzInquiryFunction *>*/ *fcns) {
	rz_return_val_if_fail(call_candidates && binary_bb_cfg && fcns, false);

	// Candidate function entry points
	RzSetU *return_addresses = rz_set_u_new();
	RzVector *cfep_addresses = rz_vector_new(sizeof(ut64), NULL, NULL);
	void **it;
	RzIterator *iter = ht_up_as_iter(call_candidates);
	rz_iterator_foreach(iter, it) {
		RzAnalysisCallCandidate *cc = *it;
		rz_set_u_add(return_addresses, cc->npc);
		rz_vector_push(cfep_addresses, &cc->candidate_addr);
	}
	rz_iterator_free(iter);
	rz_vector_sort(cfep_addresses, cmp, false, NULL);

	// Tail calls discovered by this algorithm.
	RzSetU *tail_called_addr = rz_set_u_new();
	// Set of handled cfep
	RzSetU *cfep_handled = rz_set_u_new();

	do {
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
				tail_called_addr,
				return_addresses,
				cfep_addresses,
				binary_bb_cfg);
			rz_set_u_free(visited_bbs);
			rz_set_u_add(cfep_handled, cfep_addr);
			rz_pvector_push(fcns, fcn);
		}

		iter = rz_set_u_as_iter(tail_called_addr);
		ut64 *val;
		rz_iterator_foreach(iter, val) {
			ut64 tail_cfep = *val;
			if (rz_vector_contains(cfep_addresses, &tail_cfep)) {
				continue;
			}
			rz_vector_push_front(cfep_addresses, &tail_cfep);
		}
		rz_iterator_free(iter);
		rz_set_u_clean(tail_called_addr);
	} while (rz_set_u_size(tail_called_addr) != 0);

	rz_set_u_free(cfep_handled);
	rz_set_u_free(tail_called_addr);
	rz_set_u_free(return_addresses);
	rz_vector_free(cfep_addresses);
	return true;
}
