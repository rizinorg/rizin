// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

static bool block_check_invariants(RzAnalysis *analysis) {
	RBIter iter;
	RzAnalysisBlock *block;
	ut64 last_start = UT64_MAX;
	rz_rbtree_foreach (analysis->bb_tree, iter, block, RzAnalysisBlock, _rb) {
		if (last_start != UT64_MAX) {
			mu_assert ("corrupted binary tree", block->addr >= last_start);
			mu_assert_neq (block->addr, last_start, "double blocks");
		}
		last_start = block->addr;

		mu_assert ("block->ref < 1, but it is still in the tree", block->ref >= 1);
		mu_assert ("block->ref < rz_list_length (block->fcns)", block->ref >= rz_list_length (block->fcns));

		RzListIter *fcniter;
		RzAnalysisFunction *fcn;
		rz_list_foreach (block->fcns, fcniter, fcn) {
			RzListIter *fcniter2;
			RzAnalysisFunction *fcn2;
			for (fcniter2 = fcniter->n; fcniter2 && (fcn2 = fcniter2->data, 1); fcniter2 = fcniter2->n) {
				mu_assert_ptrneq (fcn, fcn2, "duplicate function in basic block");
			}
			mu_assert ("block references function, but function does not reference block", rz_list_contains (fcn->bbs, block));
		}
	}

	RzListIter *fcniter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (analysis->fcns, fcniter, fcn) {
		RzListIter *blockiter;
		ut64 min = UT64_MAX;
		ut64 max = UT64_MIN;
		ut64 realsz = 0;
		rz_list_foreach (fcn->bbs, blockiter, block) {
			RzListIter *blockiter2;
			RzAnalysisBlock *block2;
			if (block->addr < min) {
				min = block->addr;
			}
			if (block->addr + block->size > max) {
				max = block->addr + block->size;
			}
			realsz += block->size;
			for (blockiter2 = blockiter->n; blockiter2 && (block2 = blockiter2->data, 1); blockiter2 = blockiter2->n) {
				mu_assert_ptrneq (block, block2, "duplicate basic block in function");
			}
			mu_assert ("function references block, but block does not reference function", rz_list_contains (block->fcns, fcn));
		}

		if (fcn->meta._min != UT64_MAX) {
			mu_assert_eq (fcn->meta._min, min, "function min wrong");
			mu_assert_eq (fcn->meta._max, max, "function max wrong");
		}

		mu_assert_eq (rz_analysis_function_realsize (fcn), realsz, "realsize wrong");
	}
	return true;
}

static bool block_check_leaks(RzAnalysis *analysis) {
	RBIter iter;
	RzAnalysisBlock *block;
	rz_rbtree_foreach (analysis->bb_tree, iter, block, RzAnalysisBlock, _rb) {
		if (block->ref != rz_list_length (block->fcns))  {
			mu_assert ("leaked basic block", false);
		}
	}
	return true;
}

#define assert_block_invariants(analysis) do { if (!block_check_invariants (analysis)) { return false; } } while (0)
#define assert_block_leaks(analysis) do { if (!block_check_leaks (analysis)) { return false; } } while (0)
