// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This file implements conflict resolution, for a block which are used by multiple functions.
 *
 * There are a few reasons for a functions using the same block:
 *
 * 1. The block is simply shared code. This is common in hand-written assembly.
 * 2. The block is not actually part of the function, but it is the target of a tail call
 *    and was mistakenly added to the function, because the tail call was not identified as such.
 *    In this case the block and its successors are their own function.
 *    And all the successors only call it.
 */

#include "./absint_priv.h"
#include "rz_analysis.h"
#include <rz_core.h>

#define SCORE_RULED_OUT        -50
#define SCORE_STRONGLY_DISFAV  -40
#define SCORE_VERY_UNLIKELY    -30
#define SCORE_UNLIKELY         -20
#define SCORE_SLIGHTLY_AGAINST -10
#define SCORE_NEUTRAL          0
#define SCORE_SLIGHT_HINT      10
#define SCORE_LIKELY           20
#define SCORE_VERY_LIKELY      30
#define SCORE_STRONG_FAVOR     40
#define SCORE_CERTAIN          50

typedef enum {
	CFG_CONFLICT_VERDICT_DROP = 0, ///< The block should be dropped.
	CFG_CONFLICT_VERDICT_DROP_SUCC, ///< The block and its successors should be dropped.
	CFG_CONFLICT_VERDICT_SHARED, ///< The block is likely shared with another function.
	CFG_CONFLICT_VERDICT_FCN_ENTRY, ///< The block is a likely function entry point.
	CFG_CONFLICT_VERDICT_N,
} BlockVerdict;

const char *block_verdict_names[] = {
	[CFG_CONFLICT_VERDICT_DROP] = "drop",
	[CFG_CONFLICT_VERDICT_DROP_SUCC] = "drop_succ",
	[CFG_CONFLICT_VERDICT_SHARED] = "shared",
	[CFG_CONFLICT_VERDICT_FCN_ENTRY] = "fcn_entry",
	[CFG_CONFLICT_VERDICT_N] = "num_verdicts",
};

/**
 * \brief Different hints that a block is a function entry point, shared by functions,
 * or should be blocked.
 *
 * Some of the hints are take from:
 * https://dl.acm.org/doi/10.1145/3611643.3616366
 * https://web.archive.org/web/20261018180522/https://raw.githubusercontent.com/B2R2-org/FunProbe/fefccf83ad1e5cfc077cdb7a7af0d12e9150ab42/esecfse2023-paper1571.pdf
 */
typedef enum {
	// Positive hints that the block is actually a function entry point:
	CFG_CONFLICT_OBSV_SYMBOL = 1 << 0, ///< The block is located at a symbol's address.
	CFG_CONFLICT_OBSV_IS_CALLED = 1 << 1, ///< The block is the target of a call instruction.
	CFG_CONFLICT_OBSV_SUCC_CROSS_SYMB = 1 << 2, ///< A successor jumps over a symbol to reach this block (tail-call signal).
	CFG_CONFLICT_OBSV_HAS_PDATA_ENTRY = 1 << 3, ///< The block has a PE .pdata / x64 unwind entry.
	CFG_CONFLICT_OBSV_IN_EH_FRAME = 1 << 4, ///< The block is listed in exception-handling metadata (.eh_frame).
	CFG_CONFLICT_OBSV_MULTIPLE_CALLERS = 1 << 5, ///< The block is called from many distinct locations.
	CFG_CONFLICT_OBSV_IMPORT = 1 << 6, ///< The block is a trampoline to an imported function.
	CFG_CONFLICT_OBSV_GROWS_STACK_FRAME = 1 << 7, ///< The block grows the stack frame.

	// Negative hints that the block is a function entry point.
	CFG_CONFLICT_OBSV_STARTS_NOOP = 1 << 8, ///< Block starts with a noop instruction.
	CFG_CONFLICT_OBSV_STARTS_COND_JMP = 1 << 9, ///< A successor of this block is a conditional jump.
	CFG_CONFLICT_OBSV_BEFORE_BIN_ENTRY = 1 << 10, ///< Basic block is before the entry point of the binary.
	CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH = 1 << 11, ///< Block is reached by at least one fall-through edge.
	CFG_CONFLICT_OBSV_REACHED_BY_NORMAL_JMP = 1 << 12, ///< Block is reached by a normal in-function jump.
	CFG_CONFLICT_OBSV_UNCOND_RETURNS = 1 << 13, ///< Block contains an unconditional return instruction.
	CFG_CONFLICT_OBSV_HAS_EPILOGUE_PATTERN = 1 << 14, ///< Block contains a stack-frame epilogue.
	CFG_CONFLICT_OBSV_SHRINKS_STACK_FRAME = 1 << 15, ///< The block shrinks the stack frame.
	CFG_CONFLICT_OBSV_SELF_LOOP = 1 << 16, ///< The block loops back to itself.

	// Positive hints that the block should be dropped.
	CFG_CONFLICT_OBSV_NOT_X_MAPPED = 1 << 17, ///< Block is mapped as non-executable.
	CFG_CONFLICT_OBSV_NOT_MAPPED = 1 << 18, ///< Block is not mapped at all.

	CFG_CONFLICT_OBSV_N = 19,
} BlockObservations;

typedef struct {
	BlockVerdict verdict;
	int score;
} HintScoreEntry;

typedef struct {
	BlockObservations obs;
	HintScoreEntry scores[CFG_CONFLICT_VERDICT_N + 1];
} HintScores;

static const HintScores hint_scores[] = {
	{ CFG_CONFLICT_OBSV_SYMBOL,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_IS_CALLED,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_SUCC_CROSS_SYMB,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_HAS_PDATA_ENTRY,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_VERY_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_IN_EH_FRAME,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_MULTIPLE_CALLERS,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_IMPORT,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_GROWS_STACK_FRAME,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_STARTS_NOOP,
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONGLY_DISFAV },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_STARTS_COND_JMP,
		// Only a slight hint because some architectures have a NULL check with
		// and early fail as prologue.
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHT_HINT },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_BEFORE_BIN_ENTRY,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_VERY_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHT_HINT },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH,
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONGLY_DISFAV },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_REACHED_BY_NORMAL_JMP,
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_UNCOND_RETURNS,
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_HAS_EPILOGUE_PATTERN,
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_SHRINKS_STACK_FRAME,
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_VERY_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_SELF_LOOP,
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_STRONGLY_DISFAV },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_STRONGLY_DISFAV },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_NOT_X_MAPPED,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_NOT_MAPPED,
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_DROP_SUCC, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
};

typedef struct {
	size_t total_obsv; ///< Total number of observations which went into the score.
	int score[CFG_CONFLICT_VERDICT_N];
} BlockScore;

// If the best result is below SCORE_VERDICT_MIN and
// its margin to the second is less then SCORE_VERDICT_MARGIN
// the verdict defaults to SCORE_VERDICT_UNKNOWN.
#define SCORE_VERDICT_MIN     20
#define SCORE_VERDICT_MARGIN  15
#define SCORE_VERDICT_UNKNOWN CFG_CONFLICT_VERDICT_SHARED

#define SCORE_RULED_OUT        -50
#define SCORE_STRONGLY_DISFAV  -40
#define SCORE_VERY_UNLIKELY    -30
#define SCORE_UNLIKELY         -20
#define SCORE_SLIGHTLY_AGAINST -10
#define SCORE_NEUTRAL          0
#define SCORE_SLIGHT_HINT      10
#define SCORE_LIKELY           20
#define SCORE_VERY_LIKELY      30
#define SCORE_STRONG_FAVOR     40
#define SCORE_CERTAIN          50

RZ_API RZ_OWN RzAbsIntCFGConflicts *rz_absint_cfg_conflict_new() {
	RzAbsIntCFGConflicts *conflicts = RZ_NEW0(RzAbsIntCFGConflicts);
	if (!conflicts) {
		return NULL;
	}
	conflicts->cfg_conflicts = ht_up_new(NULL, (HtUPFreeValue)rz_vector_free);
	if (!conflicts->cfg_conflicts) {
		free(conflicts);
		return NULL;
	}
	return conflicts;
}

RZ_API void rz_absint_cfg_conflict_free(RZ_OWN RZ_NULLABLE RzAbsIntCFGConflicts *conflicts) {
	if (!conflicts) {
		return;
	}
	ht_up_free(conflicts->cfg_conflicts);
	free(conflicts);
}

typedef struct {
	ut64 fcn_id;
	const RzAbsIntBlock *block;
} CFGConflictBlock;

/**
 * \brief Adds the basic block to the conflict list.
 *
 * \param conflicts The conflict map.
 * \param fcn_id The id of the function the block belongs to.
 * \param block The block that is used by more than one function.
 *
 * \return True if the block was added successfully, false in case of failure.
 */
RZ_API RzAbsIntCFGConflictAddResult rz_absint_cfg_conflict_add(RZ_NONNULL RzAbsIntCFGConflicts *conflicts, ut64 fcn_id, const RzAbsIntBlock *block) {
	rz_return_val_if_fail(conflicts, RZ_ABSINT_CONFLICT_BLOCK_ERROR);
	ut64 block_addr = rz_absint_block_get_start(block);
	RzVector *blocks = ht_up_find(conflicts->cfg_conflicts, block_addr, NULL);
	RzAbsIntCFGConflictAddResult res;
	if (!blocks) {
		res = RZ_ABSINT_CONFLICT_BLOCK_NEW;
		blocks = rz_vector_new(sizeof(CFGConflictBlock), NULL, NULL);
		if (!blocks) {
			return RZ_ABSINT_CONFLICT_BLOCK_ERROR;
		}
		ht_up_insert(conflicts->cfg_conflicts, block_addr, blocks);
	} else {
		res = RZ_ABSINT_CONFLICT_BLOCK_KNOWN;
	}
	CFGConflictBlock cfb = { .fcn_id = fcn_id, .block = block };
	rz_vector_push(blocks, &cfb);
	return res;
}

static void score_add(BlockObservations obs, BlockScore *score) {
	score->total_obsv++;
	for (size_t i = 0; hint_scores[obs].scores[i].verdict != CFG_CONFLICT_VERDICT_N; ++i) {
		score->score[hint_scores[obs].scores[i].verdict] += hint_scores[obs].scores[i].score;
	}
}

static void normalize_verdict(BlockScore *s) {
	for (int i = 0; i < CFG_CONFLICT_VERDICT_N; ++i) {
		s->score[i] /= s->total_obsv;
	}
}

static BlockVerdict pick_verdict(const BlockScore *s) {
	int best = 0, second = 1;

	for (int verdict = 1; verdict < CFG_CONFLICT_VERDICT_N; ++verdict) {
		if (s->score[verdict] > s->score[best]) {
			second = best;
			best = verdict;
		} else if (verdict != best && s->score[verdict] > s->score[second]) {
			second = verdict;
		}
	}

	int margin = s->score[best] - s->score[second];
	if (s->score[best] < SCORE_VERDICT_MIN || margin < SCORE_VERDICT_MARGIN) {
		return SCORE_VERDICT_UNKNOWN;
	}

	return (BlockVerdict)best;
}

/**
 * \brief This function has a high runtime complexity!
 */
RZ_API BlockVerdict rz_absint_block_judge(RzAnalysis *analysis,
	const RzAbsIntBlock *block,
	RzAbsIntCFGConflictSolutionCfg config) {
	ut64 block_addr = rz_absint_block_get_start(block);
	ut64 block_addr_end = rz_absint_block_get_end(block);
	if (block_addr == 0x0 && (config & RZ_ABSINT_CONFLICT_SOLUTION_REJECT_0_ADDR)) {
		// Clearly a malformed jump.
		return CFG_CONFLICT_VERDICT_DROP_SUCC;
	}
	RzIO *io = rz_analysis_get_io_bind(analysis)->io;
	RzCore *core = rz_analysis_get_core_bind(analysis)->core;
	RzBinObject *obj = rz_bin_cur_object(core->bin);

	BlockScore score = { 0 };

	// CHARACTERISTICS: Block
	RzIOMap *map = rz_io_map_get(io, block_addr);
	if (!map) {
		score_add(CFG_CONFLICT_OBSV_NOT_MAPPED, &score);
		// Ignore all other characteristics
		goto verdict;
	} else if (!(map->perm & RZ_PERM_X)) {
		score_add(CFG_CONFLICT_OBSV_NOT_X_MAPPED, &score);
	}
	const RzAnalysisFunction *fcn;
	if ((fcn = rz_analysis_get_function_at(analysis, block_addr))) {
		score_add(CFG_CONFLICT_OBSV_SYMBOL, &score);
		if (fcn->imports) {
			score_add(CFG_CONFLICT_OBSV_IMPORT, &score);
		}
	}

	// CHARACTERISTICS: Block outgoing edges
	ut64 bin_entry = rz_bin_get_first_entrypoint(obj);
	if (block_addr < bin_entry) {
		score_add(CFG_CONFLICT_OBSV_BEFORE_BIN_ENTRY, &score);
	}

	// CHARACTERISTICS: Block incoming edges
	ssize_t jmp_xrefs_to = 0;
	ssize_t call_xrefs_to = 0;
	RzAnalysisXRef *xref;
	RzListIter *iter;
	RzList *xrefs_to = rz_analysis_xrefs_get_to(analysis, block_addr);
	rz_list_foreach (xrefs_to, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_CALL) {
			call_xrefs_to++;
		} else if (xref->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
			jmp_xrefs_to++;
		}
		if (RZ_BETWEEN(block_addr, xref->from, block_addr_end)) {
			score_add(CFG_CONFLICT_OBSV_SELF_LOOP, &score);
		}
		const RzAnalysisFunction *pred_fcn = rz_analysis_fcn_next(analysis, xref->from);
		if (!pred_fcn) {
			continue;
		}
		if (pred_fcn->addr < xref->to) {
			// The xref jumped over a function entry point to this block.
			score_add(CFG_CONFLICT_OBSV_SUCC_CROSS_SYMB, &score);
		}
	}
	rz_list_free(xrefs_to);
	if (call_xrefs_to == 1) {
		score_add(CFG_CONFLICT_OBSV_IS_CALLED, &score);
	} else if (call_xrefs_to > 1) {
		score_add(CFG_CONFLICT_OBSV_MULTIPLE_CALLERS, &score);
	}
	if (jmp_xrefs_to > 0) {
		score_add(CFG_CONFLICT_OBSV_REACHED_BY_NORMAL_JMP, &score);
	}
	if (block->fallthrough_in) {
		score_add(CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH, &score);
	}
	ssize_t ret_insn = rz_analysis_op_type_contains(analysis, block_addr, block_addr_end - block_addr, -1, RZ_ANALYSIS_OP_TYPE_RET, RZ_ANALYSIS_OP_TYPE_MASK);
	if (ret_insn >= 1) {
		score_add(CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH, &score);
	}
	ssize_t cond_branch_insn = rz_analysis_op_type_contains(analysis, block_addr, block_addr_end - block_addr, 2, RZ_ANALYSIS_OP_TYPE_CJMP, RZ_ANALYSIS_OP_TYPE_CJMP);
	if (cond_branch_insn >= 1) {
		score_add(CFG_CONFLICT_OBSV_STARTS_COND_JMP, &score);
	}

	// TODO
	// CFG_CONFLICT_OBSV_HAS_PDATA_ENTRY
	// CFG_CONFLICT_OBSV_IN_EH_FRAME
	// CFG_CONFLICT_OBSV_GROWS_STACK_FRAME
	// CFG_CONFLICT_OBSV_SHRINKS_STACK_FRAME
	// CFG_CONFLICT_OBSV_STARTS_NOOP
	// CFG_CONFLICT_OBSV_HAS_EPILOGUE_PATTERN

verdict:
	normalize_verdict(&score);
	return pick_verdict(&score);
}

/**
 * \brief It requires symbol and function information to be set.
 */
RZ_API bool rz_absint_cfg_conflicts_solve(RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAbsIntCFGConflicts *conflicts,
	RzAbsIntCFGConflictSolutionCfg cfg) {
	rz_return_val_if_fail(analysis && conflicts, false);
	RzIterator iter = { 0 };
	if (!ht_up_as_iter_kv(conflicts->cfg_conflicts, &iter)) {
		rz_warn_if_reached();
		return false;
	}
	const HtUPKv *kv;
	rz_iterator_foreach(&iter, kv) {
		RzPVector *block_versions = kv->value;
		const CFGConflictBlock *cfb = rz_pvector_head(block_versions);
		BlockVerdict verdict = rz_absint_block_judge(analysis, cfb->block, cfg);
		printf("Block 0x%08lx: %s\n", kv->key, block_verdict_names[verdict]);

		switch (verdict) {
		case CFG_CONFLICT_VERDICT_DROP_SUCC:
		case CFG_CONFLICT_VERDICT_DROP:
		case CFG_CONFLICT_VERDICT_SHARED:
		case CFG_CONFLICT_VERDICT_FCN_ENTRY:
		case CFG_CONFLICT_VERDICT_N: break;
		}
	}

	return true;
}
