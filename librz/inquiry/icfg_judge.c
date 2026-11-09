// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This file implements conflict resolution, for a iCFG nodes which are used by multiple functions.
 *
 * There are a few reasons for a functions using the same node:
 *
 * 1. The node is simply shared code. This is common in hand-written assembly.
 * 2. The node is not actually part of the function, but it is the target of a tail call
 *    and was mistakenly added to the function, because the tail call was not identified as such.
 *    In this case the node and its successors are their own function.
 *    And all the predecessors only call it.
 */

#include <rz_analysis.h>
#include <rz_core.h>
#include "icfg_priv.h"
#include "rz_bin.h"
#include "rz_inquiry/rz_icfg.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_iterator.h"
#include "rz_util/rz_set.h"
#include "rz_vector.h"

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

const char *node_verdict_names[] = {
	[CFG_CONFLICT_VERDICT_DROP] = "drop",
	[CFG_CONFLICT_VERDICT_SHARED] = "shared",
	[CFG_CONFLICT_VERDICT_FCN_ENTRY] = "fcn_entry",
	[CFG_CONFLICT_VERDICT_N] = "num_verdicts",
};

/**
 * \brief Different hints that a node is a function entry point, shared by functions,
 * or should be dropped.
 *
 * Some of the hints are take from:
 * https://dl.acm.org/doi/10.1145/3611643.3616366
 * https://web.archive.org/web/20261018180522/https://raw.githubusercontent.com/B2R2-org/FunProbe/fefccf83ad1e5cfc077cdb7a7af0d12e9150ab42/esecfse2023-paper1571.pdf
 */
typedef enum {
	CFG_CONFLICT_OBSV_INVALID = 0,
	// Positive hints that the node is actually a function entry point:
	CFG_CONFLICT_OBSV_SYMBOL = 1 << 0, ///< The node is located at a symbol's address.
	CFG_CONFLICT_OBSV_IS_CALLED = 1 << 1, ///< The node is the target of a call instruction.
	CFG_CONFLICT_OBSV_SUCC_CROSS_SYMB = 1 << 2, ///< A successor jumps over a symbol to reach this node (tail-call signal).
	CFG_CONFLICT_OBSV_HAS_PDATA_ENTRY = 1 << 3, ///< The node has a PE .pdata / x64 unwind entry.
	CFG_CONFLICT_OBSV_IN_EH_FRAME = 1 << 4, ///< The node is listed in exception-handling metadata (.eh_frame).
	CFG_CONFLICT_OBSV_MULTIPLE_CALLERS = 1 << 5, ///< The node is called from many distinct locations.
	CFG_CONFLICT_OBSV_IMPORT = 1 << 6, ///< The node is a trampoline to an imported function.
	CFG_CONFLICT_OBSV_GROWS_STACK_FRAME = 1 << 7, ///< The node grows the stack frame.

	// Negative hints that the block is a function entry point.
	CFG_CONFLICT_OBSV_STARTS_NOOP = 1 << 8, ///< Node starts with a noop instruction.
	CFG_CONFLICT_OBSV_STARTS_COND_JMP = 1 << 9, ///< A successor of this block is a conditional jump.
	CFG_CONFLICT_OBSV_BEFORE_BIN_ENTRY = 1 << 10, ///< Basic block is before the entry point of the binary.
	CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH = 1 << 11, ///< Node is reached by at least one fall-through edge.
	CFG_CONFLICT_OBSV_REACHED_BY_NORMAL_JMP = 1 << 12, ///< Node is reached by a normal in-function jump.
	CFG_CONFLICT_OBSV_UNCOND_RETURNS = 1 << 13, ///< Node contains an unconditional return instruction.
	CFG_CONFLICT_OBSV_HAS_EPILOGUE_PATTERN = 1 << 14, ///< Node contains a stack-frame epilogue.
	CFG_CONFLICT_OBSV_SHRINKS_STACK_FRAME = 1 << 15, ///< The block shrinks the stack frame.
	CFG_CONFLICT_OBSV_SELF_LOOP = 1 << 16, ///< The block loops back to itself.

	// Positive hints that the block should be dropped.
	CFG_CONFLICT_OBSV_NOT_X_MAPPED = 1 << 17, ///< Node is mapped as non-executable.
	CFG_CONFLICT_OBSV_NOT_MAPPED = 1 << 18, ///< Node is not mapped at all.

	CFG_CONFLICT_OBSV_N = 19,
} NodeObservations;

typedef struct {
	ICFGNodeVerdict id;
	int score;
} HintScoreEntry;

typedef struct {
	NodeObservations obs;
	const char *name;
	HintScoreEntry verdict[CFG_CONFLICT_VERDICT_N + 1];
} HintScores;

static const HintScores hint_scores[] = {
	{ CFG_CONFLICT_OBSV_SYMBOL, "CFG_CONFLICT_OBSV_SYMBOL",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_IS_CALLED, "CFG_CONFLICT_OBSV_IS_CALLED",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_SUCC_CROSS_SYMB, "CFG_CONFLICT_OBSV_SUCC_CROSS_SYMB",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_HAS_PDATA_ENTRY, "CFG_CONFLICT_OBSV_HAS_PDATA_ENTRY",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_VERY_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_IN_EH_FRAME, "CFG_CONFLICT_OBSV_IN_EH_FRAME",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_MULTIPLE_CALLERS, "CFG_CONFLICT_OBSV_MULTIPLE_CALLERS",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_IMPORT, "CFG_CONFLICT_OBSV_IMPORT",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_GROWS_STACK_FRAME, "CFG_CONFLICT_OBSV_GROWS_STACK_FRAME",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_STARTS_NOOP, "CFG_CONFLICT_OBSV_STARTS_NOOP",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONGLY_DISFAV },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_STARTS_COND_JMP, "CFG_CONFLICT_OBSV_STARTS_COND_JMP",
		// Only a slight hint because some architectures have a NULL check with
		// and early fail as prologue.
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHT_HINT },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_BEFORE_BIN_ENTRY, "CFG_CONFLICT_OBSV_BEFORE_BIN_ENTRY",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_VERY_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHT_HINT },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH, "CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONGLY_DISFAV },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_REACHED_BY_NORMAL_JMP, "CFG_CONFLICT_OBSV_REACHED_BY_NORMAL_JMP",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_UNCOND_RETURNS, "CFG_CONFLICT_OBSV_UNCOND_RETURNS",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_HAS_EPILOGUE_PATTERN, "CFG_CONFLICT_OBSV_HAS_EPILOGUE_PATTERN",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_SHRINKS_STACK_FRAME, "CFG_CONFLICT_OBSV_SHRINKS_STACK_FRAME",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_VERY_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_SELF_LOOP, "CFG_CONFLICT_OBSV_SELF_LOOP",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_STRONGLY_DISFAV },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_NOT_X_MAPPED, "CFG_CONFLICT_OBSV_NOT_X_MAPPED",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ CFG_CONFLICT_OBSV_NOT_MAPPED, "CFG_CONFLICT_OBSV_NOT_MAPPED",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
};

typedef struct {
	size_t total_obsv; ///< Total number of observations which went into the score.
	int verdict_score[CFG_CONFLICT_VERDICT_N];
} NodeScore;

static void score_add(NodeObservations obs, NodeScore *score) {
	rz_return_if_fail(obs != CFG_CONFLICT_OBSV_N && rz_bits_count_ones_ut64(obs) == 1);
	size_t obsv_idx = rz_bits_trailing_zeros(obs);
	rz_return_if_fail(obsv_idx < CFG_CONFLICT_OBSV_N);

	score->total_obsv++;
	for (size_t i = 0; hint_scores[obsv_idx].verdict[i].id != CFG_CONFLICT_VERDICT_N; ++i) {
		ICFGNodeVerdict v = hint_scores[obsv_idx].verdict[i].id;
		int s = hint_scores[obsv_idx].verdict[i].score;
		score->verdict_score[v] += s;
	}
}

static void normalize_verdict(NodeScore *s) {
	printf("total obvs: %d\n", s->total_obsv);
	for (int i = 0; i < CFG_CONFLICT_VERDICT_N; ++i) {
		printf("%s: %d normed: %zu\n", node_verdict_names[i], s->verdict_score[i], s->verdict_score[i] / s->total_obsv);
		s->verdict_score[i] /= s->total_obsv;
	}
}

static ICFGNodeVerdict pick_verdict(const NodeScore *s) {
	int best = 0, second = 1;

	for (int verdict = 1; verdict < CFG_CONFLICT_VERDICT_N; ++verdict) {
		if (s->verdict_score[verdict] > s->verdict_score[best]) {
			second = best;
			best = verdict;
		} else if (verdict != best && s->verdict_score[verdict] > s->verdict_score[second]) {
			second = verdict;
		}
	}

	int margin = s->verdict_score[best] - s->verdict_score[second];
	if (s->verdict_score[best] < SCORE_VERDICT_MIN || margin < SCORE_VERDICT_MARGIN) {
		return SCORE_VERDICT_UNKNOWN;
	}

	return (ICFGNodeVerdict)best;
}

static bool edge_crosses_symbol(const RzVector *proc_entries, ut64 from, ut64 to) {
	if (from == to) {
		return false;
	}
	size_t n_procs = rz_vector_len(proc_entries);
	if (n_procs == 0) {
		return false;
	}
	size_t lo = 0, hi = n_procs;

	ut64 low_addr = RZ_MIN(from, to);
	ut64 high_addr = RZ_MAX(from, to);

	// Find the procedure address closest to the lower address of the edge.
	ut64 v;
	size_t mid;
	while (lo < hi) {
		mid = lo + ((hi - lo) >> 1);
		v = *(ut64 *)rz_vector_index_ptr(proc_entries, mid);
		if (v == low_addr) {
			break;
		}
		if (v < low_addr) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}

	// Check if there is a procedure address between the low and high address
	// of the edge.
	if (mid == n_procs - 1) {
		return false;
	} else if (v > low_addr || mid == 0) {
		return v < high_addr;
	} else {
		return (*(ut64 *)rz_vector_index_ptr(proc_entries, mid - 1)) < high_addr;
	}
}

/**
 * \brief This function has a high runtime complexity!
 */
static ICFGNodeVerdict rz_icfg_node_judge(
	RzICFG *icfg,
	RZ_NONNULL RzBin *bin,
	RZ_NONNULL RzIO *io,
	const RzICFGNode *node,
	RzICFGConflictSolutionCfg config) {
	RzVector *proc_entries = &icfg->proc_entries;

	if (node->memberships_n <= 1) {
		return CFG_CONFLICT_VERDICT_SKIP;
	}
	ut64 node_addr = node->addr;
	ut64 node_addr_end = node->addr + node->size;
	if (node_addr == 0x0 && (config & RZ_ICFG_CONFLICT_SOLUTION_REJECT_0_ADDR)) {
		// Clearly a malformed jump.
		return CFG_CONFLICT_VERDICT_DROP;
	}
	RzBinObject *obj = rz_bin_cur_object(bin);

	NodeScore score = { 0 };

	// CHARACTERISTICS: Block
	RzIOMap *map = rz_io_map_get(io, node_addr);
	if (!map) {
		score_add(CFG_CONFLICT_OBSV_NOT_MAPPED, &score);
		// Ignore all other characteristics
		goto verdict;
	} else if (!(map->perm & RZ_PERM_X)) {
		score_add(CFG_CONFLICT_OBSV_NOT_X_MAPPED, &score);
	}
	const RzBinSymbol *symb;
	if ((symb = rz_bin_object_get_symbol_at(obj, node_addr, true))) {
		score_add(CFG_CONFLICT_OBSV_SYMBOL, &score);
		if (symb->is_imported) {
			score_add(CFG_CONFLICT_OBSV_IMPORT, &score);
		}
	}

	ut64 bin_entry = rz_bin_get_first_entrypoint(obj);
	if (node_addr < bin_entry) {
		score_add(CFG_CONFLICT_OBSV_BEFORE_BIN_ENTRY, &score);
	}

	// CHARACTERISTICS: Node incoming edges
	RzIterator in_iter;
	if (!rz_graph_in_edges_by_id(icfg->graph, node->addr, &in_iter)) {
		rz_warn_if_reached();
		return CFG_CONFLICT_VERDICT_SKIP;
	}
	ssize_t jmps_in = 0;
	ssize_t calls_in = 0;
	RzGraphEdge *in_edge;
	rz_iterator_foreach(&in_iter, in_edge) {
		RzICFGEdgeType type = (utptr)rz_graph_edge_get_data(in_edge);
		switch (type) {
		default:
			rz_warn_if_reached();
			break;
		case RZ_ICFG_EDGE_TYPE_CALL:
			calls_in++;
			break;
		case RZ_ICFG_EDGE_TYPE_JUMP:
			jmps_in++;
			const RzGraphNode *from_node = rz_graph_edge_get_from(in_edge);
			ut64 from_addr = rz_graph_node_get_id(from_node);
			if (from_addr == node_addr) {
				score_add(CFG_CONFLICT_OBSV_SELF_LOOP, &score);
			} else if (edge_crosses_symbol(proc_entries, from_addr, node_addr)) {
				// The in edge jumps over a function entry point to this block.
				score_add(CFG_CONFLICT_OBSV_SUCC_CROSS_SYMB, &score);
			}
			break;
		case RZ_ICFG_EDGE_TYPE_FALLTHROUGH:
			score_add(CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH, &score);
			break;
		}
	}
	rz_iterator_fini(&in_iter);

	if (calls_in == 1) {
		score_add(CFG_CONFLICT_OBSV_IS_CALLED, &score);
	} else if (calls_in > 1) {
		score_add(CFG_CONFLICT_OBSV_MULTIPLE_CALLERS, &score);
	}
	if (jmps_in > 0) {
		score_add(CFG_CONFLICT_OBSV_REACHED_BY_NORMAL_JMP, &score);
	}
	// TODO: Return attributes should be generated by the interpreter which supports stack variables.
	// That way we don't have to disassemble again everything from scratch.
	RzCore *core = io->corebind.core;
	ssize_t ret_insn = rz_analysis_op_type_contains(core->analysis, node_addr, node_addr_end - node_addr, -1, RZ_ANALYSIS_OP_TYPE_RET, RZ_ANALYSIS_OP_TYPE_MASK);
	if (ret_insn >= 1) {
		score_add(CFG_CONFLICT_OBSV_UNCOND_RETURNS, &score);
	}
	// TODO: Cond. jump attributes should be generated by the interpreter
	ssize_t cond_branch_insn = rz_analysis_op_type_contains(core->analysis, node_addr, node_addr_end - node_addr, 2, RZ_ANALYSIS_OP_TYPE_CJMP, RZ_ANALYSIS_OP_TYPE_CJMP);
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
 * \brief Resolves conflicts for blocks which were executed by multiple functions.
 */
RZ_IPI bool rz_icfg_solve_conflicts(RZ_NONNULL RzICFG *icfg,
	RZ_NONNULL RzBin *bin,
	RZ_NONNULL RzIO *io,
	RzICFGConflictSolutionCfg cfg) {
	rz_return_val_if_fail(bin && io, false);
	if (rz_set_u_size(icfg->node_conflicts) == 0) {
		return true;
	}
	if (rz_vector_len(&icfg->prepared_edges) != 0) {
		RZ_LOG_ERROR("All ICFG edges must be applied before resolving conflicts.\n");
		return false;
	}

	RzIterator iter = { 0 };
	while (rz_set_u_size(icfg->node_conflicts) > 0) {
		utptr nptr = rz_set_u_take(icfg->node_conflicts);
		const RzICFGNode *cf_node = (const RzICFGNode *)nptr;

		if (!rz_graph_in_edges_by_id(icfg->graph, cf_node->addr, &iter) || cf_node->memberships_n == 1) {
			// This node shouldn't be a conflict node to begin with.
			// Conflict nodes require at least two incoming edges.
			rz_warn_if_reached();
			continue;
		}

		// Check if the intersection of the parent
		// function memberships is the same as the conflict node's memberships.
		// If that is the case, the current conflict node can be ignored.
		// Because it can't be an entry point of a potentially tail called
		// CFG.
		//
		// Example:
		// node(membership_0, membership_1, ...)
		//
		// Case I - Here we do not need to resolve the conflict node. It is part
		// the the sub-graph of its parents. They will be solved once their entry point
		// conflict is solved:
		//
		// parent0(A, B)-+
		//               +->conflict(A, B)
		// parent1(A, B)-+
		//
		// Case II - On the contrary, if we have the following situation,
		// we have to make a decission again, if conflict(A, B, C) node is an
		// entry point or shared between A, B, C.
		//
		// parent0(C)----+
		//               +->conflict(A, B, C)
		// parent1(A, B)-+
		//
		RzSetU *inter_set = rz_set_u_new();
		if (!inter_set) {
			rz_warn_if_reached();
			return false;
		}
		bool needs_judgement = false;
		RzGraphEdge *in_edge;
		rz_iterator_foreach(&iter, in_edge) {
			const RzGraphNode *g_pnode = rz_graph_edge_get_from(in_edge);
			const RzICFGNode *parent = rz_graph_node_get_data(g_pnode);
			if (parent->memberships_n == 1) {
				// The conflict node has at least 2 memberships, but the parent doesn't.
				// So we know we have Case II here.
				needs_judgement = true;
				break;
			}
			if (rz_set_u_intersection(inter_set, inter_set, parent->proc_memberships.set, NULL) != cf_node->memberships_n) {
				needs_judgement = true;
				break;
			}
		}
		rz_iterator_fini(&iter);
		if (!needs_judgement) {
			continue;
		}

		ICFGNodeVerdict verdict = rz_icfg_node_judge(icfg, bin, io, cf_node, cfg);
		printf("Node 0x%08lx: %s\n", cf_node->addr, node_verdict_names[verdict]);

		switch (verdict) {
		case CFG_CONFLICT_VERDICT_DROP:
		case CFG_CONFLICT_VERDICT_SHARED:
		case CFG_CONFLICT_VERDICT_FCN_ENTRY:
		case CFG_CONFLICT_VERDICT_N:
			rz_warn_if_reached();
			break;
		case CFG_CONFLICT_VERDICT_SKIP:
			continue;
		}
	}

	rz_iterator_fini(&iter);
	return true;
}
