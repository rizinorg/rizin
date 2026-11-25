// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This file implements conflict resolution for iCFG nodes which can be
 * shared or entry point nodes.
 * This is the case for nodes which are:
 * 1. Are reachable by a call and _another_ kind of edge (e.g. jump/fallthrough).
 * 2. Are reachable by a jump edge which crosses a possible procedure entry point.
 * 3. Reachable by more than one procedure entry point.
 *
 * Details case 3:
 * There are a few reasons for functions using the same node:
 *
 * 1. The node is simply shared code. This is common in hand-written assembly.
 * 2. The node is not actually part of the function, but it is the target of a tail call
 *    and was mistakenly added to the function, because the tail call was not identified as such.
 *    In this case the conflict node and its successors are their own function
 *    and all the predecessors only call it.
 *
 * The hint based system is inspired by https://dl.acm.org/doi/epdf/10.1145/3611643.3616366
 * It's a good read. Can recommend to take a look.
 * Archive URL:
 * https://web.archive.org/web/20261018180522/https://raw.githubusercontent.com/B2R2-org/FunProbe/fefccf83ad1e5cfc077cdb7a7af0d12e9150ab42/esecfse2023-paper1571.pdf
 */

#include <rz_analysis.h>
#include <rz_core.h>
#include "icfg_priv.h"
#include "rz_bin.h"
#include "rz_inquiry/rz_icfg.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_iterator.h"
#include "rz_util/rz_math.h"
#include "rz_util/rz_set.h"
#include "rz_vector.h"

// If the best result is below SCORE_VERDICT_MIN and
// its margin to the second is less then SCORE_VERDICT_MARGIN
// the verdict defaults to SCORE_VERDICT_UNKNOWN.
#define SCORE_VERDICT_MIN     2
#define SCORE_VERDICT_MARGIN  1
#define SCORE_VERDICT_UNKNOWN CFG_CONFLICT_VERDICT_SHARED

#define SCORE_RULED_OUT        -5
#define SCORE_STRONG_DISFAV    -4
#define SCORE_VERY_UNLIKELY    -3
#define SCORE_UNLIKELY         -2
#define SCORE_SLIGHTLY_AGAINST -1
#define SCORE_NEUTRAL          0
#define SCORE_SLIGHT_HINT      1
#define SCORE_LIKELY           2
#define SCORE_VERY_LIKELY      3
#define SCORE_STRONG_FAVOR     4
#define SCORE_CERTAIN          5

const char *node_verdict_names[] = {
	[CFG_CONFLICT_VERDICT_DROP] = "drop",
	[CFG_CONFLICT_VERDICT_SHARED] = "shared",
	[CFG_CONFLICT_VERDICT_FCN_ENTRY] = "fcn_entry",
	[CFG_CONFLICT_VERDICT_N] = "num_verdicts",
};

/**
 * \brief Different hints that a node is a function entry point, shared by functions,
 * or should be dropped.
 */
typedef enum {
	// Positive hints that the node is actually a function entry point:
	CFG_CONFLICT_OBSV_FCN_SYMBOL = 0, ///< The node is located at a symbol's address.
	CFG_CONFLICT_OBSV_IS_CALLED, ///< The node is the target of a call instruction.
	CFG_CONFLICT_OBSV_IN_JMP_CROSS_SYMB, ///< A successor jumps over a symbol to reach this node (tail-call signal).
	CFG_CONFLICT_OBSV_HAS_PDATA_ENTRY, ///< The node has a PE .pdata / x64 unwind entry.
	CFG_CONFLICT_OBSV_IN_EH_FRAME, ///< The node is listed in exception-handling metadata (.eh_frame).
	CFG_CONFLICT_OBSV_IMPORT, ///< The node is a trampoline to an imported function.
	CFG_CONFLICT_OBSV_GROWS_STACK_FRAME, ///< The node grows the stack frame.

	// Positive hint for shared blocks.
	CFG_CONFLICT_OBSV_STARTS_NOOP, ///< Node starts with a noop instruction.
	CFG_CONFLICT_OBSV_STARTS_COND_JMP, ///< A successor of this block is a conditional jump.
	CFG_CONFLICT_OBSV_BEFORE_BIN_ENTRY, ///< Basic block is before the entry point of the binary.
	CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH, ///< Node is reached by at least one fall-through edge.
	CFG_CONFLICT_OBSV_UNCOND_RETURNS, ///< Node contains an unconditional return instruction.
	CFG_CONFLICT_OBSV_HAS_EPILOGUE_PATTERN, ///< Node contains a stack-frame epilogue.
	CFG_CONFLICT_OBSV_SHRINKS_STACK_FRAME, ///< The block shrinks the stack frame.
	CFG_CONFLICT_OBSV_SELF_LOOP, ///< The block loops back to itself.
	CFG_CONFLICT_OBSV_JUMP_TARGET, ///< Block is target of a jump instruction.
	/**
	 * \brief Hint only triggers if symbols are present at all.
	 * If the conflict block has no function symbol, it is a hint that it is shared.
	 */
	CFG_CONFLICT_OBSV_NO_SYMB,

	// Positive hints that the block should be dropped.
	CFG_CONFLICT_OBSV_NOT_X_MAPPED, ///< Node is mapped as non-executable.
	CFG_CONFLICT_OBSV_NOT_MAPPED, ///< Node is not mapped at all.

	CFG_CONFLICT_OBSV_N = 20,
} NodeObservations;

typedef struct {
	ICFGNodeVerdict id;
	int score;
} HintScoreEntry;

typedef struct {
	const char *name;
	HintScoreEntry verdict[CFG_CONFLICT_VERDICT_N + 1];
} HintScores;

static const HintScores hint_scores[] = {
	{ "CFG_CONFLICT_OBSV_FCN_SYMBOL",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_IS_CALLED",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_STRONG_DISFAV },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_SUCC_CROSS_SYMB",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_NEUTRAL },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_HAS_PDATA_ENTRY",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_VERY_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_IN_EH_FRAME",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_IMPORT",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_GROWS_STACK_FRAME",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHTLY_AGAINST },
			// The drop condition hint points depend on the architecture.
			// Archs for which data bytes often decode to stack allocating,
			// should give a higher score _pro_ dropping.
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_NEUTRAL },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_STARTS_NOOP",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_DISFAV },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_STARTS_COND_JMP",
		// Only a slight hint because some architectures have a NULL check with
		// and early fail as prologue.
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHT_HINT },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			// The drop condition hint points depend on the architecture.
			// Archs for which data bytes often decode to cond. jumps,
			// should give a higher score _pro_ dropping.
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_NEUTRAL },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_BEFORE_BIN_ENTRY",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_VERY_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHT_HINT },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_SLIGHT_HINT },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_UNCOND_RETURNS",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_UNLIKELY },
			// The drop condition hint points depend on the architecture.
			// Archs for which data bytes often decode to cond. returns,
			// should give a higher score _pro_ dropping.
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_NEUTRAL },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_HAS_EPILOGUE_PATTERN",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_SHRINKS_STACK_FRAME",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_VERY_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_SELF_LOOP",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_UNLIKELY },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_STRONG_DISFAV },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_JUMP_TARGET",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_LIKELY },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_SLIGHTLY_AGAINST },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_STRONG_DISFAV },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_NO_SYMB",
		{ { CFG_CONFLICT_VERDICT_SHARED, SCORE_STRONG_FAVOR },
			{ CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_STRONG_DISFAV },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_NEUTRAL },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_NOT_X_MAPPED",
		{ { CFG_CONFLICT_VERDICT_FCN_ENTRY, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_SHARED, SCORE_RULED_OUT },
			{ CFG_CONFLICT_VERDICT_DROP, SCORE_CERTAIN },
			{ CFG_CONFLICT_VERDICT_N, SCORE_NEUTRAL } } },
	{ "CFG_CONFLICT_OBSV_NOT_MAPPED",
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
	rz_return_if_fail(obs < CFG_CONFLICT_OBSV_N);

	// printf("Score add %s: ", hint_scores[obs].name);
	score->total_obsv++;
	for (size_t i = 0; hint_scores[obs].verdict[i].id != CFG_CONFLICT_VERDICT_N; ++i) {
		ICFGNodeVerdict v = hint_scores[obs].verdict[i].id;
		int s = hint_scores[obs].verdict[i].score;
		// printf("%s=%d ", node_verdict_names[v], s);
		score->verdict_score[v] += s;
	}
	// printf("\n");
}

static ICFGNodeVerdict pick_verdict(const NodeScore *s, double *verdict_p) {
	RzVector scores = { 0 };
	rz_vector_init(&scores, sizeof(st64), NULL, NULL);
	for (size_t i = 0; i < CFG_CONFLICT_VERDICT_N; ++i) {
		st64 v_score = s->verdict_score[i];
		rz_vector_push(&scores, &v_score);
	}
	RzIterator it = { 0 };
	if (!rz_vector_as_iter(&scores, &it)) {
		rz_vector_fini(&scores);
		rz_warn_if_reached();
		return CFG_CONFLICT_VERDICT_N;
	}
	// TODO: This softmax does here effectively the same as max().
	// Ideally we should use a normalization, which gives less steep probability deltas
	// between a single point score difference.
	// So if the scores are "drop = -5 shared = 4 fcn_entry = 5" we could still say that
	// they are below the certainty lever we like to have.
	st64 softmax_score = rz_math_softmax_st64(&it, NULL);
	size_t v = 0;
	for (; v < CFG_CONFLICT_VERDICT_N; ++v) {
		if (s->verdict_score[v] == softmax_score) {
			rz_iterator_reset(&it);
			*verdict_p = rz_math_softmax_p_zi_st64(s->verdict_score[v], &it);
			goto ret_verdict;
		}
	}
	rz_iterator_fini(&it);
	rz_vector_fini(&scores);
	rz_warn_if_reached();
	return CFG_CONFLICT_VERDICT_N;

ret_verdict:
	// TODO Remove after debug.
	for (size_t i = 0; i < CFG_CONFLICT_VERDICT_N; ++i) {
		rz_iterator_reset(&it);
		// printf("(%s s=%d, p=%.06f) ", node_verdict_names[i],
		// 	s->verdict_score[i], rz_math_softmax_p_zi_st64(s->verdict_score[i], &it));
	}
	// printf("\n");
	// END

	rz_iterator_fini(&it);
	rz_vector_fini(&scores);
	return (ICFGNodeVerdict)v;
}

static inline bool is_fcn_symb(const char *type) {
	return RZ_STR_EQ(type, RZ_BIN_TYPE_FUNC_STR) || RZ_STR_EQ(type, RZ_BIN_TYPE_METH_STR);
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

	ut64 node_addr = node->addr;
	ut64 node_addr_end = node->addr + node->size;
	// TODO: Add other heuristics.
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
	if ((symb = rz_bin_object_get_symbol_at(obj, node_addr, true)) && is_fcn_symb(symb->type)) {
		score_add(CFG_CONFLICT_OBSV_FCN_SYMBOL, &score);
		if (symb->is_imported) {
			score_add(CFG_CONFLICT_OBSV_IMPORT, &score);
		}
	} else if (rz_pvector_len(obj->symbols) != 0) {
		score_add(CFG_CONFLICT_OBSV_NO_SYMB, &score);
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
	RzGraphEdge *in_edge;
	rz_iterator_foreach(&in_iter, in_edge) {
		RzICFGEdgeType type = (utptr)rz_graph_edge_get_data(in_edge);
		switch (type) {
		default:
			rz_warn_if_reached();
			break;
		case RZ_ICFG_EDGE_TYPE_CALL:
			score_add(CFG_CONFLICT_OBSV_IS_CALLED, &score);
			break;
		case RZ_ICFG_EDGE_TYPE_JUMP:
			score_add(CFG_CONFLICT_OBSV_JUMP_TARGET, &score);
			const RzGraphNode *from_node = rz_graph_edge_get_from(in_edge);
			ut64 from_addr = rz_graph_node_get_id(from_node);
			if (from_addr == node_addr) {
				score_add(CFG_CONFLICT_OBSV_SELF_LOOP, &score);
			} else if (rz_icfg_edge_crosses_symbol(proc_entries, from_addr, node_addr)) {
				// The in edge jumps over a function entry point to this block.
				score_add(CFG_CONFLICT_OBSV_IN_JMP_CROSS_SYMB, &score);
			}
			break;
		case RZ_ICFG_EDGE_TYPE_FALLTHROUGH:
			score_add(CFG_CONFLICT_OBSV_REACHED_BY_FALLTHROUGH, &score);
			break;
		}
	}
	rz_iterator_fini(&in_iter);
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

verdict: {
	double p;
	ICFGNodeVerdict verdict = pick_verdict(&score, &p);
	// REMOVE: printf("Node 0x%08lx: %s\n\n", node->addr, node_verdict_names[verdict]);
	return verdict;
}
}

// Checks if the \p cf_node (conflict node) has to be judged.
//
// This is the case if:
// 1. The node has an incoming call edge.
// 2. The node has an incoming edge which crosses a procedure entry point.
// 3. The memberships of the parent nodes, differ from the given \p cf_node.
//
// Details to 3.:
//
// Check if the intersection of the parent
// function memberships is the same as the conflict node's memberships.
// If that is the case, the current conflict node can be ignored.
// We assume it has no conflicts and can't be an entry point
// (there are some false negative cases, of course).
//
// Example:
// node(membership_0, membership_1, ...)
//
// Case I:
//
// parent0(A, B)-+
//               +->conflict(A, B)
// parent1(A, B)-+
//
// Here we do not need to resolve the conflict node. It is part
// the the sub-graph of its parents. They will be solved once their entry point
// conflict is solved.
//
// -----
//
// Case II:
// parent0(C)----+
//               +->conflict(A, B, C)
// parent1(A, B)-+
//
// On the contrary, if we have case II,
// we have to make a decission again, if conflict(A, B, C) node is an
// entry point of a function or shared between A, B, and C.
static bool node_needs_judgement(RzICFG *icfg,
	const ConflictNode *cf_node,
	const RzICFGNode *cf_icfg_node) {
	rz_return_val_if_fail(cf_node->reason != CONFLICT_REASON_INVALID, false);
	if (cf_node->reason & CONFLICT_REASON_CALL_IN || cf_node->reason & CONFLICT_REASON_CROSSES_ENTRY) {
		return true;
	}

	if (cf_icfg_node->memberships_n <= 1) {
		// Node was previously a multiple membership node,
		// but is already resolved. Skip it.
		return false;
	}
	RzSetU *inter_set = NULL;
	inter_set = rz_set_u_new();
	if (!inter_set) {
		rz_warn_if_reached();
		return false;
	}
	// Copy set.
	rz_set_u_union(inter_set, cf_icfg_node->proc_memberships.set, NULL);

	RzIterator iter = { 0 };
	if (!rz_graph_in_edges_by_id(icfg->graph, cf_icfg_node->addr, &iter)) {
		rz_iterator_fini(&iter);
		rz_set_u_free(inter_set);
		rz_warn_if_reached();
		return false;
	}
	bool needs_judgement = false;
	RzGraphEdge *in_edge;
	rz_iterator_foreach(&iter, in_edge) {
		const RzGraphNode *g_pnode = rz_graph_edge_get_from(in_edge);
		const RzICFGNode *parent = rz_graph_node_get_data(g_pnode);
		if (parent->memberships_n != cf_icfg_node->memberships_n) {
			// The conflict node has at least n memberships, but the parent doesn't.
			// So we know we have Case II here.
			needs_judgement = true;
			break;
		}
		if (rz_set_u_intersection(inter_set, inter_set, parent->proc_memberships.set, NULL) != cf_icfg_node->memberships_n) {
			needs_judgement = true;
			break;
		}
	}
	rz_iterator_fini(&iter);
	rz_set_u_free(inter_set);
	return needs_judgement;
}

static bool dont_walk_call_edges(const RzGraphEdge *e, RzGraphVisitor *vis) {
	RzICFGEdgeType type = (utptr)rz_graph_edge_get_data(e);
	switch (type) {
	case RZ_ICFG_EDGE_TYPE_FALLTHROUGH:
	case RZ_ICFG_EDGE_TYPE_JUMP:
		return true;
	case RZ_ICFG_EDGE_TYPE_CALL:
	case RZ_ICFG_EDGE_TYPE_RETURN:
		return false;
	}
	return false;
}

typedef struct {
	RzICFG *icfg;
	ut64 rm_m; // Only used in the case of single membership nodes.
	ut64 new_m;
	const RzSetU *rm_memberships;
} VisitorBundle;

static void remove_memberships(RzGraphNode *n, RzGraphVisitor *vis) {
	VisitorBundle *bundle = vis->visitor_data;
	RzICFGNode *block = rz_graph_node_get_data_mut(n);
	if (block->memberships_n == 1) {
		// Blocks with a single membership loose members.
		// They are already solved.
		return;
	}
	size_t new_m_size = rz_set_u_difference(block->proc_memberships.set, block->proc_memberships.set, bundle->rm_memberships, NULL);
	if (new_m_size == SZT_MAX) {
		rz_warn_if_reached();
		return;
	}
	if (new_m_size == 0) {
		rz_set_u_free(block->proc_memberships.set);
		block->proc_memberships.set = NULL;
		block->memberships_n = 1;
		block->proc_memberships.m = bundle->new_m;
	} else {
		rz_set_u_add(block->proc_memberships.set, bundle->new_m);
		block->memberships_n = rz_set_u_size(block->proc_memberships.set);
	}
}

static void replace_membership(RzGraphNode *n, RzGraphVisitor *vis) {
	VisitorBundle *bundle = vis->visitor_data;
	RzICFGNode *node = rz_graph_node_get_data_mut(n);
	if (node->memberships_n == 1) {
		node->proc_memberships.m = bundle->new_m;
		return;
	}
	rz_set_u_delete(node->proc_memberships.set, bundle->rm_m);
	rz_set_u_add(node->proc_memberships.set, bundle->new_m);
}

static bool convert_subgraph_to_procedure(RzICFG *icfg, const RzICFGNode *cf_node) {
	// Make all incoming edges of the node "call" edges.
	RzGraphNode *n = rz_graph_find_node(icfg->graph, cf_node->addr);
	if (!n) {
		rz_warn_if_reached();
		return false;
	}
	VisitorBundle bundle = { 0 };
	RzGraphVisitor visitor = { 0 };
	if (cf_node->memberships_n == 1) {
		// The node was identified as a procedure entry point but has only one
		// membership.
		// Replace that one with the own address.
		rz_warn_if_fail(cf_node->addr != cf_node->proc_memberships.m);
		bundle.icfg = icfg;
		bundle.new_m = cf_node->addr;
		bundle.rm_m = cf_node->proc_memberships.m;

		visitor.edge_selector = dont_walk_call_edges;
		visitor.finish_node = replace_membership;
		visitor.visitor_data = &bundle;
	} else {
		// Replace all the memberships of the current cf_node with the
		// address of cf_node.
		bundle.icfg = icfg;
		bundle.new_m = cf_node->addr;
		bundle.rm_memberships = cf_node->proc_memberships.set;
		visitor.edge_selector = dont_walk_call_edges;
		visitor.finish_node = remove_memberships;
		visitor.visitor_data = &bundle;
	}
	rz_graph_dfs_from_node(icfg->graph, n, &visitor);

	RzIterator iter = { 0 };
	if (!rz_graph_in_edges(icfg->graph, n, &iter)) {
		rz_warn_if_reached();
		return false;
	}
	RzGraphEdge *e;
	rz_iterator_foreach(&iter, e) {
		// TODO: Should we really classify fall-through edges as calls?
		// TODO: This has to handle the case of a function self-loop to its entry point.
		rz_graph_edge_set_data(e, RZ_GRAPH_INT_AS_DATA(RZ_ICFG_EDGE_TYPE_CALL));
	}
	rz_iterator_fini(&iter);
	return true;
}

// TODO Remove after debug.
RZ_OWN char *node_fmt(const RzGraphNode *n) {
	const RzICFGNode *node = rz_graph_node_get_data(n);
	return rz_icfg_node_str(node);
}

RZ_OWN char *edge_fmt(const RzGraphEdge *e) {
	RzICFGEdgeType type = (utptr)rz_graph_edge_get_data(e);
	switch (type) {
	case RZ_ICFG_EDGE_TYPE_FALLTHROUGH:
		return RZ_STR_DUP("f");
	case RZ_ICFG_EDGE_TYPE_JUMP:
		return RZ_STR_DUP("j");
	case RZ_ICFG_EDGE_TYPE_CALL:
		return RZ_STR_DUP("c");
	case RZ_ICFG_EDGE_TYPE_RETURN:
		return RZ_STR_DUP("r");
	}
	return RZ_STR_DUP("broken");
}
// END

/**
 * \brief Resolves conflicts for blocks which were executed by multiple functions.
 */
RZ_IPI bool rz_icfg_solve_conflicts(RZ_NONNULL RzICFG *icfg,
	RZ_NONNULL RzBin *bin,
	RZ_NONNULL RzIO *io,
	RzICFGConflictSolutionCfg cfg) {
	rz_return_val_if_fail(bin && io, false);
	// REMOVE:
	// char *icfg_dot = rz_graph_as_dot_str(icfg->graph, "ICFG", node_fmt, edge_fmt);
	// printf("Before:\n%s\n", icfg_dot);
	// free(icfg_dot);
	if (rz_vector_len(&icfg->node_conflicts) == 0) {
		return true;
	}
	if (rz_vector_len(&icfg->prepared_edges) != 0) {
		RZ_LOG_ERROR("All ICFG edges must be applied before resolving conflicts.\n");
		return false;
	}

	while (rz_vector_len(&icfg->node_conflicts) > 0) {
		ConflictNode cf_node = { 0 };
		rz_vector_pop(&icfg->node_conflicts, &cf_node);
		if (cf_node.reason == CONFLICT_REASON_INVALID) {
			rz_warn_if_reached();
			continue;
		}

		// TODO lookup table for icfg node.
		const RzGraphNode *cf_graph_node = rz_graph_find_node(icfg->graph, cf_node.node_addr);
		const RzICFGNode *cf_icfg_node = rz_graph_node_get_data(cf_graph_node);
		// END
		if (!node_needs_judgement(icfg, &cf_node, cf_icfg_node)) {
			// No indicator that this node has to be judged.
			continue;
		}

		ICFGNodeVerdict verdict = rz_icfg_node_judge(icfg, bin, io, cf_icfg_node, cfg);
		switch (verdict) {
		case CFG_CONFLICT_VERDICT_DROP:
			rz_graph_del_node_by_id(icfg->graph, cf_icfg_node->addr);
			break;
		case CFG_CONFLICT_VERDICT_FCN_ENTRY: {
			if (!convert_subgraph_to_procedure(icfg, cf_icfg_node)) {
				rz_warn_if_reached();
			}
			break;
		}
		case CFG_CONFLICT_VERDICT_SHARED:
		case CFG_CONFLICT_VERDICT_SKIP:
			break;
		case CFG_CONFLICT_VERDICT_N:
			rz_warn_if_reached();
			return false;
		}
	}
	// REMOVE:
	// icfg_dot = rz_graph_as_dot_str(icfg->graph, "ICFG", node_fmt, edge_fmt);
	// printf("After:\n%s\n", icfg_dot);
	// free(icfg_dot);

	return true;
}
