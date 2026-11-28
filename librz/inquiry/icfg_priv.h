// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ICFG_PRIV_H
#define RZ_ICFG_PRIV_H

#include "rz_inquiry/rz_icfg.h"
#include <rz_analysis.h>
#include <rz_core.h>
#include <rz_util/rz_set.h>

typedef struct conflict_node {
	ut64 node_addr;
	enum conflict_reason {
		CONFLICT_REASON_INVALID = 0,
		CONFLICT_REASON_CALL_IN = 1,
		CONFLICT_REASON_CROSSES_ENTRY = 1 << 1,
		CONFLICT_REASON_MULT_MEMBERS = 1 << 2,
	} reason;
} ConflictNode;

struct rz_icfg_t {
	RzVector /* ICFGEdge */ prepared_edges;
	/**
	 * \brief Sorted vector of all procedure entry points in the icfg.
	 * This is a vector and no set, so we can do O(log n) search for
	 * procedure entry points which are crossed by JUMP edges.
	 *
	 * Before the analysis starts, this vector either contains all function
	 * symbol locations and/or all detected function prologues.
	 * It gets extended with newly detected function entrypoints.
	 *
	 * If RZ_ICFG_HEURISTIC_FCN_SYMB_OVERWRITE is _not_ enabled,
	 * the node classification will also remove elements from it.
	 */
	RzVector /* ut64 */ known_entries;
	/**
	 * \brief Nodes which have to be judged to be a shared block or an entry point.
	 */
	RzVector /*<ConflictNode>*/ node_conflicts;
	RzGraph /*<RzCFGNode *, RzCFGEdgeType>*/ *graph;
	/**
	 * \brief An interval tree with all nodes of the graph.
	 * The interval tree node data is the pointer of the corresponding RzGraphNode.
	 * Interval ends are inclusive. So the end is the last byte of the last instruction in a block.
	 * end + 1 is the first byte of the next block.
	 */
	RzIntervalTree /* RzGraphNode */ itv_tree;
	RzICFGHeuristics heuristics; ///< The classification heuristics for the blocks.
};

typedef struct {
	ut64 from;
	ut64 to;
	RzICFGEdgeType type;
} ICFGEdge;

struct rz_icfg_node_t {
	ut64 addr; ///< Address of the corresponding block.
	size_t size; ///< Size the corresponding block covers in memorfromy (in bytes).
	/**
	 * Do not remove!
	 * RzAnalysisBlock stores the number of instructions it covers.
	 * When we do https://github.com/rizinorg/rizin/issues/6386 `rz_analysis_block_analyze_ops`
	 * will no longer be called on RzAnalysisBlock, and then it needs to get the number of instructions
	 * from somewhere (these ones).
	 *
	 * \brief The offsets of the instructions (packets), from the block start address.
	 * Starting at the second instruction in the block (since first is always 0), offsets from the start of the block
	 */
	RzVector /*<ut16>*/ insn_offsets;
	/**
	 * \brief The procedures entry points this block can be reached from without walking a call edge.
	 * Stored inline in \p arr as long as there are at most RZ_ICFG_PROC_MEMBERSHIPS_DEFAULT members.
	 * Otherwise a set is allocated and the members are moved into it.
	 */
	size_t memberships_n;
	union {
		RzSetU *set;
		ut64 m;
	} proc_memberships;
};

struct rz_cfg_t {
	ut64 entry;
	RzIterator *cfg_nodes; ///< An iterator over the sub-graph in the iCFG belonging to the function.
};

typedef enum {
	CFG_CONFLICT_VERDICT_DROP = 0, ///< The block should be dropped.
	// NOTE: There is intentionally no "drop node and _all_ its successors" rule here.
	// It might be tempting to add it, to delete vast invalid subgraphs, but
	// it is too easy to exploit.
	// Malware could specifically craft a node which fullfills this role and
	// let it jump to a valid code region. That would invalidate the
	// analysis in that code region.

	CFG_CONFLICT_VERDICT_SHARED, ///< The block is likely shared with another function.
	CFG_CONFLICT_VERDICT_FCN_ENTRY, ///< The block is a likely function entry point.
	CFG_CONFLICT_VERDICT_N,
	CFG_CONFLICT_VERDICT_SKIP, ///< Node was already handled.
} ICFGNodeVerdict;

typedef enum {
	RZ_ABSINT_CONFLICT_BLOCK_ERROR,
	RZ_ABSINT_CONFLICT_BLOCK_NEW,
	RZ_ABSINT_CONFLICT_BLOCK_KNOWN,
} RzICFGConflictAddResult;

RZ_IPI char *rz_icfg_node_str(const RzICFGNode *node);
RZ_IPI bool rz_icfg_edge_crosses_symbol(const RzVector *proc_entries, ut64 from, ut64 to);

static inline int uint_cmp(ut64 *a, ut64 *b, void *user) {
	return (*a > *b) - (*a < *b);
}

#endif
