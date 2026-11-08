// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ICFG_PRIV_H
#define RZ_ICFG_PRIV_H

#include "rz_inquiry/rz_icfg.h"
#include <rz_analysis.h>
#include <rz_core.h>
#include <rz_util/rz_set.h>

struct rz_icfg_t {
	RzVector /* ICFGEdge */ prepared_edges;
	RzVector /* ut64 */ proc_entries; ///< Sorted vector of all procedure entry points in the icfg.
	RzSetU /* const RzICFGNode * */ *node_conflicts; ///< Blocks which could be shared by procedures.
	RzGraph /*<RzCFGNode *, RzCFGEdgeType>*/ *graph;
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
	 * TODO: Remove after testing
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
	/**
	 * \brief Block attributes. Kept in sync with the CFG.
	 * Used for accessing most important information, without the need to access the CFG edges.
	 */
	RzICFGNodeAttr attrs;
};

struct rz_cfg_t {
	ut64 entry;
	RzIterator *cfg_nodes; ///< An iterator over the sub-graph in the iCFG belonging to the function.
};

typedef enum {
	CFG_CONFLICT_VERDICT_DROP = 0, ///< The block should be dropped.
	CFG_CONFLICT_VERDICT_SHARED, ///< The block is likely shared with another function.
	CFG_CONFLICT_VERDICT_FCN_ENTRY, ///< The block is a likely function entry point.
	CFG_CONFLICT_VERDICT_SKIP, ///< Node was already handled.
	CFG_CONFLICT_VERDICT_N,
} ICFGNodeVerdict;

typedef enum {
	RZ_ABSINT_CONFLICT_BLOCK_ERROR,
	RZ_ABSINT_CONFLICT_BLOCK_NEW,
	RZ_ABSINT_CONFLICT_BLOCK_KNOWN,
} RzICFGConflictAddResult;

#endif
