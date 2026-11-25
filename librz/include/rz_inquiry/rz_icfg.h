// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Control flow graphs (CFGs) implementations.
 */

#ifndef RZ_CFG
#define RZ_CFG

#include <rz_analysis.h>
#include <rz_util.h>

/**
 * \brief The inter-procedural CFG of the program.
 */
typedef struct rz_icfg_t RzICFG;

/**
 * \brief An iCFG node.
 */
typedef struct rz_icfg_node_t RzICFGNode;

/**
 * \brief The CFG of a single procedure.
 */
typedef struct rz_cfg_t RzCFG;

typedef enum rz_icfg_edge_type_t {
	RZ_ICFG_EDGE_TYPE_FALLTHROUGH = 0, ///< Fall through between two blocks.
	RZ_ICFG_EDGE_TYPE_JUMP, ///< Jumps to another address.
	/**
	 * \brief Calling a procedure.
	 * A control flow which usually does something like:
	 * 1. Changing control flow to a procedure entry point.
	 * 2. back up its return address
	 * 3. manipulates some kind of stack
	 * 4. manipulates the argument registers.
	 *
	 * 2.-4. do not need to be present to classify a call edge as such.
	 * E.g. tail calls are call edges as well, even though they are often
	 * "jump" instructions in assembly.
	 * Similary are fall-through edges classified as call as well,
	 * if they lead to a procedure entry point.
	 */
	RZ_ICFG_EDGE_TYPE_CALL,
	RZ_ICFG_EDGE_TYPE_RETURN, ///< Return from procedure.
} RzICFGEdgeType;

typedef enum {
	RZ_ICFG_CONFLICT_SOLUTION_DEFAULT = 0,
	RZ_ICFG_CONFLICT_SOLUTION_REJECT_0_ADDR = 1 << 0, ///< Totally reject any block at address 0x0.
} RzICFGConflictSolutionCfg;

RZ_API RZ_OWN RzICFG *rz_icfg_new();
RZ_API void rz_icfg_free(RZ_NULLABLE RZ_OWN RzICFG *icfg);

RZ_API bool rz_icfg_add_node(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 addr, size_t size, RZ_NONNULL const RzVector /*<ut16>*/ *insn_offsets, ut64 fcn_membership);
RZ_API bool rz_icfg_prepare_edge(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 from, ut64 to, RzICFGEdgeType type);
RZ_API size_t rz_icfg_apply(RZ_NONNULL RZ_BORROW RzICFG *icfg);

RZ_API bool rz_icfg_solve_conflicts(RZ_NONNULL RzICFG *icfg,
	RZ_NONNULL RzBin *bin,
	RZ_NONNULL RzIO *io,
	RzICFGConflictSolutionCfg cfg);

RZ_API bool rz_icfg_get_cfg(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 entry_point, RZ_OUT RzCFG *cfg_out);
RZ_API void rz_cfg_fini(RZ_NULLABLE RZ_BORROW RzCFG *cfg);

RZ_API bool rz_icfg_copy_to_analysis(const RZ_NONNULL RzICFG *icfg, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE RzAnalysisFcnNameChooser chooser, void *chooser_priv);

#endif // RZ_CFG
