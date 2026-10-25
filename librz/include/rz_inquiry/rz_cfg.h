// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Control flow graphs (CFGs) implementations.
 */

#ifndef RZ_CFG
#define RZ_CFG

#include <rz_util.h>

/**
 * \brief The inter-procedural CFG of the program.
 */
typedef struct rz_icfg_t RzICFG;

/**
 * \brief The CFG of a single procedure.
 */
typedef struct rz_cfg_t RzCFG;

typedef enum {
	RZ_CFG_NODE_NON = 0, ///< No attributes.
	RZ_CFG_NODE_JMP_IN = 1 << 1, ///< Block as *at least* one incoming jump edge.
	RZ_CFG_NODE_JMP_OUT = 1 << 2, ///< Block as *at least* one outgoing jump edge.
	RZ_CFG_NODE_CALL_IN = 1 << 3, ///< Block as *at least* one incoming call edge.
	RZ_CFG_NODE_CALL_OUT = 1 << 4, ///< Block as *at least* one outgoing call edge.
	RZ_CFG_NODE_FALLTRHU_IN = 1 << 5, ///< Block as *at least* one incoming fall through edge.
	RZ_CFG_NODE_FALLTRHU_OUT = 1 << 6, ///< Block as *at least* one outgoing fall through edge.
	// TODO: Other attributes of interest could be:
	// - Privilege level of that block (TEE, SM, hypervisor, guest, kernel, user etc.)
} RzCFGNodeAttr;

typedef struct rz_cfg_node_t {
	/**
	 * \brief The offsets of the instructions (packets), from the block start address.
	 * Starting at the second instruction in the block (since first is always 0), offsets from the start of the block
	 */
	RzVector /*<ut16>*/ insn_offsets;
	/**
	 * \brief The function entry points this block can be reached from without walking a call edge.
	 */
	RzVector /*<ut64>*/ fcn_memberships;
	/**
	 * \brief Block attributes. Kept in sync with the CFG.
	 * Used for accessing most important information, without the need to access the CFG edges.
	 */
	RzCFGNodeAttr attrs;
} RzCFGNode;

typedef enum rz_cfg_edge_type_t {
	RZ_CFG_EDGE_TYPE_FALLTHROUGH = 0, ///< Fall through between two blocks.
	RZ_CFG_EDGE_TYPE_JUMP, ///< Jumps to another address.
	/**
	 * \brief Calling a procedure. A jump which usually does something like:
	 * - back up its return address
	 * - manipulates some kind of stack
	 * - manipulates the argument registers.
	 * Not all of them have to be present of course.
	 *
	 * NOTE: Tail calls are call edges as well, even though they are often
	 * "jump" instructions in assembly.
	 */
	RZ_CFG_EDGE_TYPE_CALL,
	RZ_CFG_EDGE_TYPE_RETURN, ///< Return from procedure.
} RzCFGEdgeType;

RZ_API RZ_OWN RzICFG *rz_icfg_new();
RZ_API void rz_icfg_free(RZ_NULLABLE RZ_OWN RzICFG *);
RZ_API bool rz_icfg_get_cfg(RZ_NONNULL RZ_BORROW RzICFG *icfg, ut64 entry_point, RZ_OUT RzCFG *cfg_out);

RZ_API void rz_cfg_fini(RZ_NULLABLE RZ_BORROW RzCFG *cfg);

RZ_API RZ_OWN RzCFGNode *rz_icfg_node_new();
RZ_API void rz_icfg_node_free(RZ_NULLABLE RZ_OWN RzCFGNode *);

#endif // RZ_CFG
