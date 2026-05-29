// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_INQUIRY_BCFG_H
#define RZ_INQUIRY_BCFG_H

#include <rz_types.h>
#include <rz_util.h>

/**
 * \brief A block of instructions which end in a jump/call/exit.
 */
typedef struct {
	ut64 addr;
	ut64 size;
} RzInquiryBlock;

/**
 * \brief The different kind of BB CFG edges.
 */
typedef enum {
	RZ_INQUIRY_BCFG_EDGE_TYPE_NONE = 0,
	/**
	 * \brief An control flow change via a RzIL JMP. The "from" BB ends with a jump.
	 */
	RZ_INQUIRY_BCFG_EDGE_TYPE_JMP,
	/**
	 * \brief A control flow edge between two blocks where the "from" block does not end with a JUMP.
	 * It is between two blocks which were split from a single one.
	 */
	RZ_INQUIRY_BCFG_EDGE_TYPE_CF,
	/**
	 * \brief An control flow change via a RzIL JMP but by a call candidate.
	 * The "from" BB ends with a jump, very likely to a procedure.
	 */
	RZ_INQUIRY_BCFG_EDGE_TYPE_CALL,
	/**
	 * \brief This edge does not depict a control flow edge.
	 * It is an opaque edge between a call instruction and the (possible) return point of the procedure called.
	 * Note that the return point is often, but not always, the instruction at the following memory address after the call.
	 * There are multiple exceptions to it though, like tail calls, non-returning procedures, or delayed calls.
	 */
	RZ_INQUIRY_BCFG_EDGE_TYPE_CALL_RET,
	/**
	 * \brief An edge from a return instruction to its target.
	 */
	RZ_INQUIRY_BCFG_EDGE_TYPE_RETURN,
} RzInquiryBCFGEdgeType;

/**
 * \brief A control flow graph with blocks as nodes.
 * Edges can be of different jump, and call/return type.
 */
typedef struct {
	/**
	 * \brief The CFG discovered during interpretation.
	 * The node data are the addresses of basic blocks, cast to (void *).
	 */
	RzGraph /*<RzInquiryBB *, RzInquiryBCFGEdge *>*/ *graph;
} RzInquiryBCFG;

RZ_IPI RZ_OWN RzInquiryBCFG *rz_inquiry_bcfg_new(RzGraphImplType impl_type);
RZ_IPI void rz_inquiry_bcfg_free(RZ_NULLABLE RZ_OWN RzInquiryBCFG *bcfg);
RZ_IPI bool rz_inquiry_bcfg_add_block(RzInquiryBCFG *cfg, ut64 addr, ut64 size);

RZ_IPI bool rz_inquiry_bcfg_get_block(const RzInquiryBCFG *cfg, ut64 bb_addr, RZ_OUT RzInquiryBlock *bb);
RZ_IPI bool rz_inquiry_bcfg_del_out_edges(RzInquiryBCFG *cfg, ut64 bb_addr);
RZ_IPI bool rz_inquiry_bcfg_add_edge(RzInquiryBCFG *cfg, ut64 from_bb, ut64 to_bb, RzInquiryBCFGEdgeType type);
RZ_IPI bool rz_inquiry_bcfg_add_edge_xref(RzInquiryBCFG *cfg, const RzVector /*<RzAnalysisXRef>*/ *xrefs);
RZ_IPI bool rz_inquiry_bcfg_del_edge(RzInquiryBCFG *cfg, ut64 from_bb, ut64 to_bb);
RZ_API RZ_OWN RzIterator /*<RzGraphNode *>*/ *rz_inquiry_bcfg_get_outgoing_edges(const RzInquiryBCFG *cfg, ut64 bb_addr);
RZ_API RZ_OWN RzIterator /*<RzGraphNode *>*/ *rz_inquiry_bcfg_get_incoming_edges(const RzInquiryBCFG *cfg, ut64 bb_addr);

RZ_IPI bool rz_inquiry_bcfg_reduce(RzInquiryBCFG *cfg);
RZ_IPI RZ_OWN char *rz_inquiry_bcfg_as_dot(const RzInquiryBCFG *bcfg, RZ_NULLABLE const char *name);

#endif // RZ_INQUIRY_BCFG_H
