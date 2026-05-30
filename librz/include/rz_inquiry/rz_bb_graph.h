// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_INQUIRY_BB_GRAPH_H
#define RZ_INQUIRY_BB_GRAPH_H

#include <rz_types.h>
#include <rz_util.h>

typedef struct {
	ut64 addr;
	ut64 size;
} RzInquiryBB;

/**
 * \brief The different kind of BB CFG edges.
 */
typedef enum {
	RZ_INQUIRY_BB_CFG_EDGE_TYPE_NONE = 0,
	/**
	 * \brief An control flow change via a RzIL JMP. The "from" BB ends with a jump.
	 */
	RZ_INQUIRY_BB_CFG_EDGE_TYPE_JMP,
	/**
	 * \brief A control flow edge between two blocks where the "from" block does not end with a JUMP.
	 * It is between two blocks which were split from a single one.
	 */
	RZ_INQUIRY_BB_CFG_EDGE_TYPE_CF,
	/**
	 * \brief An control flow change via a RzIL JMP but by a call candidate.
	 * The "from" BB ends with a jump, very likely to a procedure.
	 */
	RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL,
	/**
	 * \brief This edge does not depict a control flow edge.
	 * It is an opaque edge between a call instruction and the (possible) return point of the procedure called.
	 * Note that the return point is often, but not always, the instruction at the following memory address after the call.
	 * There are multiple exceptions to it though, like tail calls, non-returning procedures, or delayed calls.
	 */
	RZ_INQUIRY_BB_CFG_EDGE_TYPE_CALL_RET,
	/**
	 * \brief An edge from a return instruction to its target.
	 */
	RZ_INQUIRY_BB_CFG_EDGE_TYPE_RETURN,
} RzInquiryBBCFGEdgeType;

/**
 * \brief A control flow graph with basic blocks as nodes.
 * Edges can be of different jump, and call/return type.
 */
typedef struct {
	/**
	 * \brief The CFG discovered during interpretation.
	 * The node data are the addresses of basic blocks, cast to (void *).
	 */
	RzGraph /*<RzInquiryBB *, RzInquiryBBCFGEdge *>*/ *graph;
} RzInquiryBBCFG;

RZ_IPI RZ_OWN RzInquiryBB *rz_inquiry_bb_new(ut64 addr, ut64 size);
RZ_IPI void rz_inquiry_bb_free(RZ_NULLABLE RZ_OWN RzInquiryBB *bb);

RZ_IPI RZ_OWN RzInquiryBBCFG *rz_inquiry_bb_cfg_new(RzGraphImplType impl_type);
RZ_IPI void rz_inquiry_bb_cfg_free(RZ_NULLABLE RZ_OWN RzInquiryBBCFG *bb_cfg);
RZ_IPI bool rz_inquiry_bb_cfg_add_basic_block(RzInquiryBBCFG *cfg, ut64 addr, ut64 size);
RZ_IPI bool rz_inquiry_bb_cfg_add_xrefs(RzInquiryBBCFG *cfg, RzVector /*<RzAnalysisXRef>*/ *xrefs);
RZ_IPI bool rz_inquiry_bb_cfg_get_basic_block(const RzInquiryBBCFG *cfg, ut64 bb_addr, RZ_OUT RzInquiryBB *bb);
RZ_IPI bool rz_inquiry_bb_cfg_del_out_edges(RzInquiryBBCFG *cfg, ut64 bb_addr);
RZ_IPI bool rz_inquiry_bb_cfg_add_edge(RzInquiryBBCFG *cfg, ut64 from_bb, ut64 to_bb, RzInquiryBBCFGEdgeType type);
RZ_API RZ_OWN RzIterator /*<RzGraphNode *>*/ *rz_inquiry_bb_cfg_get_outgoing_edges(const RzInquiryBBCFG *cfg, ut64 bb_addr);
RZ_API RZ_OWN RzIterator /*<RzGraphNode *>*/ *rz_inquiry_bb_cfg_get_incoming_edges(const RzInquiryBBCFG *cfg, ut64 bb_addr);

RZ_IPI bool rz_inquiry_bb_cfg_reduce(RzInquiryBBCFG *cfg);

#endif // RZ_INQUIRY_BB_GRAPH_H
