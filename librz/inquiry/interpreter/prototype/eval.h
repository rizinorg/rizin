// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PROTOYPE_EVAL_H
#define PROTOYPE_EVAL_H

#include "rz_analysis.h"
#include <rz_types.h>
#include <rz_util/rz_bitvector.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>

/**
 * \brief Abstract data getter from the RzInterpAbstrVal
 */
#define AD(av) (((ProtoIntrprAbstrData *)av))

typedef struct {
	/**
	 * \brief Set if the abstract value represents a single constant bitvector.
	 * If set, the bit vector below is a valid concrete value.
	 * If unset it is a top value, i.e. represents the set of all bitvectors.
	 */
	bool is_const;
	/**
	 * \brief The single constant value.
	 * If is_const is unset this might hold garbage.
	 */
	RzBitVector *bv;
} ProtoIntrprAbstrData;

typedef struct {
	/**
	 * \brief The procedure's entry point this frame was initialized at.
	 */
	RzBitVector entry_point;
	/**
	 * \brief The number of times that frame was initialized at the entry point.
	 * This is equivalent to the number of times the function was called at this entry point.
	 */
	ut64 instance;
	/**
	 * \brief The return address of the procedure.
	 * TODO: The return address might be wrong in case of tail calls.
	 * The prototype doesn't really check what address was stored in the link register
	 * or on the stack (due to missing abstraction of archs calling convention).
	 * Instead, it simply stores the instruction address which comes after the call
	 * in memory.
	 */
	RzBitVector return_addr;

	// TODO: The abstract stack pointer at the point of procedure entry should be tracked here.
	// But this needs to wait until we have a proper memory model implemented.
} ProtoInterprAbstrStackFrame;

typedef struct {
	HtUU *bb_invocation_count;
	RzAnalysisCallCandidate call_cand; ///< Data of a call candidate.
	RzVector /*<ProtoInterprAbstrStackFrame>*/ stack; ///< The call frame stack.
	ut64 prev_pc; ///< Previous PC. Set to UT64_MAX if it was invalid.
} ProtoIntrprPluginData;

/**
 * \brief In bytes
 *
 * TODO: find a sweet spot here where this size is as small is possible,
 * but in practice only very few heap allocations have to happen.
 */
#define BV_STACK_MAX_SIZE 0x100

/**
 * \brief Initializes an AbstractData object on the stack.
 * The bitvector pre-allocates BV_STACK_MAX_SIZE bytes on the stack for large bit vectors.
 * Any value larger than these bits will be stored in heap allocated memory.
 * Because of this the bit vector should always be passed to rz_bv_fini() after usage.
 */
#define STACK_ABSTR_DATA_OUT(name) \
	ut8 _##name##_bv_large_buf[BV_STACK_MAX_SIZE] = { 0 }; \
	RzBitVector _##name##_bv_large = { .len = BV_STACK_MAX_SIZE, ._elem_len = BV_STACK_MAX_SIZE, .bits.large_a = _##name##_bv_large_buf, .stack_alloc = true }; \
	ProtoIntrprAbstrData name = { .is_const = false, .bv = &_##name##_bv_large };

/**
 * \brief Creates abstract data on the heap with the given bit vector.
 */
static inline RZ_OWN ProtoIntrprAbstrData *adata_from_bv(const RzBitVector *bv) {
	ProtoIntrprAbstrData *ad = RZ_NEW0(ProtoIntrprAbstrData);
	ad->is_const = true;
	ad->bv = rz_bv_dup(bv);
	return ad;
}

static inline RZ_OWN ProtoIntrprAbstrData *adata_new() {
	ProtoIntrprAbstrData *ad = RZ_NEW0(ProtoIntrprAbstrData);
	ad->is_const = false;
	ad->bv = rz_bv_new(BV_STACK_MAX_SIZE);
	return ad;
}

void copy_abstr_data(ProtoIntrprAbstrData *dst, const ProtoIntrprAbstrData *src);
void write_var_to_state(RzInterpAbstrState *astate, RzILVarKind kind, ut64 var_id, const ProtoIntrprAbstrData *data);
bool read_var_from_state(RzInterpAbstrState *astate, RzILVarKind kind, ut64 var_id, RZ_OUT ProtoIntrprAbstrData *data);
bool abstr_is_true(const RzInterpInstance *iset, const ProtoIntrprAbstrData *data);
bool abstr_may_be_true(const RzInterpInstance *iset, const ProtoIntrprAbstrData *data);
bool abstr_may_be_false(const RzInterpInstance *iset, const ProtoIntrprAbstrData *data);
bool store_abstr_data(
	RzInterpInstance *iset,
	RzILMemIndex mem_idx,
	const ProtoIntrprAbstrData *addr,
	const ProtoIntrprAbstrData *src);
bool load_abstr_data(
	RzInterpInstance *iset,
	RzILMemIndex mem_idx,
	const ProtoIntrprAbstrData *addr,
	size_t n_bits,
	RZ_OUT ProtoIntrprAbstrData *out);

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpRunContext *ctx,
	const RzILOpEffect *effect,
	size_t nop_pc_inc,
	ProtoIntrprPluginData *plugin_data);
RZ_IPI bool interpreter_prototype_eval_pure(
	RzInterpRunContext *ctx,
	const RzILOpPure *pure,
	RZ_OUT ProtoIntrprAbstrData *out,
	ProtoIntrprPluginData *plugin_data);

bool report_yield_xref(
	RzInterpRunContext *ctx,
	size_t insn_pkt_size,
	ut64 from,
	const ProtoIntrprAbstrData *to,
	RzAnalysisXRefType type);

bool report_yield_call_candiate(
	RzInterpInstance *iset,
	ProtoIntrprPluginData *plugin_data);

bool set_pc(RzInterpAbstrState *state, ut64 pc,
	void *plugin_data);

bool set_abstr_pc(RzInterpAbstrState *state, ProtoIntrprAbstrData *pc,
	void *plugin_data);

void stack_frame_fini(ProtoInterprAbstrStackFrame *frame, void *unused);
void stack_frame_push(ProtoIntrprPluginData *pdata, RzBitVector *entry_point, RzBitVector *return_addr, ut64 instance);
void stack_frame_pop(ProtoIntrprPluginData *pdata, RZ_NULLABLE ProtoInterprAbstrStackFrame *frame);
bool stack_frame_top_ret_addr_cmp(ProtoIntrprPluginData *pdata, RzBitVector *addr);
void state_as_str_short(RzInterpInstance *iset, RZ_OUT RzStrBuf *out, RzInterpAbstrState *astate);

#endif // PROTOYPE_EVAL_H
