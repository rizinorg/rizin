// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PROTOYPE_EVAL_H
#define PROTOYPE_EVAL_H

#include "rz_analysis.h"
#include <rz_types.h>
#include <rz_util/rz_bitvector.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>

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

static inline RZ_OWN ProtoIntrprAbstrData *adata_new_top() {
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
	size_t nop_pc_inc);
RZ_IPI bool interpreter_prototype_eval_pure(
	RzInterpRunContext *ctx,
	const RzILOpPure *pure,
	RZ_OUT ProtoIntrprAbstrData *out);

bool report_yield_xref(
	RzInterpRunContext *ctx,
	size_t insn_pkt_size,
	ut64 from,
	const ProtoIntrprAbstrData *to,
	RzAnalysisXRefType type);

bool report_yield_call_candiate(
	RzInterpRunContext *ctx);

bool set_pc(RzInterpAbstrState *state, ut64 pc);

bool set_abstr_pc(RzInterpAbstrState *state, ProtoIntrprAbstrData *pc);

void state_as_str_short(RzInterpInstance *iset, RZ_OUT RzStrBuf *out, RzInterpAbstrState *astate);

#endif // PROTOYPE_EVAL_H
