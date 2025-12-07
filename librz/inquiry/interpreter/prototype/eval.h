// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PROTOYPE_EVAL_H
#define PROTOYPE_EVAL_H

#include <rz_types.h>
#include <rz_util/rz_bitvector.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>

/**
 * \brief Abstract data getter from the RzInterpreterAbstrVal
 */
#define AD(av) (((ProtoIntrprAbstrData *)av))

typedef struct {
	/**
	 * \brief Set if the bit vector below is a valid concrete value.
	 * If unset it is a bottom value.
	 */
	bool is_concrete;
	/**
	 * \brief The concrete value. If is_concrete is unset this might hold garbage.
	 */
	RzBitVector *bv;
} ProtoIntrprAbstrData;

/**
 * \brief In bytes
 */
#define BV_STACK_MAX_SIZE 0x1000

/**
 * \brief Initializes an AbstractData object on the stack.
 * The bitvector pre-allocates BV_STACK_MAX_SIZE bytes on the stack for large bit vectors.
 * Any value larger than these bits will be stored in heap allocated memory.
 * Because of this the bit vector should always be passed to rz_bv_fini() after usage.
 */
#define STACK_ABSTR_DATA_OUT(name) \
	ut8 _##name##_bv_large_buf[BV_STACK_MAX_SIZE] = { 0 }; \
	RzBitVector _##name##_bv_large = { .len = BV_STACK_MAX_SIZE, ._elem_len = BV_STACK_MAX_SIZE, .bits.large_a = _##name##_bv_large_buf, .stack_alloc = true }; \
	ProtoIntrprAbstrData name = { .is_concrete = false, .bv = &_##name##_bv_large };

/**
 * \brief Creates abstract data on the heap with the given bit vector.
 */
static inline RZ_OWN ProtoIntrprAbstrData *adata_from_bv(const RzBitVector *bv) {
	ProtoIntrprAbstrData *ad = RZ_NEW(ProtoIntrprAbstrData);
	ad->is_concrete = true;
	ad->bv = rz_bv_dup(bv);
	return ad;
}

static inline RZ_OWN ProtoIntrprAbstrData *adata_new() {
	ProtoIntrprAbstrData *ad = RZ_NEW(ProtoIntrprAbstrData);
	ad->is_concrete = false;
	ad->bv = rz_bv_new(BV_STACK_MAX_SIZE);
	return ad;
}

void copy_abstr_data(ProtoIntrprAbstrData *dst, const ProtoIntrprAbstrData *src);
void write_var_to_state(RzInterpreterAbstrState *state, RzILVarKind kind, ut64 var_id, const ProtoIntrprAbstrData *data);
bool read_var_from_state(RzInterpreterAbstrState *state, RzILVarKind kind, ut64 var_id, RZ_OUT ProtoIntrprAbstrData *data);
bool abstr_is_true(const RzInterpreterAbstrState *state, const ProtoIntrprAbstrData *data);
bool store_abstr_data(
	RzInterpreterAbstrState *state,
	ut64 addr,
	const ProtoIntrprAbstrData *src,
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result);
bool load_abstr_data(
	RzInterpreterAbstrState *state,
	ut64 addr,
	size_t size,
	RZ_OUT ProtoIntrprAbstrData *out,
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result);

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpreterAbstrState *state,
	const RzILOpEffect *effect,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result,
	void *plugin_data);
RZ_IPI bool interpreter_prototype_eval_pure(
	RzInterpreterAbstrState *state,
	const RzILOpPure *pure,
	RZ_OUT ProtoIntrprAbstrData *out,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result,
	void *plugin_data);

#endif // PROTOYPE_EVAL_H
