// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PROTOYPE_EVAL_H
#define PROTOYPE_EVAL_H

#include "rz_types.h"
#include "rz_util/rz_bitvector.h"
#include <rz_inquiry/rz_interpreter.h>
#include <rz_il/rz_il_opcodes.h>

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
 * \brief Initializes an AbstractData object on the stack.
 * The bit vector in it is for now hard coded to 0x2000 bytes.
 * TODO: This won't matter anymore, when in-place casting
 * and appending of bit vectors is implemented.
 */
#define STACK_ABSTR_DATA_OUT(name) \
	ut8 _##name##_bv_large_buf[0x2000 / 8] = { 0 }; \
	RzBitVector _##name##_bv_large = { .len = 0x2000, ._elem_len = 0x2000 / 8, .bits.large_a = _##name##_bv_large_buf }; \
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

void copy_abstr_data(ProtoIntrprAbstrData *dst, const ProtoIntrprAbstrData *src);
void write_var_to_state(RzInterpreterAbstrState *state, RzILVarKind kind, ut64 var_id, const ProtoIntrprAbstrData *data);
bool read_var_from_state(RzInterpreterAbstrState *state, RzILVarKind kind, ut64 var_id, RZ_OUT ProtoIntrprAbstrData *data);

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpreterAbstrState *state,
	const RzILOpEffect *effect,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	void *plugin_data);
RZ_IPI bool interpreter_prototype_eval_pure(
	RzInterpreterAbstrState *state,
	const RzILOpPure *pure,
	RZ_OUT ProtoIntrprAbstrData *out,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	void *plugin_data);

#endif // PROTOYPE_EVAL_H
