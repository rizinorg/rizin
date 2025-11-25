// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PROTOYPE_EVAL_H
#define PROTOYPE_EVAL_H

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
 * \brief Up to 64bit-bitvector.
 */
#define STACK_ABSTR_DATA_SMALL_BV(name, bit_len) \
	RzBitVector _##name##_bv = { .len = bit_len, ._elem_len = bit_len / 8, .bits.small_u = 0 }; \
	ProtoIntrprAbstrData name = { .is_concrete = false, .bv = &_##name##_bv };

/**
 * \brief Larger than 64bit-bitvector.
 */
#define STACK_ABSTR_DATA_LARGE_BV(name, bit_len) \
	ut8 _##name##_bv_buf[bit_len / 8] = { 0 }; \
	RzBitVector _##name##_bv = { .len = bit_len, ._elem_len = bit_len / 8, .bits.large_a = _##name##_bv_buf }; \
	ProtoIntrprAbstrData name = { .is_concrete = false, .bv = &_##name##_bv };

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
