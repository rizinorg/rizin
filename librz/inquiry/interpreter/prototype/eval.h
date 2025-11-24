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

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpreterAbstrState *state,
	const RzILOpEffect *effect,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	void *plugin_data);

#endif // PROTOYPE_EVAL_H
