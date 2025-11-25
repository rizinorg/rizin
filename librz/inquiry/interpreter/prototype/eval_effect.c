// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_util/rz_bitvector.h"

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpreterAbstrState *state,
	const RzILOpEffect *effect,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	void *plugin_data) {
	// STACK_ABSTR_DATA_SMALL_BV(p_out_32, 32);
	// STACK_ABSTR_DATA_LARGE_BV(p_out_128, 128);

	switch (effect->code) {
	default:
	case RZ_IL_OP_EMPTY:
		break;
	case RZ_IL_OP_NOP: {
		ProtoIntrprAbstrData *pc = AD(state->pc);
		if (pc->is_concrete) {
			// The PC is no longer a concrete value.
			// This plugin has no addition for it defined.
			break;
		}
		RzBitVector *new_pc = rz_bv_add(pc->bv, rz_bv_new(state->nop_pc_inc), NULL);
		if (!pc->bv) {
			goto error;
		}
		rz_bv_free(pc->bv);
		pc->bv = new_pc;
		break;
	}
	case RZ_IL_OP_SEQ: {
		const RzILOpEffect *next = effect->op.seq.x;
		while (next) {
			if (!interpreter_prototype_eval_effect(state, next, yield_queues, plugin_data)) {
				goto error;
			}
			next = effect->op.seq.y;
		}
	}
	case RZ_IL_OP_SET:
	case RZ_IL_OP_BRANCH:
	case RZ_IL_OP_JMP:
		// Essential for basic functioning.
		// TODO
	case RZ_IL_OP_STORE:
	case RZ_IL_OP_STOREW:
	case RZ_IL_OP_GOTO:
	case RZ_IL_OP_BLK:
	case RZ_IL_OP_REPEAT:
		// Ignore for now.
		break;
	}
	return true;
error:
	return false;
}
