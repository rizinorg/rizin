// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_util/rz_bitvector.h"

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpreterAbstrState *state,
	const RzILOpEffect *effect,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	void *plugin_data) {
	switch (effect->code) {
	default:
	case RZ_IL_OP_EMPTY:
		break;
	case RZ_IL_OP_NOP:
		if (AD(state->pc)->is_concrete) {
			// The PC is no longer a concrete value.
			// This plugin has no addition for it defined.
			break;
		}
		RzBitVector *new_pc = rz_bv_add(AD(state->pc)->bv, rz_bv_new(state->nop_pc_inc), NULL);
		if (!AD(state->pc)->bv) {
			goto error;
		}
		rz_bv_free(AD(state->pc)->bv);
		AD(state->pc)->bv = new_pc;
		break;
	case RZ_IL_OP_STORE:
	case RZ_IL_OP_STOREW:
	case RZ_IL_OP_SET:
	case RZ_IL_OP_JMP:
	case RZ_IL_OP_GOTO:
	case RZ_IL_OP_SEQ:
	case RZ_IL_OP_BLK:
	case RZ_IL_OP_REPEAT:
	case RZ_IL_OP_BRANCH:
	}
	return true;
error:
	return false;
}
