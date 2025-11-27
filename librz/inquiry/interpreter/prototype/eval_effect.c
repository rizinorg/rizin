// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_util/rz_bitvector.h"

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpreterAbstrState *state,
	const RzILOpEffect *effect,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	void *plugin_data) {
	STACK_ABSTR_DATA_OUT(eval_out);

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
		if (!rz_bv_add_inplace(pc->bv, rz_bv_new(state->nop_pc_inc), NULL)) {
			goto error;
		}
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
		break;
	}
	case RZ_IL_OP_SET: {
		ut64 vhash = effect->op.set.hash;
		if (!interpreter_prototype_eval_pure(state, effect->op.set.x, &eval_out, yield_queues, plugin_data)) {
			goto error;
		}
		HtUP *ht_vals = effect->op.set.is_local ? state->locals : state->globals;
		RzInterpreterAbstrVal *av = ht_up_find(ht_vals, vhash, NULL);
		if (!av) {
			av = RZ_NEW(RzInterpreterAbstrVal);
			av->kind = RZ_INTERPRETER_ABSTRACTION_CONST;
			av->abstr_data = RZ_NEW0(ProtoIntrprAbstrData);
			ht_up_insert(ht_vals, vhash, av);
		}
		copy_abstr_data(av->abstr_data, &eval_out);
		break;
	}
	case RZ_IL_OP_JMP: {
		if (!interpreter_prototype_eval_pure(state, effect->op.jmp.dst, &eval_out, yield_queues, plugin_data)) {
			goto error;
		}
		copy_abstr_data(state->pc->abstr_data, &eval_out);
		break;
	}
	case RZ_IL_OP_BRANCH: {
		if (!interpreter_prototype_eval_pure(state, effect->op.branch.condition, &eval_out, yield_queues, plugin_data)) {
			goto error;
		}
		if (!eval_out.is_concrete) {
			// Bottom values means we can't make a
			// decision (in this prototype implementation).
			break;
		}

		// TODO: The assumption that 0 == false is invalid.
		// It depends on the architecture and must be decided by the RzArch plugin.
		if (rz_bv_is_zero_vector(eval_out.bv)) {
			if (!interpreter_prototype_eval_effect(state, effect->op.branch.false_eff, yield_queues, plugin_data)) {
				goto error;
			}
		} else {
			if (!interpreter_prototype_eval_effect(state, effect->op.branch.false_eff, yield_queues, plugin_data)) {
				goto error;
			}
		}
		break;
	}
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
