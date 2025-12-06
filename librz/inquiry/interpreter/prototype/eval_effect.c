// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpreterAbstrState *state,
	const RzILOpEffect *effect,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result,
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
			if (!interpreter_prototype_eval_effect(state, next, yield_queues, io_request, io_result, plugin_data)) {
				goto error;
			}
			next = effect->op.seq.y;
		}
		break;
	}
	case RZ_IL_OP_SET: {
		ut64 vhash = effect->op.set.hash;
		if (!interpreter_prototype_eval_pure(state, effect->op.set.x, &eval_out, yield_queues, io_request, io_result, plugin_data)) {
			goto error;
		}
		write_var_to_state(state,
			effect->op.set.is_local ? RZ_IL_VAR_KIND_LOCAL : RZ_IL_VAR_KIND_GLOBAL,
			vhash,
			&eval_out);
		break;
	}
	case RZ_IL_OP_JMP: {
		if (!interpreter_prototype_eval_pure(state, effect->op.jmp.dst, &eval_out, yield_queues, io_request, io_result, plugin_data)) {
			goto error;
		}
		copy_abstr_data(state->pc->abstr_data, &eval_out);
		break;
	}
	case RZ_IL_OP_BRANCH: {
		if (!interpreter_prototype_eval_pure(state, effect->op.branch.condition, &eval_out, yield_queues, io_request, io_result, plugin_data)) {
			goto error;
		}
		if (!eval_out.is_concrete) {
			// Bottom values means we can't make a
			// decision (in this prototype implementation).
			break;
		}

		if (abstr_is_true(state, &eval_out)) {
			if (!interpreter_prototype_eval_effect(state, effect->op.branch.false_eff, yield_queues, io_request, io_result, plugin_data)) {
				goto error;
			}
		} else {
			if (!interpreter_prototype_eval_effect(state, effect->op.branch.false_eff, yield_queues, io_request, io_result, plugin_data)) {
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
	rz_bv_fini(eval_out.bv);
	return true;
error:
	rz_bv_fini(eval_out.bv);
	return false;
}
