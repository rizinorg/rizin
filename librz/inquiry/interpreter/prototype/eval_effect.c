// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_analysis.h"
#include "rz_util/rz_bitvector.h"

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
		ProtoIntrprAbstrData *pc = AD(state->pc->abstr_data);
		if (!pc->is_concrete) {
			// The PC is no longer a concrete value.
			// This plugin has no addition for it defined.
			break;
		}
		STACK_ABSTR_DATA_OUT(inc);
		rz_bv_set_from_ut64(inc.bv, state->nop_pc_inc);
		rz_bv_cast_inplace(inc.bv, rz_bv_len(pc->bv), false);
		if (!rz_bv_add_inplace(pc->bv, inc.bv, NULL)) {
			goto error;
		}
		break;
	}
	case RZ_IL_OP_SEQ: {
		if (!interpreter_prototype_eval_effect(state, effect->op.seq.x, yield_queues, io_request, io_result, plugin_data)) {
			goto error;
		}
		if (!interpreter_prototype_eval_effect(state, effect->op.seq.y, yield_queues, io_request, io_result, plugin_data)) {
			goto error;
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
		// Setting the PC to a bottom value is allowed here!
		// The successor function will handle this case.
		copy_abstr_data(state->pc->abstr_data, &eval_out);
		if (eval_out.is_concrete) {
			// NOTE: This prototype can't classify into call or jump.
			// Everything is just a jump for it at this point.
			report_xref_yield(state, yield_queues, rz_bv_to_ut64(AD(state->pc->abstr_data)->bv), &eval_out, RZ_ANALYSIS_XREF_TYPE_CODE);
		}
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
			if (!interpreter_prototype_eval_effect(state, effect->op.branch.true_eff, yield_queues, io_request, io_result, plugin_data)) {
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
	case RZ_IL_OP_STOREW: {
		STACK_ABSTR_DATA_OUT(st_addr);
		RzILOpPure *key = effect->code == RZ_IL_OP_STORE ? effect->op.store.key : effect->op.storew.key;
		if (!interpreter_prototype_eval_pure(state, key, &st_addr, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		if (!st_addr.is_concrete) {
			rz_bv_fini(st_addr.bv);
			break;
		}
		ut64 addr = rz_bv_to_ut64(st_addr.bv);
		RzILOpPure *pval = effect->code == RZ_IL_OP_STORE ? effect->op.store.value : effect->op.storew.value;
		if (!interpreter_prototype_eval_pure(state, pval, &st_addr, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		if (!st_addr.is_concrete) {
			rz_bv_fini(st_addr.bv);
			break;
		}
		report_xref_yield(state, yield_queues, rz_bv_to_ut64(AD(state->pc->abstr_data)->bv), &st_addr, RZ_ANALYSIS_XREF_TYPE_DATA);
		if (!store_abstr_data(state, addr, &st_addr, io_request, io_result)) {
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		rz_bv_fini(st_addr.bv);
		break;
	}
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
