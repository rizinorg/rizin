// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_analysis.h"
#include "rz_util/rz_bitvector.h"

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpreterAbstrState *state,
	const RzILOpEffect *effect,
	size_t insn_pkt_size,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result,
	void *plugin_data) {
	STACK_ABSTR_DATA_OUT(eval_out);
	ProtoIntrprAbstrData *pc = AD(state->pc->abstr_data);

	switch (effect->code) {
	default:
	case RZ_IL_OP_EMPTY:
		break;
	case RZ_IL_OP_NOP: {
		if (!pc->is_concrete) {
			// The PC is no longer a concrete value.
			// This plugin has no addition for it defined.
			break;
		}
		STACK_ABSTR_DATA_OUT(inc);
		rz_bv_set_from_ut64(inc.bv, insn_pkt_size);
		rz_bv_cast_inplace(inc.bv, rz_bv_len(pc->bv), false);
#if RZ_BUILD_DEBUG
		ut64 old_pc = rz_bv_to_ut64(pc->bv);
#endif
		if (!rz_bv_add_inplace(pc->bv, inc.bv, NULL)) {
			goto error;
		}
#if RZ_BUILD_DEBUG
		RZ_LOG_DEBUG("Prototype: NOP - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n",
			old_pc,
			rz_bv_to_ut64(pc->bv),
			pc->is_concrete ? "Concrete" : "Abstract");
#endif
		break;
	}
	case RZ_IL_OP_SEQ: {
		if (!interpreter_prototype_eval_effect(state, effect->op.seq.x, insn_pkt_size, yield_queues, io_request, io_result, plugin_data)) {
			goto error;
		}
		if (!interpreter_prototype_eval_effect(state, effect->op.seq.y, insn_pkt_size, yield_queues, io_request, io_result, plugin_data)) {
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
		if (!eval_out.is_concrete) {
			RZ_LOG_DEBUG("PC is going to be set to an abstract value! Current PC = 0x%" PFMT64x "\n", rz_bv_to_ut64(pc->bv));
		}
		RZ_LOG_DEBUG("Prototype: JMP - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n",
			rz_bv_to_ut64(pc->bv),
			rz_bv_to_ut64(eval_out.bv),
			eval_out.is_concrete ? "Concrete" : "Abstract");
		// Setting the PC to a bottom value is allowed here!
		// The successor function will handle this case.
		if (eval_out.is_concrete) {
			// NOTE: This prototype can't classify into call or jump.
			// Everything is just a jump for it at this point.
			report_yield_xref(state, insn_pkt_size, yield_queues, rz_bv_to_ut64(pc->bv), &eval_out, RZ_ANALYSIS_XREF_TYPE_CODE);
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
			if (!interpreter_prototype_eval_effect(state, effect->op.branch.true_eff, insn_pkt_size, yield_queues, io_request, io_result, plugin_data)) {
				goto error;
			}
		} else {
			if (!interpreter_prototype_eval_effect(state, effect->op.branch.false_eff, insn_pkt_size, yield_queues, io_request, io_result, plugin_data)) {
				goto error;
			}
		}
		break;
	}
	case RZ_IL_OP_STORE:
	case RZ_IL_OP_STOREW: {
		STACK_ABSTR_DATA_OUT(st_addr);
		RzILOpPure *key = effect->code == RZ_IL_OP_STORE ? effect->op.store.key : effect->op.storew.key;
		RzILMemIndex mem_idx = effect->code == RZ_IL_OP_STORE ? 0 : effect->op.storew.mem;
		if (!interpreter_prototype_eval_pure(state, key, &st_addr, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: STORE/STOREW key failed to evaluate.\n");
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		if (!st_addr.is_concrete) {
			rz_bv_fini(st_addr.bv);
			break;
		}
		if (rz_bv_len(st_addr.bv) == 64) {
			// TODO: Remove normalization.
			// Unset bit 63 is required, because the RzBuffer API only supports
			// st64 addresses.
			RzBitVector mask = { 0 };
			rz_bv_init(&mask, 64);
			rz_bv_set_from_ut64(&mask, 0x7fffffffffffffff);
			rz_bv_and_inplace(st_addr.bv, &mask);
		}

		RzILOpPure *pval = effect->code == RZ_IL_OP_STORE ? effect->op.store.value : effect->op.storew.value;
		if (!interpreter_prototype_eval_pure(state, pval, &eval_out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		if (!eval_out.is_concrete) {
			rz_bv_fini(st_addr.bv);
			break;
		}
		report_xref_yield(state, insn_pkt_size, yield_queues, rz_bv_to_ut64(AD(state->pc->abstr_data)->bv), &st_addr, RZ_ANALYSIS_XREF_TYPE_MEM_WRITE);
		if (!store_abstr_data(state, mem_idx, &st_addr, &eval_out, io_request, io_result)) {
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		rz_bv_fini(st_addr.bv);
		break;
	}
	case RZ_IL_OP_GOTO:
	case RZ_IL_OP_BLK:
	case RZ_IL_OP_REPEAT:
		RZ_LOG_ERROR("Unhandled effect %" PFMT32d "\n", effect->code);
		// Ignore for now.
		break;
	}
	rz_bv_fini(eval_out.bv);
	return true;
error:
	rz_bv_fini(eval_out.bv);
	return false;
}
