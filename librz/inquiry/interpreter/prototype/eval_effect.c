// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_analysis.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_util/rz_bitvector.h"
#include "rz_util/rz_str.h"

static bool value_indicates_ret_addr_write(RzInterpSet *iset, ProtoIntrprAbstrData *val) {
	return val->is_const &&
		(rz_bv_to_ut64(val->bv) == iset->astate->bb_addr + iset->astate->bb_size ||
			// Sparc stores the call instruction PC into o8.
			// The return instruction jumps then to o7+8.
			(rz_str_startswith(iset->astate->arch_name, "sparc") && rz_bv_to_ut64(val->bv) == iset->astate->pc));
}

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpSet *iset,
	const RzILOpEffect *effect,
	size_t insn_pkt_size,
	ProtoIntrprPluginData *plugin_data) {
	STACK_ABSTR_DATA_OUT(eval_out);
	rz_return_val_if_fail(iset->astate->pc_state == RZ_INTERP_PC_CONST, false);
	ut64 pc = iset->astate->pc;

	switch (effect->code) {
	default:
	case RZ_IL_OP_EMPTY:
		break;
	case RZ_IL_OP_NOP: {
#if 0
		STACK_ABSTR_DATA_OUT(npc);
		// First cast the bitvector, then set it.
		// This is performance critical. Since the stack allocated bv is >64 bit
		// the rz_bv_set_from_ut64() will set its whole memory, eating a lot of runtime.
		// If we cast before, it is simply an assignment to bv->small_bits.
		rz_bv_cast_inplace(npc.bv, rz_bv_len(pc->bv), false);
		rz_bv_set_from_ut64(npc.bv, insn_pkt_size);
		if (!rz_bv_add_inplace(npc.bv, pc->bv, NULL)) {
			goto error;
		}
		set_abstr_pc(iset->astate, &npc, plugin_data);
#endif
		break;
	}
	case RZ_IL_OP_SEQ: {
		if (!interpreter_prototype_eval_effect(iset, effect->op.seq.x, insn_pkt_size, plugin_data)) {
			goto error;
		}
		if (!interpreter_prototype_eval_effect(iset, effect->op.seq.y, insn_pkt_size, plugin_data)) {
			goto error;
		}
		break;
	}
	case RZ_IL_OP_SET: {
		ut64 vhash = effect->op.set.hash;
		if (!interpreter_prototype_eval_pure(iset, effect->op.set.x, &eval_out, plugin_data)) {
			goto error;
		}
		RzILVarKind kind = effect->op.set.is_local ? RZ_IL_VAR_KIND_LOCAL : RZ_IL_VAR_KIND_GLOBAL;
		write_var_to_state(iset, kind, vhash, &eval_out);
		if (value_indicates_ret_addr_write(iset, &eval_out) &&
			kind == RZ_IL_VAR_KIND_GLOBAL) {
			plugin_data->call_cand.store_addr = pc;
			plugin_data->call_cand.npc = iset->astate->bb_addr + iset->astate->bb_size;
			plugin_data->call_cand.bb_addr = iset->astate->bb_addr;
			plugin_data->call_cand.in_mem = false;
		}
		break;
	}
	case RZ_IL_OP_JMP: {
		if (!interpreter_prototype_eval_pure(iset, effect->op.jmp.dst, &eval_out, plugin_data)) {
			goto error;
		}
		if (!eval_out.is_const) {
			RZ_LOG_DEBUG("PC is going to be set to an abstract value! Current PC = 0x%" PFMT64x "\n", pc);
		}
		ut64 target = rz_bv_to_ut64(eval_out.bv);
		bool is_call = plugin_data->call_cand.store_addr;
		RZ_LOG_DEBUG("prototype: JMP - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n",
			pc, target,
			eval_out.is_const ? "Concrete" : "Abstract");

		if (eval_out.is_const) {
			RzAnalysisXRefType xref_type = RZ_ANALYSIS_XREF_TYPE_CODE;

			if (is_call) {
				// An instruction in this basic block stored the next PC.
				// Report a call candidate and assume this jump is a call.
				plugin_data->call_cand.candidate_addr = pc;
				plugin_data->call_cand.target = target;
				report_yield_call_candiate(iset, plugin_data);

				// For a call, we need to push a new frame.
				RzBitVector ret_addr = { 0 };
				rz_bv_init(&ret_addr, rz_bv_len(eval_out.bv));
				rz_bv_set_from_ut64(&ret_addr, plugin_data->call_cand.npc);

				bool found = false;
				ut64 ic = ht_uu_find(plugin_data->bb_invocation_count, plugin_data->call_cand.target, &found);
				stack_frame_push(plugin_data, eval_out.bv, &ret_addr, !found ? 0 : ic);
				rz_bv_fini(&ret_addr);

				xref_type = RZ_ANALYSIS_XREF_TYPE_CALL;
			}
			if (xref_type == RZ_ANALYSIS_XREF_TYPE_CODE && stack_frame_top_ret_addr_cmp(plugin_data, eval_out.bv)) {
				stack_frame_pop(plugin_data, NULL);
				xref_type = RZ_ANALYSIS_XREF_TYPE_RETURN;
			}

			report_yield_xref(iset, insn_pkt_size, pc, &eval_out,
				xref_type);

			// Clear the call candidate tracking variable.
			memset(&plugin_data->call_cand, 0, sizeof(plugin_data->call_cand));
		}

		if (is_call) {
			// For calls, assume control flow will continue like fallthrough.
			// TODO: set data to top that may be changed by the call
		} else {
			set_abstr_pc(iset->astate, &eval_out, plugin_data);
		}
		break;
	}
	case RZ_IL_OP_BRANCH: {
		if (!interpreter_prototype_eval_pure(iset, effect->op.branch.condition, &eval_out, plugin_data)) {
			goto error;
		}
		bool may_be_true = abstr_may_be_true(iset, &eval_out);
		bool may_be_false = abstr_may_be_true(iset, &eval_out);
		if (may_be_true && may_be_false) {
			RzInterpAbstrState *true_state = rz_interpreter_abstr_state_clone(iset, iset->astate);
			RzInterpAbstrState *false_state = iset->astate;
			iset->astate = true_state;
			if (!interpreter_prototype_eval_effect(iset, effect->op.branch.true_eff, insn_pkt_size, plugin_data)) {
				goto error;
			}
			iset->astate = false_state;
			if (!interpreter_prototype_eval_effect(iset, effect->op.branch.false_eff, insn_pkt_size, plugin_data)) {
				goto error;
			}
			if (true_state->pc_state == false_state->pc_state && true_state->pc == false_state->pc) {
				// identical target location, simply join the data and continue
				iset->plugin->join_state(true_state, false_state, iset->intrpr_priv);
			} else {
				// different jump targets, branch rather than resorting to top pc
				rz_interp_set_push(iset, true_state);
				// true_state is already in iset->astate and will be continued automatically
			}
			rz_interpreter_abstr_state_free(true_state);
		} else if (may_be_true) {
			if (!interpreter_prototype_eval_effect(iset, effect->op.branch.true_eff, insn_pkt_size, plugin_data)) {
				goto error;
			}
		} else if (may_be_false) {
			if (!interpreter_prototype_eval_effect(iset, effect->op.branch.false_eff, insn_pkt_size, plugin_data)) {
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
		if (!interpreter_prototype_eval_pure(iset, key, &st_addr, plugin_data)) {
			RZ_LOG_ERROR("prototype: STORE/STOREW key failed to evaluate.\n");
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		if (!st_addr.is_const) {
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
		if (!interpreter_prototype_eval_pure(iset, pval, &eval_out, plugin_data)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		if (!eval_out.is_const) {
			rz_bv_fini(st_addr.bv);
			break;
		}
		if (value_indicates_ret_addr_write(iset, &eval_out)) {
			plugin_data->call_cand.store_addr = pc;
			plugin_data->call_cand.npc = iset->astate->bb_addr + iset->astate->bb_size;
			plugin_data->call_cand.bb_addr = iset->astate->bb_addr;
			plugin_data->call_cand.in_mem = true;
		}
		report_yield_xref(iset, insn_pkt_size, pc, &st_addr, RZ_ANALYSIS_XREF_TYPE_MEM_WRITE);
		if (!store_abstr_data(iset, mem_idx, &st_addr, &eval_out)) {
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
