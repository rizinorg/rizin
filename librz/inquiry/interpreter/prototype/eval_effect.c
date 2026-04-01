// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_analysis.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_util/rz_bitvector.h"
#include "rz_util/rz_str.h"

static bool value_indicates_ret_addr_write(RzInterpreterSet *iset, ProtoIntrprAbstrData *val) {
	return val->is_concrete &&
		(rz_bv_to_ut64(val->bv) == iset->astate->bb_addr + iset->astate->bb_size ||
			// Sparc stores the call instruction PC into o8.
			// The return instruction jumps then to o7+8.
			(rz_str_startswith(iset->astate->arch_name, "sparc") && rz_bv_to_ut64(val->bv) == rz_bv_to_ut64(AD(iset->astate->pc->abstr_data)->bv)));
}

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpreterSet *iset,
	const RzILOpEffect *effect,
	size_t insn_pkt_size,
	ProtoIntrprPluginData *plugin_data) {
	STACK_ABSTR_DATA_OUT(eval_out);
	ProtoIntrprAbstrData *pc = AD(iset->astate->pc->abstr_data);

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
			plugin_data->call_cand.store_addr = rz_bv_to_ut64(pc->bv);
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
			report_yield_xref(iset, insn_pkt_size, rz_bv_to_ut64(pc->bv), &eval_out, RZ_ANALYSIS_XREF_TYPE_CODE);
		}
		if (plugin_data->call_cand.store_addr && eval_out.is_concrete) {
			// An instruction in this basic block stored the next PC.
			// Report a call candidate.
			plugin_data->call_cand.candidate_addr = rz_bv_to_ut64(pc->bv);
			plugin_data->call_cand.target = rz_bv_to_ut64(eval_out.bv);
			report_yield_call_candiate(iset, plugin_data);
		}
		memset(&plugin_data->call_cand, 0, sizeof(plugin_data->call_cand));
		copy_abstr_data(iset->astate->pc->abstr_data, &eval_out);
		break;
	}
	case RZ_IL_OP_BRANCH: {
		if (!interpreter_prototype_eval_pure(iset, effect->op.branch.condition, &eval_out, plugin_data)) {
			goto error;
		}
		if (!eval_out.is_concrete) {
			// Bottom values means we can't make a
			// decision (in this prototype implementation).
			break;
		}

		if (abstr_is_true(iset, &eval_out)) {
			if (!interpreter_prototype_eval_effect(iset, effect->op.branch.true_eff, insn_pkt_size, plugin_data)) {
				goto error;
			}
		} else {
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
		if (!interpreter_prototype_eval_pure(iset, pval, &eval_out, plugin_data)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		if (!eval_out.is_concrete) {
			rz_bv_fini(st_addr.bv);
			break;
		}
		if (value_indicates_ret_addr_write(iset, &eval_out)) {
			plugin_data->call_cand.store_addr = rz_bv_to_ut64(pc->bv);
			plugin_data->call_cand.npc = iset->astate->bb_addr + iset->astate->bb_size;
			plugin_data->call_cand.bb_addr = iset->astate->bb_addr;
			plugin_data->call_cand.in_mem = true;
		}
		report_yield_xref(iset, insn_pkt_size, rz_bv_to_ut64(pc->bv), &st_addr, RZ_ANALYSIS_XREF_TYPE_MEM_WRITE);
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
