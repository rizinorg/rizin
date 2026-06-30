// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_analysis.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_th.h"
#include "rz_types.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_log.h"
#include <rz_util/rz_bitvector.h>

bool report_yield_xref(
	RzInterpRunContext *ctx,
	size_t insn_pkt_size,
	ut64 from,
	const ProtoIntrprAbstrData *to,
	RzAnalysisXRefType type) {
	if (!to->is_const || rz_bv_len(to->bv) > 64) {
		// Isn't reported
		return true;
	}
	if (type == RZ_ANALYSIS_XREF_TYPE_CODE &&
		RZ_STR_EQ(ctx->astate->arch_name, "hexagon") &&
		from + insn_pkt_size == rz_bv_to_ut64(to->bv)) {
		// Ugly work around.
		// Because we don't have RzArch yet the Hexagon plugin adds a JUMP at the
		// end of each and every instruction packet.
		// This is necessary because the RzIL VM would otherwise just add 4 to the PC,
		// which is too little for a packet with 2+ instructions.
		// We don't want to report the code references to the next instruction
		// packet. So skip them here.
		return true;
	}

	RzInterpYieldRBuf *yrbuf = ctx->inst->yield_rbufs[RZ_INTERP_YIELD_KIND_XREF];
	rz_return_val_if_fail(yrbuf, false);

	ut64 to_addr = rz_bv_to_ut64(to->bv);
	RzAnalysisXRef xref = { 0 };
	xref.bb_addr = ctx->astate->bb_addr;
	xref.from = from;
	xref.to = to_addr;
	xref.type = type;
	if (yrbuf->filter(&xref, yrbuf->filter_data->io_boundaries)) {
		RZ_LOG_DEBUG("prototype: REPORT xref: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n", xref.from, xref.to, rz_analysis_ref_type_tostring(xref.type));
		if (rz_th_ring_buf_put(yrbuf->rbuf, &xref) != RZ_THREAD_RING_BUF_OK) {
			return false;
		}
	}
	return true;
}

/**
 * \brief Report the store of the next PC and report it as possible return point.
 */
bool report_yield_call_candiate(
	RzInterpRunContext *ctx) {
	RzInterpYieldRBuf *cc_rbuf = ctx->inst->yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE];
	rz_return_val_if_fail(cc_rbuf, false);

	RzAnalysisCallCandidate cc = { 0 };
	memcpy(&cc, &ctx->call_cand, sizeof(ctx->call_cand));
	if (rz_th_ring_buf_put(cc_rbuf->rbuf, &cc) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	return true;
}

void copy_abstr_data(ProtoIntrprAbstrData *dst, const ProtoIntrprAbstrData *src) {
	rz_return_if_fail(dst && src && dst->bv && src->bv);
	rz_bv_cast_inplace(dst->bv, rz_bv_len(src->bv), false);
	rz_bv_copy(dst->bv, src->bv);
	dst->is_const = src->is_const;
}

void write_var_to_state(RzInterpAbstrState *astate,
	RzILVarKind kind,
	ut64 var_id,
	const ProtoIntrprAbstrData *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = astate->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = astate->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = astate->lets;
		break;
	}
	ProtoIntrprAbstrData *av = ht_up_find(ht_vals, var_id, NULL);
	if (!av) {
		if (kind == RZ_IL_VAR_KIND_GLOBAL) {
			RZ_LOG_WARN("New global variable created: 0x%" PFMT64x "\n", var_id)
			return;
		}
		av = adata_new_top();
		if (!av) {
			rz_warn_if_reached();
			return;
		}
		ht_up_insert(ht_vals, var_id, av);
	}
	copy_abstr_data(av, data);
}

bool read_var_from_state(RzInterpAbstrState *astate,
	RzILVarKind kind,
	ut64 var_id,
	RZ_OUT ProtoIntrprAbstrData *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return false;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = astate->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = astate->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = astate->lets;
		break;
	}
	RzInterpAbstrVal *av = ht_up_find(ht_vals, var_id, NULL);
	if (!av) {
		// Variable doesn't exist.
		// This should never happen and is a bug.
		rz_warn_if_reached();
		return false;
	}
	copy_abstr_data(data, av);
	return true;
}

// Returns true if the bit vector in \p data is not zero. If it is zero or
// the abstract data is not concrete it returns false.
//
// TODO: The assumption that true != 0 is invalid.
// It depends on the architecture and must be decided by the RzArch plugin.
// State is passed due to this here as well. To make later refactoring easier.
bool abstr_is_true(const RzInterpInstance *iset, const ProtoIntrprAbstrData *data) {
	if (!data->is_const) {
		return false;
	}
	return !rz_bv_is_zero_vector(data->bv);
}

bool abstr_may_be_true(const RzInterpInstance *iset, const ProtoIntrprAbstrData *data) {
	if (!data->is_const) {
		return true;
	}
	return !rz_bv_is_zero_vector(data->bv);
}

bool abstr_may_be_false(const RzInterpInstance *iset, const ProtoIntrprAbstrData *data) {
	if (!data->is_const) {
		return true;
	}
	return rz_bv_is_zero_vector(data->bv);
}

bool store_abstr_data(
	RzInterpInstance *iset,
	RzILMemIndex mem_idx,
	const ProtoIntrprAbstrData *addr,
	const ProtoIntrprAbstrData *src) {
	// TODO: handle with memory abstractions
	return true;
}

bool load_abstr_data(
	RzInterpInstance *iset,
	RzILMemIndex mem_idx,
	const ProtoIntrprAbstrData *addr,
	size_t n_bits,
	RZ_OUT ProtoIntrprAbstrData *out) {
	RzInterpIOReadRequest io_req = { 0 };
	rz_bv_cast_inplace(out->bv, n_bits, 0);
	io_req.addr = addr->bv;
	io_req.ld_data = out->bv;
	io_req.mem_idx = mem_idx;
	io_req.n_bits = n_bits;
	io_req.big_endian = iset->il_ctx->config->big_endian;
	if (rz_th_ring_buf_put(iset->io_request_rbuf, &io_req) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	RzInterpIOResult io_res = { 0 };
	if (rz_th_ring_buf_take_blocking(iset->io_result_rbuf, &io_res) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	if (!io_res.req_ok) {
		RZ_LOG_WARN("prototype: Failed to read correct number of bytes. Requested: 0x%" PFMTSZx
			    " Received: 0x%" PFMT32x " bits.\n",
			n_bits, rz_bv_len(out->bv));
		return false;
	}
	out->is_const = true;

	char *bytes = rz_bv_as_hex_string(out->bv, true);
	RZ_LOG_DEBUG("prototype: READ @ mem:%" PFMT32d " 0x%" PFMT64x " : %s\n", mem_idx, rz_bv_to_ut64(io_req.addr), bytes);
	free(bytes);
	return true;
}

bool set_abstr_pc(RzInterpAbstrState *state, ProtoIntrprAbstrData *pc) {
	rz_return_val_if_fail(state && pc, false);
	if (pc->is_const) {
		state->pc_state = RZ_INTERP_PC_CONST;
		state->pc = rz_bv_to_ut64(pc->bv);
	} else {
		state->pc_state = RZ_INTERP_PC_ANY;
	}
	RZ_LOG_DEBUG("prototype: set_abstr_pc() - Set PC: 0x%" PFMT64x " (%s)\n",
		state->pc, state->pc_state == RZ_INTERP_PC_CONST ? "Constant" : "Top");
	return true;
}

bool set_pc(RzInterpAbstrState *state, ut64 pc) {
	rz_return_val_if_fail(state, false);
	state->pc = pc;
	state->pc_state = RZ_INTERP_PC_CONST;
	RZ_LOG_DEBUG("prototype: set_pc() - Set PC: 0x%" PFMT64x " (Constant)\n", pc);
	return true;
}

static bool value_indicates_ret_addr_write(RzInterpRunContext *ctx, ProtoIntrprAbstrData *val) {
	return val->is_const &&
		(rz_bv_to_ut64(val->bv) == ctx->astate->bb_addr + ctx->astate->bb_size ||
			// Sparc stores the call instruction PC into o8.
			// The return instruction jumps then to o7+8.
			(rz_str_startswith(ctx->astate->arch_name, "sparc") && rz_bv_to_ut64(val->bv) == ctx->astate->pc));
}

RZ_IPI bool interpreter_prototype_eval_effect(RzInterpRunContext *ctx,
	const RzILOpEffect *effect,
	size_t insn_pkt_size) {
	STACK_ABSTR_DATA_OUT(eval_out);
	rz_return_val_if_fail(ctx->astate->pc_state == RZ_INTERP_PC_CONST, false);
	ut64 pc = ctx->astate->pc;

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
		set_abstr_pc(iset->astate, &npc);
#endif
		break;
	}
	case RZ_IL_OP_SEQ: {
		if (!interpreter_prototype_eval_effect(ctx, effect->op.seq.x, insn_pkt_size)) {
			goto error;
		}
		if (!interpreter_prototype_eval_effect(ctx, effect->op.seq.y, insn_pkt_size)) {
			goto error;
		}
		break;
	}
	case RZ_IL_OP_SET: {
		ut64 vhash = effect->op.set.hash;
		if (!interpreter_prototype_eval_pure(ctx, effect->op.set.x, &eval_out)) {
			goto error;
		}
		RzILVarKind kind = effect->op.set.is_local ? RZ_IL_VAR_KIND_LOCAL : RZ_IL_VAR_KIND_GLOBAL;
		write_var_to_state(ctx->astate, kind, vhash, &eval_out);
		if (value_indicates_ret_addr_write(ctx, &eval_out) &&
			kind == RZ_IL_VAR_KIND_GLOBAL) {
			ctx->call_cand.store_addr = pc;
			ctx->call_cand.npc = ctx->astate->bb_addr + ctx->astate->bb_size;
			ctx->call_cand.bb_addr = ctx->astate->bb_addr;
			ctx->call_cand.in_mem = false;
		}
		break;
	}
	case RZ_IL_OP_JMP: {
		if (!interpreter_prototype_eval_pure(ctx, effect->op.jmp.dst, &eval_out)) {
			goto error;
		}
		if (!eval_out.is_const) {
			RZ_LOG_DEBUG("PC is going to be set to an abstract value! Current PC = 0x%" PFMT64x "\n", pc);
		}
		ut64 target = rz_bv_to_ut64(eval_out.bv);
		bool is_call = !!ctx->call_cand.store_addr;
		RZ_LOG_DEBUG("prototype: JMP - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n",
			pc, target,
			eval_out.is_const ? "Concrete" : "Abstract");

		if (eval_out.is_const) {
			RzAnalysisXRefType xref_type = RZ_ANALYSIS_XREF_TYPE_CODE;

			if (is_call) {
				// An instruction in this basic block stored the next PC.
				// Report a call candidate and assume this jump is a call.
				ctx->call_cand.candidate_addr = pc;
				ctx->call_cand.target = target;
				report_yield_call_candiate(ctx);

#if 0
				// For a call, we need to push a new frame.
				RzBitVector ret_addr = { 0 };
				rz_bv_init(&ret_addr, rz_bv_len(eval_out.bv));
				rz_bv_set_from_ut64(&ret_addr->call_cand.npc);

				bool found = false;
				ut64 ic = ht_uu_find(plugin_data->bb_invocation_count->call_cand.target, &found);
				stack_frame_push(plugin_data, eval_out.bv, &ret_addr, !found ? 0 : ic);
				rz_bv_fini(&ret_addr);
#endif

				xref_type = RZ_ANALYSIS_XREF_TYPE_CALL;
			}
#if 0
			if (xref_type == RZ_ANALYSIS_XREF_TYPE_CODE && stack_frame_top_ret_addr_cmp(plugin_data, eval_out.bv)) {
				stack_frame_pop(plugin_data, NULL);
				xref_type = RZ_ANALYSIS_XREF_TYPE_RETURN;
			}
#endif

			report_yield_xref(ctx, insn_pkt_size, pc, &eval_out,
				xref_type);

			// Clear the call candidate tracking variable.
			memset(&ctx->call_cand, 0, sizeof(ctx->call_cand));
		}

		if (is_call) {
			// For calls, assume control flow will continue like fallthrough.
			// TODO: set data to top that may be changed by the call
		} else {
			set_abstr_pc(ctx->astate, &eval_out);
		}
		break;
	}
	case RZ_IL_OP_BRANCH: {
		if (!interpreter_prototype_eval_pure(ctx, effect->op.branch.condition, &eval_out)) {
			goto error;
		}
		bool may_be_true = abstr_may_be_true(ctx->inst, &eval_out);
		bool may_be_false = abstr_may_be_true(ctx->inst, &eval_out);
		if (may_be_true && may_be_false) {
			RzInterpAbstrState *true_state = rz_interp_abstr_state_clone(ctx->inst, ctx->astate);
			RzInterpAbstrState *false_state = ctx->astate;
			ctx->astate = true_state;
			if (!interpreter_prototype_eval_effect(ctx, effect->op.branch.true_eff, insn_pkt_size)) {
				goto error;
			}
			ctx->astate = false_state;
			if (!interpreter_prototype_eval_effect(ctx, effect->op.branch.false_eff, insn_pkt_size)) {
				goto error;
			}
			if (true_state->pc_state == false_state->pc_state && true_state->pc == false_state->pc) {
				// identical target location, simply join the data and continue
				ctx->inst->plugin->join_state(true_state, false_state);
			} else {
				// different jump targets, branch rather than resorting to top pc
				rz_interp_run_push(ctx, true_state);
				// true_state is already in ctx->inst->astate and will be continued automatically
			}
			rz_interp_abstr_state_free(true_state);
		} else if (may_be_true) {
			if (!interpreter_prototype_eval_effect(ctx, effect->op.branch.true_eff, insn_pkt_size)) {
				goto error;
			}
		} else if (may_be_false) {
			if (!interpreter_prototype_eval_effect(ctx, effect->op.branch.false_eff, insn_pkt_size)) {
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
		if (!interpreter_prototype_eval_pure(ctx, key, &st_addr)) {
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
		if (!interpreter_prototype_eval_pure(ctx, pval, &eval_out)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			rz_bv_fini(st_addr.bv);
			goto error;
		}
		if (!eval_out.is_const) {
			rz_bv_fini(st_addr.bv);
			break;
		}
		if (value_indicates_ret_addr_write(ctx, &eval_out)) {
			ctx->call_cand.store_addr = pc;
			ctx->call_cand.npc = ctx->astate->bb_addr + ctx->astate->bb_size;
			ctx->call_cand.bb_addr = ctx->astate->bb_addr;
			ctx->call_cand.in_mem = true;
		}
		report_yield_xref(ctx, insn_pkt_size, pc, &st_addr, RZ_ANALYSIS_XREF_TYPE_MEM_WRITE);
		if (!store_abstr_data(ctx->inst, mem_idx, &st_addr, &eval_out)) {
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
