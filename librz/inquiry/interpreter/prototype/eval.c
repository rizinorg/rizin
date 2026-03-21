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
	RzInterpreterAbstrState *state,
	size_t insn_pkt_size,
	HtUP /*<RzInterpreterYieldKind, RzInterpreterYieldQueue *>*/ *yield_queues,
	ut64 from,
	const ProtoIntrprAbstrData *to,
	RzAnalysisXRefType type) {
	RzInterpreterYieldQueue *queue = ht_up_find(yield_queues, RZ_INTERPRETER_YIELD_KIND_XREF, NULL);
	if (!queue) {
		rz_warn_if_reached();
		return false;
	}
	if (!to->is_concrete || rz_bv_len(to->bv) > 64) {
		// Isn't reported
		return true;
	}
	if (type == RZ_ANALYSIS_XREF_TYPE_CODE &&
		RZ_STR_EQ(state->arch_name, "hexagon") &&
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

	ut64 to_addr = rz_bv_to_ut64(to->bv);
	if (queue->filter(&to_addr, queue->filter_data->io_boundaries)) {
		rz_th_lock_enter(state->shared_obj->received);

		RzAnalysisXRef *xref = &state->shared_obj->xref;
		xref->bb_addr = state->bb_addr;
		xref->from = from;
		xref->to = to_addr;
		xref->type = type;
		// TODO: Possible race condition here, if the interpreter pushes a new xref
		// before the previous one was handled.
		// But this is fine for the prototype. Real implementation needs some kind
		// of shared memory anyways.
		rz_th_queue_push(queue->yield_queue, state->shared_obj, true);
		// Don't leave collection lock. Consumer will unlock it after it collected.
	}
	return true;
}

/**
 * \brief Report the store of the next PC and report it as possible return point.
 */
bool report_yield_call_candiate(
	RzInterpreterAbstrState *state,
	HtUP /*<RzInterpreterYieldKind, RzInterpreterYieldQueue *>*/ *yield_queues,
	ProtoIntrprPluginData *plugin_data) {
	RzInterpreterYieldQueue *cc_queue = ht_up_find(yield_queues, RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE, NULL);
	if (!cc_queue) {
		rz_warn_if_reached();
		return false;
	}

	rz_th_lock_enter(state->shared_obj->received);
	RzAnalysisCallCandidate *cc = &state->shared_obj->call_cand;
	memcpy(cc, &plugin_data->call_cand, sizeof(plugin_data->call_cand));
	rz_th_queue_push(cc_queue->yield_queue, state->shared_obj, true);
	// Don't leave collection lock. Consumer will unlock it after it collected.
	return true;
}

void copy_abstr_data(ProtoIntrprAbstrData *dst, const ProtoIntrprAbstrData *src) {
	rz_return_if_fail(dst && src && dst->bv && src->bv);
	rz_bv_cast_inplace(dst->bv, rz_bv_len(src->bv), false);
	rz_bv_copy(dst->bv, src->bv);
	dst->is_concrete = src->is_concrete;
}

void write_var_to_state(RzInterpreterAbstrState *state,
	RzILVarKind kind,
	ut64 var_id,
	const ProtoIntrprAbstrData *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = state->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = state->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = state->lets;
		break;
	}
	RzInterpreterAbstrVal *av = ht_up_find(ht_vals, var_id, NULL);
	if (!av) {
		if (kind == RZ_IL_VAR_KIND_GLOBAL) {
			RZ_LOG_WARN("New global variable created: 0x%" PFMT64x "\n", var_id)
		}
		av = RZ_NEW0(RzInterpreterAbstrVal);
		ht_up_insert(ht_vals, var_id, av);
	}
	if (!av->abstr_data) {
		av->kind = RZ_INTERPRETER_ABSTRACTION_CONST;
		av->abstr_data = adata_new();
	}
	copy_abstr_data(av->abstr_data, data);
}

bool read_var_from_state(RzInterpreterAbstrState *state,
	RzILVarKind kind,
	ut64 var_id,
	RZ_OUT ProtoIntrprAbstrData *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return false;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = state->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = state->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = state->lets;
		break;
	}
	RzInterpreterAbstrVal *av = ht_up_find(ht_vals, var_id, NULL);
	if (!av || !av->abstr_data) {
		// Variable doesn't exist.
		// This should never happen and is a bug.
		rz_warn_if_reached();
		return false;
	}
	copy_abstr_data(data, av->abstr_data);
	return true;
}

// Returns true if the bit vector in \p data is not zero. If it is zero or
// the abstract data is not concrete it returns false.
//
// TODO: The assumption that true != 0 is invalid.
// It depends on the architecture and must be decided by the RzArch plugin.
// State is passed due to this here as well. To make later refactoring easier.
bool abstr_is_true(const RzInterpreterAbstrState *state, const ProtoIntrprAbstrData *data) {
	if (!data->is_concrete) {
		return false;
	}
	return !rz_bv_is_zero_vector(data->bv);
}

bool store_abstr_data(
	RzInterpreterAbstrState *state,
	RzILMemIndex mem_idx,
	const ProtoIntrprAbstrData *addr,
	const ProtoIntrprAbstrData *src,
	RzThreadQueue /*<RZ_LIFETIME(RzInquiry) RzInterpreterSharedObject *>*/ *io_request,
	RzThreadQueue /*<RZ_LIFETIME(RzInquiry) RzInterpreterSharedObject *>*/ *io_result) {
	if (!src->is_concrete) {
		// Really don't write?
		return true;
	}
	rz_th_lock_enter(state->shared_obj->received);
	RzInterpreterIORequest *io_req = &state->shared_obj->io_req;
	io_req->n_bits = rz_bv_len(src->bv);
	io_req->mem_idx = mem_idx;
	io_req->big_endian = state->il_config->big_endian;

	io_req->type = RZ_INTERPRETER_IO_WRITE;
	io_req->addr = addr->bv;
	io_req->st_data = src->bv;

	char *bytes = rz_bv_as_hex_string(src->bv, true);
	RZ_LOG_DEBUG("Prototype: STORE @ mem:%" PFMT32d " 0x%" PFMT64x " : %s\n", mem_idx, rz_bv_to_ut64(io_req->addr), bytes);
	free(bytes);

	rz_th_queue_push(io_request, state->shared_obj, true);
	// Don't leave collection lock. Consumer will unlock it after it collected.

	// Wait for write being done.
	RzInterpreterSharedObjects *so = NULL;
	if (!rz_th_queue_pop(io_result, false, (void **)&so) || !so) {
		rz_th_lock_leave(state->shared_obj->received);
		return false;
	};
	bool write_ok = so->io_res.req_ok;
	rz_th_lock_leave(so->received);

	return write_ok;
}

bool load_abstr_data(
	RzInterpreterAbstrState *state,
	RzILMemIndex mem_idx,
	const ProtoIntrprAbstrData *addr,
	size_t n_bits,
	RZ_OUT ProtoIntrprAbstrData *out,
	RzThreadQueue /*<RZ_LIFETIME(RzInquiry) RzInterpreterSharedObject *>*/ *io_request,
	RzThreadQueue /*<RZ_LIFETIME(RzInquiry) RzInterpreterSharedObject *>*/ *io_result) {

	rz_th_lock_enter(state->shared_obj->received);
	RzInterpreterIORequest *io_req = &state->shared_obj->io_req;
	rz_bv_cast_inplace(out->bv, n_bits, 0);
	io_req->type = RZ_INTERPRETER_IO_READ;
	io_req->addr = addr->bv;
	io_req->ld_data = out->bv;
	io_req->mem_idx = mem_idx;
	io_req->n_bits = n_bits;
	io_req->big_endian = state->il_config->big_endian;
	ut64 req_addr = rz_bv_to_ut64(io_req->addr);

	rz_th_queue_push(io_request, state->shared_obj, true);
	// Don't leave collection lock. Consumer will unlock it after it collected.

	// Wait for load being done.
	RzInterpreterSharedObjects *so = NULL;
	if (!rz_th_queue_pop(io_result, false, (void **)&so) || !so) {
		rz_th_lock_leave(state->shared_obj->received);
		return false;
	}
	if (!so->io_res.req_ok) {
		RZ_LOG_WARN("Prototype: Failed to read correct number of bytes. Requested: 0x%" PFMTSZx
			    " Received: 0x%" PFMT32x " bits.\n",
			n_bits, rz_bv_len(out->bv));
		rz_th_lock_leave(so->received);
		return false;
	}
	rz_th_lock_leave(so->received);

	out->is_concrete = true;

	char *bytes = rz_bv_as_hex_string(out->bv, true);
	RZ_LOG_DEBUG("Prototype: READ @ mem:%" PFMT32d " 0x%" PFMT64x " : %s\n", mem_idx, req_addr, bytes);
	free(bytes);
	return true;
}

bool set_pc(RzInterpreterAbstrState *state, ut64 pc,
	void *plugin_data) {
	rz_return_val_if_fail(state, false);
	AD(state->pc->abstr_data)->is_concrete = true;
	RZ_LOG_DEBUG("Prototype: set_pc() - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x " (Concrete)\n",
		rz_bv_to_ut64(AD(state->pc->abstr_data)->bv),
		pc);
	return rz_bv_set_from_ut64(AD(state->pc->abstr_data)->bv, pc);
}
