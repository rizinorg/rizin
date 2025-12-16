// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_analysis.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_th.h"
#include "rz_types.h"
#include "rz_util/rz_log.h"
#include <rz_util/rz_bitvector.h>

bool report_xref_yield(RzInterpreterAbstrState *state, HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues, ut64 from, const ProtoIntrprAbstrData *to, RzAnalysisXRefType type) {
	RzInterpreterYieldQueue *queue = ht_up_find(yield_queues, RZ_INTERPRETER_YIELD_KIND_XREF, NULL);
	if (!queue) {
		rz_warn_if_reached();
		return false;
	}
	if (!to->is_concrete || rz_bv_len(to->bv) > 64) {
		// Isn't reported
		return true;
	}
	ProtoInterprSharedObjects *sobj = state->ext;

	ut64 to_addr = rz_bv_to_ut64(to->bv);
	if (queue->filter(&to_addr, queue->filter_data->io_boundaries)) {
		RzAnalysisXRef *xref = &sobj->xref;
		xref->from = from;
		xref->to = to_addr;
		xref->type = type;
		// TODO: Possible race condition here, if the interpreter pushes a new xref
		// before the previous one was handled.
		// But this is fine for the prototype. Real implementation needs some kind
		// of shared memory anyways.
		rz_th_queue_push(queue->yield_queue, xref, true);
	}
	return true;
}

void copy_abstr_data(ProtoIntrprAbstrData *dst, const ProtoIntrprAbstrData *src) {
	rz_return_if_fail(dst->bv && src->bv);
	rz_bv_cast_inplace(dst->bv, rz_bv_len(src->bv), false);
	rz_bv_copy(src->bv, dst->bv);
	dst->is_concrete = src->is_concrete;
}

void write_var_to_state(RzInterpreterAbstrState *state,
	RzILVarKind kind,
	ut64 var_id,
	const ProtoIntrprAbstrData *data) {
	HtUP *ht_vals;
	switch (kind) {
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
		av = RZ_NEW(RzInterpreterAbstrVal);
		av->kind = RZ_INTERPRETER_ABSTRACTION_CONST;
		av->abstr_data = adata_new();
		ht_up_insert(ht_vals, var_id, av);
	}
	copy_abstr_data(av->abstr_data, data);
}

bool read_var_from_state(RzInterpreterAbstrState *state,
	RzILVarKind kind,
	ut64 var_id,
	RZ_OUT ProtoIntrprAbstrData *data) {
	HtUP *ht_vals;
	switch (kind) {
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
	ut64 addr,
	const ProtoIntrprAbstrData *src,
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result) {
	if (!src->is_concrete) {
		// Really don't write?
		return true;
	}
	ProtoInterprSharedObjects *sobj = state->ext;
	RzInterpreterIORequest *io_req = &sobj->io_req;
	io_req->n_bytes = rz_bv_len_bytes(src->bv);

	ut8 *buf;
	ut8 buf_stack[BV_STACK_MAX_SIZE] = { 0 };
	if (io_req->n_bytes > BV_STACK_MAX_SIZE) {
		buf = RZ_NEWS(ut8, io_req->n_bytes);
	} else {
		buf = buf_stack;
	}
	char *bytes = rz_bv_as_hex_string(src->bv, true);
	printf("Prototype: STORE @ 0x%" PFMT64x " : %s\n", io_req->addr, bytes);
	free(bytes);
	rz_bv_set_to_bytes_ble(src->bv, buf, state->il_config->big_endian);
	io_req->type = RZ_INTERPRETER_IO_WRITE;
	io_req->addr = addr;
	io_req->data = buf;

	rz_th_queue_push(io_request, io_req, true);
	// Wait for write being done.
	RzInterpreterIOResult *io_res = rz_th_queue_wait_pop(io_result, false);
	if (io_req->n_bytes > BV_STACK_MAX_SIZE) {
		free(buf);
	}

	if (!io_res) {
		// Abort of interpretation.
		return false;
	}
	return io_res->req_ok;
}

bool load_abstr_data(
	RzInterpreterAbstrState *state,
	ut64 addr,
	size_t size,
	RZ_OUT ProtoIntrprAbstrData *out,
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result) {
	ProtoInterprSharedObjects *sobj = state->ext;
	RzInterpreterIORequest *io_req = &sobj->io_req;
	io_req->type = RZ_INTERPRETER_IO_READ;
	io_req->addr = addr;
	io_req->n_bytes = size;
	rz_th_queue_push(io_request, io_req, true);
	// Wait for load being done.
	RzInterpreterIOResult *io_res = rz_th_queue_wait_pop(io_result, false);
	if (!io_res) {
		// Abort of interpretation.
		return false;
	}
	if (!io_res->req_ok) {
		RZ_LOG_WARN("Prototype: IO read failed.");
		return false;
	}
	if (io_res->read.n_bytes != size) {
		RZ_LOG_WARN("Prototype: Failed to read correct number of bytes. Requested: 0x%" PFMTSZx
		            " Received: 0x%" PFMT64x "\n", size, io_res->read.n_bytes);
		return false;
	}
	out->is_concrete = true;
	rz_bv_cast_inplace(out->bv, size, 0);
	rz_bv_set_from_bytes_ble(out->bv, io_res->read.data, 0, io_res->read.n_bytes, state->il_config->big_endian);
	char *bytes = rz_bv_as_hex_string(out->bv, true);
	printf("Prototype: READ @ 0x%" PFMT64x " : %s\n", io_req->addr, bytes);
	free(bytes);
	return true;
}

bool set_pc(RzInterpreterAbstrState *state, ut64 pc,
	void *plugin_data) {
	rz_return_val_if_fail(state, false);
	AD(state->pc->abstr_data)->is_concrete = true;
	printf("Prototype: set_pc() - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x "(Concrete)\n",
	            rz_bv_to_ut64(AD(state->pc->abstr_data)->bv),
	            pc);
	return rz_bv_set_from_ut64(AD(state->pc->abstr_data)->bv, pc);
}
