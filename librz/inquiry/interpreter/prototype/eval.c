// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_inquiry/rz_interpreter.h"
#include "rz_th.h"
#include "rz_types.h"
#include "rz_util/rz_log.h"
#include <rz_util/rz_bitvector.h>

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
	ut8 *buf;
	ut8 buf_stack[BV_STACK_MAX_SIZE] = { 0 };
	if (rz_bv_len(src->bv) > BV_STACK_MAX_SIZE * 8) {
		buf = RZ_NEWS(ut8, rz_bv_len_bytes(src->bv));
	} else {
		buf = buf_stack;
	}
	rz_bv_set_to_bytes_be(src->bv, buf);
	RzInterpreterIORequest *io_req = state->ext;
	io_req->type = RZ_INTERPRETER_IO_WRITE;
	io_req->addr = addr;
	io_req->data = buf;

	RZ_LOG_WARN("Prototype: Send store request\n");
	rz_th_queue_push(io_request, io_req, true);
	// Wait for write being done.
	RzInterpreterIOResult *io_res = rz_th_queue_wait_pop(io_result, false);
	if (rz_bv_len(src->bv) > BV_STACK_MAX_SIZE * 8) {
		free(buf);
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
	RzInterpreterIORequest *io_req = state->ext;
	io_req->type = RZ_INTERPRETER_IO_READ;
	io_req->addr = addr;
	io_req->n_bytes = size;
	RZ_LOG_WARN("Prototype: Send load request\n");
	rz_th_queue_push(io_request, io_req, true);
	// Wait for load being done.
	RzInterpreterIOResult *io_res = rz_th_queue_wait_pop(io_result, false);
	if (!io_res->req_ok) {
		return false;
	}
	if (io_res->read.n_bytes != size) {
		RZ_LOG_WARN("Prototype: Failed to read correct number of bytes.");
		return false;
	}
	out->is_concrete = true;
	rz_bv_cast_inplace(out->bv, size, 0);
	rz_bv_set_from_bytes_be(out->bv, io_res->read.data, 0, io_res->read.n_bytes);
	return false;
}
