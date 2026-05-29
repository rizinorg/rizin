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
	RzInterpSet *iset,
	size_t insn_pkt_size,
	ut64 from,
	const ProtoIntrprAbstrData *to,
	RzAnalysisXRefType type) {
	if (!to->is_concrete || rz_bv_len(to->bv) > 64) {
		// Isn't reported
		return true;
	}
	if (type == RZ_ANALYSIS_XREF_TYPE_CODE &&
		RZ_STR_EQ(iset->astate->arch_name, "hexagon") &&
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

	RzInterpYieldRBuf *yrbuf = iset->yield_rbufs[RZ_INTERP_YIELD_KIND_XREF];
	rz_return_val_if_fail(yrbuf, false);

	ut64 to_addr = rz_bv_to_ut64(to->bv);
	RzAnalysisXRef xref = { 0 };
	xref.bb_addr = iset->astate->bb_addr;
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
	RzInterpSet *iset,
	ProtoIntrprPluginData *plugin_data) {
	RzInterpYieldRBuf *cc_rbuf = iset->yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE];
	rz_return_val_if_fail(cc_rbuf, false);

	RzAnalysisCallCandidate cc = { 0 };
	memcpy(&cc, &plugin_data->call_cand, sizeof(plugin_data->call_cand));
	if (rz_th_ring_buf_put(cc_rbuf->rbuf, &cc) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	return true;
}

void copy_abstr_data(ProtoIntrprAbstrData *dst, const ProtoIntrprAbstrData *src) {
	rz_return_if_fail(dst && src && dst->bv && src->bv);
	rz_bv_cast_inplace(dst->bv, rz_bv_len(src->bv), false);
	rz_bv_copy(dst->bv, src->bv);
	dst->is_concrete = src->is_concrete;
}

void write_var_to_state(RzInterpSet *iset,
	RzILVarKind kind,
	ut64 var_id,
	const ProtoIntrprAbstrData *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = iset->astate->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = iset->astate->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = iset->astate->lets;
		break;
	}
	RzInterpAbstrVal *av = ht_up_find(ht_vals, var_id, NULL);
	if (!av) {
		if (kind == RZ_IL_VAR_KIND_GLOBAL) {
			RZ_LOG_WARN("New global variable created: 0x%" PFMT64x "\n", var_id)
		}
		av = RZ_NEW0(RzInterpAbstrVal);
		ht_up_insert(ht_vals, var_id, av);
	}
	if (!av->abstr_data) {
		av->kind = RZ_INTERP_ABSTRACTION_CONST;
		av->abstr_data = adata_new();
	}
	copy_abstr_data(av->abstr_data, data);
}

bool read_var_from_state(RzInterpSet *iset,
	RzILVarKind kind,
	ut64 var_id,
	RZ_OUT ProtoIntrprAbstrData *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return false;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = iset->astate->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = iset->astate->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = iset->astate->lets;
		break;
	}
	RzInterpAbstrVal *av = ht_up_find(ht_vals, var_id, NULL);
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
bool abstr_is_true(const RzInterpSet *iset, const ProtoIntrprAbstrData *data) {
	if (!data->is_concrete) {
		return false;
	}
	return !rz_bv_is_zero_vector(data->bv);
}

bool store_abstr_data(
	RzInterpSet *iset,
	RzILMemIndex mem_idx,
	const ProtoIntrprAbstrData *addr,
	const ProtoIntrprAbstrData *src) {
	if (!src->is_concrete) {
		// Really don't write?
		return true;
	}
	RzInterpIORequest io_req = { 0 };
	io_req.n_bits = rz_bv_len(src->bv);
	io_req.mem_idx = mem_idx;
	io_req.big_endian = iset->astate->il_config->big_endian;

	io_req.type = RZ_INTERP_IO_WRITE;
	io_req.addr = addr->bv;
	io_req.st_data = src->bv;

	char *bytes = rz_bv_as_hex_string(src->bv, true);
	RZ_LOG_DEBUG("pprototype: ototype: STORE @ mem:%" PFMT32d " 0x%" PFMT64x " : %s\n", mem_idx, rz_bv_to_ut64(io_req.addr), bytes);
	free(bytes);

	if (rz_th_ring_buf_put(iset->io_request_rbuf, &io_req) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}

	RzInterpIOResult io_res = { 0 };
	if (rz_th_ring_buf_take_blocking(iset->io_result_rbuf, &io_res) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}
	return io_res.req_ok;
}

bool load_abstr_data(
	RzInterpSet *iset,
	RzILMemIndex mem_idx,
	const ProtoIntrprAbstrData *addr,
	size_t n_bits,
	RZ_OUT ProtoIntrprAbstrData *out) {
	RzInterpIORequest io_req = { 0 };
	rz_bv_cast_inplace(out->bv, n_bits, 0);
	io_req.type = RZ_INTERP_IO_READ;
	io_req.addr = addr->bv;
	io_req.ld_data = out->bv;
	io_req.mem_idx = mem_idx;
	io_req.n_bits = n_bits;
	io_req.big_endian = iset->astate->il_config->big_endian;
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
	out->is_concrete = true;

	char *bytes = rz_bv_as_hex_string(out->bv, true);
	RZ_LOG_DEBUG("prototype: READ @ mem:%" PFMT32d " 0x%" PFMT64x " : %s\n", mem_idx, rz_bv_to_ut64(io_req.addr), bytes);
	free(bytes);
	return true;
}

bool set_abstr_pc(RzInterpAbstrState *state, ProtoIntrprAbstrData *pc,
	void *plugin_data) {
	rz_return_val_if_fail(state && pc, false);
	ProtoIntrprPluginData *pdata = plugin_data;
	ProtoIntrprAbstrData *apc = AD(state->pc->abstr_data);
	if (!apc->is_concrete || rz_bv_len(apc->bv) > 64) {
		pdata->prev_pc = UT64_MAX;
	} else {
		pdata->prev_pc = rz_bv_to_ut64(apc->bv);
	}
	copy_abstr_data(state->pc->abstr_data, pc);
	RZ_LOG_DEBUG("prototype: set_abstr_pc() - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x " (%s)\n",
		pdata->prev_pc, rz_bv_to_ut64(apc->bv), apc->is_concrete ? "Concrete" : "Abstract");
	return true;
}

bool set_pc(RzInterpAbstrState *state, ut64 pc,
	void *plugin_data) {
	rz_return_val_if_fail(state, false);
	ProtoIntrprPluginData *pdata = plugin_data;
	ProtoIntrprAbstrData *apc = AD(state->pc->abstr_data);
	if (!apc->is_concrete || rz_bv_len(apc->bv) > 64) {
		pdata->prev_pc = UT64_MAX;
	} else {
		pdata->prev_pc = rz_bv_to_ut64(apc->bv);
	}

	apc->is_concrete = true;
	RZ_LOG_DEBUG("prototype: set_pc() - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x " (Concrete)\n",
		rz_bv_to_ut64(apc->bv), pc);
	return rz_bv_set_from_ut64(apc->bv, pc);
}

void stack_frame_fini(ProtoInterprAbstrStackFrame *frame, void *unused) {
	if (!frame) {
		return;
	}
	rz_bv_fini(&frame->return_addr);
	rz_bv_fini(&frame->entry_point);
}

void stack_frame_push(ProtoIntrprPluginData *pdata, RzBitVector *entry_point, RzBitVector *return_addr, ut64 instance) {
	ProtoInterprAbstrStackFrame frame = { 0 };
	rz_bv_init(&frame.return_addr, rz_bv_len(return_addr));
	rz_bv_copy(&frame.return_addr, return_addr);
	rz_bv_init(&frame.entry_point, rz_bv_len(entry_point));
	rz_bv_copy(&frame.entry_point, entry_point);
	frame.instance = instance;
	rz_vector_push(&pdata->stack, &frame);
}

void stack_frame_pop(ProtoIntrprPluginData *pdata, RZ_NULLABLE ProtoInterprAbstrStackFrame *frame) {
	rz_vector_pop(&pdata->stack, frame);
}

bool stack_frame_top_ret_addr_cmp(ProtoIntrprPluginData *pdata, RzBitVector *addr) {
	ProtoInterprAbstrStackFrame *frame = rz_vector_tail(&pdata->stack);
	if (!frame) {
		return false;
	}
	return rz_bv_eq(&frame->return_addr, addr);
}
