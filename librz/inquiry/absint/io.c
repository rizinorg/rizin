// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "io.h"

#include <rz_core.h>

RZ_IPI RzAbsIntIOReadResult rz_absint_io_read(
	RZ_NONNULL const RzAnalysisILContext *il_ctx,
	RZ_NONNULL RzAbsIntIOReadRequest *io_req) {
	RZ_LOG_DEBUG("inquiry: Received IO read request: mem:%" PFMTSZd " 0x%" PFMT64x "\n",
		io_req->mem_idx,
		rz_bv_to_ut64(io_req->addr));
	RzILMemIndex mem_idx = io_req->mem_idx;
	if (mem_idx >= rz_vector_len(&il_ctx->memory)) {
		rz_warn_if_reached();
		return RZ_ABSINT_IO_READ_RESULT_TOP;
	}
	if (rz_bv_len(io_req->addr) == 64 && rz_bv_msb(io_req->addr)) {
		// TODO: remove this when not needed anymore
		// https://github.com/rizinorg/rizin/issues/5806
		RZ_LOG_ERROR("Due to the Unix seek() implementation, addresses with the "
			     "63 bit set can't be addresses.\n");
		return RZ_ABSINT_IO_READ_RESULT_TOP;
	}
	RzAnalysisILMem *mem = rz_vector_index_ptr(&il_ctx->memory, mem_idx);
	if (!mem->base_buf) {
		return RZ_ABSINT_IO_READ_RESULT_TOP;
	}
	// TODO: here only memory should be read that can be assumed to be constant!
	// https://github.com/rizinorg/rizin/issues/6655
	bool ok = rz_il_loadw_into(mem->base_buf, io_req->ld_data, io_req->addr, io_req->n_bits, io_req->big_endian);
	RZ_LOG_DEBUG("inquiry: Sent IO read result. Success = %s.\n", rz_str_bool(ok));
	return ok ? RZ_ABSINT_IO_READ_RESULT_OK : RZ_ABSINT_IO_READ_RESULT_TOP;
}
