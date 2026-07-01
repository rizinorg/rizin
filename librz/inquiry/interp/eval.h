// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PROTOYPE_EVAL_H
#define PROTOYPE_EVAL_H

#include "rz_analysis.h"
#include <rz_types.h>
#include <rz_util/rz_bitvector.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>

void write_var_to_state(RzInterpInstance *inst,
	RzInterpAbstrState *astate,
	RzILVarKind kind,
	ut64 var_id,
	const RzInterpAbstrVal *data);
bool read_var_from_state(RzInterpInstance *inst,
	RzInterpAbstrState *astate,
	RzILVarKind kind,
	ut64 var_id,
	RZ_OUT RzInterpAbstrVal *data);
bool load_abstr_data(
	RzInterpInstance *inst,
	RzILMemIndex mem_idx,
	const RzBitVector *addr,
	size_t n_bits,
	RZ_OUT RzInterpAbstrVal *out);

bool report_yield_xref(
	RzInterpRunContext *ctx,
	size_t insn_pkt_size,
	ut64 from,
	const RzInterpAbstrVal *to,
	RzAnalysisXRefType type);

#endif // PROTOYPE_EVAL_H
