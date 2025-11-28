// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"

void copy_abstr_data(ProtoIntrprAbstrData *dst, const ProtoIntrprAbstrData *src) {
	// TODO: For performance it should really just copy the data between bit vectors
	// Not freeing the old one and allocating a new one with rz_bv_dup().
	// But this has to wait until we can copy bit vectors between on using an array
	// and one using an ut64 to store its bits.
	rz_bv_free(dst->bv);
	dst->bv = rz_bv_dup(src->bv);
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
		av = RZ_NEW(RzInterpreterAbstrVal);
		av->kind = RZ_INTERPRETER_ABSTRACTION_CONST;
		av->abstr_data = RZ_NEW0(ProtoIntrprAbstrData);
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
