// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_util/rz_bitvector.h"

void copy_abstr_data(ProtoIntrprAbstrData *dst, const ProtoIntrprAbstrData *src) {
	// TODO: For performance it should really just copy the data between bit vectors
	// Not freeing the old one and allocating a new one with rz_bv_dup().
	// But this has to wait until we can copy bit vectors between on using an array
	// and one using an ut64 to store its bits.
	rz_bv_free(dst->bv);
	dst->bv = rz_bv_dup(src->bv);
	dst->is_concrete = src->is_concrete;
}
