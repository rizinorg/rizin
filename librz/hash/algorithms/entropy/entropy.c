// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "entropy.h"
#include <math.h>
#include <rz_util/rz_assert.h>

bool rz_entropy_init(RzEntropy *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzEntropy));
	return true;
}

bool rz_entropy_update(RzEntropy *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	for (size_t i = 0; i < len; i++) {
		ctx->count[data[i]]++;
	}
	ctx->size += len;
	return true;
}

bool rz_entropy_final(ut8 *digest, RzEntropy *ctx, bool fraction) {
	rz_return_val_if_fail(ctx && digest, false);
	double p, entropy = 0.0;
	ut64 count;
	for (size_t i = 0; i < 256; i++) {
		count = ctx->count[i];
		if (count) {
			p = ((double)count) / ctx->size;
			entropy -= p * log2(p);
		}
	}
	if (fraction && ctx->size) {
		entropy /= log2((double)RZ_MIN(ctx->size, 256));
	}
	rz_write_be_double(digest, entropy);
	return true;
}
