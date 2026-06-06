// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "serialcorr.h"
#include <rz_util/rz_assert.h>

bool rz_serialcorr_init(RzSerialCorr *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzSerialCorr));
	return true;
}

bool rz_serialcorr_update(RzSerialCorr *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	for (size_t i = 0; i < len; i++) {
		double x = (double)data[i];
		if (!ctx->started) {
			ctx->first = data[i];
			ctx->started = true;
		} else {
			ctx->sum_cross += (double)ctx->last * x;
		}
		ctx->sum += x;
		ctx->sum_sq += x * x;
		ctx->last = data[i];
		ctx->size++;
	}
	return true;
}

bool rz_serialcorr_final(ut8 *digest, RzSerialCorr *ctx) {
	rz_return_val_if_fail(ctx && digest, false);
	// Lag-1 serial correlation coefficient (with wrap-around), as in the
	// classic `ent` tool. Near 0 for compressed/encrypted data; clearly
	// non-zero for executable code, counters and gradients -- the order-aware
	// axis that entropy and chi-square (both histogram-only) cannot see.
	// Undefined cases (fewer than two bytes, or a constant block) report 0.0.
	double scc = 0.0;
	if (ctx->size > 1) {
		double n = (double)ctx->size;
		double scct1 = ctx->sum_cross + (double)ctx->last * (double)ctx->first;
		double scct2 = ctx->sum * ctx->sum;
		double scct3 = ctx->sum_sq;
		double denom = n * scct3 - scct2;
		if (denom != 0.0) {
			scc = (n * scct1 - scct2) / denom;
		}
	}
	rz_write_be_double(digest, scc);
	return true;
}
