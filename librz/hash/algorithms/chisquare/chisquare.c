// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "chisquare.h"
#include <math.h>
#include <rz_util/rz_assert.h>

bool rz_chisquare_init(RzChiSquare *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzChiSquare));
	return true;
}

bool rz_chisquare_update(RzChiSquare *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	for (size_t i = 0; i < len; i++) {
		ctx->count[data[i]]++;
	}
	ctx->size += len;
	return true;
}

bool rz_chisquare_final(ut8 *digest, RzChiSquare *ctx) {
	rz_return_val_if_fail(ctx && digest, false);
	// Pearson chi-square statistic of the byte distribution against a
	// uniform model (256 equiprobable values). For a truly uniform source
	// the expected value is 255 (the number of degrees of freedom); a
	// compressor's residual structure, packed tables or a weak cipher push
	// it far higher even when the Shannon entropy is already ~8 bits/byte.
	double chisq = 0.0;
	if (ctx->size) {
		double expected = (double)ctx->size / 256.0;
		for (size_t i = 0; i < 256; i++) {
			double diff = (double)ctx->count[i] - expected;
			chisq += (diff * diff) / expected;
		}
	}
	rz_write_be_double(digest, chisq);
	return true;
}
