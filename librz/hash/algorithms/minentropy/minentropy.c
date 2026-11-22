// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minentropy.h"
#include <math.h>
#include <rz_util/rz_assert.h>

bool rz_minentropy_init(RzMinEntropy *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzMinEntropy));
	return true;
}

bool rz_minentropy_update(RzMinEntropy *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	for (size_t i = 0; i < len; i++) {
		ctx->count[data[i]]++;
	}
	ctx->size += len;
	return true;
}

bool rz_minentropy_final(ut8 *digest, RzMinEntropy *ctx) {
	rz_return_val_if_fail(ctx && digest, false);
	// Min-entropy H_inf = -log2(max_i p_i): the conservative (worst-case)
	// entropy used by NIST SP 800-90B. Equals 8.0 for a uniform block and
	// drops as soon as one byte value dominates, exposing non-uniformity
	// that Shannon entropy can hide.
	double min_entropy = 0.0;
	if (ctx->size) {
		ut64 maxcount = 0;
		for (size_t i = 0; i < 256; i++) {
			if (ctx->count[i] > maxcount) {
				maxcount = ctx->count[i];
			}
		}
		if (maxcount) {
			// log2(size / maxcount) == -log2(maxcount / size) but avoids
			// producing an IEEE negative zero for a constant block.
			min_entropy = log2((double)ctx->size / (double)maxcount);
		}
	}
	rz_write_be_double(digest, min_entropy);
	return true;
}
