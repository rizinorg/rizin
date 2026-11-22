// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ioc.h"
#include <rz_util/rz_assert.h>

bool rz_ioc_init(RzIOC *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzIOC));
	return true;
}

bool rz_ioc_update(RzIOC *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	for (size_t i = 0; i < len; i++) {
		ctx->count[data[i]]++;
	}
	ctx->size += len;
	return true;
}

bool rz_ioc_final(ut8 *digest, RzIOC *ctx) {
	rz_return_val_if_fail(ctx && digest, false);
	// Index of coincidence: the probability that two bytes drawn from the
	// block are equal. ~1/256 (0.0039) for a uniform/random block; markedly
	// higher for text, padding, single-byte-XOR'd data and repeating-key
	// regions. Computed at several strides it is the Friedman/Kasiski test
	// for a repeating-XOR period.
	double ioc = 0.0;
	if (ctx->size > 1) {
		double numerator = 0.0;
		for (size_t i = 0; i < 256; i++) {
			double c = (double)ctx->count[i];
			numerator += c * (c - 1.0);
		}
		ioc = numerator / ((double)ctx->size * ((double)ctx->size - 1.0));
	}
	rz_write_be_double(digest, ioc);
	return true;
}
