// SPDX-FileCopyrightText: 2025 Seva <little_scamp@yahoo.comt>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file temperature.c
 * \brief Information-temperature hash plugin for Rizin
 *
 * Computes the *information temperature*
 * \f$T_{\text{info}} = \frac{H}{\log_2 N}\f$
 * where **H** is the Shannon entropy of the byte block and **N**
 * is the block length in bytes.
 *
 * Key points
 * ----------
 * * Range : 0 ≤ T<sub>info</sub> ≤ 1 for blocks ≤ 256 bytes.
 *   If `fraction == true`, the value is additionally normalised to [0, 1]
 *   exactly like “fractional entropy”.
 */

#include "temperature.h"
#include <math.h>
#include <rz_util/rz_assert.h>

bool rz_temperature_init(RzTemperature *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzTemperature));
	return true;
}

bool rz_temperature_update(RzTemperature *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	for (size_t i = 0; i < len; i++) {
		ctx->count[data[i]]++;
	}
	ctx->size += len;
	return true;
}

bool rz_temperature_final(ut8 *digest, RzTemperature *ctx, bool fraction) {
	rz_return_val_if_fail(ctx && digest, false);

	if (ctx->size <= 1) {
		rz_write_be_double(digest, 0.0);
		return true;
	}

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

	double temperature = entropy / log2((double)ctx->size);
	if (fraction) {
		temperature *= log2((double)ctx->size) /
			log2((double)RZ_MIN(ctx->size, 256));
	}
	rz_write_be_double(digest, temperature);
	return true;
}
