// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "parity.h"
#include <rz_util.h>

bool rz_parity_init(RzParity *ctx) {
	rz_return_val_if_fail(ctx, false);
	*ctx = 0;
	return true;
}

bool rz_parity_update(RzParity *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	ut32 ones = *ctx;
	for (size_t i = 0; i < len; ++i) {
		ut8 x = data[i];
		ones += ((x & 128) ? 1 : 0) + ((x & 64) ? 1 : 0) + ((x & 32) ? 1 : 0) + ((x & 16) ? 1 : 0) +
			((x & 8) ? 1 : 0) + ((x & 4) ? 1 : 0) + ((x & 2) ? 1 : 0) + ((x & 1) ? 1 : 0);
	}
	*ctx = ones;
	return true;
}

bool rz_parity_final(ut8 *digest, RzParity *ctx) {
	rz_return_val_if_fail(digest && ctx, false);
	*digest = (*ctx) & 1;
	return true;
}
