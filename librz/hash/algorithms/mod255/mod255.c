// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "mod255.h"
#include <rz_util.h>

bool rz_mod255_init(RzMod255 *ctx) {
	rz_return_val_if_fail(ctx, false);
	*ctx = 0;
	return true;
}

bool rz_mod255_update(RzMod255 *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	ut8 value = *ctx;
	for (size_t i = 0; i < len; ++i) {
		value += data[i];
	}
	*ctx = value;
	return true;
}

bool rz_mod255_final(ut8 *digest, RzMod255 *ctx) {
	rz_return_val_if_fail(digest && ctx, false);
	*digest = (*ctx) % 255;
	return true;
}
