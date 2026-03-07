// SPDX-FileCopyrightText: 2026 Ayush Dwivedi <ayushd785@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "djb2.h"
#include <rz_util.h>

#define DJB2_INIT 5381

bool rz_djb2_init(RzDjb2 *ctx) {
	rz_return_val_if_fail(ctx, false);
	*ctx = DJB2_INIT;
	return true;
}

bool rz_djb2_update(RzDjb2 *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	ut64 hash = *ctx;
	for (size_t i = 0; i < len; i++) {
		hash = ((hash << 5) + hash) + data[i];
	}
	*ctx = hash;
	return true;
}

bool rz_djb2_final(ut8 *digest, RzDjb2 *ctx) {
	rz_return_val_if_fail(digest && ctx, false);
	rz_write_le64(digest, *ctx);
	return true;
}
