// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "adler32.h"
#include <rz_util.h>

bool rz_adler32_init(RzAdler32 *ctx) {
	rz_return_val_if_fail(ctx, false);
	ctx->low = 1;
	ctx->high = 0;
	return true;
}

bool rz_adler32_update(RzAdler32 *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	for (size_t index = 0; index < len; index++) {
		ctx->low = (ctx->low + data[index]) % 65521;
		ctx->high = (ctx->high + ctx->low) % 65521;
	}
	return true;
}

bool rz_adler32_final(ut8 *digest, RzAdler32 *ctx) {
	rz_return_val_if_fail(digest && ctx, false);
	rz_write_le32(digest, ctx->high << 16 | ctx->low);
	return true;
}
