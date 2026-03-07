// SPDX-FileCopyrightText: 2026 Rifat <rifatarifoglu38@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include "ror13.h"

#define RZ_HASH_ROR13_ROTATION 0x0D

static inline ut32 ror13(ut32 x) {
	return (x >> RZ_HASH_ROR13_ROTATION) | (x << (32 - RZ_HASH_ROR13_ROTATION));
}

bool rz_ror13_init(RzROR13 *ctx) {
	rz_return_val_if_fail(ctx, false);

	*ctx = 0;

	return true;
}

bool rz_ror13_update(RzROR13 *ctx, const ut8 *data, ut64 length) {
	rz_return_val_if_fail(ctx && data, false);

	for (ut64 i = 0; i < length; ++i) {
		*ctx = ror13(*ctx);
		*ctx += (ut32)data[i];
	}

	return true;
}

bool rz_ror13_final(ut8 *digest, RzROR13 *ctx) {
	rz_return_val_if_fail(digest && ctx, false);

	rz_write_be32(digest, *ctx);

	return true;
}
