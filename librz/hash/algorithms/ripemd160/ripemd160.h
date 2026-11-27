// SPDX-FileCopyrightText: 2026 Nguyen Duc Minh
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_RIPEMD160_H
#define RZ_RIPEMD160_H

#include <rz_types.h>

#define RZ_HASH_RIPEMD160_DIGEST_SIZE  0x14
#define RZ_HASH_RIPEMD160_BLOCK_LENGTH 0x40

typedef struct ripemd160_context_t {
	ut32 digest[5];
	ut8 block[RZ_HASH_RIPEMD160_BLOCK_LENGTH];
	ut64 index;
	ut64 len_low;
	ut64 len_high;
} RzRipemd160;

void rz_ripemd160_init(RzRipemd160 *context);
bool rz_ripemd160_update(RzRipemd160 *context, const ut8 *data, ut64 length);
void rz_ripemd160_fini(ut8 *hash, RzRipemd160 *context);

#endif
