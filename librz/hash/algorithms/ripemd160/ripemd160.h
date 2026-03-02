// SPDX-FileCopyrightText: 2026 The Rizin Contributors
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HASH_RIPEMD160_H
#define RZ_HASH_RIPEMD160_H

#include <rz_types.h>

#define RZ_HASH_RIPEMD160_DIGEST_SIZE  0x14
#define RZ_HASH_RIPEMD160_BLOCK_LENGTH 0x40

typedef struct rz_hash_ripemd160_t {
	ut32 state[5];
	ut8 block[RZ_HASH_RIPEMD160_BLOCK_LENGTH];
	ut64 total_length;
	size_t block_length;
} RzHashRIPEMD160;

void rz_hash_ripemd160_init(RzHashRIPEMD160 *context);
bool rz_hash_ripemd160_update(RzHashRIPEMD160 *context, const ut8 *data, ut64 length);
void rz_hash_ripemd160_final(ut8 *digest, RzHashRIPEMD160 *context);

#endif /* RZ_HASH_RIPEMD160_H */
