// SPDX-FileCopyrightText: 2023 swedenspy <swedenspy@yahoo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HASH_MD2_H
#define RZ_HASH_MD2_H

#include <rz_types.h>

#define RZ_HASH_MD2_DIGEST_SIZE     0x10
#define RZ_HASH_MD2_BLOCK_LENGTH    0x10
#define RZ_HASH_MD2_CHECKSUM_LENGTH 0x10
#define RZ_HASH_MD2_STATE_LENGTH    0x10
#define RZ_HASH_MD2_NUM_ROUNDS      18

typedef struct {
	ut8 state[RZ_HASH_MD2_STATE_LENGTH];
	ut8 block[RZ_HASH_MD2_BLOCK_LENGTH];
	ut8 checksum[RZ_HASH_MD2_CHECKSUM_LENGTH];
	ut64 index;
} RzMD2;

void rz_md2_init(RzMD2 *context);
bool rz_md2_update(RzMD2 *context, const ut8 *data, ut64 length);
void rz_md2_fini(ut8 *hash, RzMD2 *context);

#endif /* RZ_HASH_MD2_H */
