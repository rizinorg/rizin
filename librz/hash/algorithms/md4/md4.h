// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HASH_MD4_H
#define RZ_HASH_MD4_H

#include <rz_types.h>

#define RZ_HASH_MD4_DIGEST_SIZE  0x10
#define RZ_HASH_MD4_BLOCK_LENGTH 0x40
typedef struct {
	ut32 digest[4];
	ut8 block[RZ_HASH_MD4_BLOCK_LENGTH];
	ut64 index;
	ut64 len_high;
	ut64 len_low;
} RzMD4;

void rz_md4_init(RzMD4 *context);
bool rz_md4_update(RzMD4 *context, const ut8 *data, ut64 length);
void rz_md4_fini(ut8 *hash, RzMD4 *context);

#endif /* RZ_HASH_MD4_H */
