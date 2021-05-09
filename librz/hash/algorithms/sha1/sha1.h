// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HASH_SHA1_H
#define RZ_HASH_SHA1_H

#include <rz_types.h>

#define RZ_HASH_SHA1_DIGEST_SIZE  0x14
#define RZ_HASH_SHA1_BLOCK_LENGTH 0x40
typedef struct sha1_context_t {
	ut32 digest[5];
	ut8 block[RZ_HASH_SHA1_BLOCK_LENGTH];
	ut64 index;
	ut64 len_high;
	ut64 len_low;
} RzSHA1;

void rz_sha1_init(RzSHA1 *context);
bool rz_sha1_update(RzSHA1 *context, const ut8 *data, ut64 length);
void rz_sha1_fini(ut8 *hash, RzSHA1 *context);

#endif /* RZ_HASH_SHA1_H */
