// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ENTROPY_H
#define RZ_ENTROPY_H

#include <rz_types.h>

#define RZ_HASH_ENTROPY_DIGEST_SIZE  sizeof(double)
#define RZ_HASH_ENTROPY_BLOCK_LENGTH 0

typedef struct entropy_t {
	ut64 count[256];
	ut64 size;
} RzEntropy;

bool rz_entropy_init(RzEntropy *ctx);
bool rz_entropy_update(RzEntropy *ctx, const ut8 *data, size_t len);
bool rz_entropy_final(ut8 *digest, RzEntropy *ctx, bool fraction);

#endif /* RZ_ENTROPY_H */
