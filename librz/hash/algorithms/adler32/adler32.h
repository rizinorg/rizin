// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ADLER32_H
#define RZ_ADLER32_H

#include <rz_types.h>

#define RZ_HASH_ADLER32_DIGEST_SIZE  4
#define RZ_HASH_ADLER32_BLOCK_LENGTH 0

typedef struct adler32_t {
	ut32 low, high;
} RzAdler32;

bool rz_adler32_init(RzAdler32 *ctx);
bool rz_adler32_update(RzAdler32 *ctx, const ut8 *data, size_t len);
bool rz_adler32_final(ut8 *digest, RzAdler32 *ctx);

#endif /* RZ_ADLER32_H */
