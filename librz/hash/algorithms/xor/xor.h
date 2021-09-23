// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_XOR_H
#define RZ_XOR_H

#include <rz_types.h>

#define RZ_HASH_XOR8_DIGEST_SIZE 1
#define RZ_HASH_XOR_BLOCK_LENGTH 0

typedef ut8 RzXor8;

bool rz_xor8_init(RzXor8 *ctx);
bool rz_xor8_update(RzXor8 *ctx, const ut8 *data, size_t len);
bool rz_xor8_final(ut8 *digest, RzXor8 *ctx);

#define RZ_HASH_XOR16_DIGEST_SIZE 2

typedef ut16 RzXor16;

bool rz_xor16_init(RzXor16 *ctx);
bool rz_xor16_update(RzXor16 *ctx, const ut8 *data, size_t len);
bool rz_xor16_final(ut8 *digest, RzXor16 *ctx);

#endif /* RZ_XOR_H */
