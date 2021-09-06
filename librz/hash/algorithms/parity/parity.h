// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PARITY_H
#define RZ_PARITY_H

#include <rz_types.h>

#define RZ_HASH_PARITY_DIGEST_SIZE  1
#define RZ_HASH_PARITY_BLOCK_LENGTH 0

typedef ut32 RzParity;

bool rz_parity_init(RzParity *ctx);
bool rz_parity_update(RzParity *ctx, const ut8 *data, size_t len);
bool rz_parity_final(ut8 *digest, RzParity *ctx);

#endif /* RZ_PARITY_H */
