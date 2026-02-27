// SPDX-FileCopyrightText: 2026 Rifat <rifatarifoglu38@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HASH_ROR13_H
#define RZ_HASH_ROR13_H

#include <rz_types.h>

#define RZ_HASH_ROR13_DIGEST_SIZE  0x04
#define RZ_HASH_ROR13_BLOCK_LENGTH 0x00

typedef ut32 RzROR13;

void rz_ror13_init(RzROR13 *ctx);
bool rz_ror13_update(RzROR13 *ctx, const ut8 *data, ut64 length);
void rz_ror13_final(ut8 *digest, RzROR13 *ctx);

#endif /* RZ_HASH_ROR13_H */
