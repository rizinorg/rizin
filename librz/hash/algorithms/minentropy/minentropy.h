// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MINENTROPY_H
#define RZ_MINENTROPY_H

#include <rz_types.h>

#define RZ_HASH_MINENTROPY_DIGEST_SIZE  sizeof(double)
#define RZ_HASH_MINENTROPY_BLOCK_LENGTH 0

typedef struct minentropy_t {
	ut64 count[256];
	ut64 size;
} RzMinEntropy;

bool rz_minentropy_init(RzMinEntropy *ctx);
bool rz_minentropy_update(RzMinEntropy *ctx, const ut8 *data, size_t len);
bool rz_minentropy_final(ut8 *digest, RzMinEntropy *ctx);

#endif /* RZ_MINENTROPY_H */
