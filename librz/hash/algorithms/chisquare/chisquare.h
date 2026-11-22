// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CHISQUARE_H
#define RZ_CHISQUARE_H

#include <rz_types.h>

#define RZ_HASH_CHISQUARE_DIGEST_SIZE  sizeof(double)
#define RZ_HASH_CHISQUARE_BLOCK_LENGTH 0

typedef struct chisquare_t {
	ut64 count[256];
	ut64 size;
} RzChiSquare;

bool rz_chisquare_init(RzChiSquare *ctx);
bool rz_chisquare_update(RzChiSquare *ctx, const ut8 *data, size_t len);
bool rz_chisquare_final(ut8 *digest, RzChiSquare *ctx);

#endif /* RZ_CHISQUARE_H */
