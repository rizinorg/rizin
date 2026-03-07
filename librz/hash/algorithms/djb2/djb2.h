// SPDX-FileCopyrightText: 2026 Ayush Dwivedi <ayushd785@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DJB2_H
#define RZ_DJB2_H

#include <rz_types.h>

#define RZ_HASH_DJB2_DIGEST_SIZE  8
#define RZ_HASH_DJB2_BLOCK_LENGTH 0

typedef ut64 RzDjb2;

bool rz_djb2_init(RzDjb2 *ctx);
bool rz_djb2_update(RzDjb2 *ctx, const ut8 *data, size_t len);
bool rz_djb2_final(ut8 *digest, RzDjb2 *ctx);

#endif /* RZ_DJB2_H */
