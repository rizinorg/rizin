// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MOD255_H
#define RZ_MOD255_H

#include <rz_types.h>

#define RZ_HASH_MOD255_DIGEST_SIZE  4
#define RZ_HASH_MOD255_BLOCK_LENGTH 0

typedef ut32 RzMod255;

bool rz_mod255_init(RzMod255 *ctx);
bool rz_mod255_update(RzMod255 *ctx, const ut8 *data, size_t len);
bool rz_mod255_final(ut8 *digest, RzMod255 *ctx);

#endif /* RZ_MOD255_H */
