// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HASH_SHA1_H
#define RZ_HASH_SHA1_H

#include <rz_hash.h>

void rz_sha1_init(RZ_SHA_CTX *context);
bool rz_sha1_update(RZ_SHA_CTX *context, const ut8 *data, ut64 length);
void rz_sha1_fini(ut8 *hash, RZ_SHA_CTX *context);

#endif /* RZ_HASH_SHA1_H */
