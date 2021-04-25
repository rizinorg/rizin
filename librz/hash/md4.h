// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HASH_MD4_H
#define RZ_HASH_MD4_H

#include <rz_hash.h>

void rz_md4_init(RZ_MD4_CTX *context);
bool rz_md4_update(RZ_MD4_CTX *context, const ut8 *data, ut64 length);
void rz_md4_fini(ut8 *hash, RZ_MD4_CTX *context);

#endif /* RZ_HASH_MD4_H */
