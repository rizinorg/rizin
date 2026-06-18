// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IOC_H
#define RZ_IOC_H

#include <rz_types.h>

#define RZ_HASH_IOC_DIGEST_SIZE  sizeof(double)
#define RZ_HASH_IOC_BLOCK_LENGTH 0

typedef struct ioc_t {
	ut64 count[256];
	ut64 size;
} RzIOC;

bool rz_ioc_init(RzIOC *ctx);
bool rz_ioc_update(RzIOC *ctx, const ut8 *data, size_t len);
bool rz_ioc_final(ut8 *digest, RzIOC *ctx);

#endif /* RZ_IOC_H */
