// SPDX-FileCopyrightText: 2025 Seva <little_scamp@yahoo.comt>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TEMPERATURE_H
#define RZ_TEMPERATURE_H

#include <rz_types.h>

#define RZ_HASH_TEMPERATURE_DIGEST_SIZE  sizeof(double)
#define RZ_HASH_TEMPERATURE_BLOCK_LENGTH 0

typedef struct temperature_t {
	ut64 count[256];
	ut64 size;
} RzTemperature;

bool rz_temperature_init(RzTemperature *ctx);
bool rz_temperature_update(RzTemperature *ctx, const ut8 *data, size_t len);
bool rz_temperature_final(ut8 *digest, RzTemperature *ctx, bool fraction);

#endif /* RZ_TEMPERATURE_H */
