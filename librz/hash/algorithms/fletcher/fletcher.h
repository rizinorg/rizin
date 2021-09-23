// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FLETCHER_H
#define RZ_FLETCHER_H

#include <rz_types.h>

#define RZ_HASH_FLETCHER8_DIGEST_SIZE 1
#define RZ_HASH_FLETCHER_BLOCK_LENGTH 0

typedef struct fletcher8_t {
	ut16 low, high;
} RzFletcher8;

bool rz_fletcher8_init(RzFletcher8 *ctx);
bool rz_fletcher8_update(RzFletcher8 *ctx, const ut8 *data, size_t len);
bool rz_fletcher8_final(ut8 *digest, RzFletcher8 *ctx);

#define RZ_HASH_FLETCHER16_DIGEST_SIZE 2

typedef struct fletcher16_t {
	ut32 low, high;
} RzFletcher16;

bool rz_fletcher16_init(RzFletcher16 *ctx);
bool rz_fletcher16_update(RzFletcher16 *ctx, const ut8 *data, size_t len);
bool rz_fletcher16_final(ut8 *digest, RzFletcher16 *ctx);

#define RZ_HASH_FLETCHER32_DIGEST_SIZE 4

typedef struct fletcher32_t {
	ut32 low, high;
} RzFletcher32;

bool rz_fletcher32_init(RzFletcher32 *ctx);
bool rz_fletcher32_update(RzFletcher32 *ctx, const ut8 *data, size_t len);
bool rz_fletcher32_final(ut8 *digest, RzFletcher32 *ctx);

#define RZ_HASH_FLETCHER64_DIGEST_SIZE 8

typedef struct fletcher64_t {
	ut32 low, high;
} RzFletcher64;

bool rz_fletcher64_init(RzFletcher64 *ctx);
bool rz_fletcher64_update(RzFletcher64 *ctx, const ut8 *data, size_t len);
bool rz_fletcher64_final(ut8 *digest, RzFletcher64 *ctx);

#endif /* RZ_FLETCHER_H */
