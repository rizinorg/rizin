// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HASH_SSDEEP_H
#define RZ_HASH_SSDEEP_H

#include <rz_types.h>

#define RZ_HASH_SSDEEP_BLOCK_LENGTH 4096
#define RZ_HASH_SSDEEP_DIGEST_SIZE  148

typedef struct rz_ssdeep_t RzSSDeep;

RzSSDeep *rz_ssdeep_new(void);
#define rz_ssdeep_free(x) free(x)
void rz_ssdeep_init(RzSSDeep *context);
bool rz_ssdeep_update(RzSSDeep *context, const ut8 *data, ut64 length);
void rz_ssdeep_fini(RzSSDeep *context, char *hash);
double rz_ssdeep_compare(const char *hash_a, const char *hash_b);

#endif /* RZ_HASH_SSDEEP_H */
