// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: MIT

#ifndef RZ_BASEFIND_H
#define RZ_BASEFIND_H

#include <rz_core.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_BASEFIND_STRING_MIN_LENGTH (10)
#define RZ_BASEFIND_BASE_MIN_ADDRESS  (0ull)
#define RZ_BASEFIND_BASE_MAX_ADDRESS  (0xf0000000ull)
#define RZ_BASEFIND_BASE_INCREASE     (0x1000)
#define RZ_BASEFIND_SCORE_MIN_VALUE   (1)

typedef struct rz_basefind_t {
	ut64 candidate;
	ut32 score;
} RzBaseFindScore;

RZ_API RZ_OWN RzList *rz_basefind(RZ_NONNULL RzCore *core, ut32 pointer_size);

#ifdef __cplusplus
}
#endif

#endif /* RZ_BASEFIND_H */
