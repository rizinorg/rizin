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

typedef struct rz_basefind_info_t {
	ut32 thread_idx;
	ut32 n_threads;
	ut64 begin_address;
	ut64 current_address;
	ut64 end_address;
	ut32 percentage;
} RzBaseFindThreadInfo;

typedef bool (*RzBaseFindThreadInfoCb)(const RzBaseFindThreadInfo *th_info, void *user);

typedef struct rz_basefind_options_t {
	ut32 pointer_size;
	ut32 min_score;
	ut64 start_address;
	ut64 end_address;
	ut64 increase_by;
	size_t max_threads;
	RzBaseFindThreadInfoCb callback;
	void *user;
} RzBaseFindOpt;

RZ_API RZ_OWN RzList *rz_basefind(RZ_NONNULL RzCore *core, RzBaseFindOpt *options);

#ifdef __cplusplus
}
#endif

#endif /* RZ_BASEFIND_H */
