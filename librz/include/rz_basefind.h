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
	ut64 candidate; ///< Candidate physical base address
	ut32 score; ///< Score of the candidate address
} RzBaseFindScore;

typedef struct rz_basefind_info_t {
	ut32 thread_idx; ///< Thread number
	ut32 n_threads; ///< Total number of threads
	ut64 begin_address; ///< Thread begin address
	ut64 current_address; ///< Thread current address
	ut64 end_address; ///< Thread end address
	ut32 percentage; ///< Current percentage of the thread scan
} RzBaseFindThreadInfo;

typedef bool (*RzBaseFindThreadInfoCb)(const RzBaseFindThreadInfo *th_info, void *user);

typedef struct rz_basefind_options_t {
	ut32 pointer_size; ///< Pointer size in bits (32 or 64)
	ut32 min_score; ///< Minimum score to reach to be part of the list of possible addresses
	ut64 start_address; ///< Start physical address
	ut64 end_address; ///< End physical address
	ut64 increase_by; ///< Increase the area of search by N bytes (has to be at least RZ_BASEFIND_BASE_INCREASE)
	size_t max_threads; ///< Max requested number of threads (not guaranteed).
	RzBaseFindThreadInfoCb callback; ///< When set allows to get the thread information
	void *user; ///< User pointer to pass to the callback function for the thread info
} RzBaseFindOpt;

RZ_API RZ_OWN RzList *rz_basefind(RZ_NONNULL RzCore *core, RZ_NONNULL RzBaseFindOpt *options);

#ifdef __cplusplus
}
#endif

#endif /* RZ_BASEFIND_H */
