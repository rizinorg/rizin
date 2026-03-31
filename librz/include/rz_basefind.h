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
#define RZ_BASEFIND_BASE_ALIGNMENT    (0x1000)
#define RZ_BASEFIND_SCORE_MIN_VALUE   (1)

typedef struct rz_basefind_t {
	ut64 candidate; ///< Candidate physical base address
	ut32 score; ///< Score of the candidate address
} RzBaseFindScore;

typedef struct rz_basefind_info_t {
	ut32 n_threads; ///< Total number of search threads.
	ut32 thread_idx; ///< Thread number.
	ut64 begin_address; ///< Thread related search address (start).
	ut64 current_address; ///< Thread related search address (current).
	ut64 end_address; ///< Thread related search address (end).
	ut32 percentage; ///< Progress made by the search thread.
} RzBaseFindThreadInfo;

// Used to provide user information regarding the running threads and to stop the execution when needed.
typedef bool (*RzBaseFindThreadInfoCb)(const RzBaseFindThreadInfo *th_info, void *user);

typedef struct rz_basefind_options_t {
	RzThreadNCores max_threads; ///< Max requested number of threads (not guaranteed).
	ut32 pointer_size; ///< Pointer size in bits (32 or 64)
	ut64 start_address; ///< Start search address
	ut64 end_address; ///< End search address
	ut64 alignment; ///< Memory alignment in bytes (suggested to set it to RZ_BASEFIND_BASE_ALIGNMENT)
	ut32 min_score; ///< Minimum score to reach to be part of the list of possible addresses
	ut32 min_string_len; ///< Min string length to search for
	RzBaseFindThreadInfoCb callback; ///< When set allows to get the thread information
	void *user; ///< User pointer to pass to the callback function for the thread info
} RzBaseFindOpt;

RZ_API RZ_OWN RzList /*<RzBaseFindScore *>*/ *rz_basefind(RZ_NONNULL RzCore *core, RZ_NONNULL RzBaseFindOpt *options);

#ifdef __cplusplus
}
#endif

#endif /* RZ_BASEFIND_H */
