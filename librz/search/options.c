// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include "search_internal.h"

RZ_API RZ_OWN RzSearchOpt *rz_search_opt_new() {
	RzSearchOpt *opt = RZ_NEW0(RzSearchOpt);
	if (!opt) {
		return NULL;
	}
	opt->max_threads = RZ_THREAD_N_CORES_ALL_AVAILABLE;
	opt->chunk_size = RZ_SEARCH_DEFAULT_CHUNK_SIZE;
	return opt;
}

RZ_API void rz_search_opt_free(RZ_NULLABLE RzSearchOpt *opt) {
	if (!opt) {
		return;
	}
	rz_search_find_opt_free(opt->find_opts);
	free(opt);
}

RZ_API bool rz_search_opt_set_max_hits(RZ_NONNULL RzSearchOpt *opt, size_t max_hits) {
	rz_return_val_if_fail(opt, false);
	opt->max_hits = max_hits;
	return true;
}

static bool set_chunk_size(RZ_NONNULL RzSearchOpt *opt, ut64 chunk_size) {
	rz_return_val_if_fail(opt, false);
	if (chunk_size < RZ_SEARCH_MIN_CHUNK_SIZE || chunk_size > RZ_SEARCH_MAX_CHUNK_SIZE) {
		RZ_LOG_ERROR("search: Chunk size is not in range of %#" PFMT64x "-%#" PFMT64x " bytes.\n",
			RZ_SEARCH_MIN_CHUNK_SIZE,
			RZ_SEARCH_MAX_CHUNK_SIZE);
		return false;
	}
	opt->chunk_size = chunk_size;
	return true;
}

static bool element_chunk_ratio_ok(ut64 element_size, ut64 chunk_size) {
	rz_return_val_if_fail(element_size != 0, false);
	if (element_size >= chunk_size) {
		return false;
	}
	return (chunk_size / element_size) >= RZ_SEARCH_MIN_ELEMENTS_PER_CHUNK;
}

/**
 * \brief Sets opt->element_size and the updates the chunk size dependent on `element_size`.
 * \param opt The search options.
 * \param element_size The size in bytes of the element to search for.
 */
RZ_API bool rz_search_opt_set_chunk_size(RZ_NONNULL RzSearchOpt *opt, ut64 element_size) {
	rz_return_val_if_fail(opt, false);
	if (!element_chunk_ratio_ok(element_size, opt->chunk_size)) {
		if (!set_chunk_size(opt, element_size * RZ_SEARCH_MIN_ELEMENTS_PER_CHUNK)) {
			RZ_LOG_ERROR("search: Element to search is too big.\n");
			return false;
		}
	}
	opt->element_size = element_size;
	return true;
}

RZ_API bool rz_search_opt_set_max_threads(RZ_NONNULL RzSearchOpt *opt, RzThreadNCores max_threads) {
	rz_return_val_if_fail(opt, false);
	opt->max_threads = max_threads;
	return true;
}

/**
 * \brief Returns the number of threads defined in the options \p opt.
 */
RZ_API size_t rz_search_opt_get_max_threads(RZ_NONNULL const RzSearchOpt *opt) {
	rz_return_val_if_fail(opt, 0);
	return opt->max_threads;
}

/**
 * \brief Enables the printing of progress during the search.
 *
 * \param opt The search options to update.
 * \param show_progress A string describing the progress type. Can be:
 * - "off", "no", "false", "0": No progress is printed.
 * - "interval": The currently searched in interval is printed.
 * - else: Print number of current hits during search.
 *
 * \return True if options were correctly updated, false otherwise.
 */
RZ_API bool rz_search_opt_set_show_progress_from_str(RZ_NONNULL RzSearchOpt *opt, const char *show_progress) {
	rz_return_val_if_fail(opt, false);
	if (rz_str_is_false(show_progress)) {
		opt->show_progress = RZ_SEARCH_PROGRESS_DISABLED;
	} else if (RZ_STR_EQ(show_progress, "intervals")) {
		opt->show_progress = RZ_SEARCH_PROGRESS_INTERVALS;
	} else {
		opt->show_progress = RZ_SEARCH_PROGRESS_NUM_HITS;
	}
	return true;
}

RZ_API RzSearchProgress rz_search_opt_get_show_progress(RZ_NONNULL RzSearchOpt *opt) {
	rz_return_val_if_fail(opt, RZ_SEARCH_PROGRESS_DISABLED);
	return opt->show_progress;
}

RZ_API bool rz_search_opt_set_cancel_cb(RZ_NONNULL RzSearchOpt *opt, RzSearchCancelCallback callback, void *user) {
	rz_return_val_if_fail(opt, false);
	opt->cancel_cb = callback;
	opt->cancel_usr = user;
	return true;
}

RZ_API bool rz_search_opt_set_find_options(RZ_NONNULL RzSearchOpt *opt, RZ_OWN RzSearchFindOpt *find_opts) {
	if (!opt) {
		rz_search_find_opt_free(find_opts);
		rz_return_val_if_reached(false);
	}
	rz_search_find_opt_free(opt->find_opts);
	opt->find_opts = find_opts;
	return true;
}

RZ_API const RzSearchFindOpt *rz_search_opt_get_find_options(RZ_NONNULL const RzSearchOpt *opt) {
	rz_return_val_if_fail(opt, NULL);
	return opt->find_opts;
}

RZ_API RZ_OWN RzSearchFindOpt *rz_search_find_opt_new() {
	RzSearchFindOpt *fopts = RZ_NEW0(RzSearchFindOpt);
	if (!fopts) {
		return NULL;
	}
	fopts->alignment = 1;
	return fopts;
}

RZ_API void rz_search_find_opt_free(RZ_NULLABLE RzSearchFindOpt *opt) {
	free(opt);
}

RZ_API bool rz_search_find_opt_set_overlap_match(RZ_NONNULL RzSearchFindOpt *opt, bool overlap_match) {
	rz_return_val_if_fail(opt, false);
	opt->match_overlap = overlap_match;
	return true;
}

RZ_API bool rz_search_find_opt_get_overlap_match(RZ_NONNULL RzSearchFindOpt *opt) {
	rz_return_val_if_fail(opt, false);
	return opt->match_overlap;
}

RZ_API bool rz_search_find_opt_set_alignment(RZ_NONNULL RzSearchFindOpt *opt, size_t alignment) {
	rz_return_val_if_fail(opt, false);
	opt->alignment = alignment;
	return true;
}

RZ_API ut16 rz_search_find_opt_get_alignment(RZ_NONNULL const RzSearchFindOpt *opt) {
	rz_return_val_if_fail(opt, 0);
	return opt->alignment;
}
