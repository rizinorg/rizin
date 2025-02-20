// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_config.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_regex.h>
#include <rz_core.h>
#include <rz_search.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_str_search.h>

/**
 * \brief Sets up the search find options according to the core config.
 *
 * \param core The core to get the config from.
 *
 * \return The find options to use. Or NULL in case of failure.
 */
RZ_API RZ_OWN RzSearchFindOpt *rz_core_setup_default_search_find_opts(RzCore *core) {
	rz_return_val_if_fail(core, NULL);
	RzSearchFindOpt *fopts = rz_search_find_opt_new();
	if (!fopts) {
		RZ_LOG_ERROR("Failed allocating find options.\n");
		return NULL;
	}
	if (!(rz_search_find_opt_set_inverse_match(fopts, rz_config_get_b(core->config, "search.inverse")) &&
		    rz_search_find_opt_set_overlap_match(fopts, rz_config_get_b(core->config, "search.overlap")) &&
		    rz_search_find_opt_set_alignment(fopts, rz_config_get_i(core->config, "search.align")))) {
		RZ_LOG_ERROR("Failed set find options.\n");
		rz_search_find_opt_free(fopts);
		return NULL;
	}
	return fopts;
}

/**
 * \brief Sets up the search parameters according to the core IO layer and config.
 *
 * \param core The core to get the IO maps, settings and other relevant information from.
 * \param search_opts Search options to set up. Only fields to search behavior will be set (max_threads, max hits). Can be NULL.
 *
 * \return The boundaries to search in. Or NULL in case of failure.
 */
RZ_API RZ_OWN RzList /*<RzIOMap *>*/ *rz_core_setup_io_search_parameters(RzCore *core, RZ_NULLABLE RZ_OUT RzSearchOpt *search_opts) {
	rz_return_val_if_fail(core && core->io && core->config, NULL);
	RzList *boundaries = NULL;

	if (!core->io) {
		RZ_LOG_ERROR("core: RzIO is not available.\n");
		return NULL;
	}

	boundaries = rz_core_get_boundaries_select(core, "search.from", "search.to", "search.in");
	if (!boundaries || rz_list_empty(boundaries)) {
		ut64 from = rz_config_get_i(core->config, "search.from");
		ut64 to = rz_config_get_i(core->config, "search.to");
		RZ_LOG_ERROR("core: Failed to get search boundaries within [0x%" PFMT64x ", 0x%" PFMT64x "].\n", from, to);
		goto fail;
	}

	if (search_opts) {
		// Set search options known by core.
		ut32 max_threads = rz_th_max_threads(rz_config_get_i(core->config, "search.max_threads"));
		ut32 max_hits = rz_config_get_i(core->config, "search.maxhits");
		if (!(rz_search_opt_set_max_threads(search_opts, max_threads) &&
			    rz_search_opt_set_max_hits(search_opts, max_hits))) {
			RZ_LOG_ERROR("core: Failed to setup search options.\n");
			goto fail;
		}

		RzSearchFindOpt *fopts = rz_core_setup_default_search_find_opts(core);
		if (!fopts) {
			RZ_LOG_ERROR("Failed setup find options.\n");
			goto fail;
		}
		rz_search_opt_set_find_options(search_opts, fopts);
	}

	return boundaries;
fail:
	rz_list_free(boundaries);
	return NULL;
}

static bool default_search_no_cancel(void *user, size_t n_hits, RzSearchCancelReason invoke_reason) {
	return rz_cons_is_breaked();
}

static RzList /*<RzSearchHit *>*/ *perform_search_on_core_io(RzCore *core, RZ_BORROW RzSearchOpt *search_opts, RZ_BORROW RzList /*<RzIOMap *>*/ *boundaries, RZ_BORROW RzSearchCollection *collection) {
	RzList *hits = NULL;

	hits = rz_search_on_io(search_opts, collection, core->io, boundaries);
	if (!hits) {
		ut64 from = rz_config_get_i(core->config, "search.from");
		ut64 to = rz_config_get_i(core->config, "search.to");
		RZ_LOG_ERROR("core: Failed to search within [0x%" PFMT64x ", 0x%" PFMT64x "].\n", from, to);
	}
	return hits;
}

/**
 * \brief      Finds a byte array in the IO layer of the given core and core configuration.
 *
 * \param      core    The RzCore core.
 * \param      opt     The search options to apply. If it is NULL a default set of options is used.
 * \param      pattern The bytes pattern to search.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_bytes(RZ_NONNULL RzCore *core, RZ_BORROW RZ_NULLABLE RzSearchOpt *user_opts, RZ_NONNULL RZ_OWN RzSearchBytesPattern *pattern) {
	rz_return_val_if_fail(core && core->config && pattern, NULL);
	if (rz_search_bytes_pattern_len(pattern) == 0) {
		RZ_LOG_ERROR("core: Cannot search for byte pattern if 'length' == 0.\n");
		rz_search_bytes_pattern_free(pattern);
		return NULL;
	}

	RzList *hits = NULL;
	RzList *boundaries = NULL;
	RzSearchOpt *search_opts = NULL;

	RzSearchCollection *collection = rz_search_collection_bytes();
	if (!collection ||
		!rz_search_collection_bytes_add_pattern(collection, pattern)) {
		RZ_LOG_ERROR("core: Failed to initialize search collection.\n");
		rz_search_bytes_pattern_free(pattern);
		goto quit;
	}

	if (!user_opts) {
		search_opts = rz_search_opt_new();
		if (!rz_search_opt_set_cancel_cb(search_opts, default_search_no_cancel, NULL)) {
			RZ_LOG_ERROR("search: Failed to setup callback for search options.\n");
			goto quit;
		}
	}

	// Don't pass the user provided search options.
	// They were set up by the user and we respect them.
	boundaries = rz_core_setup_io_search_parameters(core, user_opts ? NULL : search_opts);
	if (!boundaries) {
		RZ_LOG_ERROR("core: Setting up search from core failed.\n");
		goto quit;
	}
	if (!rz_search_opt_set_elemet_size(user_opts ? user_opts : search_opts, rz_search_bytes_pattern_len(pattern))) {
		RZ_LOG_ERROR("search: Failed to update chunk size in the search options.\n");
		goto quit;
	}

	hits = perform_search_on_core_io(core, user_opts ? user_opts : search_opts, boundaries, collection);

quit:
	rz_list_free(boundaries);
	rz_search_opt_free(search_opts);
	rz_search_collection_free(collection);
	return hits;
}

/**
 * \brief      Finds a string within the `search.in` boundaries.
 *
 * \param      core        The RzCore core.
 * \param      opt         The search options to apply. If NULL, a default set of options is used.
 * \param[in]  re_pattern  The regex pattern to search.
 * \param[in]  flags       The regex flags to the \p re_pattern.
 * \param[in]  expected    The expected encoding.
 *
 * \return     On success returns a valid pointer to a list of search hits, otherwise NULL.
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_string(RZ_NONNULL RzCore *core, RZ_BORROW RZ_NONNULL RzSearchOpt *user_opts, RZ_NONNULL const char *re_pattern, RzRegexFlags flags, RzStrEnc expected) {
	rz_return_val_if_fail(core && user_opts && re_pattern, NULL);

	if (RZ_STR_ISEMPTY(re_pattern)) {
		RZ_LOG_ERROR("core: invalid string: empty string.\n");
		return NULL;
	}
	if (strlen(re_pattern) >= core->bin->str_search_cfg.max_length) {
		RZ_LOG_ERROR("core: String to search is larger then search.str.max_length.\n");
		return NULL;
	}

	// Copy RzUtilStrScanOptions from RzBin
	RzUtilStrScanOptions scan_opt = {
		// buf_size is effectively the maximum string length.
		// Gets renamed with the refactor.
		.max_str_length = core->bin->str_search_cfg.max_length,
		.min_str_length = core->bin->str_search_cfg.min_length,
		.prefer_big_endian = core->analysis->big_endian,
		.check_ascii_freq = core->bin->str_search_cfg.check_ascii_freq,
	};

	RzList *hits = NULL;
	RzList *boundaries = NULL;
	RzSearchOpt *search_opts = NULL;

	RzSearchCollection *collection = rz_search_collection_strings(&scan_opt, expected, flags);
	if (!collection ||
		!rz_search_collection_string_add(collection, re_pattern, flags)) {
		rz_search_collection_free(collection);
		RZ_LOG_ERROR("core: Failed to initialize search collection.\n");
		return NULL;
	}
	boundaries = rz_core_setup_io_search_parameters(core, user_opts ? NULL : search_opts);
	if (!boundaries) {
		RZ_LOG_ERROR("core: Setting up search from core failed.\n");
		goto quit;
	}
	if (!rz_search_opt_set_elemet_size(user_opts ? user_opts : search_opts, scan_opt.max_str_length)) {
		RZ_LOG_ERROR("search: Failed to update chunk size in the search options.\n");
		goto quit;
	}

	hits = perform_search_on_core_io(core, user_opts ? user_opts : search_opts, boundaries, collection);

quit:
	rz_list_free(boundaries);
	rz_search_opt_free(search_opts);
	rz_search_collection_free(collection);
	return hits;
}
