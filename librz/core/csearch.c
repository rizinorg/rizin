// SPDX-FileCopyrightText: 2024-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2024-2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_config.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_regex.h>
#include <rz_util/rz_file.h>
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
	if (!(rz_search_find_opt_set_overlap_match(fopts, rz_config_get_b(core->config, "search.overlap")) &&
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
		if (!boundaries) {
			RZ_LOG_ERROR("Failed to initialize boundaries within [0x%" PFMT64x ", 0x%" PFMT64x "].\n", from, to);
		} else {
			RZ_LOG_ERROR("The range [0x%" PFMT64x ", 0x%" PFMT64x "] doesn't overlap with a mapped memory region or\n"
				     "the region is not included in search.in.\n",
				from, to);
		}
		goto fail;
	}

	if (search_opts) {
		// Set search options known by core.
		ut32 max_threads = rz_th_max_threads(rz_config_get_i(core->config, "search.max_threads"));
		ut32 max_hits = rz_config_get_i(core->config, "search.maxhits");
		const char *show_progress = rz_config_get(core->config, "search.show_progress");
		if (!(rz_search_opt_set_max_threads(search_opts, max_threads) &&
			    rz_search_opt_set_max_hits(search_opts, max_hits) &&
			    rz_search_opt_set_show_progress_from_str(search_opts, show_progress))) {
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

static RzSearchOpt *default_search_options() {
	RzSearchOpt *def_options = rz_search_opt_new();
	if (!def_options) {
		RZ_LOG_ERROR("search: Failed to allocate search options.\n");
		return NULL;
	} else if (!rz_search_opt_set_cancel_cb(def_options, default_search_no_cancel, NULL)) {
		RZ_LOG_ERROR("search: Failed to setup callback for search options.\n");
		rz_search_opt_free(def_options);
		return NULL;
	}

	return def_options;
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
		// override user_opts with default one
		user_opts = search_opts = default_search_options();
		if (!search_opts) {
			goto quit;
		}
	}

	boundaries = rz_core_setup_io_search_parameters(core, user_opts);
	if (!boundaries) {
		RZ_LOG_ERROR("core: Setting up search from core failed.\n");
		goto quit;
	}

	if (!rz_search_opt_set_chunk_size(user_opts, rz_search_bytes_pattern_len(pattern))) {
		RZ_LOG_ERROR("search: Failed to update chunk size in the search options.\n");
		goto quit;
	}

	hits = perform_search_on_core_io(core, user_opts, boundaries, collection);

quit:
	rz_list_free(boundaries);
	rz_search_opt_free(search_opts);
	rz_search_collection_free(collection);
	return hits;
}

/**
 * \brief      Finds a value ranges in the IO layer of the given core and core configuration.
 *
 * \param      core    The RzCore core.
 * \param      opt     The search options to apply. If it is NULL a default set of options is used.
 * \param      vranges The value ranges to search.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_values(RZ_NONNULL RzCore *core, RZ_BORROW RZ_NULLABLE RzSearchOpt *user_opts, RZ_NONNULL RZ_OWN RzVector /*<RzSearchValueRange>*/ *vranges) {
	rz_return_val_if_fail(core && core->config && vranges, NULL);
	if (rz_vector_empty(vranges)) {
		RZ_LOG_ERROR("core: No value ranges to search.\n");
		rz_vector_free(vranges);
		return NULL;
	}

	RzList *hits = NULL;
	RzList *boundaries = NULL;
	RzSearchOpt *search_opts = NULL;

	RzSearchCollection *collection = rz_search_collection_values();
	if (!collection ||
		!rz_search_collection_values_add(collection, vranges)) {
		RZ_LOG_ERROR("core: Failed to initialize search collection.\n");
		goto quit;
	}

	if (!user_opts) {
		// override user_opts with default one
		user_opts = search_opts = default_search_options();
		if (!search_opts) {
			goto quit;
		}
	}

	boundaries = rz_core_setup_io_search_parameters(core, user_opts);
	if (!boundaries) {
		RZ_LOG_ERROR("core: Setting up search from core failed.\n");
		goto quit;
	}

	if (!rz_search_opt_set_chunk_size(user_opts, RZ_SEARCH_VALUE_SEARCH_MAX_WIDTH)) {
		RZ_LOG_ERROR("search: Failed to update chunk size in the search options.\n");
		goto quit;
	}

	hits = perform_search_on_core_io(core, user_opts, boundaries, collection);

quit:
	rz_list_free(boundaries);
	rz_search_opt_free(search_opts);
	rz_search_collection_free(collection);
	return hits;
}

/**
 * \brief      Finds a string within the `search.in` boundaries.
 *
 * \param      core            The RzCore core.
 * \param      opt             The search options to apply. If NULL, a default set of options is used.
 * \param[in]  re_pattern      The regex pattern to search.
 * \param[in]  re_pattern_len  The length of \p re_pattern if it is a literal, 0 otherwise.
 * \param[in]  flags           The regex flags to the \p re_pattern.
 * \param[in]  expected        The expected encoding.
 *
 * \return     On success returns a valid pointer to a list of search hits, otherwise NULL.
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_string(RZ_NONNULL RzCore *core, RZ_BORROW RZ_NONNULL RzSearchOpt *user_opts, RZ_NONNULL const char *re_pattern, size_t re_pattern_len, RzRegexFlags cflags, RzStrEnc encoding) {
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
		.min_str_length = RZ_MAX(re_pattern_len, core->bin->str_search_cfg.min_length),
		.prefer_big_endian = core->analysis->big_endian,
		.check_ascii_freq = core->bin->str_search_cfg.check_ascii_freq,
	};

	RzList *hits = NULL;
	RzList *boundaries = NULL;
	RzSearchOpt *search_opts = NULL;
	RzSearchCollection *collection = NULL;

	if (!user_opts) {
		// override user_opts with default one
		user_opts = search_opts = default_search_options();
		if (!search_opts) {
			goto quit;
		}
	}

	boundaries = rz_core_setup_io_search_parameters(core, user_opts);
	if (!boundaries) {
		RZ_LOG_ERROR("core: Setting up search from core failed.\n");
		goto quit;
	}
	if (!rz_search_opt_set_chunk_size(user_opts, scan_opt.max_str_length)) {
		RZ_LOG_ERROR("search: Failed to update chunk size in the search options.\n");
		goto quit;
	}

	size_t match_alignment = rz_search_find_opt_get_alignment(rz_search_opt_get_find_options(user_opts));
	collection = rz_search_collection_strings(&scan_opt, rz_search_opt_get_max_threads(user_opts));
	if (!collection ||
		!rz_search_collection_string_add(collection, re_pattern, cflags, match_alignment, encoding)) {
		rz_search_collection_free(collection);
		rz_list_free(boundaries);
		RZ_LOG_ERROR("core: Failed to initialize search collection.\n");
		return NULL;
	}

	rz_search_collection_strings_check_config_improvements(
		collection, boundaries, user_opts, &scan_opt, true);

	hits = perform_search_on_core_io(core, user_opts, boundaries, collection);

quit:
	rz_list_free(boundaries);
	rz_search_opt_free(search_opts);
	rz_search_collection_free(collection);
	return hits;
}

/**
 * \brief      Finds a cryptographic material in the IO layer of the given core and core configuration.
 *
 * \param      core The RzCore core.
 * \param      opt  The search options to apply. If it is NULL a default set of options is used.
 * \param      type The cryptographic material type (if invalid, the search will be performed on all materials).
 *
 * \return     On success returns a pointer to the search hits, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_cryptographic_material(
	RZ_NONNULL RzCore *core,
	RZ_BORROW RZ_NULLABLE RzSearchOpt *user_opts,
	RzSearchCollectionCryptographicType type) {
	rz_return_val_if_fail(core && core->config, NULL);

	RzList *hits = NULL;
	RzList *boundaries = NULL;
	RzSearchOpt *search_opts = NULL;

	RzSearchCollection *collection = rz_search_collection_cryptographic();
	if (!collection) {
		return NULL;
	}

	if (!rz_search_collection_cryptographic_add(collection, type)) {
		goto quit;
	}

	if (!user_opts) {
		// override user_opts with default one
		user_opts = search_opts = default_search_options();
		if (!search_opts) {
			goto quit;
		}
	}

	// minimal element size is always 2 (since 1 would be unaligned)
	if (!rz_search_opt_set_chunk_size(user_opts, 2)) {
		RZ_LOG_ERROR("search: Failed to update chunk size in the search options.\n");
		goto quit;
	}

	boundaries = rz_core_setup_io_search_parameters(core, user_opts);
	if (!boundaries) {
		RZ_LOG_ERROR("core: Setting up search from core failed.\n");
		goto quit;
	}

	hits = perform_search_on_core_io(core, user_opts, boundaries, collection);

quit:
	rz_list_free(boundaries);
	rz_search_opt_free(search_opts);
	rz_search_collection_free(collection);
	return hits;
}

/**
 * \brief      Finds a hash material in the IO layer of the given core and core configuration.
 *
 * \param      core The RzCore core.
 * \param      opt  The search options to apply. If it is NULL a default set of options is used.
 * \param      data Optional additional search data. Some crytpographic searches require additional data (e.g. entropy search).
 *
 * \return     On success returns a pointer to the search hits, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_hash(
	RZ_NONNULL RzCore *core,
	RZ_BORROW RZ_NULLABLE RzSearchOpt *user_opts,
	RZ_NONNULL const char *algo_name,
	RZ_NONNULL const char *expected_digits,
	ut64 block_size) {
	rz_return_val_if_fail(core && core->config && core->hash, NULL);

	RzList *hits = NULL;
	RzList *boundaries = NULL;
	RzSearchOpt *search_opts = NULL;

	RzSearchCollection *collection = rz_search_collection_hash();
	if (!collection) {
		return NULL;
	}

	if (!rz_search_collection_hash_add(collection, core->hash, algo_name, expected_digits, block_size)) {
		goto quit;
	}

	if (!user_opts) {
		// override user_opts with default one
		user_opts = search_opts = default_search_options();
		if (!search_opts) {
			goto quit;
		}
	}

	if (!rz_search_opt_set_chunk_size(user_opts, rz_search_hash_get_element_size(collection))) {
		RZ_LOG_ERROR("search: Failed to update chunk size in the search options.\n");
		goto quit;
	}

	boundaries = rz_core_setup_io_search_parameters(core, user_opts);
	if (!boundaries) {
		RZ_LOG_ERROR("core: Setting up search from core failed.\n");
		goto quit;
	}

	hits = perform_search_on_core_io(core, user_opts, boundaries, collection);

quit:
	rz_list_free(boundaries);
	rz_search_opt_free(search_opts);
	rz_search_collection_free(collection);
	return hits;
}

/**
 * \brief      Finds a hash material in the IO layer of the given core and core configuration.
 *
 * \param      core The RzCore core.
 * \param      opt  The search options to apply. If it is NULL a default set of options is used.
 * \param      data Optional additional search data. Some crytpographic searches require additional data (e.g. entropy search).
 *
 * \return     On success returns a pointer to the search hits, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_entropy(
	RZ_NONNULL RzCore *core,
	RZ_BORROW RZ_NULLABLE RzSearchOpt *user_opts,
	bool fractional,
	double min_inclusive_limit,
	double max_inclusive_limit,
	ut64 block_size) {
	rz_return_val_if_fail(core && core->config && core->hash, NULL);

	RzList *hits = NULL;
	RzList *boundaries = NULL;
	RzSearchOpt *search_opts = NULL;

	RzSearchCollection *collection = rz_search_collection_entropy(core->hash);
	if (!collection) {
		return NULL;
	}

	if (!rz_search_collection_entropy_add(collection, fractional, min_inclusive_limit, max_inclusive_limit, block_size)) {
		goto quit;
	}

	if (!user_opts) {
		// override user_opts with default one
		user_opts = search_opts = default_search_options();
		if (!search_opts) {
			goto quit;
		}
	}

	if (!rz_search_opt_set_chunk_size(user_opts, block_size)) {
		RZ_LOG_ERROR("search: Failed to update chunk size in the search options.\n");
		goto quit;
	}

	boundaries = rz_core_setup_io_search_parameters(core, user_opts);
	if (!boundaries) {
		RZ_LOG_ERROR("core: Setting up search from core failed.\n");
		goto quit;
	}

	hits = perform_search_on_core_io(core, user_opts, boundaries, collection);

quit:
	rz_list_free(boundaries);
	rz_search_opt_free(search_opts);
	rz_search_collection_free(collection);
	return hits;
}

/**
 * \brief Searches magics defined in \p magic_dir.
 *
 * \param core The core to use.
 * \param user_opts User defined search options. If NULL defaults are used.
 * \param magic_dir The directory or file with magics to search for. If NULL, the directory from 'dir.magic' is used.
 *
 * \return A list of search hits or NULL in case of failure.
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_magic(RZ_NONNULL RzCore *core, RZ_BORROW RZ_NULLABLE RzSearchOpt *user_opts, RZ_NULLABLE const char *magic_dir) {
	rz_return_val_if_fail(core && core->config, NULL);
	RzList *hits = NULL;
	RzList *boundaries = NULL;
	RzSearchOpt *search_opts = NULL;
	if (!magic_dir) {
		magic_dir = rz_config_get(core->config, "dir.magic");
	}

	RzSearchCollection *collection = rz_search_collection_magic(magic_dir);
	if (!collection) {
		return NULL;
	}

	if (!user_opts) {
		// override user_opts with default one
		user_opts = search_opts = default_search_options();
		if (!search_opts) {
			goto quit;
		}
	}

	if (!rz_search_opt_set_chunk_size(user_opts, RZ_MAGIC_BUF_SIZE)) {
		RZ_LOG_ERROR("search: Failed to update chunk size in the search options.\n");
		goto quit;
	}

	boundaries = rz_core_setup_io_search_parameters(core, user_opts);
	if (!boundaries) {
		RZ_LOG_ERROR("core: Setting up search from core failed.\n");
		goto quit;
	}

	hits = perform_search_on_core_io(core, user_opts, boundaries, collection);

quit:
	rz_list_free(boundaries);
	rz_search_opt_free(search_opts);
	rz_search_collection_free(collection);
	return hits;
}
