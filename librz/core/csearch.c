// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_search.h>
#include <rz_util/rz_str_search.h>

RZ_IPI bool rz_core_search_get_interval(RZ_NONNULL RzCore *core, RZ_NONNULL RzInterval *interval) {
	rz_return_val_if_fail(core && interval, false);

	ut64 search_from = rz_config_get_i(core->config, "search.from");
	ut64 search_to = rz_config_get_i(core->config, "search.to");

	if (search_from > search_to) {
		RZ_LOG_ERROR("core: cannot perform search when 'search.from' is greater than 'search.to'\n");
		return false;
	} else if (search_from == search_to && search_from != UT64_MAX) {
		RZ_LOG_ERROR("core: cannot perform search when 'search.from' is equal to 'search.to'\n");
		return false;
	}

	interval->addr = search_from;
	interval->size = search_to - search_from;
	if (interval->addr == UT64_MAX && !interval->size) {
		RZ_LOG_WARN("core: 'search.from' and 'search.to' are equal to 0x%" PFMT64x "\n", UT64_MAX);
		RZ_LOG_WARN("core: search will be performed from address 0 to address 0x%" PFMT64x "\n", UT64_MAX);
		interval->addr = 0;
		interval->size = UT64_MAX;
	}
	return true;
}

/**
 * \brief      Finds all the preludes in the exec only memory areas.
 *
 * \param      core  The core
 * \param[in]  log   Whent true, logs to the terminal
 *
 * \return     On error returns false, otherwise true
 */
RZ_API bool rz_core_search_preludes(RZ_NONNULL RzCore *core, bool log) {
	rz_return_val_if_fail(core, NULL);
	RzInterval interval = { 0 };
	RzList *boundaries = NULL;
	RzList *hits = NULL;
	RzListIter *it = NULL;
	RzSearchHit *hit = NULL;
	RzSearchCollection *preludes = NULL;
	bool result = false;
	int analysis_depth = 0;

	if (!rz_core_search_get_interval(core, &interval)) {
		return false;
	}

	preludes = rz_analysis_preludes(core->analysis);
	if (!preludes) {
		const char *arch = rz_config_get(core->config, "asm.arch");
		RZ_LOG_INFO("core: no preludes returned by arch: %s\n", arch);
		// we silently return true, since there is nothing to do.
		// not all arch has preludes defined.
		return true;
	}

	if (core->bin->is_debugger) {
		boundaries = rz_core_get_boundaries_debug_program(core, interval);
	} else {
		boundaries = rz_core_get_boundaries_code_only(core, interval);
	}

	if (rz_list_empty(boundaries)) {
		ut64 from = rz_config_get_i(core->config, "search.from");
		ut64 to = rz_config_get_i(core->config, "search.to");
		RZ_LOG_ERROR("core: failed to get exec-only boundaries within [0x%" PFMT64x ", 0x%" PFMT64x "].\n", from, to);
		goto fail;
	}

	hits = rz_search_run(core->search_opts, preludes, core->io, boundaries);
	if (!hits) {
		ut64 from = rz_config_get_i(core->config, "search.from");
		ut64 to = rz_config_get_i(core->config, "search.to");
		RZ_LOG_ERROR("core: failed to search for preludes within [0x%" PFMT64x ", 0x%" PFMT64x "].\n", from, to);
		goto fail;
	}

	analysis_depth = rz_config_get_i(core->config, "analysis.depth");
	rz_list_foreach (hits, it, hit) {
		// add a function for each match.
		rz_core_analysis_fcn(core, hit->address, -1, RZ_ANALYSIS_XREF_TYPE_NULL, analysis_depth);
	}
	result = true;

fail:
	rz_list_free(hits);
	rz_list_free(boundaries);
	rz_search_collection_free(preludes);
	return result;
}

static RZ_OWN RzList /*<RzSearchHit *>*/ *core_run_search(RzCore *core, RzSearchOpt *search_opts, RzSearchCollection *collection) {
	RzList *boundaries = NULL;
	RzList *hits = NULL;
	const char *search_prefix = NULL;

	if (!core->io) {
		RZ_LOG_ERROR("core: cannot search RzIO is not available.\n");
		return NULL;
	}

	search_prefix = rz_config_get(core->config, "search.prefix");
	if (RZ_STR_ISEMPTY(search_prefix)) {
		// ensure thre prefix is always set.
		search_prefix = "hit";
	}

	boundaries = rz_core_get_boundaries_select(core, "search.from", "search.to", "search.in");
	if (rz_list_empty(boundaries)) {
		ut64 from = rz_config_get_i(core->config, "search.from");
		ut64 to = rz_config_get_i(core->config, "search.to");
		RZ_LOG_ERROR("core: failed to get search boundaries within [0x%" PFMT64x ", 0x%" PFMT64x "].\n", from, to);
		goto fail;
	}

	hits = rz_search_run(search_opts, collection, core->io, boundaries);
	if (!hits) {
		ut64 from = rz_config_get_i(core->config, "search.from");
		ut64 to = rz_config_get_i(core->config, "search.to");
		RZ_LOG_ERROR("core: failed to search within [0x%" PFMT64x ", 0x%" PFMT64x "].\n", from, to);
		goto fail;
	}

fail:
	rz_list_free(boundaries);
	rz_search_collection_free(collection);
	return hits;
}

/**
 * \brief      Finds a string within the search.in boundaries
 *
 * \param      core      The RzCore core
 * \param      opt       The search options to apply
 * \param[in]  string    The string to search
 * \param[in]  expected  The expected encoding
 * \param[in]  caseless  When true, caseless match.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_string(RZ_NONNULL RzCore *core, RZ_NONNULL RzSearchOpt *opt, RZ_NONNULL const char *string, RzStrEnc expected, bool caseless) {
	rz_return_val_if_fail(core && opt && string, NULL);

	if (!RZ_STR_ISEMPTY(string)) {
		RZ_LOG_ERROR("core: invalid string: empty string.\n");
		return NULL;
	}

	// Copy RzUtilStrScanOptions from RzBin
	RzUtilStrScanOptions str_opts;
	memcpy(&str_opts, &core->bin->str_search_cfg, sizeof(str_opts));
	str_opts.buf_size = rz_config_get_i(core->config, "search.buffer_size");

	RzSearchCollection *collection = rz_search_collection_strings(&str_opts, expected, caseless);
	if (!collection ||
		!rz_search_collection_string_add(collection, string)) {
		rz_search_collection_free(collection);
		return NULL;
	}

	return core_run_search(core, opt, collection);
}

/**
 * \brief      Finds AES keys within the search.in boundaries
 *
 * \param      core      The RzCore core
 * \param      opt       The search options to apply
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_aes_keys(RZ_NONNULL RzCore *core, RZ_NONNULL RzSearchOpt *opt) {
	rz_return_val_if_fail(core && opt, NULL);

	RzSearchCollection *collection = rz_search_collection_aes_keys();
	if (!collection) {
		return NULL;
	}

	return core_run_search(core, opt, collection);
}

/**
 * \brief      Finds private keys within the search.in boundaries
 *
 * \param      core      The RzCore core
 * \param      opt       The search options to apply
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_private_keys(RZ_NONNULL RzCore *core, RZ_NONNULL RzSearchOpt *opt) {
	rz_return_val_if_fail(core && opt, NULL);

	RzSearchCollection *collection = rz_search_collection_private_keys();
	if (!collection) {
		return NULL;
	}

	return core_run_search(core, opt, collection);
}

/**
 * \brief      Search for magic strings within the search.in boundaries using dir.magic sdbs
 *
 * \param      core  The RzCore core
 * \param      opt   The search options to apply
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_magic(RZ_NONNULL RzCore *core, RZ_NONNULL RzSearchOpt *opt) {
	rz_return_val_if_fail(core && opt, NULL);
	char *sys_magic = NULL;
	const char *dir_magic = rz_config_get(core->config, "dir.magic");

	if (RZ_STR_ISEMPTY(dir_magic)) {
		dir_magic = sys_magic = rz_path_system(RZ_SDB_MAGIC);
	}

	RzSearchCollection *collection = rz_search_collection_magic(dir_magic);
	free(sys_magic);

	if (!collection) {
		return NULL;
	}

	return core_run_search(core, opt, collection);
}

/**
 * \brief      Search using a regex within the search.in boundaries
 *
 * \param      core      The RzCore core
 * \param      opt       The search options to apply
 * \param[in]  regex     The regex to search
 * \param[in]  caseless  When true, caseless match.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_regex(RZ_NONNULL RzCore *core, RZ_NONNULL RzSearchOpt *opt, RZ_NONNULL const char *regex, bool caseless) {
	rz_return_val_if_fail(core && opt && regex, NULL);
	if (!RZ_STR_ISEMPTY(regex)) {
		RZ_LOG_ERROR("core: invalid string: empty string.\n");
		return NULL;
	}

	RzSearchCollection *collection = rz_search_collection_regex();
	if (!collection ||
		!rz_search_collection_regex_add(collection, regex, caseless)) {
		rz_search_collection_free(collection);
		return NULL;
	}

	return core_run_search(core, opt, collection);
}

/**
 * \brief      Finds a byte array within the search.in boundaries
 *
 * \param      core    The RzCore core
 * \param      opt     The search options to apply
 * \param[in]  bytes   The bytes to search
 * \param[in]  mask    The mask to search (can be NULL)
 * \param[in]  length  When true, caseless match.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_bytes(RZ_NONNULL RzCore *core, RZ_NONNULL RzSearchOpt *opt, RZ_NONNULL const ut8 *bytes, RZ_NULLABLE const ut8 *mask, size_t size) {
	rz_return_val_if_fail(core && opt && bytes, NULL);
	if (size < 1) {
		RZ_LOG_ERROR("core: cannot search for bytes when size < 1.\n");
		return NULL;
	}

	RzSearchCollection *collection = rz_search_collection_bytes();
	if (!collection ||
		!rz_search_collection_bytes_add(collection, "bytes", bytes, mask, size)) {
		rz_search_collection_free(collection);
		return NULL;
	}

	return core_run_search(core, opt, collection);
}

/**
 * \brief      Finds a hexadecimal pattern within the search.in boundaries
 *
 * \param      core         The RzCore core
 * \param      opt          The search options to apply
 * \param[in]  hex_pattern  The bytes to search
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_core_search_hex_pattern(RZ_NONNULL RzCore *core, RZ_NONNULL RzSearchOpt *opt, RZ_NONNULL const char *hex_pattern) {
	rz_return_val_if_fail(core && opt && hex_pattern, NULL);

	if (!RZ_STR_ISEMPTY(hex_pattern)) {
		RZ_LOG_ERROR("core: invalid hex pattern: empty string.\n");
		return NULL;
	}

	RzSearchCollection *collection = rz_search_collection_bytes();
	if (!collection ||
		!rz_search_collection_bytes_add_pattern(collection, hex_pattern)) {
		rz_search_collection_free(collection);
		return NULL;
	}

	return core_run_search(core, opt, collection);
}
