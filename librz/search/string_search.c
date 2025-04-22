// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util.h>
#include <rz_util/rz_regex.h>
#include <rz_vector.h>
#include <rz_util/ht_uu.h>
#include <rz_util/rz_str_search.h>
#include "search_internal.h"

typedef struct string_search {
	RzUtilStrScanOptions options; ///< String scan options
	RzStrEnc encoding; ///< Expected encoding
	RzPVector /*<RzDetectedString *>*/ *strings; ///< Strings to search
} StringSearch;

/**
 * \brief UTF-8 and the encoding of the real string (in memory) must not match.
 * For example, if the real string is UTF-16 or UTF-32.
 * Here we set the real (in memory encoded) string offsets and string length.
 */
static void align_offsets(RzUtilStrScanOptions options, RzStrEnc encoding, RzDetectedString *detected, RzRegexMatch *group0, ut64 *str_mem_offset, ut64 *str_mem_len, ut64 found_idx) {
	if (rz_string_enc_is_utf8_compatible(encoding)) {
		*str_mem_offset = detected->addr + group0->start;
		*str_mem_len = group0->len;
		return;
	}

	bool offset_found = false;
	bool len_found = false;

	*str_mem_offset = ht_uu_find(options.utf8_to_mem_offset_map, found_idx | (group0->start), &offset_found);
	if (!offset_found) {
		RZ_LOG_WARN("Could not determine memory offset of %s string in search. String offset will be off for: %s\n",
			rz_str_enc_as_string(detected->type), detected->string);
		*str_mem_offset = detected->addr + group0->start;
	}
	*str_mem_len = ht_uu_find(options.utf8_to_mem_offset_map, found_idx | (group0->start + group0->len), &len_found) - *str_mem_offset;
	if (!len_found) {
		if (!offset_found) {
			// If the previous offset was not found, we know something is broken.
			// If it was found on the other hand, the string is exactly as long as the whole buffer.
			// So `start + len` is OOB and hence not in the hash table.
			RZ_LOG_WARN("Could not determine length of string in memory. String length will be off.\n");
		}
		*str_mem_len = group0->len;
	}
}

static bool string_find(RzSearchFindOpt *fopt, void *user, ut64 offset, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	rz_return_val_if_fail(fopt, false);

	StringSearch *ss = (StringSearch *)user;
	RzDetectedString *detected = NULL;
	RzListIter *it_s = NULL;

	RzList *found = rz_list_newf((RzListFree)rz_detected_string_free);
	if (!found) {
		RZ_LOG_ERROR("search: failed to allocate found list for strings collection\n");
		return false;
	}

	// Copy options here so we can set the hash table.
	// The search options are a shared resource and we might get
	// race-conditions editing and freeing it.
	RzUtilStrScanOptions options = ss->options;
	options.utf8_to_mem_offset_map = ht_uu_new();

	int n_str_in_buf = rz_scan_strings_whole_buf(buffer, found, &options, ss->encoding);
	if (n_str_in_buf < 0) {
		RZ_LOG_ERROR("Failed to scan buffer for strings.\n");
		ht_uu_free(options.utf8_to_mem_offset_map);
		rz_list_free(found);
		return false;
	}

	ut64 found_idx = 0;
	*n_hits = 0;
	rz_list_foreach (found, it_s, detected) {
		void **it_m = NULL;
		rz_pvector_foreach (ss->strings, it_m) {
			RzDetectedString *find = *it_m;
			RzPVector *matches = fopt->match_overlap ? rz_regex_match_all_overlap(find->regex, detected->string, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT) : rz_regex_match_all(find->regex, detected->string, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
			void **it;
			rz_pvector_foreach (matches, it) {
				RzPVector *match = *it;
				RzRegexMatch *group0 = rz_pvector_at(match, 0);
				if (!group0) {
					RZ_LOG_ERROR("search: Failed to get group of match.\n");
					ht_uu_free(options.utf8_to_mem_offset_map);
					rz_list_free(found);
					rz_pvector_free(matches);
					return false;
				}
				ut64 str_mem_len;
				ut64 str_mem_offset;
				align_offsets(options, detected->type, detected, group0, &str_mem_offset, &str_mem_len, found_idx << 32);
				if (fopt->alignment > 1 && rz_mem_align_padding(str_mem_offset + group0->start, fopt->alignment) != 0) {
					// Match has not the correct alignment in memory.
					continue;
				}
				char *hit_type = rz_str_newf("string.%s", rz_str_enc_as_string(detected->type));
				RzSearchHit *hit = rz_search_hit_new(hit_type, str_mem_offset + offset, str_mem_len, NULL);
				free(hit_type);
				if (!hit || !rz_th_queue_push(hits, hit, true)) {
					rz_search_hit_free(hit);
					ht_uu_free(options.utf8_to_mem_offset_map);
					rz_list_free(found);
					rz_pvector_free(matches);
					return false;
				}
				(*n_hits)++;
			}
			rz_pvector_free(matches);
		}
		found_idx++;
	}

	ht_uu_free(options.utf8_to_mem_offset_map);
	rz_list_free(found);
	return true;
}

static bool string_is_empty(void *user) {
	StringSearch *ss = (StringSearch *)user;
	return rz_pvector_empty(ss->strings);
}

static void string_free(void *user) {
	if (!user) {
		return;
	}
	StringSearch *ss = (StringSearch *)user;
	rz_pvector_free(ss->strings);
	free(ss);
}

/**
 * \brief      Allocates and initialize a string RzSearchCollection
 *
 * \param      opts      The RzUtilStrScanOptions options to use
 * \param[in]  expected  The expected encoding
 * \param[in]  flags     The regex flags to the \p re_pattern.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_strings(RZ_NONNULL RzUtilStrScanOptions *opts, RzStrEnc expected, RzRegexFlags flags) {
	rz_return_val_if_fail(opts, NULL);

	StringSearch *ss = RZ_NEW0(StringSearch);
	if (!ss) {
		RZ_LOG_ERROR("search: failed to allocate StringSearch\n");
		return NULL;
	}

	ss->strings = rz_pvector_new((RzPVectorFree)rz_detected_string_free);
	if (!ss->strings) {
		RZ_LOG_ERROR("search: failed to initialize string collection\n");
		string_free(ss);
		return NULL;
	}

	ss->options = *opts; // Copy the values
	ss->encoding = expected;

	return rz_search_collection_new_bytes_space(string_find, string_is_empty, string_free, ss);
}

static RzDetectedString *setup_str_regex(const char *re_pattern, RzRegexFlags flags) {
	char *re_pattern_clone = rz_str_dup(re_pattern);
	if (!re_pattern_clone) {
		RZ_LOG_ERROR("Failed to clone regex pattern\n");
		return NULL;
	}
	RzRegex *re = rz_regex_new(re_pattern, flags, RZ_REGEX_DEFAULT, NULL);
	if (!re) {
		RZ_LOG_ERROR("Failed to compile regex pattern: '%s'\n", re_pattern);
		free(re_pattern_clone);
		return NULL;
	}
	RzDetectedString *ds = RZ_NEW0(RzDetectedString);
	if (!ds) {
		RZ_LOG_ERROR("Failed allocate memory for RzDetectedString\n");
		free(re_pattern_clone);
		rz_regex_free(re);
		return NULL;
	}
	ds->string = re_pattern_clone;
	ds->regex = re;
	ds->length = strlen(re_pattern_clone);
	return ds;
}

/**
 * \brief      Adds a new regex pattern into a string RzSearchCollection.
 *
 * \param[in]  col            The RzSearchCollection to use.
 * \param[in]  regex_pattern  The regular expression to add.
 * \param[in]  flags          The regular expression flags.
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_search_collection_string_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *regex_pattern, RzRegexFlags flags) {
	rz_return_val_if_fail(col && regex_pattern, false);

	if (!rz_search_collection_has_find_callback(col, string_find)) {
		RZ_LOG_ERROR("search: cannot add string to non-string collection\n");
		return false;
	} else if (RZ_STR_ISEMPTY(regex_pattern)) {
		RZ_LOG_ERROR("search: cannot add an empty string to a string collection\n");
		return false;
	}
	StringSearch *ss = (StringSearch *)col->user;

	RzDetectedString *s = setup_str_regex(regex_pattern, flags);
	if (!s || !rz_pvector_push(ss->strings, s)) {
		RZ_LOG_ERROR("search: cannot add the string '%s'.\n", regex_pattern);
		rz_detected_string_free(s);
		return false;
	}
	return true;
}
