// SPDX-FileCopyrightText: 2024-2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024-2025 Rot127 <rot127@posteo.com>
// SPDX-FileCopyrightText: 2024-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util.h>
#include <rz_util/rz_regex.h>
#include <rz_vector.h>
#include <rz_util/ht_uu.h>
#include <rz_util/rz_str_search.h>
#include <rz_th.h>
#include "rz_util/rz_assert.h"
#include "search_internal.h"

typedef struct string_search {
	RzUtilStrScanOptions options; ///< String scan options
	/**
	 * \brief Strings to search.
	 * Each thread gets its own thread safe copy of the patterns to search.
	 * The outer vector is indexed by thread ID.
	 */
	RzPVector /*<RzPVector<RzDetectedString *> *>*/ *strings;
	/**
	 * \brief This queue holds the thread ids. Each worker is draws a
	 * one number and then pick its thread safe object for searching strings from
	 * above.
	 * On return it must push its ID into the queue again to release it.
	 */
	RzThreadQueue *thread_ids;
} StringSearch;

/**
 * \brief Returns true if the string encoding requires scanning and conversion
 * to UTF-8 for searching.
 * Returns false if direct matching with PCRE2 is supported.
 */
RZ_API bool rz_search_str_enc_needs_scanning(RzStrEnc encoding) {
	switch (encoding) {
	case RZ_STRING_ENC_8BIT:
	case RZ_STRING_ENC_UTF8:
	case RZ_STRING_ENC_MUTF8:
	case RZ_STRING_ENC_UTF16LE:
	case RZ_STRING_ENC_UTF32LE:
	case RZ_STRING_ENC_UTF16BE:
	case RZ_STRING_ENC_UTF32BE:
		return false;
	case RZ_STRING_ENC_IBM037:
	case RZ_STRING_ENC_IBM290:
	case RZ_STRING_ENC_EBCDIC_UK:
	case RZ_STRING_ENC_EBCDIC_US:
	case RZ_STRING_ENC_EBCDIC_ES:
	case RZ_STRING_ENC_GUESS:
		return true;
	case RZ_STRING_ENC_SETTINGS:
		rz_warn_if_reached();
		return true;
	}
	rz_warn_if_reached();
	return true;
}

/**
 * \brief UTF-8 and the encoding of the real string (in memory) must not match.
 * For example, if the real string is UTF-16 or UTF-32.
 * Here we set the real (in memory encoded) string offsets and string length.
 */
static void align_offsets(RzUtilStrScanOptions options, RzStrEnc encoding, RzDetectedString *detected, RzRegexMatch *group0, ut64 *str_mem_offset, ut64 *str_mem_len) {
	if (rz_string_enc_same_char_width_as_utf8(encoding) || !detected->byte_mem_map) {
		*str_mem_offset = detected->addr + group0->start;
		*str_mem_len = group0->len;
		return;
	}

	*str_mem_offset = detected->byte_mem_map[group0->start];
	ut64 end = detected->byte_mem_map[group0->start + group0->len];
	*str_mem_len = end - *str_mem_offset;
}

static bool native_string_find(RzSearchFindOpt *fopt, RzDetectedString *find, ut64 offset, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {

	ut64 size;
	const ut8 *raw_buf = rz_buf_get_whole_hot_paths((RzBuffer *)buffer, &size);
	RzPVector *matches = NULL;

	if (fopt->match_overlap) {
		matches = rz_regex_match_all_overlap_multi(find->regex, raw_buf, size, 0, RZ_REGEX_DEFAULT);
	} else {
		matches = rz_regex_match_all_multi(find->regex, raw_buf, size, 0, RZ_REGEX_DEFAULT);
	}
	if (!matches) {
		return false;
	}
	void **it;
	rz_pvector_foreach (matches, it) {
		RzPVector *match = *it;
		RzRegexMatch *group0 = rz_pvector_at(match, 0);
		if (!group0) {
			RZ_LOG_ERROR("search: Failed to get group of match.\n");
			rz_pvector_free(matches);
			return false;
		}
		ut64 str_mem_len = group0->len * rz_string_enc_code_point_width(find->encoding);
		ut64 str_mem_offset = group0->start * rz_string_enc_code_point_width(find->encoding);
		if (find->alignment > 1 && rz_mem_align_padding(str_mem_offset, find->alignment) != 0) {
			// Match has not the correct alignment in memory.
			continue;
		}
		char hit_type[64] = { 0 };
		rz_strf(hit_type, "string.%s", rz_str_enc_as_string(find->encoding));
		RzSearchHitDetail *char_len = rz_search_hit_detail_unsigned_new(group0->len);
		RzSearchHit *hit = rz_search_hit_new(hit_type, str_mem_offset + offset, str_mem_len, char_len);
		if (!hit || !rz_th_queue_push(hits, hit, true)) {
			rz_search_hit_free(hit);
			rz_pvector_free(matches);
			return false;
		}
		(*n_hits)++;
	}
	rz_pvector_free(matches);
	return true;
}

static inline int next_i(int i, RzStrEnc enc, size_t alignment) {
	if (i < 0 || alignment >= 4) {
		return -1;
	}
	switch (enc) {
	default:
		return -1;
	case RZ_STRING_ENC_UTF16BE:
	case RZ_STRING_ENC_UTF16LE:
		return i >= 1 || alignment != 1 ? -1 : i + 1;
	case RZ_STRING_ENC_UTF32BE:
	case RZ_STRING_ENC_UTF32LE:
		return i >= 3 || !RZ_BETWEEN(1, alignment, 2) ? -1 : i + 1;
	}
}

static bool adjusted_buffer_string_find(RzSearchFindOpt *fopt, RzDetectedString *find, ut64 offset, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	if (fopt->alignment < 4 && !RZ_BETWEEN(1, fopt->alignment, 2)) {
		rz_warn_if_reached();
		return false;
	}
	ut64 ab_size;
	const ut8 *raw_buf = rz_buf_get_whole_hot_paths((RzBuffer *)buffer, &ab_size);
	if (!raw_buf || !ab_size || ab_size != rz_buf_size((RzBuffer *)buffer)) {
		rz_warn_if_reached();
		return NULL;
	}

	// PCRE2 can match UTF-8/16/32. But only if the buffer is aligned properly
	// to the code point width and is of host endianness.
	// This branch handles the cases where one or both are not true.
	size_t i = 0;
	do {
		ut8 *adjusted_buf = NULL;
		// Check if the alignment missmatches. If so, adjust it.
		if (!rz_string_code_points_align(find->encoding, find->alignment)) {
			adjusted_buf = rz_mem_copy_offset(raw_buf, ab_size, i);
			if (!adjusted_buf) {
				rz_warn_if_reached();
				return NULL;
			}
		}

		// Now swap the endianness if required.
		if (!rz_string_enc_is_utf_native_endian(find->encoding)) {
			switch (find->encoding) {
			default:
				rz_warn_if_reached();
				free(adjusted_buf);
				return NULL;
			case RZ_STRING_ENC_UTF32BE:
			case RZ_STRING_ENC_UTF32LE:
				adjusted_buf = adjusted_buf ? rz_mem_swap_bytes_4_inplace(adjusted_buf, ab_size) : rz_mem_swap_bytes_4(raw_buf, ab_size);
				break;
			case RZ_STRING_ENC_UTF16BE:
			case RZ_STRING_ENC_UTF16LE:
				adjusted_buf = adjusted_buf ? rz_mem_swap_bytes_2_inplace(adjusted_buf, ab_size) : rz_mem_swap_bytes_2(raw_buf, ab_size);
				break;
			}
		}

		if (!adjusted_buf) {
			// Alignment is fine in this iteration and there is no endianness switch.
			// So use the default buffer.
			if (!native_string_find(fopt, find, offset, buffer, hits, n_hits)) {
				return false;
			}
		} else {
			RzBuffer *ab = rz_buf_new_from_bytes(adjusted_buf, ab_size);
			if (!native_string_find(fopt, find, offset + i, ab, hits, n_hits)) {
				rz_buf_free(ab);
				return false;
			}
			rz_buf_free(ab);
		}

		i = next_i(i, find->encoding, find->alignment);
		if (i == -1) {
			break;
		}
	} while (true);
	return true;
}

static inline bool do_search_by_direct_matching(RzStrEnc encoding, size_t buf_alignment) {
	return rz_string_enc_is_utf_native_endian(encoding) &&
		rz_string_code_points_align(encoding, buf_alignment);
}

static inline bool do_search_with_adjusted_buffer(RzStrEnc encoding, size_t alignment) {
	return rz_string_enc_is_utf(encoding) && !do_search_by_direct_matching(encoding, alignment);
}

static bool string_find(RzSearchFindOpt *fopt, void *user, ut64 offset, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	rz_return_val_if_fail(fopt, false);

	void *data = NULL;
	StringSearch *ss = (StringSearch *)user;
	if (!rz_th_queue_pop(ss->thread_ids, false, &data) || !data) {
		return false;
	}

	size_t *thread_id = data;
	RzPVector *strings = rz_pvector_at(ss->strings, *thread_id);

	void **it_m = NULL;
	rz_pvector_foreach (strings, it_m) {
		RzDetectedString *find = *it_m;
		if (do_search_by_direct_matching(find->encoding, fopt->alignment)) {
			// The expected encoding is UTF with native endian.
			// Also, the alignment matches the code point width (offset is always aligned to 64bytes).
			// For those we can do simple regex matching, skipping the whole decoding stuff.
			if (!native_string_find(fopt, find, offset, buffer, hits, n_hits)) {
				goto release_thread_id_ret_false;
			}
			continue;
		} else if (do_search_with_adjusted_buffer(find->encoding, fopt->alignment)) {
			// This string search is used for UTF encodings which:
			// - Have the opposite endianness of the host system.
			// - AND/OR have a code point width not congruent to fopt->alignment.
			if (!adjusted_buffer_string_find(fopt, find, offset, buffer, hits, n_hits)) {
				goto release_thread_id_ret_false;
			}
			continue;
		}

		// Everything below is the slow and resource extensive route to search strings.
		// It will scan the whole buffer for strings, decode each one with the
		// correct encoding and length and match them.
		// This costs a lot. So it is only done for strings with:
		// A) A funny encodig we can't match directly with RzRegex/PCRE2 (e.g. EBCDIC).
		// B) Encoding must be guessed.

		RzDetectedString *detected = NULL;
		RzListIter *it_s = NULL;

		RzList *found = rz_list_newf((RzListFree)rz_detected_string_free);
		if (!found) {
			RZ_LOG_ERROR("search: failed to allocate found list for strings collection\n");
			goto release_thread_id_ret_false;
		}

		// Copy options here so we can set the hash table.
		// The search options are a shared resource and we might get
		// race-conditions editing and freeing it.
		RzUtilStrScanOptions options = ss->options;

		int n_str_in_buf = rz_scan_strings_whole_buf(buffer, found, &options, find->encoding);
		if (n_str_in_buf < 0) {
			RZ_LOG_ERROR("Failed to scan buffer for strings.\n");
			rz_list_free(found);
			goto release_thread_id_ret_false;
		}

		*n_hits = 0;
		rz_list_foreach (found, it_s, detected) {
			RzPVector *matches = NULL;
			if (fopt->match_overlap) {
				matches = rz_regex_match_all_overlap(find->regex->re8, detected->string, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
			} else {
				matches = rz_regex_match_all(find->regex->re8, detected->string, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
			}
			void **it;
			rz_pvector_foreach (matches, it) {
				RzPVector *match = *it;
				RzRegexMatch *group0 = rz_pvector_at(match, 0);
				if (!group0) {
					RZ_LOG_ERROR("search: Failed to get group of match.\n");
					rz_list_free(found);
					rz_pvector_free(matches);
					goto release_thread_id_ret_false;
				}
				ut64 str_mem_len;
				ut64 str_mem_offset;
				align_offsets(options, detected->encoding, detected, group0, &str_mem_offset, &str_mem_len);
				if (fopt->alignment > 1 && rz_mem_align_padding(str_mem_offset, fopt->alignment) != 0) {
					// Match has not the correct alignment in memory.
					continue;
				}
				if (find->alignment > 1 && rz_mem_align_padding(str_mem_offset, find->alignment) != 0) {
					// Match has not the correct alignment in memory.
					continue;
				}
				char hit_type[64] = { 0 };
				rz_strf(hit_type, "string.%s", rz_str_enc_as_string(detected->encoding));
				RzSearchHitDetail *char_len = rz_search_hit_detail_unsigned_new(find->length);
				RzSearchHit *hit = rz_search_hit_new(hit_type, str_mem_offset + offset, str_mem_len, char_len);
				if (!hit || !rz_th_queue_push(hits, hit, true)) {
					rz_search_hit_free(hit);
					rz_list_free(found);
					rz_pvector_free(matches);
					goto release_thread_id_ret_false;
				}
				(*n_hits)++;
			}
			rz_pvector_free(matches);
		}
		rz_list_free(found);
	}
	rz_th_queue_push(ss->thread_ids, thread_id, true);
	return true;

release_thread_id_ret_false:
	rz_th_queue_push(ss->thread_ids, thread_id, true);
	return false;
}

static bool string_is_empty(void *user) {
	StringSearch *ss = (StringSearch *)user;
	void **it;
	rz_pvector_foreach (ss->strings, it) {
		RzPVector *pv = *it;
		if (!rz_pvector_empty(pv)) {
			return false;
		}
	}
	return true;
}

static void string_free(void *user) {
	if (!user) {
		return;
	}
	StringSearch *ss = (StringSearch *)user;
	rz_pvector_free(ss->strings);
	rz_th_queue_free(ss->thread_ids);
	free(ss);
}

/**
 * \brief      Allocates and initialize a string RzSearchCollection
 *
 * \param      opts        The RzUtilStrScanOptions options to use.
 *                         It can be NULL if string scanning is not required.
 *                         rz_search_collection_string_add() will refuse in this case to
 *                         add patterns to the collection which require it.
 *                         Any non-UTF or guessed encoding requires scanning.
 * \param      n_threads   Number of threads for the search. Must be >0.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_strings(RZ_NULLABLE RZ_BORROW RzUtilStrScanOptions *scan_opts, size_t n_threads) {
	rz_return_val_if_fail(n_threads, NULL);
	StringSearch *ss = RZ_NEW0(StringSearch);
	if (!ss) {
		RZ_LOG_ERROR("search: failed to allocate StringSearch\n");
		return NULL;
	}

	ss->strings = rz_pvector_new((RzPVectorFree)rz_pvector_free);
	ss->thread_ids = rz_th_queue_new(n_threads, free);
	if (!ss->strings || !ss->thread_ids) {
		goto error;
	}
	for (size_t t = 0; t < n_threads; ++t) {
		RzPVector *thread_unique_str = rz_pvector_new((RzPVectorFree)rz_detected_string_free);
		if (!thread_unique_str) {
			goto error;
		}
		size_t *t_ptr = RZ_NEW(size_t);
		if (!t_ptr) {
			goto error;
		}
		*t_ptr = t;
		if (!rz_th_queue_push(ss->thread_ids, t_ptr, true)) {
			goto error;
		}
		rz_pvector_push(ss->strings, thread_unique_str);
	}

	if (scan_opts) {
		ss->options = *scan_opts; // Copy because they are shared between threads.
	}

	return rz_search_collection_new_bytes_space(string_find, string_is_empty, string_free, ss);

error:
	RZ_LOG_ERROR("search: failed to initialize string collection\n");
	string_free(ss);
	return NULL;
}

static RzDetectedString *setup_str_regex(const char *re_pattern, RzRegexFlags cflags, size_t match_alignment, RzStrEnc encoding) {
	char *re_pattern_clone = rz_str_dup(re_pattern);
	if (!re_pattern_clone) {
		RZ_LOG_ERROR("Failed to clone regex pattern\n");
		return NULL;
	}

	RzRegexMulti *re;
	if (rz_string_enc_is_utf(encoding)) {
		switch (encoding) {
		default:
			rz_warn_if_reached();
			free(re_pattern_clone);
			return NULL;
		case RZ_STRING_ENC_UTF8:
		case RZ_STRING_ENC_8BIT:
			re = rz_regex_new_multi(re_pattern, cflags, RZ_REGEX_DEFAULT, NULL, RZ_REGEX_UTF8);
			break;
		case RZ_STRING_ENC_UTF16LE:
		case RZ_STRING_ENC_UTF16BE:
			re = rz_regex_new_multi(re_pattern, cflags, RZ_REGEX_DEFAULT, NULL, RZ_REGEX_UTF16);
			break;
		case RZ_STRING_ENC_UTF32LE:
		case RZ_STRING_ENC_UTF32BE:
			re = rz_regex_new_multi(re_pattern, cflags, RZ_REGEX_DEFAULT, NULL, RZ_REGEX_UTF32);
			break;
		}
	} else {
		re = rz_regex_new_multi(re_pattern, cflags, RZ_REGEX_DEFAULT, NULL, RZ_REGEX_UTF8);
	}
	if (!re) {
		RZ_LOG_ERROR("Failed to compile regex pattern: '%s'\n", re_pattern);
		free(re_pattern_clone);
		return NULL;
	}
	RzDetectedString *ds = RZ_NEW0(RzDetectedString);
	if (!ds) {
		RZ_LOG_ERROR("Failed allocate memory for RzDetectedString\n");
		free(re_pattern_clone);
		rz_regex_free_multi(re);
		return NULL;
	}
	ds->string = re_pattern_clone;
	ds->regex = re;
	ds->length = strlen(re_pattern_clone);
	ds->encoding = encoding;
	ds->alignment = match_alignment;
	return ds;
}

/**
 * \brief      Adds a new regex pattern into a string RzSearchCollection.
 *
 * \param[in]  col             The RzSearchCollection to use.
 * \param[in]  regex_pattern   The regular expression to add.
 * \param[in]  cflags          The regular expression compile flags.
 * \param[in]  match_alignment The memory address alignment all matches must have.
 * \param[in]  encoding        The encoding of the strings to search.
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_search_collection_string_add(
	RZ_NONNULL RzSearchCollection *col,
	RZ_NONNULL const char *regex_pattern,
	RzRegexFlags cflags,
	size_t match_alignment,
	RzStrEnc encoding) {
	rz_return_val_if_fail(col && regex_pattern, false);
	StringSearch *ss = (StringSearch *)col->user;
	if ((rz_search_str_enc_needs_scanning(encoding) &&
		    ss->options.max_str_length == 0)) {
		RZ_LOG_ERROR("Cannot add pattern to collection: RzUtilStrScanOptions::max_str_length == 0."
			     "This is not allowed if the searched encoding requires string scanning.\n");
		return false;
	}

	if (!rz_search_collection_has_find_callback(col, string_find)) {
		RZ_LOG_ERROR("search: cannot add string to non-string collection\n");
		return false;
	} else if (RZ_STR_ISEMPTY(regex_pattern)) {
		RZ_LOG_ERROR("search: cannot add an empty string to a string collection\n");
		return false;
	}

	void **it;
	rz_pvector_foreach (ss->strings, it) {
		RzPVector *thread_strings = *it;
		RzDetectedString *s = setup_str_regex(regex_pattern, cflags, match_alignment, encoding);
		if (!s) {
			return false;
		}
		if (!rz_pvector_push(thread_strings, s)) {
			RZ_LOG_ERROR("search: cannot add the string '%s'.\n", regex_pattern);
			rz_detected_string_free(s);
			return false;
		}
	}
	return true;
}

/**
 * \brief Checks the elements of a string search and warns the user about possible optimizations.
 *
 * \param col The string search collection.
 * \param boundaries The search boundaries.
 * \param search_options The search options.
 * \param scan_opts The string scan options.
 * \param If true, it will print suggestions to improve the search performance as warning.
 *
 * \return Returns true if the config is optional. False otherwise.
 */
RZ_API bool rz_search_collection_strings_check_config_improvements(
	RZ_NULLABLE const RzSearchCollection *col,
	RZ_NULLABLE const RzList /*<RzIOMap *>*/ *boundaries,
	RZ_NULLABLE const RzSearchOpt *search_options,
	RZ_NULLABLE const RzUtilStrScanOptions *scan_opt,
	bool log_suggestions) {
	if (!search_options || !search_options->find_opts || !col) {
		return true;
	}
	StringSearch *ss = col->user;
	void **it;
	rz_pvector_foreach (ss->strings, it) {
		void **itt;
		RzPVector *thread_unique = *it;
		rz_pvector_foreach (thread_unique, itt) {
			RzDetectedString *ds = *itt;
			if (ds->encoding == RZ_STRING_ENC_GUESS) {
				if (log_suggestions) {
					RZ_LOG_WARN("The string encoding for the search is set to \"guess\".\n"
						    "The search will consume vastly more resources and the guessing is unreliable.\n"
						    "You can set a specific encoding with 'e str.encoding=<encoding>'.\n");
				}
				return false;
			}
			if (!rz_string_code_points_align(ds->encoding, search_options->find_opts->alignment)) {
				if (log_suggestions) {
					RZ_LOG_INFO("The string encoding has code points of more than 1 byte. But search.align is set to 1.\n"
						    "The search will consume more resources, because alignment is not a multiple of the code point size.\n"
						    "For larger binaries consider to change the encoding to a multiple of 2 (UTF-16) or 4 (UTF-32).\n");
				}
				return false;
			}
		}
	}

	return true;
}
