// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util.h>
#include <rz_util/rz_regex.h>
#include <rz_vector.h>
#include <rz_util/ht_uu.h>
#include <rz_util/rz_str_search.h>
#include "rz_util/rz_str.h"
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
static void align_offsets(RzUtilStrScanOptions options, RzStrEnc encoding, RzDetectedString *detected, RzRegexMatch *group0, ut64 *str_mem_offset, ut64 *str_mem_len) {
	if (rz_string_enc_same_char_width_as_utf8(encoding) || !detected->byte_mem_map) {
		*str_mem_offset = detected->addr + group0->start;
		*str_mem_len = group0->len;
		return;
	}

	*str_mem_offset = detected->byte_mem_map[group0->start];
	*str_mem_len = detected->byte_mem_map[group0->start + group0->len] - *str_mem_offset;
}

static bool native_string_find(RzSearchFindOpt *fopt, StringSearch *ss, ut64 offset, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {

	RzStrEnc encoding = ss->encoding;

	ut64 size;
	const ut8 *raw_buf = rz_buf_get_whole_hot_paths((RzBuffer *)buffer, &size);
	void **it_m;
	rz_pvector_foreach (ss->strings, it_m) {
		RzDetectedString *find = *it_m;
		RzPVector *matches = NULL;

		RzRegexMulti *re = rz_regex_multi_clone(find->regex, true);
		if (fopt->match_overlap) {
			matches = rz_regex_match_all_overlap_multi(re, raw_buf, size, 0, RZ_REGEX_DEFAULT);
		} else {
			matches = rz_regex_match_all_multi(re, raw_buf, size, 0, RZ_REGEX_DEFAULT);
		}
		rz_regex_free_multi_clone(re);
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
			ut64 str_mem_len = group0->len * rz_string_enc_code_point_width(encoding);
			ut64 str_mem_offset = group0->start * rz_string_enc_code_point_width(encoding);
			if (fopt->alignment > 1 && rz_mem_align_padding(str_mem_offset, fopt->alignment) != 0) {
				// Match has not the correct alignment in memory.
				continue;
			}
			if (find->alignment > 1 && rz_mem_align_padding(str_mem_offset, find->alignment) != 0) {
				// Match has not the correct alignment in memory.
				continue;
			}
			char hit_type[64] = { 0 };
			rz_strf(hit_type, "string.%s", rz_str_enc_as_string(encoding));
			RzSearchHit *hit = rz_search_hit_new(hit_type, str_mem_offset + offset, str_mem_len, NULL);
			if (!hit || !rz_th_queue_push(hits, hit, true)) {
				rz_search_hit_free(hit);
				rz_pvector_free(matches);
				return false;
			}
			(*n_hits)++;
		}
		rz_pvector_free(matches);
	}
	return true;
}

static bool string_find(RzSearchFindOpt *fopt, void *user, ut64 offset, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	rz_return_val_if_fail(fopt, false);

	StringSearch *ss = (StringSearch *)user;
	bool code_point_matches_alignment = rz_string_code_points_align(ss->encoding, fopt->alignment);
	if (rz_string_enc_is_utf_native_endian(ss->encoding) &&
		code_point_matches_alignment) {
		// The expected encoding is UTF with native endian.
		// For those we can do simple regex matching, skipping the whole decoding stuff.
		return native_string_find(fopt, ss, offset, buffer, hits, n_hits);
	}

	// Everything below is the slow and resource extensive route to search strings.
	// It will scan the whole buffer for strings, decode each one with the
	// correct encoding and length and match them.
	// This costs a lot. So it is only done for strings with:
	// A) A funny encodig we can't match directly with RzRegex/PCRE2 (e.g. EBCDIC).
	// B) Encoding must be guessed.
	// C) Matches can be at misaligned memory addresses
	//    (PCRE2 only matches strings aligned to their code point width).

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

	int n_str_in_buf = rz_scan_strings_whole_buf(buffer, found, &options, ss->encoding);
	if (n_str_in_buf < 0) {
		RZ_LOG_ERROR("Failed to scan buffer for strings.\n");
		rz_list_free(found);
		return false;
	}

	*n_hits = 0;
	rz_list_foreach (found, it_s, detected) {
		void **it_m = NULL;
		rz_pvector_foreach (ss->strings, it_m) {
			RzDetectedString *find = *it_m;
			RzRegexMulti *re = rz_regex_multi_clone(find->regex, true);
			RzPVector *matches = NULL;
			if (fopt->match_overlap) {
				matches = rz_regex_match_all_overlap(re->re8, detected->string, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
			} else {
				matches = rz_regex_match_all(re->re8, detected->string, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
			}
			rz_regex_free_multi_clone(re);
			void **it;
			rz_pvector_foreach (matches, it) {
				RzPVector *match = *it;
				RzRegexMatch *group0 = rz_pvector_at(match, 0);
				if (!group0) {
					RZ_LOG_ERROR("search: Failed to get group of match.\n");
					rz_list_free(found);
					rz_pvector_free(matches);
					return false;
				}
				ut64 str_mem_len;
				ut64 str_mem_offset;
				align_offsets(options, detected->type, detected, group0, &str_mem_offset, &str_mem_len);
				if (fopt->alignment > 1 && rz_mem_align_padding(str_mem_offset, fopt->alignment) != 0) {
					// Match has not the correct alignment in memory.
					continue;
				}
				if (find->alignment > 1 && rz_mem_align_padding(str_mem_offset, find->alignment) != 0) {
					// Match has not the correct alignment in memory.
					continue;
				}
				char hit_type[64] = { 0 };
				rz_strf(hit_type, "string.%s", rz_str_enc_as_string(detected->type));
				RzSearchHit *hit = rz_search_hit_new(hit_type, str_mem_offset + offset, str_mem_len, NULL);
				if (!hit || !rz_th_queue_push(hits, hit, true)) {
					rz_search_hit_free(hit);
					rz_list_free(found);
					rz_pvector_free(matches);
					return false;
				}
				(*n_hits)++;
			}
			rz_pvector_free(matches);
		}
	}

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
 * \param      opts        The RzUtilStrScanOptions options to use.
 *                         It is allowed to be NULL iff the expected encoding is
 *                         Unicode, has the native machines endianness, and
 *                         \p alignment is the same as the encoding code point width.
 * \param[in]  expected    The expected encoding
 * \param[in]  alignment   The alignment of matches.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_strings(RZ_BORROW RzUtilStrScanOptions *scan_opts, RzStrEnc expected, size_t alignment) {
	if ((!rz_string_enc_is_utf_native_endian(expected) ||
		    !rz_string_code_points_align(expected, alignment)) &&
		!scan_opts) {
		RZ_LOG_ERROR("Initalizeing string search collection failed: opts is not"
			     "allowed to be NULL if the searched encoding has not the same endianness as the machine.\n");
		return NULL;
	}

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

	if (scan_opts) {
		ss->options = *scan_opts; // Copy because they are shared between threads.
	}
	ss->encoding = expected;

	return rz_search_collection_new_bytes_space(string_find, string_is_empty, string_free, ss);
}

static RzDetectedString *setup_str_regex(const char *re_pattern, RzRegexFlags cflags, RzStrEnc encoding) {
	char *re_pattern_clone = rz_str_dup(re_pattern);
	if (!re_pattern_clone) {
		RZ_LOG_ERROR("Failed to clone regex pattern\n");
		return NULL;
	}

	RzRegexMulti *re;
	if (rz_string_enc_is_utf_native_endian(encoding)) {
		switch (encoding) {
		default:
			rz_warn_if_reached();
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
 * \param[in]  col             The RzSearchCollection to use.
 * \param[in]  regex_pattern   The regular expression to add.
 * \param[in]  cflags          The regular expression compile flags.
 * \param[in]  match_alignment The memory address alignment all matches must have.
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_search_collection_string_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *regex_pattern, RzRegexFlags cflags, size_t match_alignment) {
	rz_return_val_if_fail(col && regex_pattern, false);

	if (!rz_search_collection_has_find_callback(col, string_find)) {
		RZ_LOG_ERROR("search: cannot add string to non-string collection\n");
		return false;
	} else if (RZ_STR_ISEMPTY(regex_pattern)) {
		RZ_LOG_ERROR("search: cannot add an empty string to a string collection\n");
		return false;
	}
	StringSearch *ss = (StringSearch *)col->user;

	bool code_point_matches_alignment = rz_string_code_points_align(ss->encoding, match_alignment);
	RzDetectedString *s = setup_str_regex(regex_pattern, cflags, code_point_matches_alignment ? ss->encoding : RZ_STRING_ENC_UTF8);
	if (!s) {
		return false;
	}
	s->alignment = match_alignment;
	if (!rz_pvector_push(ss->strings, s)) {
		RZ_LOG_ERROR("search: cannot add the string '%s'.\n", regex_pattern);
		rz_detected_string_free(s);
		return false;
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
	if (ss->encoding == RZ_STRING_ENC_GUESS) {
		if (log_suggestions) {
			RZ_LOG_WARN("The string encoding for the search is set to \"guess\".\n"
				    "The search will consume vastly more resources and the guessing is unreliable.\n"
				    "You can set a specific encoding with 'e str.encoding=<encoding>'.\n");
		}
		return false;
	}
	if (!rz_string_code_points_align(ss->encoding, search_options->find_opts->alignment)) {
		if (log_suggestions) {
			RZ_LOG_INFO("The string encoding has code points of more than 1 byte. But search.align is set to 1.\n"
				    "The search will consume more resources, because alignment is not a multiple of the code point size.\n"
				    "For larger binaries consider to change the encoding to a multiple of 2 (UTF-16) or 4 (UTF-32).\n");
		}
		return false;
	}
	return true;
}
