// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util.h>

#include <rz_util/rz_assert.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_buf.h>
#include <rz_util/rz_regex.h>
#include <rz_util/rz_mem.h>
#include "search_internal.h"

/**
 * \brief Initialize a new search bytes pattern and return it.
 *
 * \param bytes The bytes to search for.
 * \param mask The mask to apply to the pattern and the data before comparison. (optional)
 * \param length Length of \p bytes and \p mask (if not NULL).
 * \param pattern_desc An optional description string of the pattern.
 * \param compile_regex If true it compiles \p bytes as regex.
 * This will make the search use the regex, instead of comparing the bytes.
 * The \p mask is ignored in this case.
 *
 * \return The initalized pattern or NULL in case of failure.
 */
RZ_API RZ_OWN RzSearchBytesPattern *rz_search_bytes_pattern_new(RZ_OWN ut8 *bytes, RZ_NULLABLE RZ_OWN ut8 *mask, size_t length, RZ_NULLABLE const char *pattern_desc, bool compile_regex) {
	rz_return_val_if_fail(bytes && length > 0, NULL);
	RzSearchBytesPattern *pat = RZ_NEW0(RzSearchBytesPattern);
	if (!pat) {
		RZ_LOG_ERROR("Failed to allocate pattern struct.\n");
		free(bytes);
		free(mask);
		return NULL;
	}
	pat->bytes = bytes;
	if (compile_regex) {
		pat->regex = rz_regex_new_bytes(bytes, length, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT, NULL);
	}
	pat->mask = mask;
	pat->length = length;
	pat->pattern_desc = pattern_desc;
	return pat;
}

RZ_API void rz_search_bytes_pattern_free(RZ_NULLABLE RZ_OWN RzSearchBytesPattern *hp) {
	if (!hp) {
		return;
	}
	free(hp->bytes);
	rz_regex_free(hp->regex);
	free(hp->mask);
	free(hp);
}

/**
 * \brief Return the pattern description if any.
 *
 * \return The pattern description string or NULL if there is none.
 */
RZ_API const char *rz_search_bytes_pattern_desc(RZ_NONNULL const RzSearchBytesPattern *bp) {
	rz_return_val_if_fail(bp, 0);
	return bp->pattern_desc;
}

/**
 * \brief Return the pattern length in number of bytes.
 *
 * \return Return the pattern length in number of bytes or 0 in case of failure.
 */
RZ_API size_t rz_search_bytes_pattern_len(RZ_NONNULL const RzSearchBytesPattern *bp) {
	rz_return_val_if_fail(bp, 0);
	return bp->length;
}

RZ_API RZ_OWN RzSearchBytesPattern *rz_search_bytes_pattern_copy(RZ_NONNULL RZ_BORROW RzSearchBytesPattern *hp) {
	rz_return_val_if_fail(hp, NULL);
	return rz_search_bytes_pattern_new(rz_new_copy(hp->length, hp->bytes), rz_new_copy(hp->length, hp->mask), hp->length, hp->pattern_desc, hp->regex != NULL);
}

static bool parse_custom_mask(const char *bytes_pattern, const RzRegexMatch *mask_match, const RzRegexMatch *bytes_match, ut8 *mask) {
	if (mask_match->len != bytes_match->len) {
		RZ_LOG_ERROR("Mask and bytes must have the same number of nibbles. "
			     "But they mismatch: %" PFMTSZu " != %" PFMTSZu "\n",
			mask_match->len, bytes_match->len);
		return false;
	}
	if (strchr(bytes_pattern + bytes_match->start, '.')) {
		RZ_LOG_ERROR("With a custom mask no wildcards are allowed.\n");
		return false;
	}

	rz_hex_str2bin_mask(bytes_pattern + mask_match->start, mask, NULL, false);
	return true;
}

/**
 * \brief Parses a byte pattern description string to a RzSearchBytesPattern object.
 *
 * The given byte pattern string should be of the form: `<bytes>:<mask>`.
 *
 * Formatting rules:
 * - The `mask` is optional.
 * - Mask and bytes should be given in hexadeciaml numbers.
 * - If the mask is given, it must be the same length as the bytes.
 * - Each nibble can be replaced with a '.' to indicate a wildcard nibble.
 * - Odd number of nibbles are extended on the left hand side (MSB side).
 *   This means the nibble at the right hand side is aligned to a byte.
 *
 * Examples:
 *  - `a987`: Exact pattern for the bytes '\xa9\x87'.
 *  - `a9.7`: Pattern for the bytes '\xa9\x.7', but the '.' part can be any nibble.
 *  - `.a9...c.99`: Pattern with multiple wildcards.
 *  - `a907:ff0f`: Pattern with a mask of `ff0f` and bytes of '\xa9\x07'.
 *  - `0xa907:0xff0f`: Mask and bytes with "0x" prefixes.
 */
RZ_API RZ_OWN RzSearchBytesPattern *rz_search_parse_byte_pattern(const char *byte_pattern, RZ_NULLABLE const char *pattern_desc) {
	rz_return_val_if_fail(byte_pattern, NULL);

	size_t size = 0;
	ut8 *bytes = RZ_NEWS0(ut8, strlen(byte_pattern) + 1);
	ut8 *mask = RZ_NEWS0(ut8, strlen(byte_pattern) + 1);
	RzPVector *matches = NULL;
	if (!bytes || !mask) {
		RZ_LOG_ERROR("Allocation falied.\n");
		goto error;
	}

	// Some sanity checks
	size_t ddot_count = rz_str_char_count(byte_pattern, ':');
	if (ddot_count > 1) {
		RZ_LOG_ERROR("More than one ':' is invalid.\n");
		goto error;
	}
	bool has_wildcard = strchr(byte_pattern, '.') != NULL;
	bool custom_mask = ddot_count == 1 ? true : false;

	if (rz_regex_contains("[^a-fA-F0-9.:x]", byte_pattern, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT)) {
		RZ_LOG_ERROR("Pattern contains forbitten characters. Allowed is only '0x', '0-9', 'a-f', 'A-F', '.' and ':'.\n");
		goto error;
	}
	RzRegex *regex = rz_regex_new("^(0x)?([a-fA-F.0-9]+)(:(0x)?([a-fA-F0-9.]+))?", RZ_REGEX_DEFAULT, RZ_REGEX_DEFAULT, NULL);
	matches = rz_regex_match_all_not_grouped(regex, byte_pattern, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	rz_regex_free(regex);

	if (!matches) {
		RZ_LOG_ERROR("Regex matching failed.\n");
		goto error;
	}
	RzRegexMatch *bytes_match = rz_pvector_at(matches, 2);
	RzRegexMatch *mask_match = rz_pvector_at(matches, 5);
	if (!bytes_match || (custom_mask && !mask_match)) {
		RZ_LOG_ERROR("Regex matching failed. Wrong group count.\n");
		goto error;
	}
	if (custom_mask && strchr(byte_pattern + mask_match->len, '.')) {
		RZ_LOG_ERROR("The mask cannot contain wildcards.\n");
		goto error;
	}

	bool odd_nibbles = bytes_match->len % 2 == 1;
	bool use_mask = custom_mask || has_wildcard || odd_nibbles;

	if (custom_mask) {
		use_mask = true;
		if (!parse_custom_mask(byte_pattern, mask_match, bytes_match, mask)) {
			goto error;
		}
	}
	char *byte_str = rz_str_newlen(byte_pattern + bytes_match->start, bytes_match->len);
	size = rz_hex_str2bin_mask(byte_str, bytes, custom_mask ? NULL : mask, false);
	free(byte_str);

	rz_pvector_free(matches);
	RzSearchBytesPattern *pat = rz_search_bytes_pattern_new(bytes, use_mask ? mask : NULL, size, pattern_desc, false);
	if (!use_mask) {
		free(mask);
	}
	return pat;

error:
	free(mask);
	free(bytes);
	rz_pvector_free(matches);
	return NULL;
}

static inline bool bytes_pattern_compare_no_mask(RZ_BORROW RZ_NONNULL const ut8 *buffer, RzSearchBytesPattern *hp) {
	// Without mask only a memcmp().
	return memcmp(buffer, hp->bytes, hp->length) == 0;
}

static inline bool bytes_pattern_compare_masked(RZ_BORROW RZ_NONNULL const ut8 *buffer, RzSearchBytesPattern *hp) {
	// We can't compare by casting the buffer address
	// to an ut64, ut32 etc. because the buffer address can be unaligned
	// for this integer. So we would get undefined behavior.
	// This is pretty much the simplest we can do
	// (except writing assembly I guess).
	for (size_t i = 0; i < hp->length; i++) {
		ut8 mbyte = hp->mask[i];
		if ((hp->bytes[i] & mbyte) != (buffer[i] & mbyte)) {
			return false;
		}
	}
	return true;
}

static bool bytes_find(RzSearchFindOpt *fopts, void *user, ut64 address, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	if (!fopts) {
		RZ_LOG_ERROR("bytes_find requires valid find options.\n");
		return false;
	}

	ut64 size = 0;
	// Remove const classifier. Because the buffer API is not constified, unfortunately.
	const ut8 *raw_buf = rz_buf_get_whole_hot_paths((RzBuffer *)buffer, &size);
	void **it = NULL;
	RzPVector /*<BytesPattern *>*/ *patterns = (RzPVector *)user;
	*n_hits = 0;
	rz_pvector_foreach (patterns, it) {
		RzSearchBytesPattern *hp = (RzSearchBytesPattern *)*it;
		if (hp->regex) {
			RzRegexMulti *re = rz_regex_multi_clone(hp->regex, true);
			RzPVector *matches = fopts->match_overlap ? rz_regex_match_all_overlap(hp->regex, (const char *)raw_buf, size, 0, RZ_REGEX_DEFAULT) : rz_regex_match_all(hp->regex, (const char *)raw_buf, size, 0, RZ_REGEX_DEFAULT);
			rz_regex_free_multi_clone(re);
			void **it;
			RzPVector *match;
			rz_pvector_foreach (matches, it) {
				match = *it;
				RzRegexMatch *group0 = rz_pvector_at(match, 0);
				if (fopts->alignment > 1 && rz_mem_align_padding(address + group0->start, fopts->alignment) != 0) {
					// Match has not the correct alignment in memory.
					continue;
				}
				RzSearchHit *hit = rz_search_hit_new(hp->pattern_desc, address + group0->start, group0->len, NULL);
				if (!hit || !rz_th_queue_push(hits, hit, true)) {
					rz_search_hit_free(hit);
					rz_pvector_free(matches);
					return false;
				}
				(*n_hits)++;
			}
			rz_pvector_free(matches);
			continue;
		}
		for (size_t offset = 0; offset < size;) {
			RAW_BUF_ITER_ALIGN(fopts, address, offset);
			size_t leftovers = size - offset;
			if (hp->length > leftovers) {
				break;
			}
			if (!hp->mask) {
				if (!bytes_pattern_compare_no_mask(raw_buf + offset, hp)) {
					offset++;
					continue;
				}
			} else {
				if (!bytes_pattern_compare_masked(raw_buf + offset, hp)) {
					offset++;
					continue;
				}
			}
			RzSearchHit *hit = rz_search_hit_new(hp->pattern_desc, address + offset, hp->length, NULL);
			if (!hit || !rz_th_queue_push(hits, hit, true)) {
				rz_search_hit_free(hit);
				return false;
			}
			(*n_hits)++;
			offset += fopts->match_overlap ? 1 : hp->length;
		}
	}
	return true;
}

static bool bytes_is_empty(void *user) {
	return rz_pvector_empty((RzPVector *)user);
}

/**
 * \brief      Allocates and initialize a RzSearchCollection for hexadecimal byte searching.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_bytes() {
	RzPVector /*<BytesPattern *>*/ *patterns = rz_pvector_new((RzPVectorFree)rz_search_bytes_pattern_free);
	if (!patterns) {
		RZ_LOG_ERROR("search: failed to initialize bytes collection\n");
		return NULL;
	}
	return rz_search_collection_new_bytes_space(bytes_find, bytes_is_empty, (RzSearchFreeCallback)rz_pvector_free, patterns);
}

/**
 * \brief      Parses and adds a hex pattern into a bytes RzSearchCollection
 *
 * \param[in]  col          The RzSearchCollection to use
 * \param[in]  bytes_pattern  The hexadecimal pattern to add
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_search_collection_bytes_add_pattern(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL RZ_OWN RzSearchBytesPattern *bytes_pattern) {
	rz_return_val_if_fail(col && bytes_pattern, false);

	if (!rz_search_collection_has_find_callback(col, bytes_find)) {
		RZ_LOG_ERROR("search: cannot add hex to non-bytes collection\n");
		rz_search_bytes_pattern_free(bytes_pattern);
		return false;
	}

	if (!rz_pvector_push((RzPVector *)col->user, bytes_pattern)) {
		RZ_LOG_ERROR("search: cannot add byte pattern to search.\n");
		rz_search_bytes_pattern_free(bytes_pattern);
		return false;
	}
	return true;
}

/**
 * \brief      Adds a custom bytes & mask pattern into a bytes RzSearchCollection
 *
 * \param      col           The RzSearchCollection to use
 * \param[in]  pattern_desc  The pattern description
 * \param[in]  bytes         The bytes to use
 * \param[in]  mask          The mask to apply (can be NULL)
 * \param[in]  length        The length of bytes & mask
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_search_collection_bytes_add(RZ_NONNULL RzSearchCollection *col, RZ_NULLABLE const char *pattern_desc, RZ_NONNULL const ut8 *bytes, RZ_NULLABLE const ut8 *mask, size_t length) {
	rz_return_val_if_fail(col && pattern_desc && bytes, false);

	if (!rz_search_collection_has_find_callback(col, bytes_find)) {
		RZ_LOG_ERROR("search: cannot add bytes to non-bytes collection\n");
		return false;
	} else if (length < 1) {
		RZ_LOG_ERROR("search: cannot add an empty byte sequence to a bytes collection\n");
		return false;
	} else if (RZ_STR_ISEMPTY(pattern_desc)) {
		RZ_LOG_ERROR("search: metadata is empty for the bytes collection\n");
		return false;
	}

	RzSearchBytesPattern *hp = rz_search_bytes_pattern_new(rz_new_copy(length, bytes), rz_new_copy(length, mask), length, pattern_desc, false);
	if (!hp) {
		return false;
	} else if (!rz_pvector_push((RzPVector *)col->user, hp)) {
		RZ_LOG_ERROR("search: cannot add bytes pattern.\n");
		rz_search_bytes_pattern_free(hp);
		return false;
	}
	return true;
}
