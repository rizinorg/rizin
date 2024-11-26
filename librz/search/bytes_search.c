// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_util.h>

#include "search_internal.h"

#define IS_PATBYTE(c) (IS_HEXCHAR(c) || (c) == '.')

typedef struct bytes_pattern {
	const char *metadata; ///< Pattern metadata
	ut8 *bytes; ///< Pattern bytes
	ut8 *mask; ///< Pattern mask (when NULL full match)
	ut32 length; ///< Pattern & mask length
} BytesPattern;

static void bytes_pattern_free(BytesPattern *hp) {
	if (!hp) {
		return;
	}
	free(hp->bytes);
	free(hp->mask);
	free(hp);
}

static inline ut8 patchar(char b) {
	if (b == '.') {
		return 0;
	} else if (b >= '0' && b <= '9') {
		return b - '0';
	} else if (b >= 'A' && b <= 'F') {
		return (b - 'A') + 10;
	}
	return (b - 'a') + 10;
}

static inline ut8 decode_pattern(char high, char low) {
	ut8 b = patchar(high);
	b <<= 8;
	return b | patchar(low);
}

static inline ut8 decode_mask(char high, char low) {
	ut8 m = 0;
	if (high != '.') {
		m = 0xF0;
	}
	if (low != '.') {
		m |= 0x0F;
	}
	return m;
}

// copy from given bytes
static BytesPattern *bytes_pattern_copy(const char *metadata, const ut8 *bytes, const ut8 *mask, size_t length) {
	BytesPattern *hp = RZ_NEW0(BytesPattern);
	if (!hp) {
		RZ_LOG_ERROR("search: cannot allocate BytesPattern struct\n");
		return NULL;
	}

	hp->metadata = metadata;
	hp->length = length;

	hp->bytes = RZ_NEWS(ut8, hp->length);
	if (!hp->bytes) {
		RZ_LOG_ERROR("search: cannot allocate pattern bytes\n");
		bytes_pattern_free(hp);
		return NULL;
	}
	memcpy(hp->bytes, bytes, hp->length);

	if (!mask) {
		// full match without a mask.
		return hp;
	}

	hp->mask = RZ_NEWS(ut8, hp->length);
	if (!hp->mask) {
		RZ_LOG_ERROR("search: cannot allocate pattern mask\n");
		bytes_pattern_free(hp);
		return NULL;
	}
	memcpy(hp->mask, mask, hp->length);

	return hp;
}

static BytesPattern *bytes_pattern_parse(const char *bytes_pattern) {
	BytesPattern *hp = RZ_NEW0(BytesPattern);
	if (!hp) {
		RZ_LOG_ERROR("search: cannot allocate BytesPattern struct\n");
		return NULL;
	}

	size_t length = strlen(bytes_pattern);
	if (length & 1) {
		RZ_LOG_ERROR("search: hex pattern length is a multiple of 2\n");
		return NULL;
	} else if (length > RZ_SEARCH_MAX_HEX_PATTERN) {
		RZ_LOG_ERROR("search: hex pattern length is too long (length > %u chars)\n", RZ_SEARCH_MAX_HEX_PATTERN);
		return NULL;
	}

	hp->metadata = "hex";
	hp->length = length >> 1;

	hp->bytes = RZ_NEWS0(ut8, hp->length);
	if (!hp->bytes) {
		RZ_LOG_ERROR("search: cannot allocate pattern bytes\n");
		bytes_pattern_free(hp);
		return NULL;
	}

	hp->mask = RZ_NEWS0(ut8, hp->length);
	if (!hp->mask) {
		RZ_LOG_ERROR("search: cannot allocate pattern mask\n");
		bytes_pattern_free(hp);
		return NULL;
	}

	bool full_match = true;

	for (ut32 i = 0; i < hp->length; ++i) {
		ut32 p = i << 1;
		char high = bytes_pattern[p];
		char low = bytes_pattern[p + 1];
		if (!IS_PATBYTE(high)) {
			RZ_LOG_ERROR("search: invalid hex '%c' at char %u\n", high, p);
			bytes_pattern_free(hp);
			return NULL;
		} else if (!IS_PATBYTE(low)) {
			RZ_LOG_ERROR("search: invalid hex '%c' at char %u\n", low, p + 1);
			bytes_pattern_free(hp);
			return NULL;
		}

		hp->bytes[i] = decode_pattern(high, low);
		hp->mask[i] = decode_mask(high, low);
		if (hp->mask[i] != 0xFF) {
			full_match = false;
		}
	}

	if (full_match) {
		// do not use mask and set it to NULL for full match.
		free(hp->mask);
		hp->mask = NULL;
	}

	return hp;
}

static bool bytes_pattern_compare(BytesPattern *hp, const ut8 *buffer, size_t buffer_size) {
	size_t i = 0;
	if (buffer_size < hp->length) {
		return false;
	} else if (!hp->mask) {
		// if no mask defined, then we do memcmp
		return !memcmp(buffer, hp->bytes, hp->length);
	}

#define fast_mask_compare(type) \
	for (; (hp->length - i) > sizeof(type); i += sizeof(type)) { \
		type num = *((type *)buffer + i); \
		type pat = *((type *)hp->bytes + i); \
		type mask = *((type *)hp->mask + i); \
		num &= mask; \
		if (num != pat) { \
			return false; \
		} \
	}

	fast_mask_compare(ut64);
	fast_mask_compare(ut32);
	fast_mask_compare(ut16);
	fast_mask_compare(ut8);
#undef fast_mask_compare
	return true;
}

static bool bytes_find(void *user, ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits) {
	RzPVector /*<BytesPattern *>*/ *patterns = (RzPVector *)user;
	void **it = NULL;
	BytesPattern *hp = NULL;

	rz_pvector_foreach (patterns, it) {
		hp = (BytesPattern *)*it;
		for (size_t offset = 0; offset < size;) {
			size_t leftovers = size - offset;
			if (hp->length > leftovers) {
				break;
			} else if (!bytes_pattern_compare(hp, buffer + offset, leftovers)) {
				offset++;
				continue;
			}
			RzSearchHit *hit = rz_search_hit_new(hp->metadata, address + offset, hp->length);
			if (!hit || !rz_th_queue_push(hits, hit, true)) {
				rz_search_hit_free(hit);
				return false;
			}
			offset += hp->length;
		}
	}
	return true;
}

static bool bytes_is_empty(void *user) {
	return rz_pvector_empty((RzPVector *)user);
}

/**
 * \brief      Allocates and initialize a bytes RzSearchCollection
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_bytes() {
	RzPVector /*<BytesPattern *>*/ *patterns = rz_pvector_new((RzPVectorFree)bytes_pattern_free);
	if (!patterns) {
		RZ_LOG_ERROR("search: failed to initialize bytes collection\n");
		return NULL;
	}
	return rz_search_collection_new(bytes_find, bytes_is_empty, (RzSearchFreeCallback)rz_pvector_free, patterns);
}

/**
 * \brief      Parses and adds a hex pattern into a bytes RzSearchCollection
 *
 * \param[in]  col          The RzSearchCollection to use
 * \param[in]  bytes_pattern  The hexadecimal pattern to add
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_search_collection_bytes_add_pattern(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *bytes_pattern) {
	rz_return_val_if_fail(col && bytes_pattern, false);

	if (!rz_search_collection_has_find_callback(col, bytes_find)) {
		RZ_LOG_ERROR("search: cannot add hex to non-bytes collection\n");
		return false;
	} else if (RZ_STR_ISEMPTY(bytes_pattern)) {
		RZ_LOG_ERROR("search: cannot parse an empty string as bytes pattern\n");
		return false;
	}

	BytesPattern *hp = bytes_pattern_parse(bytes_pattern);
	if (!hp) {
		return false;
	} else if (!rz_pvector_push((RzPVector *)col->user, hp)) {
		RZ_LOG_ERROR("search: cannot add '%s' hex pattern.\n", bytes_pattern);
		bytes_pattern_free(hp);
		return false;
	}
	return true;
}

/**
 * \brief      Adds a custom bytes & mask pattern into a bytes RzSearchCollection
 *
 * \param      col       The RzSearchCollection to use
 * \param[in]  metadata  The metadata to set
 * \param[in]  bytes     The bytes to use
 * \param[in]  mask      The mask to apply (can be NULL)
 * \param[in]  length    The length of bytes & mask
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_search_collection_bytes_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *metadata, RZ_NONNULL const ut8 *bytes, RZ_NULLABLE const ut8 *mask, size_t length) {
	rz_return_val_if_fail(col && metadata && bytes, false);

	if (!rz_search_collection_has_find_callback(col, bytes_find)) {
		RZ_LOG_ERROR("search: cannot add bytes to non-bytes collection\n");
		return false;
	} else if (length < 1) {
		RZ_LOG_ERROR("search: cannot add an empty byte sequence to a bytes collection\n");
		return false;
	} else if (RZ_STR_ISEMPTY(metadata)) {
		RZ_LOG_ERROR("search: metadata is empty for the bytes collection\n");
		return false;
	}

	BytesPattern *hp = bytes_pattern_copy(metadata, bytes, mask, length);
	if (!hp) {
		return false;
	} else if (!rz_pvector_push((RzPVector *)col->user, hp)) {
		RZ_LOG_ERROR("search: cannot add bytes pattern.\n");
		bytes_pattern_free(hp);
		return false;
	}
	return true;
}