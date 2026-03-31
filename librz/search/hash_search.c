// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_vector.h>
#include <rz_util.h>

#include <rz_endian.h>
#include <rz_hash.h>
#include <rz_types.h>
#include "search_internal.h"

typedef struct search_hash_context_t {
	char *algo; ///< The hash algorithm.
	ut8 *digest; ///< The expected hash digest the data block should match.
	size_t digest_len; ///< Length of the expected digest.
	ut64 block_size; ///< The data block size given as input to the hash function.
	const RzHash *rz_hash; ///< Immutable RzHash instance with all registered plugins.
} SearchHashContext;

static void search_hash_context_free(SearchHashContext *data) {
	if (!data) {
		return;
	}
	free(data->algo);
	free(data->digest);
	free(data);
}

static bool rz_search_hash_data_eq(const SearchHashContext *a, const SearchHashContext *b) {
	if (!a && !b) {
		return true;
	} else if (!a || !b) {
		return false;
	}

	if (!RZ_STR_EQ(a->algo, b->algo) || a->digest_len != b->digest_len) {
		return false;
	}

	return rz_mem_eq(a->digest, b->digest, a->digest_len);
}

static ut8 *parse_digest(const char *algo, const char *expected_digest, ut32 digest_size) {
	rz_return_val_if_fail(expected_digest, NULL);

	ut8 *out = RZ_NEWS0(ut8, digest_size);
	if (!out) {
		RZ_LOG_ERROR("search: failed to allocate %u bytes for digest.\n", digest_size);
		return NULL;
	}

	if (RZ_STR_EQ(algo, "ssdeep")) {
		rz_mem_copy(out, digest_size, expected_digest, strlen(expected_digest));
	} else {
		if (rz_regex_contains("[^a-fA-F0-9]+", expected_digest, RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT)) {
			RZ_LOG_ERROR("search: digest must be a hexadecimal string without spaces nor '0x' prefix. Got: '%s'\n", expected_digest);
			goto error;
		}
		ut32 elen = strlen(expected_digest) / 2;
		if (elen != digest_size || elen & 1) {
			RZ_LOG_ERROR("search: invalid digest size. Expected: %" PFMT32u ", got: %" PFMT32u ".\n", digest_size, (elen / 2) + elen % 2);
			goto error;
		}
		rz_hex_str2bin(expected_digest, out);
	}
	return out;

error:
	free(out);
	return NULL;
}

static RZ_OWN SearchHashContext *search_hash_context_new(RZ_NONNULL const RzHash *rz_hash,
	RZ_NONNULL const char *algo_name,
	RZ_NONNULL const char *expected_digest,
	ut64 block_size) {
	rz_return_val_if_fail(rz_hash && algo_name && expected_digest, NULL);

	if (block_size & 1 || block_size == 0) {
		RZ_LOG_ERROR("search: odd or zero block sizes are not allowed.\n");
		return NULL;
	}

	if (RZ_STR_EQ(algo_name, "entropy") ||
		RZ_STR_EQ(algo_name, "entropy_fract")) {
		RZ_LOG_ERROR("search: cannot use hash collection for '%s'. use the entropy search collection.\n", algo_name);
		return NULL;
	}

	RzHashCfg *md = rz_hash_cfg_new_with_algo2(rz_hash, algo_name);
	if (!md) {
		RZ_LOG_ERROR("search: invalid hash algorithm '%s'.\n", algo_name);
		return NULL;
	}

	ut32 digest_size = rz_hash_cfg_size(md, algo_name);
	rz_hash_cfg_free(md);
	if (digest_size < 1) {
		rz_warn_if_reached();
		return NULL;
	}

	ut8 *digest = parse_digest(algo_name, expected_digest, digest_size);
	if (!digest) {
		return NULL;
	}

	SearchHashContext *data = RZ_NEW(SearchHashContext);
	if (!data) {
		RZ_LOG_ERROR("search: failed to allocate SearchHashContext.\n");
		free(digest);
		return NULL;
	}

	data->digest = digest;
	data->digest_len = digest_size;
	data->algo = rz_str_dup(algo_name);
	data->block_size = block_size;
	data->rz_hash = rz_hash;
	return data;
}

static bool hashes_match(const SearchHashContext *data, const ut8 *calculated_hash, ut32 hsize) {
	rz_return_val_if_fail(data && calculated_hash && hsize != 0, false);

	// All the others just compare digest in with memory compare.
	return rz_mem_eq(data->digest, calculated_hash, hsize);
}

static RzSearchHit *calculate_hash_and_compare(const SearchHashContext *data, ut64 address, const ut8 *buffer, size_t buf_size) {
	rz_return_val_if_fail(data && buffer, NULL);
	RzHashCfg *md = rz_hash_cfg_new_with_algo2(data->rz_hash, data->algo);
	if (!md) {
		return NULL;
	} else if (!rz_hash_cfg_update(md, buffer, buf_size)) {
		RZ_LOG_ERROR("search: hash config update failed.\n");
		rz_hash_cfg_free(md);
		return NULL;
	} else if (!rz_hash_cfg_final(md)) {
		RZ_LOG_ERROR("search: hash config final failed.\n");
		rz_hash_cfg_free(md);
		return NULL;
	}

	RzHashSize hsize = 0;
	const ut8 *calculated_hash = rz_hash_cfg_get_result(md, data->algo, &hsize);
	if (hsize != data->digest_len) {
		rz_hash_cfg_free(md);
		rz_warn_if_reached();
		return NULL;
	}

	bool is_match = hashes_match(data, calculated_hash, hsize);
	rz_hash_cfg_free(md);

	if (!is_match) {
		return NULL;
	}

	return rz_search_hit_new(data->algo, address, buf_size, NULL);
}

static bool hash_find(RzSearchFindOpt *fopts, void *user, ut64 address, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	RzPVector /*<SearchHashContext *>*/ *pvec = (RzPVector *)user;

	ut64 n_bytes = 0;
	// Remove const classifier. Because the buffer API is not constified, unfortunately.
	const ut8 *bytes = rz_buf_get_whole_hot_paths((RzBuffer *)buffer, &n_bytes);

	*n_hits = 0;
	for (size_t offset = 0; offset < n_bytes;) {
		if (fopts->alignment > 1 && rz_mem_align_padding(address + offset, fopts->alignment) != 0) {
			// Match has not the correct alignment in memory.
			offset += rz_mem_align_padding(address + offset, fopts->alignment);
			continue;
		}
		size_t leftovers = n_bytes - offset;
		size_t match_len = UT64_MAX;
		size_t i;
		void **it;
		const SearchHashContext *data;
		rz_pvector_enumerate (pvec, it, i) {
			data = (SearchHashContext *)*it;
			RzSearchHit *hit = calculate_hash_and_compare(data, address + offset, bytes + offset, RZ_MIN(leftovers, data->block_size));
			if (!hit) {
				continue;
			} else if (!rz_th_queue_push(hits, hit, true)) {
				rz_search_hit_free(hit);
				return false;
			}
			(*n_hits)++;
			if (!fopts->match_overlap) {
				match_len = RZ_MIN(match_len, hit->size);
				break;
			}
		}
		if (fopts->match_overlap || !match_len || match_len >= n_bytes) {
			offset++;
		} else {
			offset += match_len;
		}
	}
	return true;
}

static bool hash_is_empty(void *user) {
	return rz_vector_len((RzVector *)user) < 1;
}

static bool already_in_hash_collection(const RzPVector /*<SearchHashContext *>*/ *vec, SearchHashContext *data) {
	void **it;
	rz_pvector_foreach (vec, it) {
		SearchHashContext *in_coll_data = *it;
		if (rz_search_hash_data_eq(in_coll_data, data)) {
			return true;
		}
	}
	return false;
}

/**
 * \brief      Adds a new hash method into a hash RzSearchCollection.
 *
 * \param[in]  col   The RzSearchCollection to use.
 * \param[in]  data  The hash data to add and search for.
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_search_collection_hash_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const RzHash *rz_hash, RZ_NONNULL const char *algo_name, RZ_NONNULL const char *expected_digest, ut64 block_size) {
	rz_return_val_if_fail(col && rz_hash && algo_name && expected_digest, false);

	if (!rz_search_collection_has_find_callback(col, hash_find)) {
		RZ_LOG_ERROR("search: cannot add hash method to non-hash search collection\n");
		return false;
	}

	SearchHashContext *ctx = search_hash_context_new(rz_hash, algo_name, expected_digest, block_size);
	if (!ctx) {
		return false;
	}

	RzPVector /*<SearchHashContext *>*/ *pvec = (RzPVector *)col->user;

	if (already_in_hash_collection(pvec, ctx)) {
		RZ_LOG_WARN("search: %s already in hash search collection!\n", algo_name);
		search_hash_context_free(ctx);
		return true;
	}

	if (!rz_pvector_push(pvec, ctx)) {
		RZ_LOG_ERROR("search: failed to add %s to hash search collection\n", algo_name);
		search_hash_context_free(ctx);
		return false;
	}
	return true;
}

/**
 * \brief      Allocates and initialize a pkey RzSearchCollection
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_hash() {
	RzPVector /*<SearchHashContext *>*/ *vec = rz_pvector_new((RzPVectorFree)search_hash_context_free);
	if (!vec) {
		RZ_LOG_ERROR("search: cannot allocate internal data for hash search collection\n");
		return NULL;
	}

	return rz_search_collection_new_bytes_space(hash_find, hash_is_empty, (RzSearchFreeCallback)rz_pvector_free, vec);
}

/**
 * \brief Returns the element size required to satisfy the requirements of all hash algorithms
 * in this collection.
 *
 * \param collection The collection to get the element size for.
 *
 * \return The element size or 0 in case of failure.
 */
RZ_API ut64 rz_search_hash_get_element_size(RZ_NONNULL RzSearchCollection *collection) {
	rz_return_val_if_fail(collection, 0);
	if (!rz_search_collection_has_find_callback(collection, hash_find)) {
		RZ_LOG_ERROR("search: requires a hash search collection. But the given collection isn't one.\n");
		return 0;
	}

	RzPVector *pvec = collection->user;
	if (!pvec || rz_pvector_empty(pvec)) {
		RZ_LOG_ERROR("search: no hash algorithms added to search colleciton.\n");
		return 0;
	}
	ut64 block_size = 0;
	void **it;
	rz_pvector_foreach (pvec, it) {
		SearchHashContext *data = *it;
		block_size = RZ_MAX(block_size, data->block_size);
	}
	return block_size;
}
