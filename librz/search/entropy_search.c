// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_vector.h>
#include <rz_util.h>

#include <rz_endian.h>
#include <rz_hash.h>
#include <rz_types.h>
#include "search_internal.h"

typedef struct search_entropy_range_t {
	bool fractional; ///< Defines if the entropy range is fractional or not.
	double min_inclusive_limit; ///< Min inclusive range
	double max_inclusive_limit; ///< Max inclusive range
	ut64 block_size; ///< The data block size given as input to the hash function.
} SearchEntropyRange;

typedef struct search_entropy_t {
	RzVector /*<SearchEntropyRange>*/ ranges; ///< Entropy range list
	const RzHash *rz_hash; ///< Immutable RzHash instance with all registered plugins.
} SearchEntropy;

static RzSearchHit *calculate_entropy_and_compare(RzHashCfg *cfg, const SearchEntropyRange *range, ut64 address, const ut8 *buffer, size_t buf_size) {
	rz_return_val_if_fail(cfg && buffer, NULL);
	if (!rz_hash_cfg_init(cfg)) {
		RZ_LOG_ERROR("search: entropy init failed.\n");
		return NULL;
	}
	if (!rz_hash_cfg_update(cfg, buffer, buf_size)) {
		RZ_LOG_ERROR("search: entropy update failed.\n");
		return NULL;
	}
	if (!rz_hash_cfg_final(cfg)) {
		RZ_LOG_ERROR("search: entropy final failed.\n");
		return NULL;
	}

	const char *algo = range->fractional ? "entropy_fract" : "entropy";

	RzHashSize hsize = 0;
	const ut8 *calculated_entropy = rz_hash_cfg_get_result(cfg, algo, &hsize);
	if (hsize != sizeof(double)) {
		rz_warn_if_reached();
		return NULL;
	}

	double entropy = rz_read_be_double(calculated_entropy);
	if (entropy < range->min_inclusive_limit || entropy > range->max_inclusive_limit) {
		return NULL;
	}

	RzSearchHitDetail *detail = rz_search_hit_detail_double_new(entropy);
	if (!detail) {
		RZ_LOG_ERROR("search: failed to allocate entropy hit detail.\n");
		return NULL;
	}
	return rz_search_hit_new(algo, address, buf_size, detail);
}

static bool entropy_find(RzSearchFindOpt *fopts, void *user, ut64 address, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	SearchEntropy *ctx = (SearchEntropy *)user;

	RzHashCfg *entropy_norm = rz_hash_cfg_new_with_algo2(ctx->rz_hash, "entropy");
	RzHashCfg *entropy_fract = rz_hash_cfg_new_with_algo2(ctx->rz_hash, "entropy_fract");
	if (!entropy_norm || !entropy_fract) {
		rz_hash_cfg_free(entropy_norm);
		rz_hash_cfg_free(entropy_fract);
		return false;
	}

	// required to reset the status.
	rz_hash_cfg_final(entropy_norm);
	rz_hash_cfg_final(entropy_fract);

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
		const SearchEntropyRange *range;

		rz_vector_enumerate (&ctx->ranges, range, i) {
			size_t block_size = RZ_MIN(leftovers, range->block_size);
			RzHashCfg *hcfg = range->fractional ? entropy_fract : entropy_norm;
			RzSearchHit *hit = calculate_entropy_and_compare(hcfg, range, address + offset, bytes + offset, block_size);
			if (!hit) {
				continue;
			} else if (!rz_th_queue_push(hits, hit, true)) {
				rz_search_hit_free(hit);
				rz_hash_cfg_free(entropy_norm);
				rz_hash_cfg_free(entropy_fract);
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

	rz_hash_cfg_free(entropy_norm);
	rz_hash_cfg_free(entropy_fract);
	return true;
}

static bool entropy_is_empty(void *user) {
	SearchEntropy *ctx = (SearchEntropy *)user;
	return rz_vector_len(&ctx->ranges) < 1;
}

static bool already_in_collection(SearchEntropy *ctx, SearchEntropyRange *find) {
	SearchEntropyRange *range;
	rz_vector_foreach (&ctx->ranges, range) {
		if (range->fractional == find->fractional &&
			range->min_inclusive_limit == find->min_inclusive_limit &&
			range->max_inclusive_limit == find->max_inclusive_limit &&
			range->block_size == find->block_size) {
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
RZ_API bool rz_search_collection_entropy_add(RZ_NONNULL RzSearchCollection *col, bool fractional, double min_inclusive_limit, double max_inclusive_limit, ut64 block_size) {
	rz_return_val_if_fail(col, false);

	if (!rz_search_collection_has_find_callback(col, entropy_find)) {
		RZ_LOG_ERROR("search: cannot add entropy range to non-entropy search collection\n");
		return false;
	}

	if (min_inclusive_limit < 0) {
		RZ_LOG_ERROR("search: cannot add entropy range when min value is less than 0\n");
		return false;
	} else if (max_inclusive_limit < min_inclusive_limit) {
		RZ_LOG_ERROR("search: cannot add entropy range when max value is less than min (max %.4f < %.4f min)\n", max_inclusive_limit, min_inclusive_limit);
		return false;
	} else if (fractional && max_inclusive_limit > 1.0) {
		RZ_LOG_ERROR("search: cannot add fractional entropy range when max value is greater than 1\n");
		return false;
	} else if (!fractional && max_inclusive_limit > 8.0) {
		RZ_LOG_ERROR("search: cannot add fractional entropy range when max value is greater than 8\n");
		return false;
	}

	SearchEntropy *ctx = (SearchEntropy *)col->user;

	SearchEntropyRange range = { 0 };
	range.fractional = fractional;
	range.min_inclusive_limit = min_inclusive_limit;
	range.max_inclusive_limit = max_inclusive_limit;
	range.block_size = block_size;

	if (already_in_collection(ctx, &range)) {
		RZ_LOG_ERROR("search: [%f,%f] range is already in the entropy search collection\n", min_inclusive_limit, max_inclusive_limit);
		return false;
	}

	if (!rz_vector_push(&ctx->ranges, &range)) {
		RZ_LOG_ERROR("search: failed to add [%f,%f] range to entropy search collection\n", min_inclusive_limit, max_inclusive_limit);
		return false;
	}
	return true;
}

static void entropy_free(SearchEntropy *ctx) {
	if (!ctx) {
		return;
	}

	rz_vector_fini(&ctx->ranges);
	free(ctx);
}

/**
 * \brief      Allocates and initialize a pkey RzSearchCollection
 *
 * \param[in]  type The type of hash algorithm to initialize the collection for.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_entropy(RZ_NONNULL const RzHash *rz_hash) {
	rz_return_val_if_fail(rz_hash, NULL);

	SearchEntropy *ctx = RZ_NEW0(SearchEntropy);
	if (!ctx) {
		RZ_LOG_ERROR("search: cannot allocate internal data for entropy search collection\n");
		return NULL;
	}
	ctx->rz_hash = rz_hash;
	rz_vector_init(&ctx->ranges, sizeof(SearchEntropyRange), NULL, NULL);
	return rz_search_collection_new_bytes_space(entropy_find, entropy_is_empty, (RzSearchFreeCallback)entropy_free, ctx);
}
