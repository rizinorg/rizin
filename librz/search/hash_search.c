// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_vector.h>
#include <rz_util.h>

#include <rz_endian.h>
#include <rz_hash.h>
#include <rz_types.h>
#include "search_internal.h"

static void rz_search_hash_data_free(RzSearchHashFindData *data) {
	if (!data) {
		return;
	}
	free(data->algo);
	free(data->digits);
	free(data);
}

static bool rz_search_hash_data_eq(const RzSearchHashFindData *a, const RzSearchHashFindData *b) {
	if (!a && !b) {
		return true;
	} else if (!a || !b) {
		return false;
	}

	if (!RZ_STR_EQ(a->algo, b->algo) || a->digits_len != b->digits_len) {
		return false;
	}

	return rz_mem_eq(a->digits, b->digits, a->digits_len);
}

static ut8 *parse_digits(const char *algo, const char *expected_digits, ut32 digit_size) {
	rz_return_val_if_fail(expected_digits, NULL);
	ut8 *out = RZ_NEWS0(ut8, digit_size);
	if (rz_str_startswith(algo, "entropy")) {
		double entropy_threshold = rz_num_get_float(NULL, expected_digits);
		if (entropy_threshold < 0.0) {
			RZ_LOG_ERROR("Threshold '%02f' cannot be smaller than 0.0.\n", entropy_threshold);
			goto error;
		}
		if (rz_str_startswith(algo, "entropy_fract") && entropy_threshold > 1.0) {
			RZ_LOG_ERROR("Threshold '%02f' cannot be larger than 1.0.\n", entropy_threshold);
			goto error;
		}
		rz_write_be_double(out, entropy_threshold);
	} else if (rz_str_startswith(algo, "ssdeep")) {
		rz_mem_copy(out, digit_size, expected_digits, strlen(expected_digits));
	} else {
		if (rz_regex_contains("[^a-fA-F0-9]+", expected_digits, RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT)) {
			RZ_LOG_ERROR("digits must be a hexadecimal string without spaces nor '0x' prefix. Got: '%s'\n", expected_digits);
			goto error;
		}
		ut32 elen = strlen(expected_digits) / 2;
		if (elen != digit_size || elen & 1) {
			RZ_LOG_ERROR("Expected digits don't have the correct number of bytes. Expected: %" PFMT32u ", got: %" PFMT32u ".\n", digit_size, (elen / 2) + elen % 2);
			goto error;
		}
		rz_hex_str2bin(expected_digits, out);
	}
	return out;

error:
	free(out);
	return NULL;
}

RZ_API RZ_OWN RzSearchHashFindData *rz_search_hash_get_find_data(const RzHash *rz_hash, RZ_NONNULL const char *algo_name, RZ_NONNULL const char *expected_digits, const char *block_size_arg) {
	rz_return_val_if_fail(algo_name && expected_digits, NULL);
	ut64 block_size = rz_num_get(NULL, block_size_arg);
	if (block_size & 1 || block_size == 0) {
		RZ_LOG_ERROR("Odd or zero block sizes are not allowed.\n");
		return NULL;
	}

	RzHashCfg *md = rz_hash_cfg_new(rz_hash);
	if (!md || !rz_hash_cfg_configure(md, algo_name)) {
		RZ_LOG_ERROR("The hash algorithm '%s' is not supported for the search. List supported with the command 'Lh'.\n", algo_name);
		return NULL;
	}
	ut32 digit_size = rz_hash_cfg_size(md, algo_name);
	if (digit_size == 0) {
		RZ_LOG_ERROR("The hash algorithm '%s' is not supported for the search. List supported with the command 'Lh'.\n", algo_name);
		return NULL;
	}
	rz_hash_cfg_free(md);

	ut8 *digits = parse_digits(algo_name, expected_digits, digit_size);
	if (!digits) {
		RZ_LOG_ERROR("Failed to parse has search arguments.\n");
		return NULL;
	}
	RzSearchHashFindData *data = RZ_NEW(RzSearchHashFindData);
	if (!data) {
		return NULL;
	}
	data->digits = digits;
	data->digits_len = digit_size;
	data->algo = rz_str_dup(algo_name);
	data->block_size = block_size;
	data->rz_hash = rz_hash;
	return data;
}

static RzHashCfg *init_hash_config(RzPVector /*<RzSearchHashFindData *>*/ *pvec) {
	void **it;
	const RzSearchHashFindData *data = rz_pvector_at(pvec, 0);
	if (!data) {
		goto error;
	}
	RzHashCfg *cfg = rz_hash_cfg_new(data->rz_hash);
	rz_pvector_foreach (pvec, it) {
		data = *it;
		if (!rz_hash_cfg_configure(cfg, data->algo)) {
			RZ_LOG_ERROR("Failed to setup config for '%s'.\n", data->algo);
			goto error;
		}
	}
	return cfg;

error:
	return NULL;
}

static bool hashes_match(const RzSearchHashFindData *data, const ut8 *calculated_hash, ut32 hsize) {
	rz_return_val_if_fail(data && calculated_hash && hsize != 0, false);
	if (rz_str_startswith(data->algo, "entropy")) {
		return hsize == sizeof(double) && rz_read_be_double(calculated_hash) >= rz_read_be_double(data->digits);
	}
	// All the others just compare digits in with memory compare.
	return rz_mem_eq(data->digits, calculated_hash, hsize);
}

static RzSearchHit *hash_and_compare(RzHashCfg *cfg, const RzSearchHashFindData *data, ut64 address, const ut8 *buffer, size_t buf_size) {
	rz_return_val_if_fail(cfg && data && buffer, NULL);
	if (!rz_hash_cfg_init(cfg)) {
		RZ_LOG_ERROR("Hash config init failed.\n");
		return NULL;
	}
	if (!rz_hash_cfg_update(cfg, buffer, buf_size)) {
		RZ_LOG_ERROR("Hash config update failed.\n");
		return NULL;
	}
	if (!rz_hash_cfg_final(cfg)) {
		RZ_LOG_ERROR("Hash config final failed.\n");
		return NULL;
	}
	RzHashSize hsize;
	const ut8 *calculated_hash = rz_hash_cfg_get_result(cfg, data->algo, &hsize);
	if (hsize != data->digits_len) {
		rz_warn_if_reached();
		return NULL;
	}
	if (!hashes_match(data, calculated_hash, hsize)) {
		return NULL;
	}
	RzSearchHit *hit = rz_search_hit_new(data->algo, address, buf_size, NULL);
	if (!hit) {
		return NULL;
	}
	if (!rz_str_startswith(data->algo, "entropy")) {
		// No need to add the details for those. Because the user already passed the hash value
		// as argument. So it is known.
		return hit;
	}
	RzSearchiHitDetailHash *hd = RZ_NEW(RzSearchiHitDetailHash);

	hd->hash = RZ_NEWS(ut8, hsize);
	rz_mem_copy(hd->hash, hsize, calculated_hash, hsize);
	hd->hash_size = hsize;
	hd->algo = rz_str_dup(data->algo);
	hd->hash_str = rz_hash_cfg_get_result_string(cfg, data->algo, NULL, false);
	if (!rz_search_hit_add_details(hit, RZ_SEARCH_HIT_DETAIL_HASH, hd)) {
		RZ_LOG_ERROR("Failed to add search it details. Omit hit.\n");
		rz_search_hit_free(hit);
		return NULL;
	}
	return hit;
}

static bool hash_find(RzSearchFindOpt *fopts, void *user, ut64 address, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	RzPVector /*<RzSearchHashFindData *>*/ *pvec = (RzPVector *)user;

	RzHashCfg *hcfg = init_hash_config(pvec);
	if (!hcfg) {
		return false;
	}

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
		const RzSearchHashFindData *data;
		rz_pvector_enumerate (pvec, it, i) {
			data = (RzSearchHashFindData *)*it;
			RzSearchHit *hit = hash_and_compare(hcfg, data, address + offset, bytes + offset, RZ_MIN(leftovers, data->block_size));
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

static bool already_in_hash_collection(const RzPVector /*<RzSearchHashFindData *>*/ *vec, RzSearchHashFindData *data) {
	void **it;
	rz_pvector_foreach (vec, it) {
		RzSearchHashFindData *in_coll_data = *it;
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
RZ_API bool rz_search_collection_hash_add(RZ_NONNULL RzSearchCollection *col, RZ_OWN RZ_NONNULL RzSearchHashFindData *data) {
	rz_return_val_if_fail(col && data, false);

	if (!rz_search_collection_has_find_callback(col, hash_find)) {
		RZ_LOG_ERROR("search: cannot add hash method to non-hash search collection\n");
		return false;
	}

	RzPVector /*<RzSearchHashFindData *>*/ *pvec = (RzPVector *)col->user;

	if (already_in_hash_collection(pvec, data)) {
		RZ_LOG_WARN("search: %s already in hash search collection!\n", data->algo);
		return true;
	}

	if (!rz_pvector_push(pvec, data)) {
		RZ_LOG_ERROR("search: failed to add %s to hash search collection\n", data->algo);
		return false;
	}
	return true;
}

/**
 * \brief      Allocates and initialize a pkey RzSearchCollection
 *
 * \param[in]  type The type of hash algorithm to initialize the collection for.
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_hash() {
	RzPVector /*<RzSearchHashFindData *>*/ *vec = rz_pvector_new((RzPVectorFree)rz_search_hash_data_free);
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
		RZ_LOG_ERROR("Requires a hash search collection. But the given collection isn't one.\n");
		return 0;
	}

	RzPVector *pvec = collection->user;
	if (!pvec || rz_pvector_empty(pvec)) {
		RZ_LOG_ERROR("No hash algorithms added to search colleciton.\n");
		return 0;
	}
	ut64 block_size = 0;
	void **it;
	rz_pvector_foreach (pvec, it) {
		RzSearchHashFindData *data = *it;
		block_size = RZ_MAX(block_size, data->block_size);
	}
	return block_size;
}
