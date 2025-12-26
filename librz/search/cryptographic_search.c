// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include <rz_vector.h>
#include <rz_util.h>

#include "search_internal.h"

#include "cryptographic_search_aes.c"
#include "cryptographic_search_sm4.c"
#include "cryptographic_search_pki.c"
#include "cryptographic_search_x509.c"

typedef RzSearchHit *(*CryptographicCallback)(ut64 address, const ut8 *buffer, size_t size);

typedef struct cryptographic_method_t {
	const char *name;
	CryptographicCallback find;
} CryptographicMethod;

static CryptographicMethod cryptographic_methods[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_ENUM_SIZE] = {
	[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_AES_128] = { "aes128", aes_128_find },
	[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_AES_192] = { "aes192", aes_192_find },
	[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_AES_256] = { "aes256", aes_256_find },
	[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_SM4_BE] = { "sm4be", sm4_be_find },
	[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_SM4_LE] = { "sm4le", sm4_le_find },
	[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_RSA] = { "rsa", rsa_find },
	[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_ECC] = { "ecc", ecc_find },
	[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_PKCS8_PRIVKEY] = { "pkcs8_pkey", pkcs8_privkey_find },
	[RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_X509] = { "x509", x509_find },
};

RZ_API bool rz_search_collection_cryptographic_name_to_type(RZ_NONNULL const char *name, RzSearchCollectionCryptographicType *type) {
	rz_return_val_if_fail(name && type, false);

	if (RZ_STR_ISEMPTY(name)) {
		return false;
	}

	for (RzSearchCollectionCryptographicType mtype = 0; mtype < RZ_ARRAY_SIZE(cryptographic_methods); ++mtype) {
		const char *mname = cryptographic_methods[mtype].name;
		if (rz_str_casecmp(name, mname)) {
			continue;
		}
		*type = mtype;
		return true;
	}
	return false;
}

static bool cryptographic_find(RzSearchFindOpt *fopts, void *user, ut64 address, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits) {
	RzPVector /*<CryptographicCallback *>*/ *pvec = (RzPVector *)user;

	ut64 n_bytes = 0;
	// Remove const classifier. Because the buffer API is not constified, unfortunately.
	const ut8 *bytes = rz_buf_get_whole_hot_paths((RzBuffer *)buffer, &n_bytes);

	RzSearchHit *hit = NULL;
	CryptographicCallback find_cb = NULL;
	void **it;

	*n_hits = 0;
	for (size_t offset = 0; offset < n_bytes;) {
		if (fopts->alignment > 1 && rz_mem_align_padding(address + offset, fopts->alignment) != 0) {
			// Match has not the correct alignment in memory.
			offset += rz_mem_align_padding(address + offset, fopts->alignment);
			continue;
		}
		size_t leftovers = n_bytes - offset;
		size_t match_len = UT64_MAX;
		rz_pvector_foreach (pvec, it) {
			find_cb = (CryptographicCallback)*it;
			hit = find_cb(address + offset, bytes + offset, leftovers);
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

static bool cryptographic_is_empty(void *user) {
	return rz_pvector_len((RzPVector *)user) < 1;
}

/**
 * \brief      Allocates and initialize a pkey RzSearchCollection
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_cryptographic() {
	RzPVector /*<CryptographicCallback *>*/ *pvec = rz_pvector_new(NULL);
	if (!pvec) {
		RZ_LOG_ERROR("search: cannot allocate internal data for cryptographic search collection\n");
		return NULL;
	}

	return rz_search_collection_new_bytes_space(cryptographic_find, cryptographic_is_empty, (RzSearchFreeCallback)rz_pvector_free, pvec);
}

/**
 * \brief      Adds a new cryptographic method into a cryptographic RzSearchCollection.
 *
 * \param[in]  col   The RzSearchCollection to use.
 * \param[in]  type  The cryptographic method to add.
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_search_collection_cryptographic_add(RZ_NONNULL RzSearchCollection *col, RzSearchCollectionCryptographicType type) {
	rz_return_val_if_fail(col, false);

	if (!rz_search_collection_has_find_callback(col, cryptographic_find)) {
		RZ_LOG_ERROR("search: cannot add cryptographic method to non-cryptographic search collection\n");
		return false;
	}

	if (type >= RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_ALL) {
		RzPVector *pvec = col->user;
		CryptographicCallback find_cb;
		for (size_t i = 0; i < RZ_SEARCH_COLLECTION_CRYPTOGRAPHIC_ENUM_SIZE; ++i) {
			find_cb = cryptographic_methods[i].find;
			if (rz_pvector_contains(pvec, find_cb)) {
				RZ_LOG_WARN("search: %s already in cryptographic search collection!\n", cryptographic_methods[i].name);
				continue;
			}
			if (!rz_pvector_push(pvec, find_cb)) {
				const char *name = cryptographic_methods[i].name;
				RZ_LOG_ERROR("search: cannot add %s to cryptographic search collection\n", name);
				return false;
			}
		}
		return true;
	}

	if (!cryptographic_methods[type].find) {
		RZ_LOG_ERROR("The crypto type has no search method defined.\n");
		return false;
	}

	RzPVector /*<CryptographicCallback *>*/ *pvec = (RzPVector *)col->user;
	CryptographicCallback find = cryptographic_methods[type].find;
	const char *name = cryptographic_methods[type].name;

	if (rz_pvector_contains(pvec, find)) {
		RZ_LOG_WARN("search: %s already in cryptographic search collection!\n", name);
		return true; // do not fail.
	} else if (!rz_pvector_push(pvec, find)) {
		RZ_LOG_ERROR("search: failed to add %s to cryptographic search collection\n", name);
		return false;
	}

	return true;
}
