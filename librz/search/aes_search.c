// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2007 Victor Muñoz
// SPDX-License-Identifier: CC0-1.0

/*
 * Find expanded AES keys in memory
 *
 * Algorithm discovered and developed by Victor Muñoz
 *  - PoC and source published at 24c3 at December 2007
 *
 * Thanks for the great moments and code snippets!
 *
 * This source is public domain. Feel free to use it and distribute it.
 */

#include <rz_search.h>
#include <rz_crypto/rz_aes.h>

#include "search_internal.h"

#define AES128_SEARCH_LENGTH 24
#define AES192_SEARCH_LENGTH 32
#define AES256_SEARCH_LENGTH 40
#define AES128_KEY_LENGTH    16
#define AES192_KEY_LENGTH    24
#define AES256_KEY_LENGTH    32

typedef bool (*SearchAesKey)(ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits);

static bool aes256_key_test(const ut8 *buf) {
	bool word1 = buf[32] == (buf[0] ^ Sbox[buf[29]] ^ 1) && buf[33] == (buf[1] ^ Sbox[buf[30]]) && buf[34] == (buf[2] ^ Sbox[buf[31]]) && buf[35] == (buf[3] ^ Sbox[buf[28]]);
	bool word2 = (buf[36] == (buf[4] ^ buf[32]) && buf[37] == (buf[5] ^ buf[33]) && buf[38] == (buf[6] ^ buf[34]) && buf[39] == (buf[7] ^ buf[35]));
	return word1 && word2;
}

static bool aes192_key_test(const ut8 *buf) {
	bool word1 = buf[24] == (buf[0] ^ Sbox[buf[21]] ^ 1) && buf[25] == (buf[1] ^ Sbox[buf[22]]) && buf[26] == (buf[2] ^ Sbox[buf[23]]) && buf[27] == (buf[3] ^ Sbox[buf[20]]);
	bool word2 = buf[28] == (buf[4] ^ buf[24]) && buf[29] == (buf[5] ^ buf[25]) && buf[30] == (buf[6] ^ buf[26]) && buf[31] == (buf[7] ^ buf[27]);
	return word1 && word2;
}

static bool aes128_key_test(const ut8 *buf) {
	bool word1 = buf[16] == (buf[0] ^ Sbox[buf[13]] ^ 1) && buf[17] == (buf[1] ^ Sbox[buf[14]]) && buf[18] == (buf[2] ^ Sbox[buf[15]]) && buf[19] == (buf[3] ^ Sbox[buf[12]]);
	bool word2 = buf[20] == (buf[4] ^ buf[16]) && buf[21] == (buf[5] ^ buf[17]) && buf[22] == (buf[6] ^ buf[18]) && buf[23] == (buf[7] ^ buf[19]);
	return word1 && word2;
}

#define SEARCH_OVER_AES_KEY_FCN(name) search_over_aes_##name
#define SEARCH_OVER_AES_KEY(bits) \
	static bool SEARCH_OVER_AES_KEY_FCN(bits)(ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits) { \
		for (size_t offset = 0; offset < size; offset += AES##bits##_SEARCH_LENGTH) { \
			if (aes##bits##_key_test(buffer + offset)) { \
				RzSearchHit *hit = rz_search_hit_new("aes", address + offset, AES##bits##_KEY_LENGTH); \
				if (!hit || !rz_th_queue_push(hits, hit, true)) { \
					rz_search_hit_free(hit); \
					return false; \
				} \
			} \
		} \
		return true; \
	}

SEARCH_OVER_AES_KEY(128)
SEARCH_OVER_AES_KEY(192)
SEARCH_OVER_AES_KEY(256)

bool search_over_aes(RzPVector /*<SearchAesKey *>*/ *collection, ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits) {
	void **it;
	rz_pvector_foreach (collection, it) {
		SearchAesKey search_key = (SearchAesKey)*it;
		if (!search_key(address, buffer, size, hits)) {
			return false;
		}
	}
	return true;
}

/**
 * \brief      Allocates and initialize an AES RzSearchCollection
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_aes_keys() {
	RzSearchCollection *sc = rz_search_collection_new(search_over_aes, NULL);
	if (!sc) {
		return NULL;
	}
	if (!rz_pvector_push(sc->collection, SEARCH_OVER_AES_KEY_FCN(128)) ||
		!rz_pvector_push(sc->collection, SEARCH_OVER_AES_KEY_FCN(192)) ||
		!rz_pvector_push(sc->collection, SEARCH_OVER_AES_KEY_FCN(256))) {
		RZ_LOG_ERROR("search: failed to initialize AES search collection\n");
		rz_search_collection_free(sc);
		return NULL;
	}
	return sc;
}
