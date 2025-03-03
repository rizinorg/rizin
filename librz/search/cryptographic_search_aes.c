// SPDX-FileCopyrightText: 2024-2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2007 Victor Muñoz
// SPDX-License-Identifier: CC0-1.0

/**
 * \file cryptographic_search_aes.c
 * Find expanded AES keys in memory
 *
 * Algorithm discovered and developed by Victor Muñoz
 *  - PoC and source published at 24c3 at December 2007
 *
 * Thanks for the great moments and code snippets!
 *
 * This source is public domain. Feel free to use it and distribute it.
 */

#include <rz_crypto/rz_aes.h>

#define AES128_SEARCH_LENGTH 24
#define AES192_SEARCH_LENGTH 32
#define AES256_SEARCH_LENGTH 40

#define AES128_KEY_LENGTH 16
#define AES192_KEY_LENGTH 24
#define AES256_KEY_LENGTH 32

static bool aes_256_key_test(const ut8 *buf) {
	bool word1 = buf[32] == (buf[0] ^ Sbox[buf[29]] ^ 1) && buf[33] == (buf[1] ^ Sbox[buf[30]]) && buf[34] == (buf[2] ^ Sbox[buf[31]]) && buf[35] == (buf[3] ^ Sbox[buf[28]]);
	bool word2 = (buf[36] == (buf[4] ^ buf[32]) && buf[37] == (buf[5] ^ buf[33]) && buf[38] == (buf[6] ^ buf[34]) && buf[39] == (buf[7] ^ buf[35]));
	return word1 && word2;
}

static bool aes_192_key_test(const ut8 *buf) {
	bool word1 = buf[24] == (buf[0] ^ Sbox[buf[21]] ^ 1) && buf[25] == (buf[1] ^ Sbox[buf[22]]) && buf[26] == (buf[2] ^ Sbox[buf[23]]) && buf[27] == (buf[3] ^ Sbox[buf[20]]);
	bool word2 = buf[28] == (buf[4] ^ buf[24]) && buf[29] == (buf[5] ^ buf[25]) && buf[30] == (buf[6] ^ buf[26]) && buf[31] == (buf[7] ^ buf[27]);
	return word1 && word2;
}

static bool aes_128_key_test(const ut8 *buf) {
	bool word1 = buf[16] == (buf[0] ^ Sbox[buf[13]] ^ 1) && buf[17] == (buf[1] ^ Sbox[buf[14]]) && buf[18] == (buf[2] ^ Sbox[buf[15]]) && buf[19] == (buf[3] ^ Sbox[buf[12]]);
	bool word2 = buf[20] == (buf[4] ^ buf[16]) && buf[21] == (buf[5] ^ buf[17]) && buf[22] == (buf[6] ^ buf[18]) && buf[23] == (buf[7] ^ buf[19]);
	return word1 && word2;
}

#define AES_KEY_FIND(bits) \
	static RzSearchHit *aes_##bits##_find(ut64 address, const ut8 *bytes, size_t n_bytes) { \
		if (n_bytes >= AES##bits##_SEARCH_LENGTH && \
			aes_##bits##_key_test(bytes)) { \
			return rz_search_hit_new("aes" RZ_STR(bits), address, AES##bits##_KEY_LENGTH); \
		} \
		return NULL; \
	}

AES_KEY_FIND(128)
AES_KEY_FIND(192)
AES_KEY_FIND(256)
