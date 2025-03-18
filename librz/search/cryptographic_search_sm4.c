// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2022 Sylvain Pelissier
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file cryptographic_search_sm4.c
 * Find expanded SM4 keys in memory
 */

#include <rz_crypto/rz_sm4.h>

#define SM4_SEARCH_LENGTH 24
#define SM4_CONST_KEY_4   0x70777e85u
#define SM4_CONST_KEY_5   0x8c939aa1u

#define SM4_KEY_FIND(name) \
	static RzSearchHitDetail *sm4_##name##_key_detail(const ut8 *buf) { \
		ut8 key[RZ_SM4_KEY_SIZE] = { 0 }; \
		ut32 word[4]; \
		word[0] = rz_read_at_##name##32(buf, (0 << 2)); \
		word[1] = rz_read_at_##name##32(buf, (1 << 2)); \
		word[2] = rz_read_at_##name##32(buf, (2 << 2)); \
		word[3] = rz_read_at_##name##32(buf, (3 << 2)); \
		rz_sm4_extract_master_key(word, key); \
		return rz_search_hit_detail_bytes_new(key, sizeof(key)); \
	} \
	static bool sm4_##name##_key_test(const ut8 *buf) { \
		ut32 word0 = rz_read_at_##name##32(buf, (0 << 2)); \
		ut32 word1 = rz_read_at_##name##32(buf, (1 << 2)); \
		ut32 word2 = rz_read_at_##name##32(buf, (2 << 2)); \
		ut32 word3 = rz_read_at_##name##32(buf, (3 << 2)); \
		ut32 word4 = rz_read_at_##name##32(buf, (4 << 2)); \
		ut32 word5 = rz_read_at_##name##32(buf, (5 << 2)); \
		bool test1 = (word4 == (word0 ^ (rz_sm4_round_key(word1 ^ word2 ^ word3 ^ SM4_CONST_KEY_4)))); \
		bool test2 = (word5 == (word1 ^ (rz_sm4_round_key(word2 ^ word3 ^ word4 ^ SM4_CONST_KEY_5)))); \
		return test1 && test2; \
	} \
	static RzSearchHit *sm4_##name##_find(ut64 address, const ut8 *bytes, size_t n_bytes) { \
		if (n_bytes >= SM4_SEARCH_LENGTH && \
			sm4_##name##_key_test(bytes)) { \
			RzSearchHitDetail *detail = sm4_##name##_key_detail(bytes); \
			if (!detail) { \
				RZ_LOG_ERROR("search: failed to allocate sm4 master key detail.\n"); \
				return NULL; \
			} \
			return rz_search_hit_new("sm4." RZ_STR(name), address, RZ_SM4_KEY_SIZE, detail); \
		} \
		return NULL; \
	}

SM4_KEY_FIND(be)
SM4_KEY_FIND(le)
