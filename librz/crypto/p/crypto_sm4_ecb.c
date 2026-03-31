// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2023 0xSh4dy <rakshitawasthi17@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_crypto/rz_sm4.h>
#include "crypto_sm4.h"

// clang-format off
static const ut8 SM4_SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

static const ut32 SM4_CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static const ut32 SM4_FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};
// clang-format on

static ut32 sm4_rol32(ut32 n, ut32 c) {
	const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
	c &= mask;
	return (n << c) | (n >> ((-c) & mask));
}

static ut32 sm4_ecb_transform_internal(ut32 val) {
	ut8 buf[4];
	rz_write_at_be32(buf, val, 0);
	for (ut32 i = 0; i < 4; i++) {
		buf[i] = SM4_SBOX[buf[i]];
	}
	return rz_read_be32(buf);
}

RZ_API void rz_sm4_extract_master_key(const ut32 word[4], ut8 key_out[RZ_SM4_KEY_SIZE]) {
	ut32 partial[4] = { 0 };
	partial[3] = word[3] ^ (rz_sm4_round_key(word[2] ^ word[1] ^ word[0] ^ SM4_CK[3]));
	partial[2] = word[2] ^ (rz_sm4_round_key(word[1] ^ word[0] ^ partial[3] ^ SM4_CK[2]));
	partial[1] = word[1] ^ (rz_sm4_round_key(word[0] ^ partial[3] ^ partial[2] ^ SM4_CK[1]));
	partial[0] = word[0] ^ (rz_sm4_round_key(partial[3] ^ partial[2] ^ partial[1] ^ SM4_CK[0]));

	rz_write_at_be32(key_out, SM4_FK[0] ^ partial[0], 0);
	rz_write_at_be32(key_out, SM4_FK[1] ^ partial[1], 4);
	rz_write_at_be32(key_out, SM4_FK[2] ^ partial[2], 8);
	rz_write_at_be32(key_out, SM4_FK[3] ^ partial[3], 12);
}

RZ_API ut32 rz_sm4_round_key(ut32 val) {
	ut32 x = sm4_ecb_transform_internal(val);
	return x ^ sm4_rol32(x, 13) ^ sm4_rol32(x, 23);
}

static ut32 sm4_ecb_transform(ut32 val) {
	ut32 x = sm4_ecb_transform_internal(val);
	return x ^ sm4_rol32(x, 2) ^ sm4_rol32(x, 10) ^ sm4_rol32(x, 18) ^ sm4_rol32(x, 24);
}

static void sm4_setkey_internal(sm4_state_t *s, const ut8 *key) {
	ut32 mk[4];
	ut32 rk[4];

	for (ut32 i = 0; i < 4; i++) {
		mk[i] = rz_read_at_be32(key, i << 2);
	}

	for (ut32 i = 0; i < 4; i++) {
		rk[i] = mk[i] ^ SM4_FK[i];
	}

	for (ut32 i = 0; i < 32; i++) {
		ut32 temp = rk[0] ^ rz_sm4_round_key(rk[1] ^ rk[2] ^ rk[3] ^ SM4_CK[i]);
		s->round_keys[i] = temp;
		rk[0] = rk[1];
		rk[1] = rk[2];
		rk[2] = rk[3];
		rk[3] = temp;
	}
}

static void sm4_setkey_enc(sm4_state_t *s, const ut8 *key) {
	sm4_setkey_internal(s, key);
}

static void sm4_setkey_dec(sm4_state_t *s, const ut8 *key) {
	sm4_setkey_internal(s, key);
	for (int i = 0; i < 16; i++) {
		ut32 temp = s->round_keys[i];
		s->round_keys[i] = s->round_keys[31 - i];
		s->round_keys[31 - i] = temp;
	}
}

static bool sm4_ecb_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	sm4_state_t *s = (sm4_state_t *)cry->user;
	cry->dir = direction;
	if (keylen != RZ_SM4_KEY_SIZE) {
		return false;
	}
	if (direction == RZ_CRYPTO_DIR_ENCRYPT) {
		sm4_setkey_enc(s, key);
	} else {
		sm4_setkey_dec(s, key);
	}
	return true;
}

static int sm4_ecb_get_key_size(RzCrypto *cry) {
	return RZ_SM4_KEY_SIZE;
}

static bool sm4_use(const char *algo) {
	return !strcmp(algo, "sm4-ecb");
}

static void sm4_round(const ut32 *round_key, const ut8 *input, ut8 *output) {
	ut32 x[36], i;
	for (i = 0; i < 4; i++) {
		x[i] = rz_read_be32(input + 4 * i);
	}
	for (i = 0; i < 32; i++) {
		x[i + 4] = x[i] ^ sm4_ecb_transform(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ round_key[i]);
	}

	rz_write_at_be32(output, x[35], 0);
	rz_write_at_be32(output, x[34], 4);
	rz_write_at_be32(output, x[33], 8);
	rz_write_at_be32(output, x[32], 12);
}

static void sm4_ecb_encrypt(const ut32 *round_key, int length, const ut8 *input, ut8 *output) {
	int times = length / 16;
	for (ut32 i = 0; i < times; i++) {
		sm4_round(round_key, input, output);
		input += 16;
		output += 16;
	}
}

static int get_next_available_len(int curr_len) {
	return ((curr_len + 15) / 16) * 16;
}

static bool sm4_update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry, 0);
	sm4_state_t *state = (sm4_state_t *)cry->user;
	int old_len = len;
	if (len < 1) {
		return false;
	}

	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		if (len % 16 == 0) {
			len += 16;
		} else {
			len = get_next_available_len(len);
		}
	}

	ut8 *output = RZ_NEWS0(ut8, len);
	if (!output) {
		return false;
	}

	ut8 *padded_input = RZ_NEWS0(ut8, len);
	if (!padded_input) {
		free(output);
		return false;
	}
	state->original_len = old_len;

	memcpy(padded_input, buf, old_len);

	sm4_ecb_encrypt(state->round_keys, len, padded_input, output);

	rz_crypto_append(cry, output, len);

	free(output);
	free(padded_input);
	return true;
}

static bool sm4_final(RzCrypto *cry, const ut8 *buf, int len) {
	return sm4_update(cry, buf, len);
}

static bool sm4_ecb_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(sm4_state_t);
	return cry->user != NULL;
}

static bool sm4_ecb_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_sm4_ecb = {
	.name = "sm4-ecb",
	.author = "0xSh4dy",
	.license = "LGPL-3",
	.description = "ShangMi 4 symmetric-key block cipher (ECB block mode)",
	.set_key = sm4_ecb_set_key,
	.get_key_size = sm4_ecb_get_key_size,
	.use = sm4_use,
	.update = sm4_update,
	.final = sm4_final,
	.init = sm4_ecb_init,
	.fini = sm4_ecb_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_sm4_ecb,
	.version = RZ_VERSION
};
#endif