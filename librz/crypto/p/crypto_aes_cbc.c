// SPDX-FileCopyrightText: 2016-2017 rakholiyajenish.07 <rakholiyajenish.07@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include "crypto_aes_algo.h"

#define BLOCK_SIZE 16

static struct aes_state st;
static bool iv_set = 0;
static ut8 iv[32];

static bool aes_cbc_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	if (!(keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	st.key_size = keylen;
	st.rounds = 6 + (int)(keylen / 4);
	st.columns = (int)(keylen / 4);
	memcpy(st.key, key, keylen);
	cry->dir = direction;
	return true;
}

static int aes_cbc_get_key_size(RzCrypto *cry) {
	return st.key_size;
}

static bool aes_cbc_set_iv(RzCrypto *cry, const ut8 *iv_src, int ivlen) {
	if (ivlen != BLOCK_SIZE) {
		return false;
	}
	memcpy(iv, iv_src, BLOCK_SIZE);
	iv_set = 1;
	return true;
}

static bool aes_cbc_use(const char *algo) {
	return algo && !strcmp(algo, "aes-cbc");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	if (!iv_set) {
		eprintf("IV not set. Use -I [iv]\n");
		return false;
	}
	const int diff = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / BLOCK_SIZE;

	ut8 *const obuf = calloc(1, size);
	if (!obuf) {
		return false;
	}

	ut8 *const ibuf = calloc(1, size);
	if (!ibuf) {
		free(obuf);
		return false;
	}

	memset(ibuf, 0, size);
	memcpy(ibuf, buf, len);

	if (diff) {
		ibuf[len] = 8; // 0b1000;
	}

	int i, j;
	if (cry->dir == 0) {
		for (i = 0; i < blocks; i++) {
			for (j = 0; j < BLOCK_SIZE; j++) {
				ibuf[i * BLOCK_SIZE + j] ^= iv[j];
			}
			aes_encrypt(&st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
			memcpy(iv, obuf + BLOCK_SIZE * i, BLOCK_SIZE);
		}
	} else if (cry->dir == 1) {
		for (i = 0; i < blocks; i++) {
			aes_decrypt(&st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
			for (j = 0; j < BLOCK_SIZE; j++) {
				obuf[i * BLOCK_SIZE + j] ^= iv[j];
			}
			memcpy(iv, buf + BLOCK_SIZE * i, BLOCK_SIZE);
		}
	}

	rz_crypto_append(cry, obuf, size);
	free(obuf);
	free(ibuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

RzCryptoPlugin rz_crypto_plugin_aes_cbc = {
	.name = "aes-cbc",
	.set_key = aes_cbc_set_key,
	.get_key_size = aes_cbc_get_key_size,
	.set_iv = aes_cbc_set_iv,
	.use = aes_cbc_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_aes_cbc,
	.version = RZ_VERSION
};
#endif
