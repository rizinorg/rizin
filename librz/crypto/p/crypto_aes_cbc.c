// SPDX-FileCopyrightText: 2016-2017 rakholiyajenish.07 <rakholiyajenish.07@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include "crypto_aes_algo.h"

#define BLOCK_SIZE 16

typedef struct aes_cbc_context_t {
	aes_state_t st;
	bool iv_set;
	ut8 iv[32];
} AesCbcCtx;

static bool aes_cbc_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);

	if (!(keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	AesCbcCtx *ctx = (AesCbcCtx *)cry->user;

	ctx->st.key_size = keylen;
	ctx->st.rounds = 6 + (int)(keylen / 4);
	ctx->st.columns = (int)(keylen / 4);
	memcpy(ctx->st.key, key, keylen);
	cry->dir = direction;
	return true;
}

static int aes_cbc_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	AesCbcCtx *ctx = (AesCbcCtx *)cry->user;

	return ctx->st.key_size;
}

static bool aes_cbc_set_iv(RzCrypto *cry, const ut8 *iv_src, int ivlen) {
	rz_return_val_if_fail(cry->user && iv_src, false);
	AesCbcCtx *ctx = (AesCbcCtx *)cry->user;

	if (ivlen != BLOCK_SIZE) {
		return false;
	}
	memcpy(ctx->iv, iv_src, BLOCK_SIZE);
	ctx->iv_set = true;
	return true;
}

static bool aes_cbc_use(const char *algo) {
	return algo && !strcmp(algo, "aes-cbc");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, false);
	AesCbcCtx *ctx = (AesCbcCtx *)cry->user;

	if (len < 1) {
		return false;
	}

	if (!ctx->iv_set) {
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
	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		for (i = 0; i < blocks; i++) {
			for (j = 0; j < BLOCK_SIZE; j++) {
				ibuf[i * BLOCK_SIZE + j] ^= ctx->iv[j];
			}
			aes_encrypt(&ctx->st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
			memcpy(ctx->iv, obuf + BLOCK_SIZE * i, BLOCK_SIZE);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			aes_decrypt(&ctx->st, ibuf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
			for (j = 0; j < BLOCK_SIZE; j++) {
				obuf[i * BLOCK_SIZE + j] ^= ctx->iv[j];
			}
			memcpy(ctx->iv, buf + BLOCK_SIZE * i, BLOCK_SIZE);
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

static bool aes_cbc_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(AesCbcCtx);
	return cry->user != NULL;
}

static bool aes_cbc_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_aes_cbc = {
	.name = "aes-cbc",
	.author = "rakholiyajenish.07",
	.license = "LGPL-3",
	.set_key = aes_cbc_set_key,
	.get_key_size = aes_cbc_get_key_size,
	.set_iv = aes_cbc_set_iv,
	.use = aes_cbc_use,
	.update = update,
	.final = final,
	.init = aes_cbc_init,
	.fini = aes_cbc_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_aes_cbc,
	.version = RZ_VERSION
};
#endif
