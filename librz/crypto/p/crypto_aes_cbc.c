// SPDX-FileCopyrightText: 2016-2017 rakholiyajenish.07 <rakholiyajenish.07@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>
#include <aes.h>

typedef struct aes_cbc_context_t {
	struct aes_ctx st;
	bool iv_set;
	ut8 iv[32];
} AesCbcCtx;

static void encryptaes(struct aes_ctx *ctx, ut8 *in, ut8 *out) {
	switch (ctx->key_size) {
	case AES128_KEY_SIZE:
		aes128_encrypt(&ctx->u.ctx128, AES_BLOCK_SIZE, out, in);
		break;
	case AES192_KEY_SIZE:
		aes192_encrypt(&ctx->u.ctx192, AES_BLOCK_SIZE, out, in);
		break;
	case AES256_KEY_SIZE:
		aes256_encrypt(&ctx->u.ctx256, AES_BLOCK_SIZE, out, in);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

static void decryptaes(struct aes_ctx *ctx, ut8 *in, ut8 *out) {
	switch (ctx->key_size) {
	case AES128_KEY_SIZE:
		aes128_decrypt(&ctx->u.ctx128, AES_BLOCK_SIZE, out, in);
		break;
	case AES192_KEY_SIZE:
		aes192_decrypt(&ctx->u.ctx192, AES_BLOCK_SIZE, out, in);
		break;
	case AES256_KEY_SIZE:
		aes256_decrypt(&ctx->u.ctx256, AES_BLOCK_SIZE, out, in);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

static bool aes_cbc_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);

	if (!(keylen == AES128_KEY_SIZE || keylen == AES192_KEY_SIZE || keylen == AES256_KEY_SIZE)) {
		return false;
	}
	AesCbcCtx *ctx = (AesCbcCtx *)cry->user;

	ctx->st.key_size = keylen;
	switch (keylen) {
	case AES128_KEY_SIZE:
		if (direction == RZ_CRYPTO_DIR_ENCRYPT) {
			aes128_set_encrypt_key(&ctx->st.u.ctx128, key);
		} else {
			aes128_set_decrypt_key(&ctx->st.u.ctx128, key);
		}
		break;
	case AES192_KEY_SIZE:
		if (direction == RZ_CRYPTO_DIR_ENCRYPT) {
			aes192_set_encrypt_key(&ctx->st.u.ctx192, key);
		} else {
			aes192_set_decrypt_key(&ctx->st.u.ctx192, key);
		}
		break;
	case AES256_KEY_SIZE:
		if (direction == RZ_CRYPTO_DIR_ENCRYPT) {
			aes256_set_encrypt_key(&ctx->st.u.ctx256, key);
		} else {
			aes256_set_decrypt_key(&ctx->st.u.ctx256, key);
		}
		break;
	default:
		rz_warn_if_reached();
		break;
	}
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

	if (ivlen != AES_BLOCK_SIZE) {
		return false;
	}
	memcpy(ctx->iv, iv_src, AES_BLOCK_SIZE);
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
	const int diff = (AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / AES_BLOCK_SIZE;

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
			for (j = 0; j < AES_BLOCK_SIZE; j++) {
				ibuf[i * AES_BLOCK_SIZE + j] ^= ctx->iv[j];
			}
			encryptaes(&ctx->st, ibuf + AES_BLOCK_SIZE * i, obuf + AES_BLOCK_SIZE * i);
			memcpy(ctx->iv, obuf + AES_BLOCK_SIZE * i, AES_BLOCK_SIZE);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			decryptaes(&ctx->st, ibuf + AES_BLOCK_SIZE * i, obuf + AES_BLOCK_SIZE * i);
			for (j = 0; j < AES_BLOCK_SIZE; j++) {
				obuf[i * AES_BLOCK_SIZE + j] ^= ctx->iv[j];
			}
			memcpy(ctx->iv, buf + AES_BLOCK_SIZE * i, AES_BLOCK_SIZE);
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
	.description = "AES symmetric-key block cipher (CBC block mode)",
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
