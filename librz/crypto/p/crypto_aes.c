// SPDX-FileCopyrightText: 2015-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>
#include <aes.h>

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

static bool aes_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	struct aes_ctx *st = (struct aes_ctx *)cry->user;

	if (!(keylen == AES128_KEY_SIZE || keylen == AES192_KEY_SIZE || keylen == AES256_KEY_SIZE)) {
		return false;
	}
	st->key_size = keylen;
	switch (keylen) {
	case AES128_KEY_SIZE:
		if (direction == RZ_CRYPTO_DIR_ENCRYPT) {
			aes128_set_encrypt_key(&st->u.ctx128, key);
		} else {
			aes128_set_decrypt_key(&st->u.ctx128, key);
		}
		break;
	case AES192_KEY_SIZE:
		if (direction == RZ_CRYPTO_DIR_ENCRYPT) {
			aes192_set_encrypt_key(&st->u.ctx192, key);
		} else {
			aes192_set_decrypt_key(&st->u.ctx192, key);
		}
		break;
	case AES256_KEY_SIZE:
		if (direction == RZ_CRYPTO_DIR_ENCRYPT) {
			aes256_set_encrypt_key(&st->u.ctx256, key);
		} else {
			aes256_set_decrypt_key(&st->u.ctx256, key);
		}
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	cry->dir = direction;
	return true;
}

static int aes_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	struct aes_ctx *st = (struct aes_ctx *)cry->user;

	return st->key_size;
}

static bool aes_use(const char *algo) {
	return !strcmp(algo, "aes-ecb");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, 0);
	struct aes_ctx *st = (struct aes_ctx *)cry->user;

	if (len < 1) {
		return false;
	}

	// Pad to the block size, do not append dummy block
	const int diff = (AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / AES_BLOCK_SIZE;
	int i;

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
	// Padding should start like 100000...
	if (diff) {
		ibuf[len] = 8; // 0b1000;
	}

	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		for (i = 0; i < blocks; i++) {
			const int delta = AES_BLOCK_SIZE * i;
			encryptaes(st, ibuf + delta, obuf + delta);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			const int delta = AES_BLOCK_SIZE * i;
			decryptaes(st, ibuf + delta, obuf + delta);
		}
	}

	// printf("%128s\n", obuf);

	rz_crypto_append(cry, obuf, size);
	free(obuf);
	free(ibuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

static bool aes_ecb_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(struct aes_ctx);
	return cry->user != NULL;
}

static bool aes_ecb_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_aes = {
	.name = "aes-ecb",
	.author = "Nettle project,pancake",
	.license = "LGPL3",
	.description = "AES symmetric-key block cipher (ECB block mode)",
	.set_key = aes_set_key,
	.get_key_size = aes_get_key_size,
	.use = aes_use,
	.update = update,
	.final = final,
	.init = aes_ecb_init,
	.fini = aes_ecb_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_aes,
	.version = RZ_VERSION
};
#endif
