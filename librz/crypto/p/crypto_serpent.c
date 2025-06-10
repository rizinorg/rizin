// SPDX-FileCopyrightText: 2017 NicsTr <nicolas.bordes@grenoble-inp.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include "crypto_serpent_algo.h"

static bool serpent_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	serpent_state_t *st = (serpent_state_t *)cry->user;

	if ((keylen != 128 / 8) && (keylen != 192 / 8) && (keylen != 256 / 8)) {
		return false;
	}
	st->key_size = keylen * 8;
	for (size_t i = 0; i < keylen / 4; i++) {
		st->key[i] = rz_read_at_le32(key, i * 4);
	}
	cry->dir = direction;
	return true;
}

static int serpent_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	serpent_state_t *st = (serpent_state_t *)cry->user;

	return st->key_size;
}

static bool serpent_use(const char *algo) {
	return !strcmp(algo, "serpent-ecb");
}

#define BLOCK_SIZE 16

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, 0);
	serpent_state_t *st = (serpent_state_t *)cry->user;
	if (len < 1) {
		return false;
	}

	// Pad to the block size, do not append dummy block
	const int diff = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / BLOCK_SIZE;
	int i, j;

	ut8 *const obuf = calloc(4, size / 4);
	if (!obuf) {
		return false;
	}
	ut32 *const ibuf = calloc(4, size / 4);
	if (!ibuf) {
		free(obuf);
		return false;
	}
	ut32 *const tmp = calloc(4, size / 4);
	if (!tmp) {
		free(obuf);
		free(ibuf);
		return false;
	}

	// Construct ut32 blocks from byte stream
	for (j = 0; j < len / 4; j++) {
		ibuf[j] = rz_read_le32(buf + 4 * j);
	}
	if (len & 0x3) {
		ut8 tail[4] = { 0 }; // Zero padding
		memcpy(tail, buf + (len & ~0x3), len & 0x3);
		ibuf[len / 4] = rz_read_le32(tail);
	}

	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		for (i = 0; i < blocks; i++) {
			// delta in number of ut32
			const int delta = (BLOCK_SIZE * i) / 4;
			serpent_encrypt(st, ibuf + delta, tmp + delta);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			// delta in number of ut32
			const int delta = (BLOCK_SIZE * i) / 4;
			serpent_decrypt(st, ibuf + delta, tmp + delta);
		}
	}

	// Construct ut32 blocks from byte stream
	int k;
	for (j = 0; j < size / 4; j++) {
		k = 4 * j;
		obuf[k] = tmp[j] & 0xff;
		obuf[k + 1] = (tmp[j] >> 8) & 0xff;
		obuf[k + 2] = (tmp[j] >> 16) & 0xff;
		obuf[k + 3] = (tmp[j] >> 24) & 0xff;
	}

	rz_crypto_append(cry, obuf, size);
	free(obuf);
	free(ibuf);
	free(tmp);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

static bool serpent_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(serpent_state_t);
	return cry->user != NULL;
}

static bool serpent_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_serpent = {
	.name = "serpent-ecb",
	.author = "NicsTr",
	.license = "LGPL-3",
	.description = "Serpent symmetric-key block cipher (ECB block mode)",
	.set_key = serpent_set_key,
	.get_key_size = serpent_get_key_size,
	.use = serpent_use,
	.update = update,
	.final = final,
	.init = serpent_init,
	.fini = serpent_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_serpent,
	.version = RZ_VERSION
};
#endif
