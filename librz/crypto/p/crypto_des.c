// SPDX-FileCopyrightText: 2017 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

struct des_state {
	ut32 keylo[16]; // round key low
	ut32 keyhi[16]; // round key hi
	ut32 buflo; // buf low
	ut32 bufhi; // buf hi
	int key_size;
	int rounds;
	int i;
};

static ut32 be32(const ut8 *buf4) {
	ut32 val = buf4[0] << 8;
	val |= buf4[1];
	val <<= 8;
	val |= buf4[2];
	val <<= 8;
	val |= buf4[3];
	return val;
}

static void wbe32(ut8 *buf4, ut32 val) {
	buf4[0] = (val >> 24);
	buf4[1] = (val >> 16) & 0xFF;
	buf4[2] = (val >> 8) & 0xFF;
	buf4[3] = val & 0xFF;
}

static int des_encrypt(struct des_state *st, const ut8 *input, ut8 *output) {
	if (!st || !input || !output) {
		return false;
	}
	st->buflo = be32(input + 0);
	st->bufhi = be32(input + 4);

	// first permutation
	rz_des_permute_block0(&st->buflo, &st->bufhi);

	for (st->i = 0; st->i < 16; st->i++) {
		rz_des_round(&st->buflo, &st->bufhi, &st->keylo[st->i], &st->keyhi[st->i]);
	}
	// last permutation
	rz_des_permute_block1(&st->bufhi, &st->buflo);

	// result
	wbe32(output + 0, st->bufhi);
	wbe32(output + 4, st->buflo);

	return true;
}

static int des_decrypt(struct des_state *st, const ut8 *input, ut8 *output) {
	if (!st || !input || !output) {
		return false;
	}
	st->buflo = be32(input + 0);
	st->bufhi = be32(input + 4);
	// first permutation
	rz_des_permute_block0(&st->buflo, &st->bufhi);

	for (st->i = 0; st->i < 16; st->i++) {
		rz_des_round(&st->buflo, &st->bufhi, &st->keylo[15 - st->i], &st->keyhi[15 - st->i]);
	}

	// last permutation
	rz_des_permute_block1(&st->bufhi, &st->buflo);
	// result
	wbe32(output + 0, st->bufhi);
	wbe32(output + 4, st->buflo);
	return true;
}

static bool des_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, 0);
	struct des_state *st = (struct des_state *)cry->user;

	ut32 keylo, keyhi, i;
	if (keylen != DES_KEY_SIZE) {
		return false;
	}
	// splitting the key in hi & lo
	keylo = be32(key);
	keyhi = be32(key + 4);

	st->key_size = DES_KEY_SIZE;
	st->rounds = 16;
	cry->dir = direction;
	// key permutation to derive round keys
	rz_des_permute_key(&keylo, &keyhi);

	for (i = 0; i < 16; i++) {
		// filling round keys space
		rz_des_round_key(i, &st->keylo[i], &st->keyhi[i], &keylo, &keyhi);
	}

	return true;
}

static int des_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	struct des_state *st = (struct des_state *)cry->user;
	return st->key_size;
}

static bool des_use(const char *algo) {
	return algo && !strcmp(algo, "des-ecb");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, false);
	struct des_state *st = (struct des_state *)cry->user;

	if (len <= 0) {
		return false;
	}

	// Pad to the block size, do not append dummy block
	const int diff = (DES_BLOCK_SIZE - (len % DES_BLOCK_SIZE)) % DES_BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / DES_BLOCK_SIZE;

	ut8 *const obuf = calloc(1, size);
	if (!obuf) {
		return false;
	}

	ut8 *const ibuf = calloc(1, size);
	if (!ibuf) {
		free(obuf);
		return false;
	}

	memset(ibuf + len, 0, (size - len));
	memcpy(ibuf, buf, len);
	// got it from AES, should be changed??
	// Padding should start like 100000...
	//	if (diff) {
	//		ibuf[len] = 8; //0b1000;
	//	}

	int i;
	if (cry->dir == RZ_CRYPTO_DIR_DECRYPT) {
		for (i = 0; i < blocks; i++) {
			ut32 next = (DES_BLOCK_SIZE * i);
			des_decrypt(st, ibuf + next, obuf + next);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			ut32 next = (DES_BLOCK_SIZE * i);
			des_encrypt(st, ibuf + next, obuf + next);
		}
	}

	rz_crypto_append(cry, obuf, size);
	free(obuf);
	free(ibuf);
	return 0;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

static bool des_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);
	cry->user = RZ_NEW0(struct des_state);
	return cry->user != NULL;
}

static bool des_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_des = {
	.name = "des-ecb",
	.author = "deroad",
	.license = "LGPL-3",
	.description = "DES symmetric-key block cipher (ECB block mode)",
	.set_key = des_set_key,
	.get_key_size = des_get_key_size,
	.use = des_use,
	.update = update,
	.final = final,
	.init = des_init,
	.fini = des_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_des,
	.version = RZ_VERSION
};
#endif
