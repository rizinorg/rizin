// SPDX-FileCopyrightText: 2023 0xSh4dy <rakshitawasthi17@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include "crypto_sm4.h"

static void sm4_setkey_enc(sm4_state *s, const ut8 *key) {
}

static void sm4_setkey_dec(sm4_state *s, const ut8 *key) {
}

static bool sm4_ecb_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	sm4_state *s = (sm4_state *)cry->user;

	if (keylen != SM4_KEY_SIZE) {
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
	return SM4_KEY_SIZE;
}

static bool sm4_use(const char *algo) {
	return !strcmp(algo, "sm4-ecb");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

static bool sm4_ecb_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(sm4_state);
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
	.set_key = sm4_ecb_set_key,
	.get_key_size = sm4_ecb_get_key_size,
	.use = sm4_use,
	.update = update,
	.final = final,
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