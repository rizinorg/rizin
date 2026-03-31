// SPDX-FileCopyrightText: 2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

#define MAX_ROL_KEY_SIZE 32768

struct rol_state {
	ut8 key[MAX_ROL_KEY_SIZE];
	int key_size;
};

static bool rol_init_state(struct rol_state *const state, const ut8 *key, int keylen) {
	if (!state || !key || keylen < 1 || keylen > MAX_ROL_KEY_SIZE) {
		return false;
	}
	int i;
	state->key_size = keylen;
	for (i = 0; i < keylen; i++) {
		state->key[i] = key[i];
	}
	return true;
}

static void rol_crypt(struct rol_state *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		ut8 count = state->key[i % state->key_size] & 7;
		ut8 inByte = inbuf[i];
		outbuf[i] = (inByte << count) | (inByte >> ((8 - count) & 7));
	}
}

static bool rol_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	struct rol_state *st = (struct rol_state *)cry->user;

	cry->dir = direction;
	return rol_init_state(st, key, keylen);
}

static int rol_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	struct rol_state *st = (struct rol_state *)cry->user;

	return st->key_size;
}

static bool rol_use(const char *algo) {
	return !strcmp(algo, "rol");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, false);
	struct rol_state *st = (struct rol_state *)cry->user;

	if (cry->dir) {
		eprintf("Use ROR algorithm to decrypt\n");
		return false;
	}
	ut8 *obuf = calloc(1, len);
	if (!obuf) {
		return false;
	}
	rol_crypt(st, buf, obuf, len);
	rz_crypto_append(cry, obuf, len);
	free(obuf);
	return true;
}

static bool rol_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(struct rol_state);
	return cry->user != NULL;
}

static bool rol_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_rol = {
	.name = "rol",
	.author = "pancake",
	.license = "LGPL-3",
	.description = "Rotate Left symmetric-key block cipher",
	.set_key = rol_set_key,
	.get_key_size = rol_get_key_size,
	.use = rol_use,
	.update = update,
	.final = update,
	.init = rol_init,
	.fini = rol_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_rol,
	.version = RZ_VERSION
};
#endif
