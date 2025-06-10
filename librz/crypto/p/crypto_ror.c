// SPDX-FileCopyrightText: 2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

#define MAX_ROR_KEY_SIZE 32768

struct ror_state {
	ut8 key[MAX_ROR_KEY_SIZE];
	int key_size;
};

static bool ror_init_state(struct ror_state *const state, const ut8 *key, int keylen) {
	if (!state || !key || keylen < 1 || keylen > MAX_ROR_KEY_SIZE) {
		return false;
	}
	int i;
	state->key_size = keylen;
	for (i = 0; i < keylen; i++) {
		state->key[i] = key[i];
	}
	return true;
}

static void ror_crypt(struct ror_state *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		ut8 count = state->key[i % state->key_size] & 7;
		ut8 inByte = inbuf[i];
		outbuf[i] = (inByte >> count) | (inByte << ((8 - count) & 7));
	}
}

static bool ror_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	struct ror_state *st = (struct ror_state *)cry->user;

	cry->dir = direction;
	return ror_init_state(st, key, keylen);
}

static int ror_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	struct ror_state *st = (struct ror_state *)cry->user;

	return st->key_size;
}

static bool ror_use(const char *algo) {
	return !strcmp(algo, "ror");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, false);
	struct ror_state *st = (struct ror_state *)cry->user;

	if (cry->dir) {
		eprintf("Use ROL algorithm to decrypt\n");
		return false;
	}
	ut8 *obuf = calloc(1, len);
	if (!obuf) {
		return false;
	}
	ror_crypt(st, buf, obuf, len);
	rz_crypto_append(cry, obuf, len);
	free(obuf);
	return true;
}

static bool ror_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(struct ror_state);
	return cry->user != NULL;
}

static bool ror_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_ror = {
	.name = "ror",
	.author = "pancake",
	.license = "LGPL-3",
	.description = "Rotate Right symmetric-key block cipher",
	.set_key = ror_set_key,
	.get_key_size = ror_get_key_size,
	.use = ror_use,
	.update = update,
	.final = update,
	.init = ror_init,
	.fini = ror_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_ror,
	.version = RZ_VERSION
};
#endif
