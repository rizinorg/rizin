// SPDX-FileCopyrightText: 2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

struct rc4_state {
	ut8 perm[256];
	ut8 index1;
	ut8 index2;
	int key_size;
};

static __inline void swap_bytes(ut8 *a, ut8 *b) {
	if (a != b) {
		ut8 temp = *a;
		*a = *b;
		*b = temp;
	}
}

/*
 * Initialize an RC4 state buffer using the supplied key,
 * which can have arbitrary length.
 */

static bool rc4_init_state(struct rc4_state *const state, const ut8 *key, int keylen) {
	ut8 j;
	int i;

	if (!state || !key || keylen < 1) {
		return false;
	}
	state->key_size = keylen;
	/* Initialize state with identity permutation */
	for (i = 0; i < 256; i++) {
		state->perm[i] = (ut8)i;
	}
	state->index1 = 0;
	state->index2 = 0;

	/* Randomize the permutation using key data */
	for (j = i = 0; i < 256; i++) {
		j += state->perm[i] + key[i % keylen];
		swap_bytes(&state->perm[i], &state->perm[j]);
	}
	return true;
}

/*
 * Encrypt some data using the supplied RC4 state buffer.
 * The input and output buffers may be the same buffer.
 * Since RC4 is a stream cypher, this function is used
 * for both encryption and decryption.
 */
static void rc4_crypt(struct rc4_state *const state, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	ut8 j;

	for (i = 0; i < buflen; i++) {
		/* Update modification indices */
		state->index1++;
		state->index2 += state->perm[state->index1];
		/* Modify permutation */
		swap_bytes(&state->perm[state->index1],
			&state->perm[state->index2]);
		/* Encrypt/decrypt next byte */
		j = state->perm[state->index1] + state->perm[state->index2];
		outbuf[i] = inbuf[i] ^ state->perm[j];
	}
}

///////////////////////////////////////////////////////////

static bool rc4_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	struct rc4_state *st = (struct rc4_state *)cry->user;

	return rc4_init_state(st, key, keylen);
}

static int rc4_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	struct rc4_state *st = (struct rc4_state *)cry->user;

	return st->key_size;
}

static bool rc4_use(const char *algo) {
	return !strcmp(algo, "rc4");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, false);
	struct rc4_state *st = (struct rc4_state *)cry->user;

	ut8 *obuf = calloc(1, len);
	if (!obuf) {
		return false;
	}
	rc4_crypt(st, buf, obuf, len);
	rz_crypto_append(cry, obuf, len);
	free(obuf);
	return false;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

static bool rc4_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(struct rc4_state);
	return cry->user != NULL;
}

static bool rc4_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_rc4 = {
	.name = "rc4",
	.author = "pancake",
	.license = "LGPL-3",
	.description = "RC4 symmetric-key block cipher",
	.set_key = rc4_set_key,
	.get_key_size = rc4_get_key_size,
	.use = rc4_use,
	.update = update,
	.final = final,
	.init = rc4_init,
	.fini = rc4_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_rc4,
	.version = RZ_VERSION
};
#endif
