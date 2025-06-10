// SPDX-FileCopyrightText: 2016 rakholiyajenish.07 <rakholiyajenish.07@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// Implemented AES version of RC6. keylen = 16, 23, or 32 bytes; w = 32; and r = 20.
#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

#define Pw         0xb7e15163
#define Qw         0x9e3779b9
#define BLOCK_SIZE 16
#define r          20
#define w          32
#define ROTL(x, y) (((x) << ((y) & (w - 1))) | ((x) >> (w - ((y) & (w - 1)))))
#define ROTR(x, y) (((x) >> ((y) & (w - 1))) | ((x) << (w - ((y) & (w - 1)))))

struct rc6_state {
	ut32 S[2 * r + 4];
	int key_size;
};

static bool rc6_init_state(struct rc6_state *const state, const ut8 *key, int keylen) {
	if (keylen != 128 / 8 && keylen != 192 / 8 && keylen != 256 / 8) {
		return false;
	}

	int u = w / 8;
	int c = keylen / u;
	int t = 2 * r + 4;

	ut32 *L = RZ_NEWS(ut32, c);
	if (!L) {
		rz_warn_if_reached();
		return false;
	}

	ut32 A = 0, B = 0, k = 0, j = 0;
	ut32 v = 3 * t; // originally v = 2 * ((c > t) ? c : t);

	int i;

	for (i = 0; i < c; i++) {
		L[i] = rz_read_at_le32(key, i * 4);
	}

	(state->S)[0] = Pw;
	for (i = 1; i < t; i++) {
		(state->S)[i] = (state->S)[i - 1] + Qw;
	}

	for (i = 0; i < v; i++) {
		A = (state->S)[k] = ROTL(((state->S)[k] + A + B), 3);
		B = L[j] = ROTL((L[j] + A + B), (A + B));
		k = (k + 1) % t;
		j = (j + 1) % c;
	}

	state->key_size = keylen / 8;

	free(L);
	return true;
}

static void rc6_encrypt(struct rc6_state *const state, const ut8 *inbuf, ut8 *outbuf) {
	ut32 t, u;
	ut32 aux;
	ut32 data[BLOCK_SIZE / 4];
	int i;
	for (i = 0; i < BLOCK_SIZE / 4; i++) {
		data[i] = rz_read_at_le32(inbuf, i * 4);
	}

	ut32 A = data[0], B = data[1], C = data[2], D = data[3];

	// S is key
	B = B + (state->S)[0];
	D = D + (state->S)[1];

	for (i = 1; i <= r; i++) {
		t = ROTL(B * (2 * B + 1), 5); // lgw == 5
		u = ROTL(D * (2 * D + 1), 5);
		A = ROTL(A ^ t, u) + (state->S)[2 * i];
		C = ROTL(C ^ u, t) + (state->S)[2 * i + 1];

		aux = A;
		A = B;
		B = C;
		C = D;
		D = aux;
	}

	A = A + (state->S)[2 * (r + 1)];
	C = C + (state->S)[2 * (r + 1) + 1];
	data[0] = A;
	data[1] = B;
	data[2] = C;
	data[3] = D;

	for (i = 0; i < BLOCK_SIZE; i++) {
		outbuf[i] = (ut8)((data[i / 4] >> (i % 4) * 8) & 0xff);
	}
}

static void rc6_decrypt(struct rc6_state *const state, const ut8 *inbuf, ut8 *outbuf) {
	ut32 t, u;
	ut32 aux;
	ut32 data[BLOCK_SIZE / 4];
	int i;
	int off = 0;

	for (i = 0; i < BLOCK_SIZE / 4; i++) {
		data[i] = (inbuf[off++] & 0xff);
		data[i] |= ((inbuf[off++] & 0xff) << 8);
		data[i] |= ((inbuf[off++] & 0xff) << 16);
		data[i] |= ((inbuf[off++] & 0xff) << 24);
	}

	ut32 A = data[0], B = data[1], C = data[2], D = data[3];

	C = C - (state->S)[2 * (r + 1) + 1];
	A = A - (state->S)[2 * (r + 1)];

	for (i = r; i >= 1; i--) {
		aux = D;
		D = C;
		C = B;
		B = A;
		A = aux;

		u = ROTL(D * (2 * D + 1), 5);
		t = ROTL(B * (2 * B + 1), 5);
		C = ROTR(C - (state->S)[2 * i + 1], t) ^ u;
		A = ROTR(A - (state->S)[2 * i], u) ^ t;
	}

	D = D - (state->S)[1];
	B = B - (state->S)[0];

	data[0] = A;
	data[1] = B;
	data[2] = C;
	data[3] = D;

	for (i = 0; i < BLOCK_SIZE; i++) {
		outbuf[i] = (ut8)((data[i / 4] >> (i % 4) * 8) & 0xff);
	}
}

static bool rc6_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	struct rc6_state *st = (struct rc6_state *)cry->user;

	cry->dir = direction;

	return rc6_init_state(st, key, keylen);
}

static int rc6_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	struct rc6_state *st = (struct rc6_state *)cry->user;

	return st->key_size;
}

static bool rc6_use(const char *algo) {
	return !strcmp(algo, "rc6");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, false);
	struct rc6_state *st = (struct rc6_state *)cry->user;

	if (len % BLOCK_SIZE != 0) { // let user handle with with pad.
		eprintf("Input should be multiple of 128bit.\n");
		return false;
	}

	const int blocks = len / BLOCK_SIZE;

	ut8 *obuf = calloc(1, len);
	if (!obuf) {
		return false;
	}

	int i;
	if (cry->dir == RZ_CRYPTO_DIR_DECRYPT) {
		for (i = 0; i < blocks; i++) {
			rc6_decrypt(st, buf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			rc6_encrypt(st, buf + BLOCK_SIZE * i, obuf + BLOCK_SIZE * i);
		}
	}

	rz_crypto_append(cry, obuf, len);
	free(obuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

static bool rc6_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(struct rc6_state);
	return cry->user != NULL;
}

static bool rc6_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_rc6 = {
	.name = "rc6",
	.author = "rakholiyajenish.07",
	.license = "LGPL-3",
	.description = "RC6 symmetric-key block cipher",
	.set_key = rc6_set_key,
	.get_key_size = rc6_get_key_size,
	.use = rc6_use,
	.update = update,
	.final = final,
	.init = rc6_init,
	.fini = rc6_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_rc6,
	.version = RZ_VERSION
};
#endif
