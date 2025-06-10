// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

int mod(int a, int b) {
	if (b < 0) {
		return mod(-a, -b);
	}
	int ret = a % b;
	if (ret < 0) {
		ret += b;
	}
	return ret;
}

static bool rot_init_state(ut8 *rotkey, const ut8 *key, int keylen) {
	if (rotkey && key && keylen > 0) {
		int i = atoi((const char *)key);
		*rotkey = (ut8)mod(i, 26);
		return true;
	}
	return false;
}

static void rot_crypt(ut8 key, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		outbuf[i] = inbuf[i];
		if ((inbuf[i] < 'a' || inbuf[i] > 'z') && (inbuf[i] < 'A' || inbuf[i] > 'Z')) {
			continue;
		}
		outbuf[i] += key;
		outbuf[i] -= (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
		outbuf[i] = mod(outbuf[i], 26);
		outbuf[i] += (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
	}
}

static void rot_decrypt(ut8 key, const ut8 *inbuf, ut8 *outbuf, int buflen) {
	int i;
	for (i = 0; i < buflen; i++) {
		outbuf[i] = inbuf[i];
		if ((inbuf[i] < 'a' || inbuf[i] > 'z') && (inbuf[i] < 'A' || inbuf[i] > 'Z')) {
			continue;
		}
		outbuf[i] += 26; // adding so that subtracting does not make it negative
		outbuf[i] -= key;
		outbuf[i] -= (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
		outbuf[i] = mod(outbuf[i], 26);
		outbuf[i] += (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
	}
}

static bool rot_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	ut8 *rot_key = (ut8 *)cry->user;

	if (keylen > (sizeof(ut8) * 8) || keylen < 0) {
		return false;
	}

	cry->dir = direction;

	return rot_init_state(rot_key, key, keylen);
}

static int rot_get_key_size(RzCrypto *cry) {
	// Returning number of bytes occupied by ut8
	return 1;
}

static bool rot_use(const char *algo) {
	return !strcmp(algo, "rot");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, false);
	ut8 *rot_key = (ut8 *)cry->user;

	ut8 *obuf = calloc(1, len);
	if (!obuf) {
		return false;
	}
	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		rot_crypt(*rot_key, buf, obuf, len);
	} else {
		rot_decrypt(*rot_key, buf, obuf, len);
	}
	rz_crypto_append(cry, obuf, len);
	free(obuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

static bool rol_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(ut8);
	return cry->user != NULL;
}

static bool rol_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_rot = {
	.name = "rot",
	.author = "pancake",
	.license = "LGPL-3",
	.description = "Caesar symmetric-key cipher",
	.set_key = rot_set_key,
	.get_key_size = rot_get_key_size,
	.use = rot_use,
	.update = update,
	.final = final,
	.init = rol_init,
	.fini = rol_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_rot,
	.version = RZ_VERSION
};
#endif
