// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>

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

static bool rot_init(ut8 *rotkey, const ut8 *key, int keylen) {
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
		outbuf[i] += 26; //adding so that subtracting does not make it negative
		outbuf[i] -= key;
		outbuf[i] -= (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
		outbuf[i] = mod(outbuf[i], 26);
		outbuf[i] += (inbuf[i] >= 'a' && inbuf[i] <= 'z') ? 'a' : 'A';
	}
}

static ut8 rot_key;
static int flag = 0;

static bool rot_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	flag = direction;
	return rot_init(&rot_key, key, keylen);
}

static int rot_get_key_size(RzCrypto *cry) {
	//Returning number of bytes occupied by ut8
	return 1;
}

static bool rot_use(const char *algo) {
	return !strcmp(algo, "rot");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	ut8 *obuf = calloc(1, len);
	if (!obuf) {
		return false;
	}
	if (flag == 0) {
		rot_crypt(rot_key, buf, obuf, len);
	} else if (flag == 1) {
		rot_decrypt(rot_key, buf, obuf, len);
	}
	rz_crypto_append(cry, obuf, len);
	free(obuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

RzCryptoPlugin rz_crypto_plugin_rot = {
	.name = "rot",
	.set_key = rot_set_key,
	.get_key_size = rot_get_key_size,
	.use = rot_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_rot,
	.version = RZ_VERSION
};
#endif
