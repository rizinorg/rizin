// SPDX-FileCopyrightText: 2009-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_lib.h>
#include <rz_crypto.h>

static bool punycode_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	cry->dir = direction;
	return true;
}

static int punycode_get_key_size(RzCrypto *cry) {
	return 0;
}

static bool punycode_use(const char *algo) {
	return !strcmp(algo, "punycode");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	if (len < 1 || !buf) {
		return false;
	}

	char *obuf;
	int olen;
	if (cry->dir == RZ_CRYPTO_DIR_DECRYPT) {
		obuf = rz_punycode_decode((const char *)buf, len, &olen);
	} else {
		obuf = rz_punycode_encode(buf, len, &olen);
	}
	rz_crypto_append(cry, (ut8 *)obuf, olen);
	free(obuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

RzCryptoPlugin rz_crypto_plugin_punycode = {
	.name = "punycode",
	.author = "pancake",
	.license = "LGPL-3",
	.description = "Punycode encoder/decoder",
	.set_key = punycode_set_key,
	.get_key_size = punycode_get_key_size,
	.use = punycode_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_punycode,
	.version = RZ_VERSION
};
#endif
