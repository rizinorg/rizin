// SPDX-FileCopyrightText: 2016-2017 rakholiyajenish.07 <rakholiyajenish.07@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

#define INSIZE 32768

static bool base91_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	cry->dir = direction;
	return true;
}

static int base91_get_key_size(RzCrypto *cry) {
	return 0;
}

static bool base91_use(const char *algo) {
	return algo && !strcmp(algo, "base91");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	int olen = INSIZE;
	if (!cry || !buf || len < 1) {
		return false;
	}
	ut8 *obuf = malloc(olen);
	if (!obuf) {
		return false;
	}
	if (cry->dir == 0) {
		olen = rz_base91_encode((char *)obuf, (const ut8 *)buf, len);
	} else if (cry->dir == 1) {
		olen = rz_base91_decode(obuf, (const char *)buf, len);
	}
	rz_crypto_append(cry, obuf, olen);
	free(obuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

RzCryptoPlugin rz_crypto_plugin_base91 = {
	.name = "base91",
	.set_key = base91_set_key,
	.get_key_size = base91_get_key_size,
	.use = base91_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_base91,
	.version = RZ_VERSION
};
#endif
