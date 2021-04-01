// SPDX-FileCopyrightText: 2016-2017 rakholiyajenish.07 <rakholiyajenish.07@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

static bool base64_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	cry->dir = direction;
	return true;
}

static int base64_get_key_size(RzCrypto *cry) {
	return 0;
}

static bool base64_use(const char *algo) {
	return !strcmp(algo, "base64");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	int olen = 0;
	ut8 *obuf = NULL;
	if (cry->dir == 0) {
		olen = ((len + 2) / 3) * 4;
		obuf = malloc(olen + 1);
		if (!obuf) {
			return false;
		}
		rz_base64_encode((char *)obuf, (const ut8 *)buf, len);
	} else if (cry->dir == 1) {
		olen = 4 + ((len / 4) * 3);
		if (len > 0) {
			olen -= (buf[len - 1] == '=') ? ((buf[len - 2] == '=') ? 2 : 1) : 0;
		}
		obuf = malloc(olen + 4);
		if (!obuf) {
			return false;
		}
		olen = rz_base64_decode(obuf, (const char *)buf, len);
	}
	if (olen > 0) {
		rz_crypto_append(cry, obuf, olen);
	}
	free(obuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	if (!buf) {
		return true;
	}
	return update(cry, buf, len);
}

RzCryptoPlugin rz_crypto_plugin_base64 = {
	.name = "base64",
	.set_key = base64_set_key,
	.get_key_size = base64_get_key_size,
	.use = base64_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_base64,
	.version = RZ_VERSION
};
#endif
