// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

static bool base85_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	cry->dir = direction;
	return true;
}

static int base85_get_key_size(RzCrypto *cry) {
	return 0;
}

static bool base85_use(const char *algo) {
	return !strcmp(algo, "base85");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	if (!cry || !buf || len <= 0) {
		return false;
	}
	ut8 *out = NULL;
	size_t out_len = 0;
	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		char *enc = rz_base85_encode_dyn((char *)buf, (size_t)len, 0, 0, 1);
		if (!enc) {
			return false;
		}
		out = (ut8 *)enc;
		out_len = strlen(enc);
	} else if (cry->dir == RZ_CRYPTO_DIR_DECRYPT) {
		out = (ut8 *)rz_base85_decode_dyn((const char *)buf, (st64)len, 0, 0, &out_len);
		if (!out) {
			return false;
		}
	} else {
		return false;
	}
	rz_crypto_append(cry, out, (int)out_len);
	free(out);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	if (!buf || len == 0) {
		return true;
	}
	return update(cry, buf, len);
}

RzCryptoPlugin rz_crypto_plugin_base85 = {
	.name = "base85",
	.author = "Ahmed Ibrahim",
	.license = "LGPL-3",
	.description = "Base85 encoder/decoder",
	.set_key = base85_set_key,
	.get_key_size = base85_get_key_size,
	.use = base85_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_base85,
	.version = RZ_VERSION
};
#endif
