// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

static bool base32_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	cry->dir = direction;
	return true;
}

static int base32_get_key_size(RzCrypto *cry) {
	return 0;
}

static bool base32_use(const char *algo) {
	return !strcmp(algo, "base32");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	if (!cry || !buf || len <= 0) {
		return false;
	}

	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		size_t outlen = 1 + 8 * ((len + 4) / 5);
		char *encoded = malloc(outlen);
		if (!encoded) {
			return false;
		}
		rz_base32_encode(encoded, buf, len);
		rz_crypto_append(cry, (const ut8 *)encoded, strlen(encoded));
		free(encoded);

	} else {
		size_t outlen = 1 + 5 * ((len + 7) / 8);
		ut8 *decoded = malloc(outlen);
		if (!decoded) {
			return false;
		}
		st64 decoded_len = rz_base32_decode(decoded, (const char *)buf, len);
		if (decoded_len == -1) {
			free(decoded);
			return false;
		}
		rz_crypto_append(cry, decoded, decoded_len);
		free(decoded);
	}

	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	if (!buf) {
		return true;
	}
	return update(cry, buf, len);
}

RzCryptoPlugin rz_crypto_plugin_base32 = {
	.name = "base32",
	.author = "Ahmed Ibrahim",
	.license = "LGPL-3",
	.description = "Base32 encoder/decoder",
	.set_key = base32_set_key,
	.get_key_size = base32_get_key_size,
	.use = base32_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_base32,
	.version = RZ_VERSION
};
#endif
