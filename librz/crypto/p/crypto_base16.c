// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

static bool base16_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	cry->dir = direction;
	return true;
}

static int base16_get_key_size(RzCrypto *cry) {
	return 0;
}

static bool base16_use(const char *algo) {
	return !strcmp(algo, "base16");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	if (!cry || !buf || len <= 0) {
		return false;
	}

	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		size_t outlen = 1 + 2 * len;
		char *encoded = malloc(outlen);
		if (!encoded) {
			return false;
		}
		rz_base16_encode(encoded, buf, len);
		rz_crypto_append(cry, (const ut8 *)encoded, strlen(encoded));
		free(encoded);

	} else {
		size_t outlen = (size_t)(len / 2 + 1);
		ut8 *decoded = malloc(outlen);
		if (!decoded) {
			return false;
		}

		st64 decoded_len = rz_base16_decode(decoded, (const char *)buf);
		if (decoded_len == 0) { // truly invalid
			free(decoded);
			return false;
		}
		if (decoded_len < 0) { // odd nibbles handled, still valid
			decoded_len = -decoded_len;
		}

		rz_crypto_append(cry, decoded, (size_t)decoded_len);
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

RzCryptoPlugin rz_crypto_plugin_base16 = {
	.name = "base16",
	.author = "Ahmed Ibrahim",
	.license = "LGPL-3",
	.description = "Base16 encoder/decoder",
	.set_key = base16_set_key,
	.get_key_size = base16_get_key_size,
	.use = base16_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_base16,
	.version = RZ_VERSION
};
#endif
