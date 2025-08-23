// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include <rz_util.h>

static bool base36_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	cry->dir = direction;
	return true;
}

static int base36_get_key_size(RzCrypto *cry) {
	return 0;
}

static bool base36_use(const char *algo) {
	return !strcmp(algo, "base36");
}

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	if (!cry || !buf || len <= 0) {
		return false;
	}
	ut8 *out = NULL;
	size_t out_len = 0;

	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		if (len > 8) { /* > 64‑bit won’t fit in our encoder */
			RZ_LOG_ERROR("base36: encoder supports up to 64‑bit values (%d > 8 bytes)\n", len);
			return false;
		}
		ut64 val = 0;
		for (int i = 0; i < len; i++) {
			val = (val << 8) | buf[i];
		}
		char *enc = rz_base36_encode_dyn(val);
		if (!enc) {
			return false;
		}
		out = (ut8 *)enc;
		out_len = strlen(enc);

	} else if (cry->dir == RZ_CRYPTO_DIR_DECRYPT) {
		ut64 val = 0;
		st64 ret = rz_base36_decode(&val, (const char *)buf, (size_t)len);
		/* Here, rz_base36_decode returns 0 either for the value 0 or on error.
		 * We consider empty input an error.  */
		if (ret < 0) {
			return false;
		}

		// convert val →  big‑endian byte array
		ut8 tmp[8];
		int idx = 8;
		if (val == 0) {
			tmp[--idx] = 0;
		} else {
			while (val > 0) {
				tmp[--idx] = (ut8)(val & 0xff);
				val >>= 8;
			}
		}
		out_len = 8 - idx;
		out = (ut8 *)malloc(out_len);
		if (!out) {
			return false;
		}
		memcpy(out, tmp + idx, out_len);

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

RzCryptoPlugin rz_crypto_plugin_base36 = {
	.name = "base36",
	.author = "abcSup",
	.license = "LGPL-3",
	.description = "Base36 encoder/decoder",
	.set_key = base36_set_key,
	.get_key_size = base36_get_key_size,
	.use = base36_use,
	.update = update,
	.final = final
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_base36,
	.version = RZ_VERSION
};
#endif
