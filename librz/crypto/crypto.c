// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_crypto.h>
#include "config.h"
#include <rz_util.h>

#define RZ_CRYPTO_OUTPUT_SIZE 4096

RZ_LIB_VERSION(rz_crypto);

static RzCryptoPlugin *crypto_static_plugins[] = {
	RZ_CRYPTO_STATIC_PLUGINS
};

static const struct {
	const char *name;
	RzCryptoSelector bit;
} crypto_name_bytes[] = {
	{ "all", UT64_MAX },
	{ "rc2", RZ_CRYPTO_RC2 },
	{ "rc4", RZ_CRYPTO_RC4 },
	{ "rc6", RZ_CRYPTO_RC6 },
	{ "aes-ecb", RZ_CRYPTO_AES_ECB },
	{ "aes-cbc", RZ_CRYPTO_AES_CBC },
	{ "ror", RZ_CRYPTO_ROR },
	{ "rol", RZ_CRYPTO_ROL },
	{ "rot", RZ_CRYPTO_ROT },
	{ "blowfish", RZ_CRYPTO_BLOWFISH },
	{ "cps2", RZ_CRYPTO_CPS2 },
	{ "des-ecb", RZ_CRYPTO_DES_ECB },
	{ "xor", RZ_CRYPTO_XOR },
	{ "serpent-ecb", RZ_CRYPTO_SERPENT },
};

static const struct {
	const char *name;
	RzCryptoSelector bit;
} codec_name_bytes[] = {
	{ "all", UT64_MAX },
	{ "base64", RZ_CODEC_B64 },
	{ "base91", RZ_CODEC_B91 },
	{ "punycode", RZ_CODEC_PUNYCODE },
};

RZ_API const char *rz_crypto_name(const RzCryptoSelector bit) {
	size_t i;
	for (i = 1; i < RZ_ARRAY_SIZE(crypto_name_bytes); i++) {
		if (bit == crypto_name_bytes[i].bit) {
			return crypto_name_bytes[i].name;
		}
	}
	return "";
}

RZ_API const char *rz_crypto_codec_name(const RzCryptoSelector bit) {
	size_t i;
	for (i = 1; i < RZ_ARRAY_SIZE(codec_name_bytes); i++) {
		if (bit == codec_name_bytes[i].bit) {
			return codec_name_bytes[i].name;
		}
	}
	return "";
}

RZ_API const RzCryptoPlugin *rz_crypto_plugin_by_index(size_t index) {
	const size_t size = RZ_ARRAY_SIZE(crypto_static_plugins);
	if (index >= size) {
		return NULL;
	}
	return crypto_static_plugins[index];
}

RZ_API int rz_crypto_add(RzCrypto *cry, RzCryptoPlugin *h) {
	// add a check ?
	rz_list_append(cry->plugins, h);
	return true;
}

RZ_API int rz_crypto_del(RzCrypto *cry, RzCryptoPlugin *h) {
	rz_list_delete_data(cry->plugins, h);
	return true;
}

RZ_API RzCrypto *rz_crypto_new(void) {
	RzCrypto *cry = RZ_NEW0(RzCrypto);
	if (!cry) {
		goto rz_crypto_new_bad;
	}

	cry->output_size = RZ_CRYPTO_OUTPUT_SIZE;
	cry->output = malloc(RZ_CRYPTO_OUTPUT_SIZE);
	if (!cry->output) {
		goto rz_crypto_new_bad;
	}

	cry->plugins = rz_list_newf((RzListFree)free);
	if (!cry->plugins) {
		goto rz_crypto_new_bad;
	}

	for (ut32 i = 0; crypto_static_plugins[i]; i++) {
		RzCryptoPlugin *p = RZ_NEW0(RzCryptoPlugin);
		if (!p) {
			goto rz_crypto_new_bad;
		}
		memcpy(p, crypto_static_plugins[i], sizeof(RzCryptoPlugin));
		rz_crypto_add(cry, p);
	}
	return cry;

rz_crypto_new_bad:
	RZ_LOG_ERROR("[!] crypto: failed to allocate\n");
	rz_crypto_free(cry);
	return NULL;
}

RZ_API void rz_crypto_free(RzCrypto *cry) {
	if (!cry) {
		return;
	}
	if (cry->h && cry->h->fini && !cry->h->fini(cry)) {
		RZ_LOG_ERROR("[!] crypto: error terminating '%s' plugin\n", cry->h->name);
	}
	rz_list_free(cry->plugins);
	free(cry->output);
	free(cry->key);
	free(cry->iv);
	free(cry);
}

RZ_API bool rz_crypto_use(RzCrypto *cry, const char *algo) {
	RzListIter *iter;
	RzCryptoPlugin *h;
	if (cry->h && cry->h->fini && !cry->h->fini(cry)) {
		RZ_LOG_ERROR("[!] crypto: error terminating '%s' plugin\n", cry->h->name);
	}
	rz_list_foreach (cry->plugins, iter, h) {
		rz_warn_if_fail(h && h->use);
		if (h && h->use(algo)) {
			if (h->init && !h->init(cry)) {
				RZ_LOG_ERROR("[!] crypto: error initializing '%s' plugin\n", cry->h->name);
				return false;
			}

			cry->h = h;
			return true;
		}
	}
	return false;
}

RZ_API bool rz_crypto_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	if (keylen < 0) {
		keylen = strlen((const char *)key);
	}
	if (!cry || !cry->h || !cry->h->set_key) {
		return false;
	}
	return cry->h->set_key(cry, key, keylen, mode, direction);
}

RZ_API bool rz_crypto_set_iv(RzCrypto *cry, const ut8 *iv, int ivlen) {
	return (cry && cry->h && cry->h->set_iv) ? cry->h->set_iv(cry, iv, ivlen) : 0;
}

// return the number of bytes written in the output buffer
RZ_API int rz_crypto_update(RzCrypto *cry, const ut8 *buf, int len) {
	return (cry && cry->h && cry->h->update) ? cry->h->update(cry, buf, len) : 0;
}

RZ_API int rz_crypto_final(RzCrypto *cry, const ut8 *buf, int len) {
	return (cry && cry->h && cry->h->final) ? cry->h->final(cry, buf, len) : 0;
}

// TODO: internal api?? used from plugins? TODO: use rz_buf here
RZ_API int rz_crypto_append(RzCrypto *cry, const ut8 *buf, int len) {
	if (!cry || !buf) {
		return -1;
	}
	if (cry->output_len + len > cry->output_size) {
		cry->output_size += 4096 + len;
		cry->output = realloc(cry->output, cry->output_size);
	}
	if (!cry->output) {
		rz_warn_if_reached();
		cry->output_size = 0;
		return 0;
	}
	memcpy(cry->output + cry->output_len, buf, len);
	cry->output_len += len;
	return cry->output_len;
}

RZ_API const ut8 *rz_crypto_get_output(RzCrypto *cry, int *size) {
	if (cry->output_size < 1 || !cry->output) {
		if (size) {
			*size = 0;
		}
		return NULL;
	}
	if (size) {
		*size = cry->output_len;
	}
	return cry->output;
}
