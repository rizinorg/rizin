// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_crypto.h>
#include <rz_lib.h>
#include <rz_util.h>
#include "rz_crypto_plugins.h"

static RzCryptoPlugin *crypto_static_plugins[] = { &rz_crypto_plugin_aes, &rz_crypto_plugin_aes_cbc, &rz_crypto_plugin_base64, &rz_crypto_plugin_base91, &rz_crypto_plugin_blowfish, &rz_crypto_plugin_cps2, &rz_crypto_plugin_des, &rz_crypto_plugin_punycode, &rz_crypto_plugin_rc2, &rz_crypto_plugin_rc4, &rz_crypto_plugin_rc6, &rz_crypto_plugin_rol, &rz_crypto_plugin_ror, &rz_crypto_plugin_rot, &rz_crypto_plugin_serpent, &rz_crypto_plugin_xor, &rz_crypto_plugin_sm4_ecb };

#define RZ_CRYPTO_OUTPUT_SIZE 4096

RZ_LIB_VERSION(rz_crypto);

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
	{ "sm4-ecb", RZ_CRYPTO_SM4_ECB },
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

RZ_API RZ_BORROW const char *rz_crypto_name(const RzCryptoSelector bit) {
	size_t i;
	for (i = 1; i < RZ_ARRAY_SIZE(crypto_name_bytes); i++) {
		if (bit == crypto_name_bytes[i].bit) {
			return crypto_name_bytes[i].name;
		}
	}
	return "";
}

RZ_API RZ_BORROW const char *rz_crypto_codec_name(const RzCryptoSelector bit) {
	size_t i;
	for (i = 1; i < RZ_ARRAY_SIZE(codec_name_bytes); i++) {
		if (bit == codec_name_bytes[i].bit) {
			return codec_name_bytes[i].name;
		}
	}
	return "";
}

RZ_API RZ_BORROW const RzCryptoPlugin *rz_crypto_plugin_by_index(RZ_NONNULL RzCrypto *cry, size_t index) {
	rz_return_val_if_fail(cry, NULL);

	RzIterator *it = ht_sp_as_iter(cry->plugins);
	RzCryptoPlugin **val;
	size_t i = 0;

	rz_iterator_foreach(it, val) {
		const RzCryptoPlugin *plugin = *val;
		if (i == index) {
			rz_iterator_free(it);
			return plugin;
		}
		i++;
	}
	rz_iterator_free(it);
	return NULL;
}

RZ_API bool rz_crypto_plugin_add(RZ_NONNULL RzCrypto *cry, RZ_NONNULL RzCryptoPlugin *plugin) {
	rz_return_val_if_fail(cry && plugin, false);
	ht_sp_insert(cry->plugins, plugin->name, plugin);
	return true;
}

RZ_API bool rz_crypto_plugin_del(RZ_NONNULL RzCrypto *cry, RZ_NONNULL RzCryptoPlugin *plugin) {
	rz_return_val_if_fail(cry && plugin, false);
	if (cry->h == plugin && cry->h->fini) {
		cry->h->fini(cry);
		cry->h = NULL;
	}
	ht_sp_delete(cry->plugins, plugin->name);
	return true;
}

RZ_API RZ_OWN RzCrypto *rz_crypto_new(void) {
	RzCrypto *cry = RZ_NEW0(RzCrypto);
	if (!cry) {
		goto rz_crypto_new_bad;
	}

	cry->output_size = RZ_CRYPTO_OUTPUT_SIZE;
	cry->output = malloc(RZ_CRYPTO_OUTPUT_SIZE);
	if (!cry->output) {
		goto rz_crypto_new_bad;
	}

	cry->plugins = ht_sp_new(HT_STR_DUP, NULL, NULL);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(crypto_static_plugins); ++i) {
		ht_sp_insert(cry->plugins, crypto_static_plugins[i]->name, crypto_static_plugins[i]);
	}
	if (!cry->plugins) {
		goto rz_crypto_new_bad;
	}
	return cry;

rz_crypto_new_bad:
	RZ_LOG_ERROR("[!] crypto: failed to allocate\n");
	rz_crypto_free(cry);
	return NULL;
}

RZ_API void rz_crypto_free(RZ_NULLABLE RzCrypto *cry) {
	if (!cry) {
		return;
	}
	if (cry->h && cry->h->fini && !cry->h->fini(cry)) {
		RZ_LOG_ERROR("[!] crypto: error terminating '%s' plugin\n", cry->h->name);
	}
	ht_sp_free(cry->plugins);
	free(cry->output);
	free(cry->key);
	free(cry->iv);
	free(cry);
}

/**
 * \brief Reset the internal state of RzCrypto.
 *
 * Prepare the RzCrypto instance to be run on a new input. This includes
 * resetting the current plugin, the output, key, iv.
 *
 * \param cry RzCrypto reference
 */
RZ_API void rz_crypto_reset(RZ_NONNULL RzCrypto *cry) {
	rz_return_if_fail(cry);

	if (cry->h && cry->h->fini && !cry->h->fini(cry)) {
		RZ_LOG_ERROR("[!] crypto: error terminating '%s' plugin\n", cry->h->name);
	}
	cry->h = NULL;
	RZ_FREE(cry->key);
	RZ_FREE(cry->iv);
	cry->output_len = 0;
}

RZ_API bool rz_crypto_use(RZ_NONNULL RzCrypto *cry, RZ_NONNULL const char *algo) {
	rz_return_val_if_fail(cry && algo, false);
	RzIterator *it = ht_sp_as_iter(cry->plugins);
	RzCryptoPlugin **val;
	if (cry->h && cry->h->fini && !cry->h->fini(cry)) {
		RZ_LOG_ERROR("[!] crypto: error terminating '%s' plugin\n", cry->h->name);
	}
	rz_iterator_foreach(it, val) {
		RzCryptoPlugin *h = *val;
		rz_warn_if_fail(h && h->use);
		if (h && h->use(algo)) {
			if (h->init && !h->init(cry)) {
				RZ_LOG_ERROR("[!] crypto: error initializing '%s' plugin\n", cry->h->name);
				rz_iterator_free(it);
				return false;
			}

			cry->h = h;
			rz_iterator_free(it);
			return true;
		}
	}
	rz_iterator_free(it);
	return false;
}

RZ_API bool rz_crypto_set_key(RZ_NULLABLE RzCrypto *cry, RZ_NULLABLE const ut8 *key, int keylen, int mode, int direction) {
	if (keylen < 0) {
		keylen = key ? strlen((const char *)key) : 0;
	}
	if (!cry || !cry->h || !cry->h->set_key) {
		return false;
	}
	return cry->h->set_key(cry, key, keylen, mode, direction);
}

RZ_API bool rz_crypto_set_iv(RZ_NULLABLE RzCrypto *cry, RZ_NULLABLE const ut8 *iv, int ivlen) {
	return (cry && cry->h && cry->h->set_iv) ? cry->h->set_iv(cry, iv, ivlen) : 0;
}

// return the number of bytes written in the output buffer
RZ_API int rz_crypto_update(RZ_NULLABLE RzCrypto *cry, RZ_NULLABLE const ut8 *buf, int len) {
	return (cry && cry->h && cry->h->update) ? cry->h->update(cry, buf, len) : 0;
}

RZ_API int rz_crypto_final(RZ_NULLABLE RzCrypto *cry, RZ_NULLABLE const ut8 *buf, int len) {
	return (cry && cry->h && cry->h->final) ? cry->h->final(cry, buf, len) : 0;
}

// TODO: internal api?? used from plugins? TODO: use rz_buf here
RZ_API int rz_crypto_append(RZ_NONNULL RzCrypto *cry, RZ_NONNULL const ut8 *buf, int len) {
	rz_return_val_if_fail(cry && buf, -1);
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

RZ_API RZ_BORROW const ut8 *rz_crypto_get_output(RZ_NONNULL RzCrypto *cry, RZ_NULLABLE int *size) {
	rz_return_val_if_fail(cry, NULL);
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
