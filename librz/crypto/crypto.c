/* radare - LGPL - Copyright 2009-2017 - pancake */

#include "rz_crypto.h"
#include "config.h"

R_LIB_VERSION (rz_crypto);

static const struct {
	const char *name;
	RzCryptoSelector bit;
} crypto_name_bytes[] = {
	{ "all", UT64_MAX },
	{ "rc2", R_CRYPTO_RC2 },
	{ "rc4", R_CRYPTO_RC4 },
	{ "rc6", R_CRYPTO_RC6 },
	{ "aes-ecb", R_CRYPTO_AES_ECB },
	{ "aes-cbc", R_CRYPTO_AES_CBC },
	{ "ror", R_CRYPTO_ROR },
	{ "rol", R_CRYPTO_ROL },
	{ "rot", R_CRYPTO_ROT },
	{ "blowfish", R_CRYPTO_BLOWFISH },
	{ "cps2", R_CRYPTO_CPS2 },
	{ "des-ecb", R_CRYPTO_DES_ECB },
	{ "xor", R_CRYPTO_XOR },
	{ "serpent-ecb", R_CRYPTO_SERPENT },
	{ NULL, 0 }
};

static const struct {
	const char *name;
	RzCryptoSelector bit;
} codec_name_bytes[] = {
	{ "all", UT64_MAX },
	{ "base64", R_CODEC_B64 },
	{ "base91", R_CODEC_B91 },
	{ "punycode", R_CODEC_PUNYCODE },
	{ NULL, 0 }
};

RZ_API const char *rz_crypto_name(const RzCryptoSelector bit) {
	size_t i;
	for (i = 1; crypto_name_bytes[i].bit; i++) {
		if (bit & crypto_name_bytes[i].bit) {
			return crypto_name_bytes[i].name;
		}
	}
	return "";
}

RZ_API const char *rz_crypto_codec_name(const RzCryptoSelector bit) {
	size_t i;
	for (i = 1; codec_name_bytes[i].bit; i++) {
		if (bit & codec_name_bytes[i].bit) {
			return codec_name_bytes[i].name;
		}
	}
	return "";
}

static RzCryptoPlugin *crypto_static_plugins[] = {
	R_CRYPTO_STATIC_PLUGINS
};

RZ_API RzCrypto *rz_crypto_init(RzCrypto *cry, int hard) {
	int i;
	if (cry) {
		cry->iv = NULL;
		cry->key = NULL;
		cry->key_len = 0;
		cry->user = NULL;
		if (hard) {
			// first call initializes the output_* variables
			rz_crypto_get_output (cry, NULL);
			cry->plugins = rz_list_newf (NULL);
			for (i = 0; crypto_static_plugins[i]; i++) {
				RzCryptoPlugin *p = R_NEW0 (RzCryptoPlugin);
				if (!p) {
					free (cry);
					return NULL;
				}
				memcpy (p, crypto_static_plugins[i], sizeof (RzCryptoPlugin));
				rz_crypto_add (cry, p);
			}
		}
	}
	return cry;
}

RZ_API int rz_crypto_add(RzCrypto *cry, RzCryptoPlugin *h) {
	// add a check ?
	rz_list_append (cry->plugins, h);
	return true;
}

RZ_API int rz_crypto_del(RzCrypto *cry, RzCryptoPlugin *h) {
	rz_list_delete_data (cry->plugins, h);
	return true;
}

RZ_API struct rz_crypto_t *rz_crypto_new(void) {
	RzCrypto *cry = R_NEW0 (RzCrypto);
	return rz_crypto_init (cry, true);
}

RZ_API struct rz_crypto_t *rz_crypto_as_new(struct rz_crypto_t *cry) {
	RzCrypto *c = R_NEW0 (RzCrypto);
	if (c) {
		rz_crypto_init (c, false); // soft init
		memcpy (&c->plugins, &cry->plugins, sizeof (cry->plugins));
	}
	return c;
}

RZ_API struct rz_crypto_t *rz_crypto_free(RzCrypto *cry) {
	// TODO: call the destructor function of the plugin to destroy the *user pointer if needed
	rz_list_free (cry->plugins);
	free (cry->output);
	free (cry->key);
	free (cry->iv);
	free (cry);
	return NULL;
}

RZ_API bool rz_crypto_use(RzCrypto *cry, const char *algo) {
	RzListIter *iter;
	RzCryptoPlugin *h;
	rz_list_foreach (cry->plugins, iter, h) {
		if (h && h->use && h->use (algo)) {
			cry->h = h;
			cry->key_len = h->get_key_size (cry);
			cry->key = calloc (1, cry->key_len);
			return cry->key != NULL;
		}
	}
	return false;
}

RZ_API bool rz_crypto_set_key(RzCrypto *cry, const ut8* key, int keylen, int mode, int direction) {
	if (keylen < 0) {
		keylen = strlen ((const char *)key);
	}
	if (!cry || !cry->h || !cry->h->set_key) {
		return false;
	}
	return cry->h->set_key (cry, key, keylen, mode, direction);
}

RZ_API int rz_crypto_get_key_size(RzCrypto *cry) {
	return (cry && cry->h && cry->h->get_key_size)?
		cry->h->get_key_size (cry): 0;
}

RZ_API bool rz_crypto_set_iv(RzCrypto *cry, const ut8 *iv, int ivlen) {
	return (cry && cry->h && cry->h->set_iv)?
		cry->h->set_iv(cry, iv, ivlen): 0;
}

// return the number of bytes written in the output buffer
RZ_API int rz_crypto_update(RzCrypto *cry, const ut8 *buf, int len) {
	return (cry && cry->h && cry->h->update)?
		cry->h->update (cry, buf, len): 0;
}

RZ_API int rz_crypto_final(RzCrypto *cry, const ut8 *buf, int len) {
	return (cry && cry->h && cry->h->final)?
		cry->h->final (cry, buf, len): 0;
}

// TODO: internal api?? used from plugins? TODO: use rz_buf here
RZ_API int rz_crypto_append(RzCrypto *cry, const ut8 *buf, int len) {
	if (!cry || !buf) {
		return -1;
	}
	if (cry->output_len+len > cry->output_size) {
		cry->output_size += 4096 + len;
		cry->output = realloc (cry->output, cry->output_size);
	}
	memcpy (cry->output + cry->output_len, buf, len);
	cry->output_len += len;
	return cry->output_len;
}

RZ_API ut8 *rz_crypto_get_output(RzCrypto *cry, int *size) {
	if (cry->output_size < 1) {
		return NULL;
	}
	ut8 *buf = calloc (1, cry->output_size);
	if (!buf) {
		return NULL;
	}
	if (size) {
		*size = cry->output_len;
		memcpy (buf, cry->output, *size);
	} else {
		/* initialize */
		const int size = 4096;
		cry->output = realloc (buf, size);
		if (!cry->output) {
			free (buf);
			return NULL;
		}
		cry->output_len = 0;
		cry->output_size = size;

		return NULL;
	}
	return buf;
}
