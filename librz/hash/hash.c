// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <xxhash.h>
#include "algorithms/ssdeep/ssdeep.h"
#include "rz_hash_plugins.h"

RZ_LIB_VERSION(rz_hash);

#define hash_cfg_can_hmac(c)    ((c)->status == RZ_MSG_DIGEST_STATUS_ALLOC)
#define hash_cfg_can_init(c)    ((c)->status == RZ_MSG_DIGEST_STATUS_FINAL || (c)->status == RZ_MSG_DIGEST_STATUS_ALLOC)
#define hash_cfg_can_update(c)  ((c)->status == RZ_MSG_DIGEST_STATUS_INIT || (c)->status == RZ_MSG_DIGEST_STATUS_UPDATE)
#define hash_cfg_can_final(c)   ((c)->status == RZ_MSG_DIGEST_STATUS_ALLOC || (c)->status == RZ_MSG_DIGEST_STATUS_INIT || (c)->status == RZ_MSG_DIGEST_STATUS_UPDATE)
#define hash_cfg_has_finshed(c) ((c)->status == RZ_MSG_DIGEST_STATUS_FINAL)

typedef struct hash_cfg_config_t {
	void *context;
	ut8 *digest;
	ut8 *hmac_key;
	RzHashSize digest_size;
	const RzHashPlugin *plugin;
} HashCfgConfig;

#if HAVE_LIB_SSL
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/**
 * From openssl 3.0 some algos got moved to the legacy provider.
 * this means that their availability requires to preload a provider
 * before calling the initialization of each algorithms.
 */

#define REQUIRE_OPENSSL_PROVIDER 1
#include <openssl/provider.h>

typedef struct {
	OSSL_PROVIDER *provider;
	size_t counter;
} RzHashOpenSSL;

static RzHashOpenSSL *openssl_lib = NULL;

static void rz_hash_init_openssl_lib(void) {
	if (!openssl_lib) {
		openssl_lib = RZ_NEW0(RzHashOpenSSL);
		if (!openssl_lib) {
			RZ_LOG_ERROR("Cannot allocate RzHashOpenSSL\n");
			return;
		}
		openssl_lib->provider = OSSL_PROVIDER_try_load(NULL, "legacy", 1);
		if (!OSSL_PROVIDER_available(NULL, "legacy")) {
			RZ_LOG_WARN("Cannot load openssl legacy provider. Some algorithm might not be available.\n");
		}
	}
	openssl_lib->counter++;
}

static void rz_hash_fini_openssl_lib(void) {
	if (!openssl_lib || (--openssl_lib->counter) > 0) {
		return;
	}
	OSSL_PROVIDER_unload(openssl_lib->provider);
	free(openssl_lib);
	openssl_lib = NULL;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30000000L */
#endif /* HAVE_LIB_SSL */

static RzHashPlugin *hash_static_plugins[] = { RZ_HASH_STATIC_PLUGINS };

/**
 * \brief      Calculates the ssdeep digest of the given input
 *
 * \param[in]  input  The input buffer
 * \param[in]  size   The size of the input
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN char *rz_hash_ssdeep(RZ_NONNULL const ut8 *input, size_t size) {
	rz_return_val_if_fail(input, NULL);
	char *digest = malloc(RZ_HASH_SSDEEP_DIGEST_SIZE);
	if (!digest) {
		RZ_LOG_ERROR("msg digest: cannot allocate ssdeep digest buffer\n");
		return NULL;
	}

	RzSSDeep *ctx = rz_ssdeep_new();
	if (!ctx) {
		RZ_LOG_ERROR("msg digest: cannot allocate ssdeep context\n");
		free(digest);
		return NULL;
	}

	rz_ssdeep_update(ctx, input, size);
	rz_ssdeep_fini(ctx, digest);
	rz_ssdeep_free(ctx);
	return digest;
}

/**
 * \brief      Calculates the distance of 2 ssdeep hashes and returns their similarity
 *
 * \param[in]  hash_a      Hash A to compare
 * \param[in]  hash_b      Hash B to compare
 *
 * \return     On success returns a number between 0.0 and 1.0 (included), otherwise negative
 */
RZ_API double rz_hash_ssdeep_compare(RZ_NONNULL const char *hash_a, RZ_NONNULL const char *hash_b) {
	rz_return_val_if_fail(hash_a && hash_b, -1.0);
	return rz_ssdeep_compare(hash_a, hash_b);
}

/**
 * \brief      Calculates the xxhash digest of the given input
 *
 * \param[in]  input  The input buffer
 * \param[in]  size   The size of the input
 *
 * \return     The resulting digest of the input
 */
RZ_API ut32 rz_hash_xxhash(RZ_NONNULL const ut8 *input, size_t size) {
	rz_return_val_if_fail(input, 0);
	return XXH32(input, size, 0);
}

/**
 * \brief      Calculates the entropy of the given input
 *
 * \param[in]  data  The input buffer
 * \param[in]  size  The size of the input
 *
 * \return     The resulting entropy of the input
 */
RZ_API double rz_hash_entropy(RZ_NONNULL const ut8 *data, ut64 len) {
	rz_return_val_if_fail(data, 0.0);
	const RzHashPlugin *plugin = &rz_hash_plugin_entropy;
	ut8 *digest = NULL;
	if (!plugin->small_block(data, len, &digest, NULL)) {
		RZ_LOG_ERROR("msg digest: cannot calculate entropy\n");
		return 0.0;
	}
	double e = rz_read_be_double(digest);
	free(digest);
	return e;
}

/**
 * \brief      Calculates the fractional entropy of the given input
 *
 * \param[in]  data  The input buffer
 * \param[in]  size  The size of the input
 *
 * \return     The resulting fractional entropy of the input
 */
RZ_API double rz_hash_entropy_fraction(RZ_NONNULL const ut8 *data, ut64 len) {
	rz_return_val_if_fail(data, 0.0);
	const RzHashPlugin *plugin = &rz_hash_plugin_entropy_fract;
	ut8 *digest = NULL;
	if (!plugin->small_block(data, len, &digest, NULL)) {
		RZ_LOG_ERROR("msg digest: cannot calculate entropy fraction\n");
		return 0.0;
	}
	double e = rz_read_be_double(digest);
	free(digest);
	return e;
}

static int hash_cfg_config_compare(const void *value, const void *data, void *user) {
	const HashCfgConfig *mdc = (const HashCfgConfig *)data;
	const char *name = (const char *)value;
	return strcmp(name, mdc->plugin->name);
}

static void hash_cfg_config_free(HashCfgConfig *mdc) {
	rz_return_if_fail(mdc && mdc->plugin);

	mdc->plugin->context_free(mdc->context);
	free(mdc->hmac_key);
	free(mdc->digest);
	free(mdc);
}

static HashCfgConfig *hash_cfg_config_new(const RzHashPlugin *plugin) {
	rz_return_val_if_fail(plugin, NULL);

	HashCfgConfig *mdc = RZ_NEW0(HashCfgConfig);
	if (!mdc) {
		RZ_LOG_ERROR("msg digest: cannot allocate memory for config.\n");
		return NULL;
	}

	mdc->context = plugin->context_new();
	if (!mdc->context) {
		RZ_LOG_ERROR("msg digest: cannot allocate memory for context.\n");
		free(mdc);
		return NULL;
	}

	mdc->digest_size = plugin->digest_size(mdc->context);
	rz_warn_if_fail(mdc->digest_size > 0);

	mdc->digest = RZ_NEWS0(ut8, mdc->digest_size);
	if (!mdc->context) {
		RZ_LOG_ERROR("msg digest: cannot allocate memory for digest.\n");
		plugin->context_free(mdc->context);
		free(mdc);
		return NULL;
	}
	mdc->plugin = plugin;

	return mdc;
}

RZ_API RZ_BORROW const RzHashPlugin *rz_hash_plugin_by_name(RZ_NONNULL RzHash *rh, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(name && rh, NULL);

	bool found = false;
	const RzHashPlugin *rhp = ht_sp_find(rh->plugins, name, &found);
	if (found) {
		return rhp;
	}
	return NULL;
}

RZ_API RZ_OWN RzHashCfg *rz_hash_cfg_new(RZ_NONNULL RzHash *rh) {
	rz_return_val_if_fail(rh, NULL);

	RzHashCfg *md = RZ_NEW0(RzHashCfg);
	if (!md) {
		RZ_LOG_ERROR("msg digest: cannot allocate memory.\n");
		return NULL;
	}

	md->configurations = rz_list_newf((RzListFree)hash_cfg_config_free);
	if (!md->configurations) {
		RZ_LOG_ERROR("msg digest: cannot allocate memory for the configurations.\n");
		free(md);
		return NULL;
	}
	md->hash = rh;

	return md;
}

/**
 * \brief Returns a message digest context with the give algo already configured
 *
 * message digest allocates and configures already the structure
 * with the given algorithm and runs also the algo init.
 * when fails to allocate or configure or initialize, returns NULL.
 * */
RZ_API RZ_OWN RzHashCfg *rz_hash_cfg_new_with_algo(RZ_NONNULL RzHash *rh, RZ_NONNULL const char *name, RZ_NULLABLE const ut8 *key, ut64 key_size) {
	rz_return_val_if_fail(rh && name, NULL);
	RzHashCfg *md = rz_hash_cfg_new(rh);
	if (!md) {
		return NULL;
	}

	if (!rz_hash_cfg_configure(md, name)) {
		rz_hash_cfg_free(md);
		return NULL;
	}

	if (key && !rz_hash_cfg_hmac(md, key, key_size)) {
		rz_hash_cfg_free(md);
		return NULL;
	}

	if (!rz_hash_cfg_init(md)) {
		rz_hash_cfg_free(md);
		return NULL;
	}

	return md;
}

RZ_API void rz_hash_cfg_free(RZ_NONNULL RzHashCfg *md) {
	rz_return_if_fail(md);

	rz_list_free(md->configurations);
	free(md);
}

/**
 * \brief Allocates and configures the plugin message digest context
 *
 * message digest internally allocates a HashCfgConfig which
 * contains all the information needed for the plugin to work.
 * */
RZ_API bool rz_hash_cfg_configure(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(md && name, false);

	if (rz_list_find(md->configurations, name, hash_cfg_config_compare, NULL)) {
		RZ_LOG_WARN("msg digest: '%s' was already configured; skipping.\n", name);
		return false;
	}

	bool is_all = !strcmp(name, "all");

	if (is_all && rz_list_length(md->configurations) > 0) {
		RZ_LOG_WARN("msg digest: '%s' was already configured; skipping.\n", name);
		return false;
	}

	HashCfgConfig *mdc = NULL;
	RzIterator *it = ht_sp_as_iter(md->hash->plugins);
	const RzHashPlugin **val;

	rz_iterator_foreach(it, val) {
		const RzHashPlugin *plugin = *val;
		if (is_all || !strcmp(plugin->name, name)) {
			mdc = hash_cfg_config_new(plugin);
			if (!mdc) {
				rz_iterator_free(it);
				return false;
			}

			if (!rz_list_append(md->configurations, mdc)) {
				RZ_LOG_ERROR("msg digest: cannot allocate memory for list entry.\n");
				hash_cfg_config_free(mdc);
				rz_iterator_free(it);
				return false;
			}

			if (!is_all) {
				rz_iterator_free(it);
				return true;
			}
		}
	}
	rz_iterator_free(it);

	if (is_all) {
		return true;
	}

	RZ_LOG_ERROR("msg digest: '%s' does not exists.\n", name);
	return false;
}

/**
 * \brief Sets the key for the hmac algorithm
 *
 * message digest sets the hmac key
 * */
RZ_API bool rz_hash_cfg_hmac(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const ut8 *key, ut64 key_size) {
	rz_return_val_if_fail(md && key && key_size && hash_cfg_can_hmac(md), false);

	RzHashSize block_size = 0;
	RzListIter *iter = NULL;
	HashCfgConfig *mdc = NULL;
	rz_list_foreach (md->configurations, iter, mdc) {
		if (!mdc->plugin->support_hmac) {
			// RZ_LOG_ERROR("msg digest: hmac is not supported by %s.\n", mdc->plugin->name);
			continue;
		}

		block_size = mdc->plugin->block_size(mdc->context);
		if (block_size < 1) {
			RZ_LOG_ERROR("msg digest: hmac block size is < 1.\n");
			return false;
		}

		mdc->hmac_key = malloc(block_size);
		if (!mdc->hmac_key) {
			RZ_LOG_ERROR("msg digest: cannot allocate memory for hmac key.\n");
			return false;
		}

		memset(mdc->hmac_key, 0, block_size);
		if (block_size < key_size) {
			RzHashSize tmp_size;
			ut8 *tmp = NULL;
			if (!mdc->plugin->small_block(key, key_size, &tmp, &tmp_size)) {
				RZ_LOG_ERROR("msg digest: failed to call init for hmac %s key.\n", mdc->plugin->name);
				return false;
			}
			memcpy(mdc->hmac_key, tmp, tmp_size);
			free(tmp);
		} else {
			memcpy(mdc->hmac_key, key, key_size);
		}
	}

	return true;
}

/**
 * \brief Resets/initialize the message digest contextes
 *
 * RzHashCfg contains a list of configurations; this method will call
 * the init method of all the plugins stored in its list.
 * */
RZ_API bool rz_hash_cfg_init(RZ_NONNULL RzHashCfg *md) {
	rz_return_val_if_fail(md && hash_cfg_can_init(md), false);

	RzListIter *iter = NULL;
	HashCfgConfig *mdc = NULL;
	rz_list_foreach (md->configurations, iter, mdc) {
		if (!mdc->plugin->init(mdc->context)) {
			RZ_LOG_ERROR("msg digest: failed to call init for %s.\n", mdc->plugin->name);
			return false;
		}
		if (mdc->hmac_key) {
			RzHashSize block_size = mdc->plugin->block_size(mdc->context);
			ut8 *i_pad = malloc(block_size);
			if (!i_pad) {
				RZ_LOG_ERROR("msg digest: failed to allocate memory for ipad.\n");
				return false;
			}
			for (ut32 i = 0; i < block_size; i++) {
				i_pad[i] = 0x36 ^ mdc->hmac_key[i];
			}
			if (!mdc->plugin->update(mdc->context, i_pad, block_size)) {
				RZ_LOG_ERROR("msg digest: failed to call update for hmac %s ipad.\n", mdc->plugin->name);
				free(i_pad);
				return false;
			}
			free(i_pad);
		}
	}

	md->status = RZ_MSG_DIGEST_STATUS_INIT;
	return true;
}

/**
 * \brief Inserts data into each the message digest contextes
 *
 * RzHashCfg contains a list of configurations; this method will call
 * the update method of all the plugins stored in its list.
 * */
RZ_API bool rz_hash_cfg_update(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const ut8 *data, ut64 size) {
	rz_return_val_if_fail(md && hash_cfg_can_update(md), false);

	RzListIter *iter = NULL;
	HashCfgConfig *mdc = NULL;
	rz_list_foreach (md->configurations, iter, mdc) {
		if (!mdc->plugin->update(mdc->context, data, size)) {
			RZ_LOG_ERROR("msg digest: failed to call update for %s.\n", mdc->plugin->name);
			return false;
		}
	}

	md->status = RZ_MSG_DIGEST_STATUS_UPDATE;
	return true;
}

/**
 * \brief Generates the final value of the message digest contextes
 *
 * RzHashCfg contains a list of configurations; this method will call
 * the final method of all the plugins stored in its list.
 * */
RZ_API bool rz_hash_cfg_final(RZ_NONNULL RzHashCfg *md) {
	rz_return_val_if_fail(md && hash_cfg_can_final(md), false);

	RzListIter *iter = NULL;
	HashCfgConfig *mdc = NULL;
	rz_list_foreach (md->configurations, iter, mdc) {
		if (!mdc->plugin->final(mdc->context, mdc->digest)) {
			RZ_LOG_ERROR("msg digest: failed to call final for %s.\n", mdc->plugin->name);
			return false;
		}

		if (mdc->hmac_key) {
			RzHashSize block_size = mdc->plugin->block_size(mdc->context);
			ut8 *o_pad = malloc(block_size);
			if (!o_pad) {
				RZ_LOG_ERROR("msg digest: failed to allocate memory for opad.\n");
				return false;
			}

			for (ut32 i = 0; i < block_size; i++) {
				o_pad[i] = 0x5c ^ mdc->hmac_key[i];
			}

			if (!mdc->plugin->init(mdc->context)) {
				RZ_LOG_ERROR("msg digest: failed to call init for hmac %s opad.\n", mdc->plugin->name);
				free(o_pad);
				return false;
			}
			if (!mdc->plugin->update(mdc->context, o_pad, block_size)) {
				RZ_LOG_ERROR("msg digest: failed to call update for hmac %s opad.\n", mdc->plugin->name);
				free(o_pad);
				return false;
			}
			free(o_pad);
			if (!mdc->plugin->update(mdc->context, mdc->digest, mdc->digest_size)) {
				RZ_LOG_ERROR("msg digest: failed to call update for hmac %s opad.\n", mdc->plugin->name);
				return false;
			}
			if (!mdc->plugin->final(mdc->context, mdc->digest)) {
				RZ_LOG_ERROR("msg digest: failed to call final for hmac %s opad.\n", mdc->plugin->name);
				return false;
			}
		}
	}

	md->status = RZ_MSG_DIGEST_STATUS_FINAL;
	return true;
}

/**
 * \brief Calculate the final hash by iterating its result N times.
 *
 * RzHashCfg contains a list of configurations; this method will iterate N times
 * each configuration final result.
 * */
RZ_API bool rz_hash_cfg_iterate(RZ_NONNULL RzHashCfg *md, size_t iterate) {
	rz_return_val_if_fail(md && hash_cfg_has_finshed(md), false);

	RzListIter *iter = NULL;
	HashCfgConfig *mdc = NULL;
	rz_list_foreach (md->configurations, iter, mdc) {
		for (size_t i = 0; i < iterate; ++i) {
			if (!mdc->plugin->init(mdc->context)) {
				RZ_LOG_ERROR("msg digest: failed to call init %s for iteration.\n", mdc->plugin->name);
				return false;
			}
			if (!mdc->plugin->update(mdc->context, mdc->digest, mdc->digest_size)) {
				RZ_LOG_ERROR("msg digest: failed to call update %s for iteration.\n", mdc->plugin->name);
				return false;
			}
			if (!mdc->plugin->final(mdc->context, mdc->digest)) {
				RZ_LOG_ERROR("msg digest: failed to call final %s for iteration.\n", mdc->plugin->name);
				return false;
			}
		}
	}

	return true;
}

/**
 * \brief Returns the digest value of the requested algorithm name
 *
 * RzHashCfg contains a list of configurations; this method will search
 * for the configuration with the given name and if found return the digest value.
 * */
RZ_API RZ_BORROW const ut8 *rz_hash_cfg_get_result(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const char *name, RZ_NONNULL ut32 *size) {
	rz_return_val_if_fail(md && name && hash_cfg_has_finshed(md), false);

	RzListIter *it = rz_list_find(md->configurations, name, hash_cfg_config_compare, NULL);
	if (!it) {
		RZ_LOG_ERROR("msg digest: cannot find configuration for '%s' algorithm.\n", name);
		return NULL;
	}

	HashCfgConfig *mdc = (HashCfgConfig *)rz_list_iter_get_data(it);
	rz_return_val_if_fail(mdc, NULL);

	if (size) {
		*size = mdc->digest_size;
	}
	return mdc->digest;
}

/**
 * \brief Returns the digest value of the requested algorithm name
 *
 * RzHashCfg contains a list of configurations; this method will search
 * for the configuration with the given name and if found return the digest value.
 * */
RZ_API RZ_OWN char *rz_hash_cfg_get_result_string(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const char *name, RZ_NULLABLE ut32 *size, bool invert) {
	rz_return_val_if_fail(md && name && hash_cfg_has_finshed(md), false);

	ut32 pos = 0;
	RzListIter *it = rz_list_find(md->configurations, name, hash_cfg_config_compare, NULL);
	if (!it) {
		RZ_LOG_ERROR("msg digest: cannot find configuration for '%s' algorithm.\n", name);
		return NULL;
	}

	HashCfgConfig *mdc = (HashCfgConfig *)rz_list_iter_get_data(it);
	rz_return_val_if_fail(mdc, NULL);

	if (!strncmp(name, "entropy", strlen("entropy"))) {
		double entropy = rz_read_be_double(mdc->digest);
		return rz_str_newf("%.8f", entropy);
	} else if (!strcmp(name, "ssdeep")) {
		return rz_str_dup((char *)mdc->digest);
	}

	char *string = malloc((mdc->digest_size * 2) + 1);
	if (!string) {
		RZ_LOG_ERROR("msg digest: cannot find allocate memory for string result.\n");
		return NULL;
	}

	for (ut32 i = 0; i < mdc->digest_size; i++) {
		pos = invert ? (mdc->digest_size - 1 - i) : i;
		sprintf(&string[i * 2], "%02x", mdc->digest[pos]);
	}
	string[mdc->digest_size * 2] = 0;

	if (size) {
		*size = (mdc->digest_size * 2) + 1;
	}
	return string;
}

/**
 * \brief Returns the digest size of the requested algorithm name
 *
 * Returns the digest size of the initialized configuration.
 * */
RZ_API RzHashSize rz_hash_cfg_size(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(md && name, 0);

	RzListIter *it = rz_list_find(md->configurations, name, hash_cfg_config_compare, NULL);
	if (!it) {
		RZ_LOG_ERROR("msg digest: cannot find configuration for '%s' algorithm.\n", name);
		return 0;
	}

	HashCfgConfig *mdc = (HashCfgConfig *)rz_list_iter_get_data(it);
	rz_return_val_if_fail(mdc, 0);
	return mdc->plugin->digest_size(mdc->context);
}

/**
 * \brief Returns the digest size of the requested algorithm name
 *
 * Returns the digest size of the initialized configuration.
 * */
RZ_API RZ_OWN ut8 *rz_hash_cfg_calculate_small_block(RZ_NONNULL RzHash *rh, RZ_NONNULL const char *name, RZ_NONNULL const ut8 *buffer, ut64 bsize, RZ_NONNULL RzHashSize *osize) {
	rz_return_val_if_fail(rh && name && buffer, NULL);

	ut8 *result = NULL;
	const RzHashPlugin *plugin = rz_hash_plugin_by_name(rh, name);
	if (!plugin) {
		return NULL;
	}

	if (!plugin->small_block(buffer, bsize, &result, osize)) {
		RZ_LOG_ERROR("msg digest: cannot calculate small block with %s.\n", plugin->name);
		return NULL;
	}
	return result;
}

RZ_API RZ_OWN char *rz_hash_cfg_calculate_small_block_string(RZ_NONNULL RzHash *rh, RZ_NONNULL const char *name, RZ_NONNULL const ut8 *buffer, ut64 bsize, RZ_NULLABLE ut32 *size, bool invert) {
	rz_return_val_if_fail(rh && name && buffer, NULL);

	ut32 pos = 0;
	RzHashSize digest_size = 0;
	ut8 *digest = NULL;
	if (!(digest = rz_hash_cfg_calculate_small_block(rh, name, buffer, bsize, &digest_size))) {
		return NULL;
	}

	if (!strncmp(name, "entropy", strlen("entropy"))) {
		double entropy = rz_read_be_double(digest);
		free(digest);
		return rz_str_newf("%.8f", entropy);
	} else if (!strcmp(name, "ssdeep")) {
		return (char *)digest;
	}

	char *string = malloc((digest_size * 2) + 1);
	if (!string) {
		RZ_LOG_ERROR("msg digest: cannot find allocate memory for string result.\n");
		free(digest);
		return NULL;
	}

	for (ut32 i = 0; i < digest_size; i++) {
		pos = invert ? (digest_size - 1 - i) : i;
		sprintf(&string[i * 2], "%02x", digest[pos]);
	}
	string[digest_size * 2] = 0;

	if (size) {
		*size = (digest_size * 2) + 1;
	}
	free(digest);
	return string;
}

/**
 * Create a new RzHash object where plugins can be registered and specific
 * configurations can be created from.
 */
RZ_API RzHash *rz_hash_new(void) {
	RzHash *rh = RZ_NEW0(RzHash);
	if (!rh) {
		return NULL;
	}
#if REQUIRE_OPENSSL_PROVIDER
	rz_hash_init_openssl_lib();
#endif /* REQUIRE_OPENSSL_PROVIDER */
	rh->plugins = ht_sp_new(HT_STR_DUP, NULL, NULL);
	for (int i = 0; i < RZ_ARRAY_SIZE(hash_static_plugins); i++) {
		rz_hash_plugin_add(rh, hash_static_plugins[i]);
	}
	return rh;
}

RZ_API void rz_hash_free(RZ_NULLABLE RzHash *rh) {
	if (!rh) {
		return;
	}
	ht_sp_free(rh->plugins);
	free(rh);
#if REQUIRE_OPENSSL_PROVIDER
	rz_hash_fini_openssl_lib();
#endif /* REQUIRE_OPENSSL_PROVIDER */
}

/**
 * \brief Add a new plugin to \p rh so that \p RzHashCfg can be created using
 * specific algorithms.
 */
RZ_API bool rz_hash_plugin_add(RZ_NONNULL RzHash *rh, RZ_NONNULL RZ_OWN RzHashPlugin *plugin) {
	rz_return_val_if_fail(rh && plugin && plugin->name, false);
	ht_sp_insert(rh->plugins, plugin->name, plugin);
	return true;
}

RZ_API bool rz_hash_plugin_del(RZ_NONNULL RzHash *rh, RZ_NONNULL RzHashPlugin *plugin) {
	rz_return_val_if_fail(rh && plugin, false);
	return ht_sp_delete(rh->plugins, plugin->name);
}
