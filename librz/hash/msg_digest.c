// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_msg_digest.h>
#include <rz_util.h>
#include <xxhash.h>

RZ_LIB_VERSION(rz_msg_digest);

#define msg_digest_can_hmac(c)    ((c)->status == RZ_MSG_DIGEST_STATUS_ALLOC)
#define msg_digest_can_init(c)    ((c)->status == RZ_MSG_DIGEST_STATUS_FINAL || (c)->status == RZ_MSG_DIGEST_STATUS_ALLOC)
#define msg_digest_can_update(c)  ((c)->status == RZ_MSG_DIGEST_STATUS_INIT || (c)->status == RZ_MSG_DIGEST_STATUS_UPDATE)
#define msg_digest_can_final(c)   ((c)->status == RZ_MSG_DIGEST_STATUS_ALLOC || (c)->status == RZ_MSG_DIGEST_STATUS_INIT || (c)->status == RZ_MSG_DIGEST_STATUS_UPDATE)
#define msg_digest_has_finshed(c) ((c)->status == RZ_MSG_DIGEST_STATUS_FINAL)

typedef struct msg_digest_config_t {
	void *context;
	ut8 *digest;
	ut8 *hmac_key;
	RzMsgDigestSize digest_size;
	const RzMsgDigestPlugin *plugin;
} MsgDigestConfig;

const static RzMsgDigestPlugin *msg_digest_plugins[] = {
	&rz_msg_digest_plugin_md4,
	&rz_msg_digest_plugin_md5,
	&rz_msg_digest_plugin_sha1,
	&rz_msg_digest_plugin_sha256,
	&rz_msg_digest_plugin_sha384,
	&rz_msg_digest_plugin_sha512,
	&rz_msg_digest_plugin_fletcher8,
	&rz_msg_digest_plugin_fletcher16,
	&rz_msg_digest_plugin_fletcher32,
	&rz_msg_digest_plugin_fletcher64,
	&rz_msg_digest_plugin_adler32,
	&rz_msg_digest_plugin_crca_crc8smbus,
	&rz_msg_digest_plugin_crca_crc8cdma2000,
	&rz_msg_digest_plugin_crca_crc8darc,
	&rz_msg_digest_plugin_crca_crc8dvbs2,
	&rz_msg_digest_plugin_crca_crc8ebu,
	&rz_msg_digest_plugin_crca_crc8icode,
	&rz_msg_digest_plugin_crca_crc8itu,
	&rz_msg_digest_plugin_crca_crc8maxim,
	&rz_msg_digest_plugin_crca_crc8rohc,
	&rz_msg_digest_plugin_crca_crc8wcdma,
	&rz_msg_digest_plugin_crca_crc15can,
	&rz_msg_digest_plugin_crca_crc16,
	&rz_msg_digest_plugin_crca_crc16citt,
	&rz_msg_digest_plugin_crca_crc16usb,
	&rz_msg_digest_plugin_crca_crc16hdlc,
	&rz_msg_digest_plugin_crca_crc16augccitt,
	&rz_msg_digest_plugin_crca_crc16buypass,
	&rz_msg_digest_plugin_crca_crc16cdma2000,
	&rz_msg_digest_plugin_crca_crc16dds110,
	&rz_msg_digest_plugin_crca_crc16dectr,
	&rz_msg_digest_plugin_crca_crc16dectx,
	&rz_msg_digest_plugin_crca_crc16dnp,
	&rz_msg_digest_plugin_crca_crc16en13757,
	&rz_msg_digest_plugin_crca_crc16genibus,
	&rz_msg_digest_plugin_crca_crc16maxim,
	&rz_msg_digest_plugin_crca_crc16mcrf4xx,
	&rz_msg_digest_plugin_crca_crc16riello,
	&rz_msg_digest_plugin_crca_crc16t10dif,
	&rz_msg_digest_plugin_crca_crc16teledisk,
	&rz_msg_digest_plugin_crca_crc16tms37157,
	&rz_msg_digest_plugin_crca_crca,
	&rz_msg_digest_plugin_crca_crc16kermit,
	&rz_msg_digest_plugin_crca_crc16modbus,
	&rz_msg_digest_plugin_crca_crc16x25,
	&rz_msg_digest_plugin_crca_crc16xmodem,
	&rz_msg_digest_plugin_crca_crc24,
	&rz_msg_digest_plugin_crca_crc32,
	&rz_msg_digest_plugin_crca_crc32ecma267,
	&rz_msg_digest_plugin_crca_crc32c,
	&rz_msg_digest_plugin_crca_crc32bzip2,
	&rz_msg_digest_plugin_crca_crc32d,
	&rz_msg_digest_plugin_crca_crc32mpeg2,
	&rz_msg_digest_plugin_crca_crc32posix,
	&rz_msg_digest_plugin_crca_crc32q,
	&rz_msg_digest_plugin_crca_crc32jamcrc,
	&rz_msg_digest_plugin_crca_crc32xfer,
	&rz_msg_digest_plugin_crca_crc64,
	&rz_msg_digest_plugin_crca_crc64ecma182,
	&rz_msg_digest_plugin_crca_crc64we,
	&rz_msg_digest_plugin_crca_crc64xz,
	&rz_msg_digest_plugin_crca_crc64iso,
	&rz_msg_digest_plugin_xor8,
	&rz_msg_digest_plugin_xor16,
	&rz_msg_digest_plugin_xxhash32,
	&rz_msg_digest_plugin_parity,
	&rz_msg_digest_plugin_entropy,
	&rz_msg_digest_plugin_entropy_fract,
};

RZ_API ut32 rz_hash_xxhash(const ut8 *input, size_t size) {
	return XXH32(input, size, 0);
}

RZ_API double rz_hash_entropy(const ut8 *data, ut64 len) {
	const RzMsgDigestPlugin *plugin = &rz_msg_digest_plugin_entropy;
	ut8 *digest = NULL;
	if (!plugin->small_block(data, len, &digest, NULL)) {
		RZ_LOG_ERROR("msg digest: cannot calculate entropy\n");
		return 0.0;
	}
	double e = rz_read_be_double(digest);
	free(digest);
	return e;
}

RZ_API double rz_hash_entropy_fraction(const ut8 *data, ut64 len) {
	const RzMsgDigestPlugin *plugin = &rz_msg_digest_plugin_entropy_fract;
	ut8 *digest = NULL;
	if (!plugin->small_block(data, len, &digest, NULL)) {
		RZ_LOG_ERROR("msg digest: cannot calculate entropy fraction\n");
		return 0.0;
	}
	double e = rz_read_be_double(digest);
	free(digest);
	return e;
}

static int msg_digest_config_compare(const void *value, const void *data) {
	const MsgDigestConfig *mdc = (const MsgDigestConfig *)data;
	const char *name = (const char *)value;
	return strcmp(name, mdc->plugin->name);
}

static void msg_digest_config_free(MsgDigestConfig *mdc) {
	rz_return_if_fail(mdc && mdc->plugin);

	mdc->plugin->context_free(mdc->context);
	free(mdc->hmac_key);
	free(mdc->digest);
	free(mdc);
}

static MsgDigestConfig *msg_digest_config_new(const RzMsgDigestPlugin *plugin) {
	rz_return_val_if_fail(plugin, NULL);

	MsgDigestConfig *mdc = RZ_NEW0(MsgDigestConfig);
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

RZ_API const RzMsgDigestPlugin *rz_msg_digest_plugin_by_index(size_t index) {
	const size_t size = RZ_ARRAY_SIZE(msg_digest_plugins);
	if (index >= size) {
		return NULL;
	}
	return msg_digest_plugins[index];
}

RZ_API const RzMsgDigestPlugin *rz_msg_digest_plugin_by_name(const char *name) {
	rz_return_val_if_fail(name, NULL);

	const RzMsgDigestPlugin *plugin = NULL;
	for (ut32 i = 0; i < RZ_ARRAY_SIZE(msg_digest_plugins); ++i) {
		plugin = msg_digest_plugins[i];
		if (!strcmp(plugin->name, name)) {
			return plugin;
		}
	}
	return NULL;
}

RZ_API RzMsgDigest *rz_msg_digest_new() {
	RzMsgDigest *md = RZ_NEW0(RzMsgDigest);
	if (!md) {
		RZ_LOG_ERROR("msg digest: cannot allocate memory.\n");
		return NULL;
	}

	md->configurations = rz_list_newf((RzListFree)msg_digest_config_free);
	if (!md->configurations) {
		RZ_LOG_ERROR("msg digest: cannot allocate memory for the configurations.\n");
		free(md);
		return NULL;
	}

	return md;
}

/**
 * \brief Returns a message digest context with the give algo already configured
 *
 * message digest allocates and configures already the structure
 * with the given algorithm and runs also the algo init.
 * when fails to allocate or configure or initialize, returns NULL.
 * */
RZ_API RzMsgDigest *rz_msg_digest_new_with_algo(const char *name, const ut8 *key, ut64 key_size) {
	rz_return_val_if_fail(name, NULL);
	RzMsgDigest *md = rz_msg_digest_new();
	if (!md) {
		return NULL;
	}

	if (!rz_msg_digest_configure(md, name)) {
		rz_msg_digest_free(md);
		return NULL;
	}

	if (key && !rz_msg_digest_hmac(md, key, key_size)) {
		rz_msg_digest_free(md);
		return NULL;
	}

	if (!rz_msg_digest_init(md)) {
		rz_msg_digest_free(md);
		return NULL;
	}

	return md;
}

RZ_API void rz_msg_digest_free(RzMsgDigest *md) {
	rz_return_if_fail(md);

	rz_list_free(md->configurations);
	free(md);
}

/**
 * \brief Allocates and configures the plugin message digest context
 *
 * message digest allocates internally a MsgDigestConfig which
 * contains all the needed informations to the plugin to work.
 * */
RZ_API bool rz_msg_digest_configure(RzMsgDigest *md, const char *name) {
	rz_return_val_if_fail(md && name, false);

	if (rz_list_find(md->configurations, name, msg_digest_config_compare)) {
		RZ_LOG_WARN("msg digest: '%s' was already configured; skipping.\n", name);
		return false;
	}

	bool is_all = !strcmp(name, "all");

	MsgDigestConfig *mdc = NULL;
	const RzMsgDigestPlugin *plugin = NULL;

	for (ut32 i = 0; i < RZ_ARRAY_SIZE(msg_digest_plugins); ++i) {
		plugin = msg_digest_plugins[i];
		if (is_all || !strcmp(plugin->name, name)) {
			mdc = msg_digest_config_new(plugin);
			if (!mdc) {
				return false;
			}

			if (!rz_list_append(md->configurations, mdc)) {
				RZ_LOG_ERROR("msg digest: cannot allocate memory for list entry.\n");
				msg_digest_config_free(mdc);
				return false;
			}

			return true;
		}
	}

	RZ_LOG_ERROR("msg digest: '%s' does not exists.\n", name);
	return false;
}

/**
 * \brief Sets the key for the hmac algorithm
 *
 * message digest sets the hmac key
 * */
RZ_API bool rz_msg_digest_hmac(RzMsgDigest *md, const ut8 *key, ut64 key_size) {
	rz_return_val_if_fail(md && key && key_size && msg_digest_can_hmac(md), false);

	RzMsgDigestSize block_size = 0;
	RzListIter *iter = NULL;
	MsgDigestConfig *mdc = NULL;
	rz_list_foreach (md->configurations, iter, mdc) {
		if (!mdc->plugin->support_hmac) {
			//RZ_LOG_ERROR("msg digest: hmac is not supported by %s.\n", mdc->plugin->name);
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
			if (!mdc->plugin->init(mdc->context)) {
				RZ_LOG_ERROR("msg digest: failed to call init for hmac %s key.\n", mdc->plugin->name);
				return false;
			}
			if (!mdc->plugin->update(mdc->context, key, key_size)) {
				RZ_LOG_ERROR("msg digest: failed to call update for hmac %s key.\n", mdc->plugin->name);
				return false;
			}
			if (!mdc->plugin->final(mdc->context, mdc->hmac_key)) {
				RZ_LOG_ERROR("msg digest: failed to call final for hmac %s key.\n", mdc->plugin->name);
				return false;
			}
		} else {
			memcpy(mdc->hmac_key, key, key_size);
		}
	}

	return true;
}

/**
 * \brief Resets/initialize the message digest contextes
 *
 * RzMsgDigest contains a list of configurations; this method will call
 * the init method of all the plugins stored in its list.
 * */
RZ_API bool rz_msg_digest_init(RzMsgDigest *md) {
	rz_return_val_if_fail(md && msg_digest_can_init(md), false);

	RzListIter *iter = NULL;
	MsgDigestConfig *mdc = NULL;
	rz_list_foreach (md->configurations, iter, mdc) {
		if (!mdc->plugin->init(mdc->context)) {
			RZ_LOG_ERROR("msg digest: failed to call init for %s.\n", mdc->plugin->name);
			return false;
		}
		if (mdc->hmac_key) {
			RzMsgDigestSize block_size = mdc->plugin->block_size(mdc->context);
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
 * RzMsgDigest contains a list of configurations; this method will call
 * the update method of all the plugins stored in its list.
 * */
RZ_API bool rz_msg_digest_update(RzMsgDigest *md, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(md && msg_digest_can_update(md), false);

	RzListIter *iter = NULL;
	MsgDigestConfig *mdc = NULL;
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
 * RzMsgDigest contains a list of configurations; this method will call
 * the final method of all the plugins stored in its list.
 * */
RZ_API bool rz_msg_digest_final(RzMsgDigest *md) {
	rz_return_val_if_fail(md && msg_digest_can_final(md), false);

	RzListIter *iter = NULL;
	MsgDigestConfig *mdc = NULL;
	rz_list_foreach (md->configurations, iter, mdc) {
		if (!mdc->plugin->final(mdc->context, mdc->digest)) {
			RZ_LOG_ERROR("msg digest: failed to call final for %s.\n", mdc->plugin->name);
			return false;
		}

		if (mdc->hmac_key) {
			RzMsgDigestSize block_size = mdc->plugin->block_size(mdc->context);
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
 * RzMsgDigest contains a list of configurations; this method will iterate N times
 * each configuration final result.
 * */
RZ_API bool rz_msg_digest_iterate(RzMsgDigest *md, size_t iterate) {
	rz_return_val_if_fail(md && msg_digest_has_finshed(md), false);

	RzListIter *iter = NULL;
	MsgDigestConfig *mdc = NULL;
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
 * RzMsgDigest contains a list of configurations; this method will search
 * for the configuration with the given name and if found return the digest value.
 * */
RZ_API const ut8 *rz_msg_digest_get_result(RzMsgDigest *md, const char *name, ut32 *size) {
	rz_return_val_if_fail(md && name && msg_digest_has_finshed(md), false);

	RzListIter *it = rz_list_find(md->configurations, name, msg_digest_config_compare);
	if (!it) {
		RZ_LOG_ERROR("msg digest: cannot find configuration for '%s' algorithm.\n", name);
		return NULL;
	}

	MsgDigestConfig *mdc = (MsgDigestConfig *)rz_list_iter_get_data(it);
	rz_return_val_if_fail(mdc, NULL);

	if (size) {
		*size = mdc->digest_size;
	}
	return mdc->digest;
}

/**
 * \brief Returns the digest value of the requested algorithm name
 *
 * RzMsgDigest contains a list of configurations; this method will search
 * for the configuration with the given name and if found return the digest value.
 * */
RZ_API char *rz_msg_digest_get_result_string(RzMsgDigest *md, const char *name, ut32 *size, bool invert) {
	rz_return_val_if_fail(md && name && msg_digest_has_finshed(md), false);

	ut32 pos = 0;
	RzListIter *it = rz_list_find(md->configurations, name, msg_digest_config_compare);
	if (!it) {
		RZ_LOG_ERROR("msg digest: cannot find configuration for '%s' algorithm.\n", name);
		return NULL;
	}

	MsgDigestConfig *mdc = (MsgDigestConfig *)rz_list_iter_get_data(it);
	rz_return_val_if_fail(mdc, NULL);

	if (!strncmp(name, "entropy", 7)) {
		double entropy = rz_read_be_double(mdc->digest);
		return rz_str_newf("%.8f", entropy);
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
RZ_API RzMsgDigestSize rz_msg_digest_size(RzMsgDigest *md, const char *name) {
	rz_return_val_if_fail(md && name, 0);

	RzListIter *it = rz_list_find(md->configurations, name, msg_digest_config_compare);
	if (!it) {
		RZ_LOG_ERROR("msg digest: cannot find configuration for '%s' algorithm.\n", name);
		return 0;
	}

	MsgDigestConfig *mdc = (MsgDigestConfig *)rz_list_iter_get_data(it);
	rz_return_val_if_fail(mdc, 0);
	return mdc->plugin->digest_size(mdc->context);
}

/**
 * \brief Returns the digest size of the requested algorithm name
 *
 * Returns the digest size of the initialized configuration.
 * */
RZ_API ut8 *rz_msg_digest_calculate_small_block(const char *name, const ut8 *buffer, ut64 bsize, RzMsgDigestSize *osize) {
	rz_return_val_if_fail(name && buffer, NULL);

	ut8 *result = NULL;
	const RzMsgDigestPlugin *plugin = NULL;

	for (ut32 i = 0; i < RZ_ARRAY_SIZE(msg_digest_plugins); ++i) {
		plugin = msg_digest_plugins[i];
		if (!strcmp(plugin->name, name)) {
			if (!plugin->small_block(buffer, bsize, &result, osize)) {
				RZ_LOG_ERROR("msg digest: cannot calculate small block with %s.\n", plugin->name);
				return NULL;
			}
			return result;
		}
	}

	return NULL;
}

RZ_API char *rz_msg_digest_calculate_small_block_string(const char *name, const ut8 *buffer, ut64 bsize, ut32 *size, bool invert) {
	rz_return_val_if_fail(name && buffer, NULL);

	ut32 pos = 0;
	RzMsgDigestSize digest_size;
	ut8 *digest = NULL;
	if (!(digest = rz_msg_digest_calculate_small_block(name, buffer, bsize, &digest_size))) {
		return NULL;
	}

	if (!strncmp(name, "entropy", 7)) {
		double entropy = rz_read_be_double(digest);
		free(digest);
		return rz_str_newf("%.8f", entropy);
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
