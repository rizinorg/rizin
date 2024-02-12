// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_OPENSSL_COMMON_H
#define RZ_OPENSSL_COMMON_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/err.h>

#include <rz_util.h>

#define rz_openssl_plugin_context_new(pluginname) \
	static void *openssl_plugin_##pluginname##_context_new() { \
		return EVP_MD_CTX_new(); \
	}

#define rz_openssl_plugin_context_free(pluginname) \
	static void openssl_plugin_##pluginname##_context_free(void *context) { \
		rz_return_if_fail(context); \
		EVP_MD_CTX_free((EVP_MD_CTX *)context); \
	}

#define rz_openssl_plugin_digest_size(pluginname, evpmd) \
	static RzHashSize openssl_plugin_##pluginname##_digest_size(void *context) { \
		return EVP_MD_size(evpmd()); \
	}

#define rz_openssl_plugin_block_size(pluginname, evpmd) \
	static RzHashSize openssl_plugin_##pluginname##_block_size(void *context) { \
		return EVP_MD_block_size(evpmd()); \
	}

#define rz_openssl_plugin_init(pluginname, evpmd) \
	static bool openssl_plugin_##pluginname##_init(void *context) { \
		rz_return_val_if_fail(context, false); \
		if (EVP_DigestInit_ex((EVP_MD_CTX *)context, evpmd(), NULL) != 1) { \
			char emsg[256] = { 0 }; \
			ERR_error_string_n(ERR_get_error(), emsg, sizeof(emsg)); \
			RZ_LOG_ERROR("openssl: %s\n", emsg); \
			ERR_clear_error(); \
			return false; \
		} \
		return true; \
	}

#define rz_openssl_plugin_update(pluginname) \
	static bool openssl_plugin_##pluginname##_update(void *context, const ut8 *data, ut64 size) { \
		rz_return_val_if_fail((context) && (data), false); \
		if (size < 1) { \
			return true; \
		} \
		if (EVP_DigestUpdate((EVP_MD_CTX *)context, data, size) != 1) { \
			char emsg[256] = { 0 }; \
			ERR_error_string_n(ERR_get_error(), emsg, sizeof(emsg)); \
			RZ_LOG_ERROR("openssl: %s\n", emsg); \
			ERR_clear_error(); \
			return false; \
		} \
		return true; \
	}

#define rz_openssl_plugin_final(pluginname) \
	static bool openssl_plugin_##pluginname##_final(void *context, ut8 *digest) { \
		rz_return_val_if_fail((context) && (digest), false); \
		if (EVP_DigestFinal_ex((EVP_MD_CTX *)context, digest, NULL) != 1) { \
			char emsg[256] = { 0 }; \
			ERR_error_string_n(ERR_get_error(), emsg, sizeof(emsg)); \
			RZ_LOG_ERROR("openssl: %s\n", emsg); \
			ERR_clear_error(); \
			return false; \
		} \
		return true; \
	}

#define rz_openssl_plugin_small_block(pluginname, evpmd) \
	static bool openssl_plugin_##pluginname##_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) { \
		rz_return_val_if_fail((data) && (digest), false); \
		const EVP_MD *evp_md = evpmd(); \
		if (!evp_md) { \
			return false; \
		} \
		RzHashSize dgst_size = EVP_MD_size(evp_md); \
		ut8 *dgst = malloc(dgst_size); \
		if (!dgst) { \
			return false; \
		} \
		EVP_MD_CTX *context = EVP_MD_CTX_new(); \
		if (!context) { \
			free(dgst); \
			return false; \
		} \
		if (EVP_DigestInit_ex(context, evp_md, NULL) != 1) { \
			EVP_MD_CTX_free(context); \
			free(dgst); \
			return false; \
		} \
		if (EVP_DigestUpdate(context, data, size) != 1) { \
			EVP_MD_CTX_free(context); \
			free(dgst); \
			return false; \
		} \
		if (EVP_DigestFinal_ex(context, dgst, NULL) != 1) { \
			EVP_MD_CTX_free(context); \
			free(dgst); \
			return false; \
		} \
		*digest = dgst; \
		if (digest_size) { \
			*digest_size = dgst_size; \
		} \
		EVP_MD_CTX_free(context); \
		return true; \
	}

#define rz_openssl_plugin_define_hash_cfg(pluginname, evpmd, canhmac) \
	rz_openssl_plugin_context_new(pluginname); \
	rz_openssl_plugin_context_free(pluginname); \
	rz_openssl_plugin_digest_size(pluginname, evpmd); \
	rz_openssl_plugin_block_size(pluginname, evpmd); \
	rz_openssl_plugin_init(pluginname, evpmd); \
	rz_openssl_plugin_update(pluginname); \
	rz_openssl_plugin_final(pluginname); \
	rz_openssl_plugin_small_block(pluginname, evpmd); \
	RzHashPlugin rz_hash_plugin_##pluginname = { \
		.name = #pluginname, \
		.license = "Apache 2.0", \
		.author = "OpenSSL Team", \
		.support_hmac = canhmac, \
		.context_new = openssl_plugin_##pluginname##_context_new, \
		.context_free = openssl_plugin_##pluginname##_context_free, \
		.digest_size = openssl_plugin_##pluginname##_digest_size, \
		.block_size = openssl_plugin_##pluginname##_block_size, \
		.init = openssl_plugin_##pluginname##_init, \
		.update = openssl_plugin_##pluginname##_update, \
		.final = openssl_plugin_##pluginname##_final, \
		.small_block = openssl_plugin_##pluginname##_small_block, \
	}

#endif /* RZ_OPENSSL_COMMON_H */
