#ifndef RZ_OPENSSL_COMMON_H
#define RZ_OPENSSL_COMMON_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/md5.h>

/*
EVP_md2
EVP_md5
EVP_sha
EVP_sha1
EVP_dss
EVP_dss1
EVP_mdc2
EVP_ripemd160
EVP_sha224
EVP_sha256
EVP_sha384
EVP_sha512
*/

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
	static RzMsgDigestSize openssl_plugin_##pluginname##_digest_size(void *context) { \
		return EVP_MD_size(evpmd()); \
	}

#define rz_openssl_plugin_block_size(pluginname, evpmd) \
	static RzMsgDigestSize openssl_plugin_##pluginname##_block_size(void *context) { \
		return EVP_MD_block_size(evpmd()); \
	}

#define rz_openssl_plugin_init(pluginname, evpmd) \
	static bool openssl_plugin_##pluginname##_init(void *context) { \
		rz_return_val_if_fail(context, false); \
		if (EVP_DigestInit_ex((EVP_MD_CTX *)context, evpmd(), NULL) != 1) { \
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
			return false; \
		} \
		return true; \
	}

#define rz_openssl_plugin_final(pluginname) \
	static bool openssl_plugin_##pluginname##_final(void *context, ut8 *digest) { \
		rz_return_val_if_fail((context) && (digest), false); \
		if (EVP_DigestFinal_ex((EVP_MD_CTX *)context, digest, NULL) != 1) { \
			return false; \
		} \
		return true; \
	}

#define rz_openssl_plugin_define_msg_digest(pluginname, evpmd, canhmac) \
	rz_openssl_plugin_context_new(pluginname); \
	rz_openssl_plugin_context_free(pluginname); \
	rz_openssl_plugin_digest_size(pluginname, evpmd); \
	rz_openssl_plugin_block_size(pluginname, evpmd); \
	rz_openssl_plugin_init(pluginname, evpmd); \
	rz_openssl_plugin_update(pluginname); \
	rz_openssl_plugin_final(pluginname); \
	RzMsgDigestPlugin rz_msg_digest_plugin_##pluginname = { \
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
	}

#endif /* RZ_OPENSSL_COMMON_H */
