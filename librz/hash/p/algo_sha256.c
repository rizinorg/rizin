// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_hash_cfg(sha256, EVP_sha256, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/sha2/sha2.h"

static void *plugin_sha256_context_new() {
	return RZ_NEW0(RZ_SHA256_CTX);
}

static void plugin_sha256_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_sha256_digest_size(void *context) {
	return SHA256_DIGEST_LENGTH;
}

static RzHashSize plugin_sha256_block_size(void *context) {
	return SHA256_BLOCK_LENGTH;
}

static bool plugin_sha256_init(void *context) {
	rz_return_val_if_fail(context, false);

	SHA256_Init((RZ_SHA256_CTX *)context);
	return true;
}

static bool plugin_sha256_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	SHA256_Update((RZ_SHA256_CTX *)context, data, size);
	return true;
}

static bool plugin_sha256_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	SHA256_Final(digest, (RZ_SHA256_CTX *)context);
	return true;
}

static bool plugin_sha256_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(SHA256_DIGEST_LENGTH);
	if (!dgst) {
		return false;
	}

	RZ_SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data, size);
	SHA256_Final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = SHA256_DIGEST_LENGTH;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_sha256 = {
	.name = "sha256",
	.author = "Aaron D. Gifford",
	.license = "BSD-3",
	.description = "SHA-256 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_sha256_context_new,
	.context_free = plugin_sha256_context_free,
	.digest_size = plugin_sha256_digest_size,
	.block_size = plugin_sha256_block_size,
	.init = plugin_sha256_init,
	.update = plugin_sha256_update,
	.final = plugin_sha256_final,
	.small_block = plugin_sha256_small_block,
};

#endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_sha256,
	.version = RZ_VERSION
};
#endif
