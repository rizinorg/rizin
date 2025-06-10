// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_hash_cfg(sha512, EVP_sha512, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/sha2/sha2.h"

static void *plugin_sha512_context_new() {
	return RZ_NEW0(RZ_SHA512_CTX);
}

static void plugin_sha512_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_sha512_digest_size(void *context) {
	return SHA512_DIGEST_LENGTH;
}

static RzHashSize plugin_sha512_block_size(void *context) {
	return SHA512_BLOCK_LENGTH;
}

static bool plugin_sha512_init(void *context) {
	rz_return_val_if_fail(context, false);

	SHA512_Init((RZ_SHA512_CTX *)context);
	return true;
}

static bool plugin_sha512_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	SHA512_Update((RZ_SHA512_CTX *)context, data, size);
	return true;
}

static bool plugin_sha512_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	SHA512_Final(digest, (RZ_SHA512_CTX *)context);
	return true;
}

static bool plugin_sha512_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(SHA512_DIGEST_LENGTH);
	if (!dgst) {
		return false;
	}

	RZ_SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, data, size);
	SHA512_Final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = SHA512_DIGEST_LENGTH;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_sha512 = {
	.name = "sha512",
	.author = "Aaron D. Gifford",
	.license = "BSD-3",
	.description = "SHA-512 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_sha512_context_new,
	.context_free = plugin_sha512_context_free,
	.digest_size = plugin_sha512_digest_size,
	.block_size = plugin_sha512_block_size,
	.init = plugin_sha512_init,
	.update = plugin_sha512_update,
	.final = plugin_sha512_final,
	.small_block = plugin_sha512_small_block,
};

#endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_sha512,
	.version = RZ_VERSION
};
#endif
