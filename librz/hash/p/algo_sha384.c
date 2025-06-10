// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_hash_cfg(sha384, EVP_sha384, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/sha2/sha2.h"

static void *plugin_sha384_context_new() {
	return RZ_NEW0(RZ_SHA384_CTX);
}

static void plugin_sha384_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_sha384_digest_size(void *context) {
	return SHA384_DIGEST_LENGTH;
}

static RzHashSize plugin_sha384_block_size(void *context) {
	return SHA384_BLOCK_LENGTH;
}

static bool plugin_sha384_init(void *context) {
	rz_return_val_if_fail(context, false);

	SHA384_Init((RZ_SHA384_CTX *)context);
	return true;
}

static bool plugin_sha384_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	SHA384_Update((RZ_SHA384_CTX *)context, data, size);
	return true;
}

static bool plugin_sha384_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	SHA384_Final(digest, (RZ_SHA384_CTX *)context);
	return true;
}

static bool plugin_sha384_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(SHA384_DIGEST_LENGTH);
	if (!dgst) {
		return false;
	}

	RZ_SHA384_CTX ctx;
	SHA384_Init(&ctx);
	SHA384_Update(&ctx, data, size);
	SHA384_Final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = SHA384_DIGEST_LENGTH;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_sha384 = {
	.name = "sha384",
	.author = "Aaron D. Gifford",
	.license = "BSD-3",
	.description = "SHA-384 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_sha384_context_new,
	.context_free = plugin_sha384_context_free,
	.digest_size = plugin_sha384_digest_size,
	.block_size = plugin_sha384_block_size,
	.init = plugin_sha384_init,
	.update = plugin_sha384_update,
	.final = plugin_sha384_final,
	.small_block = plugin_sha384_small_block,
};

#endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_sha384,
	.version = RZ_VERSION
};
#endif
