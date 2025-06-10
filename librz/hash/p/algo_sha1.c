// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_hash_cfg(sha1, EVP_sha1, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/sha1/sha1.h"

static void *plugin_sha1_context_new() {
	return RZ_NEW0(RzSHA1);
}

static void plugin_sha1_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_sha1_digest_size(void *context) {
	return RZ_HASH_SHA1_DIGEST_SIZE;
}

static RzHashSize plugin_sha1_block_size(void *context) {
	return RZ_HASH_SHA1_BLOCK_LENGTH;
}

static bool plugin_sha1_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_sha1_init((RzSHA1 *)context);
	return true;
}

static bool plugin_sha1_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_sha1_update((RzSHA1 *)context, data, size);
	return true;
}

static bool plugin_sha1_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_sha1_fini(digest, (RzSHA1 *)context);
	return true;
}

static bool plugin_sha1_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_SHA1_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzSHA1 ctx;
	rz_sha1_init(&ctx);
	rz_sha1_update(&ctx, data, size);
	rz_sha1_fini(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_SHA1_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_sha1 = {
	.name = "sha1",
	.license = "LGPL3",
	.author = "deroad",
	.description = "SHA-1 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_sha1_context_new,
	.context_free = plugin_sha1_context_free,
	.digest_size = plugin_sha1_digest_size,
	.block_size = plugin_sha1_block_size,
	.init = plugin_sha1_init,
	.update = plugin_sha1_update,
	.final = plugin_sha1_final,
	.small_block = plugin_sha1_small_block,
};

#endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_sha1,
	.version = RZ_VERSION
};
#endif
