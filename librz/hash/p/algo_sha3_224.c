// SPDX-FileCopyrightText: 2021 Ashish <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_hash_cfg(sha3_224, EVP_sha3_224, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/sha3/sha3.h"

#define SHA3_224_BLOCK_LENGTH  144
#define SHA3_224_DIGEST_LENGTH 28

static void *plugin_sha3_224_context_new() {
	return RZ_NEW0(sha3_context);
}

static void plugin_sha3_224_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_sha3_224_digest_size(void *context) {
	return SHA3_224_DIGEST_LENGTH;
}

static RzHashSize plugin_sha3_224_block_size(void *context) {
	return SHA3_224_BLOCK_LENGTH;
}

static bool plugin_sha3_224_init(void *context) {
	rz_return_val_if_fail(context, false);
	sha3_Init224((sha3_context *)context);
	return true;
}

static bool plugin_sha3_224_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context, false);
	sha3_Update((sha3_context *)context, data, (size_t)size);
	return true;
}

static bool plugin_sha3_224_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	const void *hash_ptr = sha3_Finalize((sha3_context *)context);
	if (!hash_ptr) {
		return false;
	}

	memcpy(digest, hash_ptr, SHA3_224_DIGEST_LENGTH);
	return true;
}

static bool plugin_sha3_224_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(SHA3_224_DIGEST_LENGTH);
	if (!dgst) {
		return false;
	}

	sha3_context ctx;
	sha3_Init224(&ctx);
	sha3_Update(&ctx, data, size);
	const void *hash_ptr = sha3_Finalize(&ctx);
	if (hash_ptr) {
		memcpy(dgst, hash_ptr, SHA3_224_DIGEST_LENGTH);
	} else {
		free(dgst);
		return false;
	}
	*digest = dgst;
	if (digest_size) {
		*digest_size = SHA3_224_DIGEST_LENGTH;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_sha3_224 = {
	.name = "sha3-224",
	.author = "Andrey Jivsov",
	.license = "BSD-3",
	.description = "SHA3-224 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_sha3_224_context_new,
	.context_free = plugin_sha3_224_context_free,
	.digest_size = plugin_sha3_224_digest_size,
	.block_size = plugin_sha3_224_block_size,
	.init = plugin_sha3_224_init,
	.update = plugin_sha3_224_update,
	.final = plugin_sha3_224_final,
	.small_block = plugin_sha3_224_small_block,
};

#endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_sha3_224,
	.version = RZ_VERSION
};
#endif
