// SPDX-FileCopyrightText: 2021 Ashish <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

// OpenSSL does not have keccak
// #if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

// #include "../algorithms/openssl_common.h"
// rz_openssl_plugin_define_hash_cfg(sha512, EVP_sha3_512, true);

// #else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/sha3/sha3.h"

#define keccak_512_BLOCK_LENGTH  72
#define keccak_512_DIGEST_LENGTH 64

static void *plugin_keccak_512_context_new() {

	return RZ_NEW0(sha3_context);
}

static void plugin_keccak_512_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_keccak_512_digest_size(void *context) {
	return keccak_512_DIGEST_LENGTH;
}

static RzHashSize plugin_keccak_512_block_size(void *context) {
	return keccak_512_BLOCK_LENGTH;
}

static bool plugin_keccak_512_init(void *context) {
	rz_return_val_if_fail(context, false);
	sha3_Init512((sha3_context *)context);
	sha3_SetFlags(context, SHA3_FLAGS_KECCAK);
	return true;
}

static bool plugin_keccak_512_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context, false);
	sha3_Update((sha3_context *)context, data, (size_t)size);
	return true;
}

static bool plugin_keccak_512_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	const void *hash_ptr = sha3_Finalize((sha3_context *)context);
	if (!hash_ptr) {
		return false;
	}

	memcpy(digest, hash_ptr, keccak_512_DIGEST_LENGTH);
	return true;
}

static bool plugin_keccak_512_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(keccak_512_DIGEST_LENGTH);
	if (!dgst) {
		return false;
	}

	sha3_context ctx;
	sha3_Init512(&ctx);
	sha3_SetFlags(&ctx, SHA3_FLAGS_KECCAK);
	sha3_Update(&ctx, data, size);
	const void *hash_ptr = sha3_Finalize(&ctx);
	if (hash_ptr) {
		memcpy(dgst, hash_ptr, keccak_512_DIGEST_LENGTH);
	} else {
		free(dgst);
		return false;
	}
	*digest = dgst;
	if (digest_size) {
		*digest_size = keccak_512_DIGEST_LENGTH;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_keccak_512 = {
	.name = "keccak-512",
	.author = "Andrey Jivsov",
	.license = "BSD-3",
	.description = "KECCAK-512 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_keccak_512_context_new,
	.context_free = plugin_keccak_512_context_free,
	.digest_size = plugin_keccak_512_digest_size,
	.block_size = plugin_keccak_512_block_size,
	.init = plugin_keccak_512_init,
	.update = plugin_keccak_512_update,
	.final = plugin_keccak_512_final,
	.small_block = plugin_keccak_512_small_block,
};

// #endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_keccak_512,
	.version = RZ_VERSION
};
#endif
