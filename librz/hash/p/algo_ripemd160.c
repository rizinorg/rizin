// SPDX-FileCopyrightText: 2026 The Rizin Contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_hash_cfg(ripemd160, EVP_ripemd160, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/ripemd160/ripemd160.h"

static void *plugin_ripemd160_context_new() {
	return RZ_NEW0(RzHashRIPEMD160);
}

static void plugin_ripemd160_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_ripemd160_digest_size(void *context) {
	return RZ_HASH_RIPEMD160_DIGEST_SIZE;
}

static RzHashSize plugin_ripemd160_block_size(void *context) {
	return RZ_HASH_RIPEMD160_BLOCK_LENGTH;
}

static bool plugin_ripemd160_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_hash_ripemd160_init((RzHashRIPEMD160 *)context);
	return true;
}

static bool plugin_ripemd160_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	return rz_hash_ripemd160_update((RzHashRIPEMD160 *)context, data, size);
}

static bool plugin_ripemd160_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_hash_ripemd160_final(digest, (RzHashRIPEMD160 *)context);
	return true;
}

static bool plugin_ripemd160_small_block(const ut8 *data, ut64 size, ut8 **digest,
		RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_RIPEMD160_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzHashRIPEMD160 ctx;
	rz_hash_ripemd160_init(&ctx);
	rz_hash_ripemd160_update(&ctx, data, size);
	rz_hash_ripemd160_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_RIPEMD160_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_ripemd160 = {
	.name = "ripemd160",
	.license = "LGPL3",
	.author = "Rizin Contributors",
	.description = "RIPEMD-160 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_ripemd160_context_new,
	.context_free = plugin_ripemd160_context_free,
	.digest_size = plugin_ripemd160_digest_size,
	.block_size = plugin_ripemd160_block_size,
	.init = plugin_ripemd160_init,
	.update = plugin_ripemd160_update,
	.final = plugin_ripemd160_final,
	.small_block = plugin_ripemd160_small_block,
};

#endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_ripemd160,
	.version = RZ_VERSION
};
#endif
