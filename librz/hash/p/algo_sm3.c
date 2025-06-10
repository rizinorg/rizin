// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_hash_cfg(sm3, EVP_sm3, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/sm3/sm3.h"

static void *plugin_sm3_context_new() {
	return RZ_NEW0(sm3_ctx_t);
}

static void plugin_sm3_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_sm3_digest_size(void *context) {
	return SM3_DIGEST_SIZE;
}

static RzHashSize plugin_sm3_block_size(void *context) {
	return SM3_BLOCK_SIZE;
}

static bool plugin_sm3_init(void *context) {
	rz_return_val_if_fail(context, false);

	sm3_init_ctx((sm3_ctx_t *)context);
	return true;
}

static bool plugin_sm3_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	sm3_process_bytes(data, size, (sm3_ctx_t *)context);
	return true;
}

static bool plugin_sm3_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	sm3_finish_ctx((sm3_ctx_t *)context, digest);
	return true;
}

static bool plugin_sm3_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(SM3_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	sm3_ctx_t ctx;
	sm3_init_ctx(&ctx);
	sm3_process_bytes(data, size, &ctx);
	sm3_finish_ctx(&ctx, dgst);

	*digest = dgst;
	if (digest_size) {
		*digest_size = SM3_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_sm3 = {
	.name = "sm3",
	.license = "LGPL2",
	.author = "FSF/deroad",
	.description = "ShangMi 3 (SM3) cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_sm3_context_new,
	.context_free = plugin_sm3_context_free,
	.digest_size = plugin_sm3_digest_size,
	.block_size = plugin_sm3_block_size,
	.init = plugin_sm3_init,
	.update = plugin_sm3_update,
	.final = plugin_sm3_final,
	.small_block = plugin_sm3_small_block,
};

#endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_sm3,
	.version = RZ_VERSION
};
#endif
