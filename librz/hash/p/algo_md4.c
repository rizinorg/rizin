// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_hash_cfg(md4, EVP_md4, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/md4/md4.h"

static void *plugin_md4_context_new() {
	return RZ_NEW0(RzMD4);
}

static void plugin_md4_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_md4_digest_size(void *context) {
	return RZ_HASH_MD4_DIGEST_SIZE;
}

static RzHashSize plugin_md4_block_size(void *context) {
	return RZ_HASH_MD4_BLOCK_LENGTH;
}

static bool plugin_md4_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_md4_init((RzMD4 *)context);
	return true;
}

static bool plugin_md4_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_md4_update((RzMD4 *)context, data, size);
	return true;
}

static bool plugin_md4_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_md4_fini(digest, (RzMD4 *)context);
	return true;
}

static bool plugin_md4_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_MD4_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzMD4 ctx;
	rz_md4_init(&ctx);
	rz_md4_update(&ctx, data, size);
	rz_md4_fini(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_MD4_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_md4 = {
	.name = "md4",
	.license = "LGPL3",
	.author = "deroad",
	.description = "MD4 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_md4_context_new,
	.context_free = plugin_md4_context_free,
	.digest_size = plugin_md4_digest_size,
	.block_size = plugin_md4_block_size,
	.init = plugin_md4_init,
	.update = plugin_md4_update,
	.final = plugin_md4_final,
	.small_block = plugin_md4_small_block,
};

#endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_md4,
	.version = RZ_VERSION
};
#endif
