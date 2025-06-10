// SPDX-FileCopyrightText: 2023 swedenspy <swedenspy@yahoo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/md2/md2.h"

static void *plugin_md2_context_new() {
	return RZ_NEW0(RzMD2);
}

static void plugin_md2_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_md2_digest_size(void *context) {
	return RZ_HASH_MD2_DIGEST_SIZE;
}

static RzHashSize plugin_md2_block_size(void *context) {
	return RZ_HASH_MD2_BLOCK_LENGTH;
}

static bool plugin_md2_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_md2_init((RzMD2 *)context);
	return true;
}

static bool plugin_md2_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_md2_update((RzMD2 *)context, data, size);
	return true;
}

static bool plugin_md2_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_md2_fini(digest, (RzMD2 *)context);
	return true;
}

static bool plugin_md2_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_MD2_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzMD2 ctx;
	rz_md2_init(&ctx);
	rz_md2_update(&ctx, data, size);
	rz_md2_fini(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_MD2_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_md2 = {
	.name = "md2",
	.license = "LGPL3",
	.author = "swedenspy",
	.description = "MD2 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_md2_context_new,
	.context_free = plugin_md2_context_free,
	.digest_size = plugin_md2_digest_size,
	.block_size = plugin_md2_block_size,
	.init = plugin_md2_init,
	.update = plugin_md2_update,
	.final = plugin_md2_final,
	.small_block = plugin_md2_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_md2,
	.version = RZ_VERSION
};
#endif
