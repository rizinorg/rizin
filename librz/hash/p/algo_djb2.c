// SPDX-FileCopyrightText: 2026 Ayush Dwivedi <ayushd785@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/djb2/djb2.h"

static void *plugin_djb2_context_new() {
	return RZ_NEW0(RzDjb2);
}

static void plugin_djb2_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_djb2_digest_size(void *context) {
	return RZ_HASH_DJB2_DIGEST_SIZE;
}

static RzHashSize plugin_djb2_block_size(void *context) {
	return RZ_HASH_DJB2_BLOCK_LENGTH;
}

static bool plugin_djb2_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_djb2_init((RzDjb2 *)context);
	return true;
}

static bool plugin_djb2_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_djb2_update((RzDjb2 *)context, data, size);
	return true;
}

static bool plugin_djb2_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_djb2_final(digest, (RzDjb2 *)context);
	return true;
}

static bool plugin_djb2_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_DJB2_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzDjb2 ctx;
	rz_djb2_init(&ctx);
	rz_djb2_update(&ctx, data, size);
	rz_djb2_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_DJB2_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_djb2 = {
	.name = "djb2",
	.license = "LGPL3",
	.author = "Ayush Dwivedi",
	.description = "DJB2 hash function by Daniel Bernstein",
	.support_hmac = false,
	.context_new = plugin_djb2_context_new,
	.context_free = plugin_djb2_context_free,
	.digest_size = plugin_djb2_digest_size,
	.block_size = plugin_djb2_block_size,
	.init = plugin_djb2_init,
	.update = plugin_djb2_update,
	.final = plugin_djb2_final,
	.small_block = plugin_djb2_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_djb2,
	.version = RZ_VERSION
};
#endif
