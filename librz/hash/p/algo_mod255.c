// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/mod255/mod255.h"

static void *plugin_mod255_context_new() {
	return RZ_NEW0(RzMod255);
}

static void plugin_mod255_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_mod255_digest_size(void *context) {
	return RZ_HASH_MOD255_DIGEST_SIZE;
}

static RzHashSize plugin_mod255_block_size(void *context) {
	return RZ_HASH_MOD255_BLOCK_LENGTH;
}

static bool plugin_mod255_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_mod255_init((RzMod255 *)context);
	return true;
}

static bool plugin_mod255_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_mod255_update((RzMod255 *)context, data, size);
	return true;
}

static bool plugin_mod255_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_mod255_final(digest, (RzMod255 *)context);
	return true;
}

static bool plugin_mod255_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_MOD255_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzMod255 ctx;
	rz_mod255_init(&ctx);
	rz_mod255_update(&ctx, data, size);
	rz_mod255_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_MOD255_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_mod255 = {
	.name = "mod255",
	.license = "LGPL3",
	.author = "deroad",
	.description = "Modulo 255 checksum",
	.support_hmac = false,
	.context_new = plugin_mod255_context_new,
	.context_free = plugin_mod255_context_free,
	.digest_size = plugin_mod255_digest_size,
	.block_size = plugin_mod255_block_size,
	.init = plugin_mod255_init,
	.update = plugin_mod255_update,
	.final = plugin_mod255_final,
	.small_block = plugin_mod255_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_mod255,
	.version = RZ_VERSION
};
#endif
