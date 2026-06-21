// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/xor/xor.h"

static void *plugin_xor8_context_new() {
	return RZ_NEW0(RzXor8);
}

static void plugin_xor8_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_xor8_digest_size(void *context) {
	return RZ_HASH_XOR8_DIGEST_SIZE;
}

static RzHashSize plugin_xor8_block_size(void *context) {
	return RZ_HASH_XOR_BLOCK_LENGTH;
}

static bool plugin_xor8_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_xor8_init((RzXor8 *)context);
	return true;
}

static bool plugin_xor8_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_xor8_update((RzXor8 *)context, data, size);
	return true;
}

static bool plugin_xor8_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_xor8_final(digest, (RzXor8 *)context);
	return true;
}

static bool plugin_xor8_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_XOR8_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzXor8 ctx;
	rz_xor8_init(&ctx);
	rz_xor8_update(&ctx, data, size);
	rz_xor8_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_XOR8_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_xor8 = {
	.name = "xor8",
	.license = "LGPL3",
	.author = "deroad",
	.description = "XOR-8 checksum",
	.support_hmac = false,
	.context_new = plugin_xor8_context_new,
	.context_free = plugin_xor8_context_free,
	.digest_size = plugin_xor8_digest_size,
	.block_size = plugin_xor8_block_size,
	.init = plugin_xor8_init,
	.update = plugin_xor8_update,
	.final = plugin_xor8_final,
	.small_block = plugin_xor8_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_xor8,
	.version = RZ_VERSION
};
#endif
