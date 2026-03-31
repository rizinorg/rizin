// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>
#include <blake3.h>

static void *plugin_blake3_context_new() {
	return RZ_NEW0(blake3_hasher);
}

static void plugin_blake3_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_blake3_digest_size(void *context) {
	return BLAKE3_OUT_LEN;
}

static RzHashSize plugin_blake3_block_size(void *context) {
	return BLAKE3_BLOCK_LEN;
}

static bool plugin_blake3_init(void *context) {
	rz_return_val_if_fail(context, false);
	blake3_hasher_init((blake3_hasher *)context);
	return true;
}

static bool plugin_blake3_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	blake3_hasher_update((blake3_hasher *)context, data, size);
	return true;
}

static bool plugin_blake3_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	blake3_hasher_finalize((blake3_hasher *)context, digest, BLAKE3_OUT_LEN);
	return true;
}

static bool plugin_blake3_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(BLAKE3_OUT_LEN);
	if (!dgst) {
		return false;
	}

	blake3_hasher ctx;
	blake3_hasher_init(&ctx);
	blake3_hasher_update(&ctx, data, size);
	blake3_hasher_finalize(&ctx, dgst, BLAKE3_OUT_LEN);

	*digest = dgst;
	if (digest_size) {
		*digest_size = BLAKE3_OUT_LEN;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_blake3 = {
	.name = "blake3",
	.license = "CC0",
	.author = "Samuel Neves,Jack O'Connor",
	.description = "BLAKE3 cryptographic hash",
	.support_hmac = false,
	.context_new = plugin_blake3_context_new,
	.context_free = plugin_blake3_context_free,
	.digest_size = plugin_blake3_digest_size,
	.block_size = plugin_blake3_block_size,
	.init = plugin_blake3_init,
	.update = plugin_blake3_update,
	.final = plugin_blake3_final,
	.small_block = plugin_blake3_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_blake3,
	.version = RZ_VERSION
};
#endif
