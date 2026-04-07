// SPDX-FileCopyrightText: 2026
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include <rz_lib.h>

typedef ut32 RzFnv1a32;

#define RZ_HASH_FNV1A32_DIGEST_SIZE  4
#define RZ_HASH_FNV1A32_BLOCK_LENGTH 0

static void *plugin_fnv1a32_context_new() {
	return RZ_NEW0(RzFnv1a32);
}

static void plugin_fnv1a32_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_fnv1a32_digest_size(void *context) {
	return RZ_HASH_FNV1A32_DIGEST_SIZE;
}

static RzHashSize plugin_fnv1a32_block_size(void *context) {
	return RZ_HASH_FNV1A32_BLOCK_LENGTH;
}

static bool plugin_fnv1a32_init(void *context) {
	rz_return_val_if_fail(context, false);
	RzFnv1a32 *ctx = (RzFnv1a32 *)context;
	*ctx = 0x811c9dc5U; // FNV offset basis
	return true;
}

static bool plugin_fnv1a32_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context, false);
	if (size > 0) {
		rz_return_val_if_fail(data, false);
	}

	RzFnv1a32 *ctx = (RzFnv1a32 *)context;
	ut32 hash = *ctx;

	for (ut64 i = 0; i < size; ++i) {
		hash ^= data[i];
		hash *= 0x01000193U; // FNV prime
	}

	*ctx = hash;
	return true;
}

static bool plugin_fnv1a32_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	RzFnv1a32 *ctx = (RzFnv1a32 *)context;
	rz_write_be32(digest, *ctx);
	return true;
}

static bool plugin_fnv1a32_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(digest, false);
	if (size > 0) {
		rz_return_val_if_fail(data, false);
	}

	ut8 *dgst = malloc(RZ_HASH_FNV1A32_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzFnv1a32 ctx = 0;
	plugin_fnv1a32_init(&ctx);
	plugin_fnv1a32_update(&ctx, data, size);
	plugin_fnv1a32_final(&ctx, dgst);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_FNV1A32_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_fnv1a = {
	.name = "fnv1a",
	.license = "Public Domain",
	.author = "rizin",
	.description = "FNV-1a 32-bit non-cryptographic hash",
	.support_hmac = false,
	.context_new = plugin_fnv1a32_context_new,
	.context_free = plugin_fnv1a32_context_free,
	.digest_size = plugin_fnv1a32_digest_size,
	.block_size = plugin_fnv1a32_block_size,
	.init = plugin_fnv1a32_init,
	.update = plugin_fnv1a32_update,
	.final = plugin_fnv1a32_final,
	.small_block = plugin_fnv1a32_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_fnv1a,
	.version = RZ_VERSION
};
#endif

