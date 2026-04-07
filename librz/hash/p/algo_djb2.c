// SPDX-FileCopyrightText: 2026
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include <rz_lib.h>

typedef ut32 RzDjb2;

#define RZ_HASH_DJB2_DIGEST_SIZE  4
#define RZ_HASH_DJB2_BLOCK_LENGTH 0

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
	RzDjb2 *ctx = (RzDjb2 *)context;
	*ctx = 5381U;
	return true;
}

static bool plugin_djb2_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context, false);
	if (size > 0) {
		rz_return_val_if_fail(data, false);
	}

	RzDjb2 *ctx = (RzDjb2 *)context;
	ut32 hash = *ctx;
	for (ut64 i = 0; i < size; ++i) {
		hash = ((hash << 5) + hash + data[i]);
	}
	*ctx = hash;
	return true;
}

static bool plugin_djb2_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	RzDjb2 *ctx = (RzDjb2 *)context;
	rz_write_be32(digest, *ctx);
	return true;
}

static bool plugin_djb2_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(digest, false);
	if (size > 0) {
		rz_return_val_if_fail(data, false);
	}

	ut8 *dgst = malloc(RZ_HASH_DJB2_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzDjb2 ctx = 0;
	plugin_djb2_init(&ctx);
	plugin_djb2_update(&ctx, data, size);
	plugin_djb2_final(&ctx, dgst);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_DJB2_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_djb2 = {
	.name = "djb2",
	.license = "Public Domain",
	.author = "rizin",
	.description = "djb2 32-bit non-cryptographic hash",
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

