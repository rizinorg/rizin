// SPDX-FileCopyrightText: 2026 shessaanand <shessaasiva@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include <rz_lib.h>

typedef ut32 RzRor13;

#define RZ_HASH_ROR13_DIGEST_SIZE  4
#define RZ_HASH_ROR13_BLOCK_LENGTH 0

static void *plugin_ror13_context_new() {
	return RZ_NEW0(RzRor13);
}

static void plugin_ror13_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_ror13_digest_size(void *context) {
	return RZ_HASH_ROR13_DIGEST_SIZE;
}

static RzHashSize plugin_ror13_block_size(void *context) {
	return RZ_HASH_ROR13_BLOCK_LENGTH;
}

static bool plugin_ror13_init(void *context) {
	rz_return_val_if_fail(context, false);

	RzRor13 *ctx = (RzRor13 *)context;
	*ctx = 0;

	return true;
}

static bool plugin_ror13_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context, false);
	if (size > 0) {
		rz_return_val_if_fail(data, false);
	}

	RzRor13 *ctx = (RzRor13 *)context;
	ut32 hash = *ctx;

	for (ut64 i = 0; i < size; ++i) {
		hash = (hash >> 13) | (hash << (32 - 13));
		hash += data[i];
	}

	*ctx = hash;
	return true;
}

static bool plugin_ror13_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	RzRor13 *ctx = (RzRor13 *)context;
	ut32 hash = *ctx;

	rz_write_be32(digest, hash);
	return true;
}

static bool plugin_ror13_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(digest, false);
	if (size > 0) {
		rz_return_val_if_fail(data, false);
	}

	ut8 *dgst = malloc(RZ_HASH_ROR13_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzRor13 ctx = { 0 };
	plugin_ror13_init(&ctx);
	plugin_ror13_update(&ctx, data, size);
	plugin_ror13_final(&ctx, dgst);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_ROR13_DIGEST_SIZE;
	}
	return true;
}

RZ_API RzHashPlugin rz_hash_plugin_ror13 = {
	.name = "ror13",
	.license = "LGPL3",
	.author = "shessaanand",
	.description = "ROR13 API hashing",
	.support_hmac = false,
	.context_new = plugin_ror13_context_new,
	.context_free = plugin_ror13_context_free,
	.digest_size = plugin_ror13_digest_size,
	.block_size = plugin_ror13_block_size,
	.init = plugin_ror13_init,
	.update = plugin_ror13_update,
	.final = plugin_ror13_final,
	.small_block = plugin_ror13_small_block,
};
