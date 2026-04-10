// SPDX-FileCopyrightText: 2026 cheese-cakee
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>
#include <xxhash.h>

#define RZ_HASH_XXHASH64_DIGEST_SIZE  8
#define RZ_HASH_XXHASH64_BLOCK_LENGTH 0

static void *plugin_xxhash64_context_new() {
	return XXH64_createState();
}

static void plugin_xxhash64_context_free(void *context) {
	XXH64_freeState((XXH64_state_t *)context);
}

static RzHashSize plugin_xxhash64_digest_size(void *context) {
	return RZ_HASH_XXHASH64_DIGEST_SIZE;
}

static RzHashSize plugin_xxhash64_block_size(void *context) {
	return RZ_HASH_XXHASH64_BLOCK_LENGTH;
}

static bool plugin_xxhash64_init(void *context) {
	rz_return_val_if_fail(context, false);

	XXH64_reset((XXH64_state_t *)context, 0);
	return true;
}

static bool plugin_xxhash64_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	XXH64_update((XXH64_state_t *)context, data, size);
	return true;
}

static bool plugin_xxhash64_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	ut64 dgst = XXH64_digest((XXH64_state_t *)context);
	rz_write_be64(digest, dgst);
	return true;
}

static bool plugin_xxhash64_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_XXHASH64_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	ut64 result = XXH64(data, size, 0);
	rz_write_be64(dgst, result);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_XXHASH64_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_xxhash64 = {
	.name = "xxhash64",
	.license = "LGPL3",
	.author = "cheese-cakee",
	.description = "xxHash64 non-cryptographic hash",
	.support_hmac = false,
	.context_new = plugin_xxhash64_context_new,
	.context_free = plugin_xxhash64_context_free,
	.digest_size = plugin_xxhash64_digest_size,
	.block_size = plugin_xxhash64_block_size,
	.init = plugin_xxhash64_init,
	.update = plugin_xxhash64_update,
	.final = plugin_xxhash64_final,
	.small_block = plugin_xxhash64_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_xxhash64,
	.version = RZ_VERSION
};
#endif
