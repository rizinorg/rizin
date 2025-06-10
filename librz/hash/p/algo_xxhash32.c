// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>
#include <xxhash.h>

#define RZ_HASH_XXHASH32_DIGEST_SIZE  4
#define RZ_HASH_XXHASH32_BLOCK_LENGTH 0

static void *plugin_xxhash32_context_new() {
	return XXH32_createState();
}

static void plugin_xxhash32_context_free(void *context) {
	XXH32_freeState((XXH32_state_t *)context);
}

static RzHashSize plugin_xxhash32_digest_size(void *context) {
	return RZ_HASH_XXHASH32_DIGEST_SIZE;
}

static RzHashSize plugin_xxhash32_block_size(void *context) {
	return RZ_HASH_XXHASH32_BLOCK_LENGTH;
}

static bool plugin_xxhash32_init(void *context) {
	rz_return_val_if_fail(context, false);

	XXH32_reset((XXH32_state_t *)context, 0);
	return true;
}

static bool plugin_xxhash32_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	XXH32_update((XXH32_state_t *)context, data, size);
	return true;
}

static bool plugin_xxhash32_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	ut32 dgst = XXH32_digest((XXH32_state_t *)context);
	rz_write_le32(digest, dgst);
	return true;
}

static bool plugin_xxhash32_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_XXHASH32_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	ut32 result = XXH32(data, size, 0);
	rz_write_le32(dgst, result);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_XXHASH32_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_xxhash32 = {
	.name = "xxhash32",
	.license = "LGPL3",
	.author = "deroad",
	.description = "xxHash32 non-cryptographic hash",
	.support_hmac = false,
	.context_new = plugin_xxhash32_context_new,
	.context_free = plugin_xxhash32_context_free,
	.digest_size = plugin_xxhash32_digest_size,
	.block_size = plugin_xxhash32_block_size,
	.init = plugin_xxhash32_init,
	.update = plugin_xxhash32_update,
	.final = plugin_xxhash32_final,
	.small_block = plugin_xxhash32_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_xxhash32,
	.version = RZ_VERSION
};
#endif
