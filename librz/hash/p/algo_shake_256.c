// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/shake/shake.h"

#define shake_256_BLOCK_LENGTH  136
#define shake_256_DIGEST_LENGTH 64

static void *plugin_shake_256_context_new() {
	return RZ_NEW0(shake_context);
}

static void plugin_shake_256_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_shake_256_digest_size(void *context) {
	return shake_256_DIGEST_LENGTH;
}

static RzHashSize plugin_shake_256_block_size(void *context) {
	return shake_256_BLOCK_LENGTH;
}

static bool plugin_shake_256_init(void *context) {
	rz_return_val_if_fail(context, false);
	shake_Init256((shake_context *)context);
	return true;
}

static bool plugin_shake_256_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context, false);
	shake_Update((shake_context *)context, data, (size_t)size);
	return true;
}

static bool plugin_shake_256_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	shake_Finalize((shake_context *)context);
	shake_Squeeze((shake_context *)context, digest, shake_256_DIGEST_LENGTH);
	return true;
}

static bool plugin_shake_256_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(shake_256_DIGEST_LENGTH);
	if (!dgst) {
		return false;
	}

	shake_context ctx;
	shake_Init256(&ctx);
	shake_Update(&ctx, data, size);
	shake_Finalize(&ctx);
	shake_Squeeze(&ctx, dgst, shake_256_DIGEST_LENGTH);

	*digest = dgst;
	if (digest_size) {
		*digest_size = shake_256_DIGEST_LENGTH;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_shake_256 = {
	.name = "shake-256",
	.author = "Andrey Jivsov",
	.license = "BSD-3",
	.description = "SHAKE-256 extendable-output function",
	.support_hmac = false,
	.context_new = plugin_shake_256_context_new,
	.context_free = plugin_shake_256_context_free,
	.digest_size = plugin_shake_256_digest_size,
	.block_size = plugin_shake_256_block_size,
	.init = plugin_shake_256_init,
	.update = plugin_shake_256_update,
	.final = plugin_shake_256_final,
	.small_block = plugin_shake_256_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_shake_256,
	.version = RZ_VERSION
};
#endif
