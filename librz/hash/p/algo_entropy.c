// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/entropy/entropy.h"

static void *plugin_entropy_context_new() {
	return RZ_NEW0(RzEntropy);
}

static void plugin_entropy_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_entropy_digest_size(void *context) {
	return RZ_HASH_ENTROPY_DIGEST_SIZE;
}

static RzHashSize plugin_entropy_block_size(void *context) {
	return RZ_HASH_ENTROPY_BLOCK_LENGTH;
}

static bool plugin_entropy_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_entropy_init((RzEntropy *)context);
	return true;
}

static bool plugin_entropy_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_entropy_update((RzEntropy *)context, data, size);
	return true;
}

static bool plugin_entropy_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_entropy_final(digest, (RzEntropy *)context, false);
	return true;
}

static bool plugin_entropy_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_ENTROPY_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzEntropy ctx;
	rz_entropy_init(&ctx);
	rz_entropy_update(&ctx, data, size);
	rz_entropy_final(dgst, &ctx, false);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_ENTROPY_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_entropy = {
	.name = "entropy",
	.license = "LGPL3",
	.author = "deroad",
	.description = "Entropy [0.0-8.0] range",
	.support_hmac = false,
	.context_new = plugin_entropy_context_new,
	.context_free = plugin_entropy_context_free,
	.digest_size = plugin_entropy_digest_size,
	.block_size = plugin_entropy_block_size,
	.init = plugin_entropy_init,
	.update = plugin_entropy_update,
	.final = plugin_entropy_final,
	.small_block = plugin_entropy_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_entropy,
	.version = RZ_VERSION
};
#endif
