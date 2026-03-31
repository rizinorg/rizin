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
	return sizeof(double);
}

static RzHashSize plugin_entropy_block_size(void *context) {
	return 0;
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

	rz_entropy_final(digest, (RzEntropy *)context, true);
	return true;
}

static bool plugin_entropy_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(sizeof(double));
	if (!dgst) {
		return false;
	}

	RzEntropy ctx;
	rz_entropy_init(&ctx);
	rz_entropy_update(&ctx, data, size);
	rz_entropy_final(dgst, &ctx, true);

	*digest = dgst;
	if (digest_size) {
		*digest_size = sizeof(double);
	}
	return true;
}

RzHashPlugin rz_hash_plugin_entropy_fract = {
	.name = "entropy_fract",
	.license = "LGPL3",
	.author = "deroad",
	.description = "Fractional entropy [0.0-1.0] range",
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
	.data = &rz_hash_plugin_entropy_fract,
	.version = RZ_VERSION
};
#endif
