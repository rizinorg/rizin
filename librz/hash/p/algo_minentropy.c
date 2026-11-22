// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/minentropy/minentropy.h"

static void *plugin_minentropy_context_new() {
	return RZ_NEW0(RzMinEntropy);
}

static void plugin_minentropy_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_minentropy_digest_size(void *context) {
	return RZ_HASH_MINENTROPY_DIGEST_SIZE;
}

static RzHashSize plugin_minentropy_block_size(void *context) {
	return RZ_HASH_MINENTROPY_BLOCK_LENGTH;
}

static bool plugin_minentropy_init(void *context) {
	rz_return_val_if_fail(context, false);
	rz_minentropy_init((RzMinEntropy *)context);
	return true;
}

static bool plugin_minentropy_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	rz_minentropy_update((RzMinEntropy *)context, data, size);
	return true;
}

static bool plugin_minentropy_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	rz_minentropy_final(digest, (RzMinEntropy *)context);
	return true;
}

static bool plugin_minentropy_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_MINENTROPY_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzMinEntropy ctx;
	rz_minentropy_init(&ctx);
	rz_minentropy_update(&ctx, data, size);
	rz_minentropy_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_MINENTROPY_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_minentropy = {
	.name = "minentropy",
	.license = "LGPL3",
	.author = "xvilka",
	.description = "Min-entropy [0.0-8.0] range",
	.support_hmac = false,
	.context_new = plugin_minentropy_context_new,
	.context_free = plugin_minentropy_context_free,
	.digest_size = plugin_minentropy_digest_size,
	.block_size = plugin_minentropy_block_size,
	.init = plugin_minentropy_init,
	.update = plugin_minentropy_update,
	.final = plugin_minentropy_final,
	.small_block = plugin_minentropy_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_minentropy,
	.version = RZ_VERSION
};
#endif
