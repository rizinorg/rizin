// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/parity/parity.h"

static void *plugin_parity_context_new() {
	return RZ_NEW0(RzParity);
}

static void plugin_parity_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_parity_digest_size(void *context) {
	return RZ_HASH_PARITY_DIGEST_SIZE;
}

static RzHashSize plugin_parity_block_size(void *context) {
	return RZ_HASH_PARITY_BLOCK_LENGTH;
}

static bool plugin_parity_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_parity_init((RzParity *)context);
	return true;
}

static bool plugin_parity_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_parity_update((RzParity *)context, data, size);
	return true;
}

static bool plugin_parity_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_parity_final(digest, (RzParity *)context);
	return true;
}

static bool plugin_parity_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_PARITY_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzParity ctx;
	rz_parity_init(&ctx);
	rz_parity_update(&ctx, data, size);
	rz_parity_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_PARITY_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_parity = {
	.name = "parity",
	.license = "LGPL3",
	.author = "deroad",
	.description = "Parity checksum",
	.support_hmac = false,
	.context_new = plugin_parity_context_new,
	.context_free = plugin_parity_context_free,
	.digest_size = plugin_parity_digest_size,
	.block_size = plugin_parity_block_size,
	.init = plugin_parity_init,
	.update = plugin_parity_update,
	.final = plugin_parity_final,
	.small_block = plugin_parity_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_parity,
	.version = RZ_VERSION
};
#endif
