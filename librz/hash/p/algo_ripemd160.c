// SPDX-FileCopyrightText: 2026 Duck
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_asn1.h>

#include "../algorithms/ripemd160/ripemd160.h"
#include "rz_util/rz_assert.h"

static void *plugin_ripemd160_context_new() {
	return RZ_NEW0(RzRipemd160);
}

static void plugin_ripemd160_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_ripemd160_digest_size(void *context) {
	return RZ_HASH_RIPEMD160_DIGEST_SIZE;
}

static RzHashSize plugin_ripemd160_block_size(void *context) {
	return RZ_HASH_RIPEMD160_BLOCK_LENGTH;
}

static bool plugin_ripemd160_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_ripemd160_init((RzRipemd160 *)context);
	return true;
}

static bool plugin_ripemd160_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_ripemd160_update((RzRipemd160 *)context, data, size);
	return true;
}

static bool plugin_ripemd160_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_ripemd160_fini(digest, (RzRipemd160 *)context);
	return true;
}
static bool plugin_ripemd160_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_RIPEMD160_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzRipemd160 ctx;
	rz_ripemd160_init(&ctx);
	rz_ripemd160_update(&ctx, data, size);
	rz_ripemd160_fini(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_RIPEMD160_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_ripemd160 = {
	.name = "ripemd160",
	.license = "LGPL3",
	.author = "Duck",
	.description = "Ripemd-160 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_ripemd160_context_new,
	.context_free = plugin_ripemd160_context_free,
	.digest_size = plugin_ripemd160_digest_size,
	.block_size = plugin_ripemd160_block_size,
	.init = plugin_ripemd160_init,
	.update = plugin_ripemd160_update,
	.final = plugin_ripemd160_final,
	.small_block = plugin_ripemd160_small_block,
};
