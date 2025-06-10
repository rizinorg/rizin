// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/ssdeep/ssdeep.h"

static void *plugin_ssdeep_context_new() {
	return rz_ssdeep_new();
}

static void plugin_ssdeep_context_free(void *context) {
	rz_ssdeep_free(context);
}

static RzHashSize plugin_ssdeep_digest_size(void *context) {
	return RZ_HASH_SSDEEP_DIGEST_SIZE;
}

static RzHashSize plugin_ssdeep_block_size(void *context) {
	return RZ_HASH_SSDEEP_BLOCK_LENGTH;
}

static bool plugin_ssdeep_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_ssdeep_init((RzSSDeep *)context);
	return true;
}

static bool plugin_ssdeep_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_ssdeep_update((RzSSDeep *)context, data, size);
	return true;
}

static bool plugin_ssdeep_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_ssdeep_fini((RzSSDeep *)context, (char *)digest);
	return true;
}

static bool plugin_ssdeep_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);

	ut8 *dgst = malloc(RZ_HASH_SSDEEP_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzSSDeep *ctx = rz_ssdeep_new();
	if (!ctx) {
		free(dgst);
		return false;
	}

	rz_ssdeep_update(ctx, data, size);
	rz_ssdeep_fini(ctx, (char *)dgst);
	rz_ssdeep_free(ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_SSDEEP_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_ssdeep = {
	.name = "ssdeep",
	.license = "LGPL3",
	.author = "deroad",
	.description = "SSDeep Context Triggered Piecewise Hash (CTPH, fuzzy hash)",
	.support_hmac = false,
	.context_new = plugin_ssdeep_context_new,
	.context_free = plugin_ssdeep_context_free,
	.digest_size = plugin_ssdeep_digest_size,
	.block_size = plugin_ssdeep_block_size,
	.init = plugin_ssdeep_init,
	.update = plugin_ssdeep_update,
	.final = plugin_ssdeep_final,
	.small_block = plugin_ssdeep_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_ssdeep,
	.version = RZ_VERSION
};
#endif
