// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/chisquare/chisquare.h"

static void *plugin_chisquare_context_new() {
	return RZ_NEW0(RzChiSquare);
}

static void plugin_chisquare_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_chisquare_digest_size(void *context) {
	return RZ_HASH_CHISQUARE_DIGEST_SIZE;
}

static RzHashSize plugin_chisquare_block_size(void *context) {
	return RZ_HASH_CHISQUARE_BLOCK_LENGTH;
}

static bool plugin_chisquare_init(void *context) {
	rz_return_val_if_fail(context, false);
	rz_chisquare_init((RzChiSquare *)context);
	return true;
}

static bool plugin_chisquare_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	rz_chisquare_update((RzChiSquare *)context, data, size);
	return true;
}

static bool plugin_chisquare_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	rz_chisquare_final(digest, (RzChiSquare *)context);
	return true;
}

static bool plugin_chisquare_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_CHISQUARE_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzChiSquare ctx;
	rz_chisquare_init(&ctx);
	rz_chisquare_update(&ctx, data, size);
	rz_chisquare_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_CHISQUARE_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_chisquare = {
	.name = "chisquare",
	.license = "LGPL3",
	.author = "xvilka",
	.description = "Chi-square goodness-of-fit vs uniform",
	.support_hmac = false,
	.context_new = plugin_chisquare_context_new,
	.context_free = plugin_chisquare_context_free,
	.digest_size = plugin_chisquare_digest_size,
	.block_size = plugin_chisquare_block_size,
	.init = plugin_chisquare_init,
	.update = plugin_chisquare_update,
	.final = plugin_chisquare_final,
	.small_block = plugin_chisquare_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_chisquare,
	.version = RZ_VERSION
};
#endif
