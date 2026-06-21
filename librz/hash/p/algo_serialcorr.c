// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/serialcorr/serialcorr.h"

static void *plugin_serialcorr_context_new() {
	return RZ_NEW0(RzSerialCorr);
}

static void plugin_serialcorr_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_serialcorr_digest_size(void *context) {
	return RZ_HASH_SERIALCORR_DIGEST_SIZE;
}

static RzHashSize plugin_serialcorr_block_size(void *context) {
	return RZ_HASH_SERIALCORR_BLOCK_LENGTH;
}

static bool plugin_serialcorr_init(void *context) {
	rz_return_val_if_fail(context, false);
	rz_serialcorr_init((RzSerialCorr *)context);
	return true;
}

static bool plugin_serialcorr_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	rz_serialcorr_update((RzSerialCorr *)context, data, size);
	return true;
}

static bool plugin_serialcorr_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	rz_serialcorr_final(digest, (RzSerialCorr *)context);
	return true;
}

static bool plugin_serialcorr_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_SERIALCORR_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzSerialCorr ctx;
	rz_serialcorr_init(&ctx);
	rz_serialcorr_update(&ctx, data, size);
	rz_serialcorr_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_SERIALCORR_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_serialcorr = {
	.name = "serialcorr",
	.license = "LGPL3",
	.author = "xvilka",
	.description = "Serial correlation coefficient [-1.0-1.0]",
	.support_hmac = false,
	.context_new = plugin_serialcorr_context_new,
	.context_free = plugin_serialcorr_context_free,
	.digest_size = plugin_serialcorr_digest_size,
	.block_size = plugin_serialcorr_block_size,
	.init = plugin_serialcorr_init,
	.update = plugin_serialcorr_update,
	.final = plugin_serialcorr_final,
	.small_block = plugin_serialcorr_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_serialcorr,
	.version = RZ_VERSION
};
#endif
