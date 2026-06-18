// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/ioc/ioc.h"

static void *plugin_ioc_context_new() {
	return RZ_NEW0(RzIOC);
}

static void plugin_ioc_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_ioc_digest_size(void *context) {
	return RZ_HASH_IOC_DIGEST_SIZE;
}

static RzHashSize plugin_ioc_block_size(void *context) {
	return RZ_HASH_IOC_BLOCK_LENGTH;
}

static bool plugin_ioc_init(void *context) {
	rz_return_val_if_fail(context, false);
	rz_ioc_init((RzIOC *)context);
	return true;
}

static bool plugin_ioc_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	rz_ioc_update((RzIOC *)context, data, size);
	return true;
}

static bool plugin_ioc_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	rz_ioc_final(digest, (RzIOC *)context);
	return true;
}

static bool plugin_ioc_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_IOC_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzIOC ctx;
	rz_ioc_init(&ctx);
	rz_ioc_update(&ctx, data, size);
	rz_ioc_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_IOC_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_ioc = {
	.name = "ioc",
	.license = "LGPL3",
	.author = "xvilka",
	.description = "Index of coincidence [0.0-1.0] range",
	.support_hmac = false,
	.context_new = plugin_ioc_context_new,
	.context_free = plugin_ioc_context_free,
	.digest_size = plugin_ioc_digest_size,
	.block_size = plugin_ioc_block_size,
	.init = plugin_ioc_init,
	.update = plugin_ioc_update,
	.final = plugin_ioc_final,
	.small_block = plugin_ioc_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_ioc,
	.version = RZ_VERSION
};
#endif
