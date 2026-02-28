// SPDX-FileCopyrightText: 2026 Rifat <rifatarifoglu38@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../algorithms/ror13/ror13.h"

#include <rz_hash.h>
#include <rz_util.h>

static void *plugin_ror13_context_new() {
	return RZ_NEW0(RzROR13);
}

static void plugin_ror13_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_ror13_digest_size(void *context) {
	return RZ_HASH_ROR13_DIGEST_SIZE;
}

static RzHashSize plugin_ror13_block_size(void *context) {
	return RZ_HASH_ROR13_BLOCK_LENGTH;
}

static bool plugin_ror13_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_ror13_init((RzROR13 *)context);
	return true;
}

static bool plugin_ror13_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_ror13_update((RzROR13 *)context, data, size);
	return true;
}

static bool plugin_ror13_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_ror13_final(digest, (RzROR13 *)context);
	return true;
}

static bool plugin_ror13_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_ROR13_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzROR13 ctx;
	rz_ror13_init(&ctx);
	rz_ror13_update(&ctx, data, size);
	rz_ror13_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_ROR13_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_ror13 = {
	.name = "ror13",
	.license = "LGPL3",
	.author = "Rifat",
	.description = "ROR13 Windows shellcode API hash",
	.support_hmac = false,
	.context_new = plugin_ror13_context_new,
	.context_free = plugin_ror13_context_free,
	.digest_size = plugin_ror13_digest_size,
	.block_size = plugin_ror13_block_size,
	.init = plugin_ror13_init,
	.update = plugin_ror13_update,
	.final = plugin_ror13_final,
	.small_block = plugin_ror13_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_ror13,
	.version = RZ_VERSION
};
#endif
