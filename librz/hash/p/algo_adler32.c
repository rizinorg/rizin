// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/adler32/adler32.h"

static void *plugin_adler32_context_new() {
	return RZ_NEW0(RzAdler32);
}

static void plugin_adler32_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_adler32_digest_size(void *context) {
	return RZ_HASH_ADLER32_DIGEST_SIZE;
}

static RzHashSize plugin_adler32_block_size(void *context) {
	return RZ_HASH_ADLER32_BLOCK_LENGTH;
}

static bool plugin_adler32_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_adler32_init((RzAdler32 *)context);
	return true;
}

static bool plugin_adler32_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_adler32_update((RzAdler32 *)context, data, size);
	return true;
}

static bool plugin_adler32_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_adler32_final(digest, (RzAdler32 *)context);
	return true;
}

static bool plugin_adler32_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_ADLER32_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzAdler32 ctx;
	rz_adler32_init(&ctx);
	rz_adler32_update(&ctx, data, size);
	rz_adler32_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_ADLER32_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_adler32 = {
	.name = "adler32",
	.license = "LGPL3",
	.author = "deroad",
	.description = "Adler-32 checksum",
	.support_hmac = false,
	.context_new = plugin_adler32_context_new,
	.context_free = plugin_adler32_context_free,
	.digest_size = plugin_adler32_digest_size,
	.block_size = plugin_adler32_block_size,
	.init = plugin_adler32_init,
	.update = plugin_adler32_update,
	.final = plugin_adler32_final,
	.small_block = plugin_adler32_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_adler32,
	.version = RZ_VERSION
};
#endif
