// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>
#include <blake2.h>

/**
 * This file implements RzHashPlugin for BLAKE2xs:
 *   - blake2xs : extendable-output (XOF) built on blake2s, arbitrary digest length
 */

static void *plugin_blake2xs_context_new(void) {
	return RZ_NEW0(blake2xs_state);
}

static void plugin_blake2xs_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_blake2xs_digest_size(void *context) {
	return BLAKE2S_OUTBYTES;
}

static RzHashSize plugin_blake2xs_block_size(void *context) {
	return BLAKE2S_BLOCKBYTES;
}

static bool plugin_blake2xs_init(void *context) {
	rz_return_val_if_fail(context, false);
	return blake2xs_init((blake2xs_state *)context, BLAKE2S_OUTBYTES) == 0;
}

static bool plugin_blake2xs_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	return blake2xs_update((blake2xs_state *)context, data, size) == 0;
}

static bool plugin_blake2xs_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	return blake2xs_final((blake2xs_state *)context, digest, BLAKE2S_OUTBYTES) == 0;
}

static bool plugin_blake2xs_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(BLAKE2S_OUTBYTES);
	if (!dgst) {
		return false;
	}
	if (blake2xs(dgst, BLAKE2S_OUTBYTES, data, size, NULL, 0) < 0) {
		free(dgst);
		return false;
	}
	*digest = dgst;
	if (digest_size) {
		*digest_size = BLAKE2S_OUTBYTES;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_blake2xs = {
	.name = "blake2xs",
	.license = "LGPL3",
	.author = "Farhan-25",
	.description = "BLAKE2xs cryptographic hash",
	.support_hmac = false,
	.context_new = plugin_blake2xs_context_new,
	.context_free = plugin_blake2xs_context_free,
	.digest_size = plugin_blake2xs_digest_size,
	.block_size = plugin_blake2xs_block_size,
	.init = plugin_blake2xs_init,
	.update = plugin_blake2xs_update,
	.final = plugin_blake2xs_final,
	.small_block = plugin_blake2xs_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin_blake2xs = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_blake2xs,
	.version = RZ_VERSION
};
#endif