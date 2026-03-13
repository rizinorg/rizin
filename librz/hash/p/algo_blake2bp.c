// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>
#include <blake2.h>

/**
 * This file implements RzHashPlugin for BLAKE2bp:
 *   - blake2bp : parallel (4-lane) blake2b, up to 512-bit digest
 */

static void *plugin_blake2bp_context_new(void) {
	return RZ_NEW0(blake2bp_state);
}

static void plugin_blake2bp_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_blake2bp_digest_size(void *context) {
	return BLAKE2B_OUTBYTES;
}

static RzHashSize plugin_blake2bp_block_size(void *context) {
	return BLAKE2B_BLOCKBYTES;
}

static bool plugin_blake2bp_init(void *context) {
	rz_return_val_if_fail(context, false);
	return blake2bp_init((blake2bp_state *)context, BLAKE2B_OUTBYTES) == 0;
}

static bool plugin_blake2bp_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	return blake2bp_update((blake2bp_state *)context, data, size) == 0;
}

static bool plugin_blake2bp_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	return blake2bp_final((blake2bp_state *)context, digest, BLAKE2B_OUTBYTES) == 0;
}

static bool plugin_blake2bp_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(BLAKE2B_OUTBYTES);
	if (!dgst) {
		return false;
	}
	if (blake2bp(dgst, BLAKE2B_OUTBYTES, data, size, NULL, 0) < 0) {
		free(dgst);
		return false;
	}
	*digest = dgst;
	if (digest_size) {
		*digest_size = BLAKE2B_OUTBYTES;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_blake2bp = {
	.name = "blake2bp",
	.license = "LGPL3",
	.author = "Farhan-25",
	.description = "BLAKE2bp cryptographic hash",
	.support_hmac = false,
	.context_new = plugin_blake2bp_context_new,
	.context_free = plugin_blake2bp_context_free,
	.digest_size = plugin_blake2bp_digest_size,
	.block_size = plugin_blake2bp_block_size,
	.init = plugin_blake2bp_init,
	.update = plugin_blake2bp_update,
	.final = plugin_blake2bp_final,
	.small_block = plugin_blake2bp_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin_blake2bp = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_blake2bp,
	.version = RZ_VERSION
};
#endif