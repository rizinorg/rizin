// SPDX-FileCopyrightText: 2026 Ashish Kumar
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/murmur3/murmur3.h"

typedef struct {
	ut8 *buffer;
	ut64 buffer_len;
	ut64 buffer_alloc;
	uint32_t seed;
} Murmur3x86_128Context;

static void *plugin_murmur3_x86_128_context_new() {
	return RZ_NEW0(Murmur3x86_128Context);
}

static void plugin_murmur3_x86_128_context_free(void *context) {
	if (context) {
		Murmur3x86_128Context *ctx = (Murmur3x86_128Context *)context;
		free(ctx->buffer);
		free(ctx);
	}
}

static RzHashSize plugin_murmur3_x86_128_digest_size(void *context) {
	return MURMUR3_128_DIGEST_LENGTH;
}

static RzHashSize plugin_murmur3_x86_128_block_size(void *context) {
	return 16;
}

static bool plugin_murmur3_x86_128_init(void *context) {
	rz_return_val_if_fail(context, false);
	Murmur3x86_128Context *ctx = (Murmur3x86_128Context *)context;
	free(ctx->buffer);
	ctx->buffer = NULL;
	ctx->buffer_len = 0;
	ctx->buffer_alloc = 0;
	ctx->seed = 0;
	return true;
}

static bool plugin_murmur3_x86_128_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	Murmur3x86_128Context *ctx = (Murmur3x86_128Context *)context;

	ut64 new_len = ctx->buffer_len + size;
	if (new_len > ctx->buffer_alloc) {
		ut64 new_alloc = RZ_MAX(new_len, ctx->buffer_alloc * 2);
		ut8 *tmp = realloc(ctx->buffer, new_alloc);
		if (!tmp) {
			return false;
		}
		ctx->buffer = tmp;
		ctx->buffer_alloc = new_alloc;
	}
	memcpy(ctx->buffer + ctx->buffer_len, data, size);
	ctx->buffer_len = new_len;
	return true;
}

static bool plugin_murmur3_x86_128_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	Murmur3x86_128Context *ctx = (Murmur3x86_128Context *)context;

	ut32 result[4] = { 0 };
	ut8 empty = 0;
	MurmurHash3_x86_128(ctx->buffer ? ctx->buffer : &empty, (int)ctx->buffer_len, ctx->seed, result);
	rz_write_be32(digest + 0, result[3]);
	rz_write_be32(digest + 4, result[2]);
	rz_write_be32(digest + 8, result[1]);
	rz_write_be32(digest + 12, result[0]);
	return true;
}

static bool plugin_murmur3_x86_128_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(MURMUR3_128_DIGEST_LENGTH);
	if (!dgst) {
		return false;
	}

	ut32 result[4] = { 0 };
	MurmurHash3_x86_128(data, (int)size, 0, result);
	rz_write_be32(dgst + 0, result[3]);
	rz_write_be32(dgst + 4, result[2]);
	rz_write_be32(dgst + 8, result[1]);
	rz_write_be32(dgst + 12, result[0]);

	*digest = dgst;
	if (digest_size) {
		*digest_size = MURMUR3_128_DIGEST_LENGTH;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_murmur3_x86_128 = {
	.name = "murmur3-x86-128",
	.author = "Austin Appleby",
	.license = "MIT",
	.description = "MurmurHash3 x86 128-bit non-cryptographic hash",
	.support_hmac = false,
	.context_new = plugin_murmur3_x86_128_context_new,
	.context_free = plugin_murmur3_x86_128_context_free,
	.digest_size = plugin_murmur3_x86_128_digest_size,
	.block_size = plugin_murmur3_x86_128_block_size,
	.init = plugin_murmur3_x86_128_init,
	.update = plugin_murmur3_x86_128_update,
	.final = plugin_murmur3_x86_128_final,
	.small_block = plugin_murmur3_x86_128_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_murmur3_x86_128,
	.version = RZ_VERSION
};
#endif
