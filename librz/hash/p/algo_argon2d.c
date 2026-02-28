// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/*
 * Argon2d — data-dependent memory-hard KDF.
 * Fixed hardcoded salt: 8b30da014d96e374876d0d2523c5b844
 * Same password will always produce the same hash.
 */

#include <rz_hash.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_mem.h>
#include <string.h>
#include <stdlib.h>
#include "../algorithms/argon2/argon2.h"

#define ARGON2D_DIGEST_LENGTH 32U
#define ARGON2D_SALT_LENGTH   16U
#define ARGON2D_OUTPUT_LENGTH (ARGON2D_SALT_LENGTH + ARGON2D_DIGEST_LENGTH)
#define ARGON2D_T_COST        3U
#define ARGON2D_M_COST        65536U
#define ARGON2D_PARALLELISM   4U

/* Fixed salt — 8b30da014d96e374876d0d2523c5b844 */
static const ut8 argon2d_fixed_salt[ARGON2D_SALT_LENGTH] = {
	0x8b, 0x30, 0xda, 0x01, 0x4d, 0x96, 0xe3, 0x74,
	0x87, 0x6d, 0x0d, 0x25, 0x23, 0xc5, 0xb8, 0x44
};

typedef struct {
	ut8 *buf;
	ut64 len;
	ut64 cap;
} plugin_argon2d_state;

static void *plugin_argon2d_context_new(void) {
	return RZ_NEW0(plugin_argon2d_state);
}

static void plugin_argon2d_context_free(void *context) {
	if (!context) {
		return;
	}
	plugin_argon2d_state *st = (plugin_argon2d_state *)context;
	if (st->buf) {
		rz_mem_memzero(st->buf, (size_t)st->cap);
		free(st->buf);
	}
	free(st);
}

static RzHashSize plugin_argon2d_digest_size(void *context) {
	return ARGON2D_OUTPUT_LENGTH;
}

static RzHashSize plugin_argon2d_block_size(void *context) {
	return 1;
}

static bool plugin_argon2d_init(void *context) {
	rz_return_val_if_fail(context, false);
	plugin_argon2d_state *st = (plugin_argon2d_state *)context;
	if (st->buf) {
		rz_mem_memzero(st->buf, (size_t)st->cap);
	}
	st->len = 0;
	return true;
}

static bool plugin_argon2d_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	if (size == 0) {
		return true;
	}
	plugin_argon2d_state *st = (plugin_argon2d_state *)context;
	ut64 needed = st->len + size;
	if (needed > st->cap) {
		ut64 new_cap = needed * 2;
		ut8 *nb = (ut8 *)realloc(st->buf, (size_t)new_cap);
		if (!nb) {
			return false;
		}
		st->buf = nb;
		st->cap = new_cap;
	}
	memcpy(st->buf + (size_t)st->len, data, (size_t)size);
	st->len += size;
	return true;
}

static bool plugin_argon2d_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	plugin_argon2d_state *st = (plugin_argon2d_state *)context;
	if (st->len == 0) {
		return false;
	}

	ut8 *salt = digest;
	ut8 *dgst = digest + ARGON2D_SALT_LENGTH;

	memcpy(salt, argon2d_fixed_salt, ARGON2D_SALT_LENGTH);

	int ret = argon2d_hash_raw(
		ARGON2D_T_COST, ARGON2D_M_COST, ARGON2D_PARALLELISM,
		st->buf, (size_t)st->len,
		salt, ARGON2D_SALT_LENGTH,
		dgst, ARGON2D_DIGEST_LENGTH);

	if (st->buf) {
		rz_mem_memzero(st->buf, (size_t)st->cap);
	}
	st->len = 0;
	return ret == ARGON2_OK;
}

static bool plugin_argon2d_small_block(const ut8 *data, ut64 size,
	ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	if (size == 0) {
		return false;
	}
	ut8 *out = (ut8 *)malloc(ARGON2D_OUTPUT_LENGTH);
	if (!out) {
		return false;
	}
	ut8 *salt = out;
	ut8 *dgst = out + ARGON2D_SALT_LENGTH;

	memcpy(salt, argon2d_fixed_salt, ARGON2D_SALT_LENGTH);

	int ret = argon2d_hash_raw(
		ARGON2D_T_COST, ARGON2D_M_COST, ARGON2D_PARALLELISM,
		data, (size_t)size,
		salt, ARGON2D_SALT_LENGTH,
		dgst, ARGON2D_DIGEST_LENGTH);

	if (ret != ARGON2_OK) {
		free(out);
		return false;
	}
	*digest = out;
	if (digest_size) {
		*digest_size = ARGON2D_OUTPUT_LENGTH;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_argon2d = {
	.name = "argon2d",
	.author = "Farhan-25",
	.license = "CC0",
	.description = "Argon2d checksum",
	.support_hmac = false,
	.context_new = plugin_argon2d_context_new,
	.context_free = plugin_argon2d_context_free,
	.digest_size = plugin_argon2d_digest_size,
	.block_size = plugin_argon2d_block_size,
	.init = plugin_argon2d_init,
	.update = plugin_argon2d_update,
	.final = plugin_argon2d_final,
	.small_block = plugin_argon2d_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_argon2d,
	.version = RZ_VERSION
};
#endif
