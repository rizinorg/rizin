// SPDX-FileCopyrightText: 2026 AHMEDSAMI11
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#define DJB2_INIT                 5381UL
#define RZ_HASH_DJB2_DIGEST_SIZE  4
#define RZ_HASH_DJB2_BLOCK_LENGTH 0

typedef struct {
	ut32 hash;
} DJB2State;

static void *plugin_djb2_context_new() {
	DJB2State *s = RZ_NEW0(DJB2State);
	return s;
}
static void plugin_djb2_context_free(void *context) {
	free(context);
}
static RzHashSize plugin_djb2_digest_size(void *context) {
	return RZ_HASH_DJB2_DIGEST_SIZE;
}
static RzHashSize plugin_djb2_block_size(void *context) {
	return RZ_HASH_DJB2_BLOCK_LENGTH;
}
static bool plugin_djb2_init(void *context) {
	rz_return_val_if_fail(context, false);
	DJB2State *s = (DJB2State *)context;
	s->hash = DJB2_INIT;
	return true;
}
static bool plugin_djb2_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	DJB2State *s = (DJB2State *)context;
	for (ut64 i = 0; i < size; i++) {
		s->hash = ((s->hash << 5) + s->hash) ^ (ut32)data[i];
	}
	return true;
}
static bool plugin_djb2_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	DJB2State *s = (DJB2State *)context;
	rz_write_le32(digest, s->hash);
	return true;
}
static bool plugin_djb2_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_DJB2_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}
	ut32 hash = DJB2_INIT;
	for (ut64 i = 0; i < size; i++) {
		hash = ((hash << 5) + hash) ^ (ut32)data[i];
	}
	rz_write_le32(dgst, hash);
	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_DJB2_DIGEST_SIZE;
	}
	return true;
}
RzHashPlugin rz_hash_plugin_djb2 = {
	.name = "djb2",
	.license = "LGPL3",
	.author = "AHMEDSAMI11",
	.description = "djb2 non-cryptographic hash",
	.support_hmac = false,
	.context_new = plugin_djb2_context_new,
	.context_free = plugin_djb2_context_free,
	.digest_size = plugin_djb2_digest_size,
	.block_size = plugin_djb2_block_size,
	.init = plugin_djb2_init,
	.update = plugin_djb2_update,
	.final = plugin_djb2_final,
	.small_block = plugin_djb2_small_block,
};
#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_djb2,
	.version = RZ_VERSION
};
#endif
