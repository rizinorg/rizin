// SPDX-FileCopyrightText: 2026 AHMEDSAMI11
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_hash.h>
#include <rz_util/rz_assert.h>

/* FNV-1a 32-bit constants */
#define FNV1A_32_OFFSET_BASIS 0x811c9dc5UL
#define FNV1A_32_PRIME        0x01000193UL
#define RZ_HASH_FNV1A32_DIGEST_SIZE  4
#define RZ_HASH_FNV1A32_BLOCK_LENGTH 0

/* FNV-1a 64-bit constants */
#define FNV1A_64_OFFSET_BASIS 0xcbf29ce484222325ULL
#define FNV1A_64_PRIME        0x00000100000001b3ULL
#define RZ_HASH_FNV1A64_DIGEST_SIZE  8
#define RZ_HASH_FNV1A64_BLOCK_LENGTH 0

/* ── state structs ── */
typedef struct { ut32 hash; } FNV1a32State;
typedef struct { ut64 hash; } FNV1a64State;

/* ════════════════════════════════
 *  FNV-1a 32-bit
 * ════════════════════════════════ */
static void *plugin_fnv1a32_context_new() {
	FNV1a32State *s = RZ_NEW0(FNV1a32State);
	return s;
}
static void plugin_fnv1a32_context_free(void *context) {
	free(context);
}
static RzHashSize plugin_fnv1a32_digest_size(void *context) {
	return RZ_HASH_FNV1A32_DIGEST_SIZE;
}
static RzHashSize plugin_fnv1a32_block_size(void *context) {
	return RZ_HASH_FNV1A32_BLOCK_LENGTH;
}
static bool plugin_fnv1a32_init(void *context) {
	rz_return_val_if_fail(context, false);
	FNV1a32State *s = (FNV1a32State *)context;
	s->hash = FNV1A_32_OFFSET_BASIS;
	return true;
}
static bool plugin_fnv1a32_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	FNV1a32State *s = (FNV1a32State *)context;
	for (ut64 i = 0; i < size; i++) {
		s->hash ^= (ut32)data[i];
		s->hash *= FNV1A_32_PRIME;
	}
	return true;
}
static bool plugin_fnv1a32_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	FNV1a32State *s = (FNV1a32State *)context;
	rz_write_le32(digest, s->hash);
	return true;
}
static bool plugin_fnv1a32_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_FNV1A32_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}
	ut32 hash = FNV1A_32_OFFSET_BASIS;
	for (ut64 i = 0; i < size; i++) {
		hash ^= (ut32)data[i];
		hash *= FNV1A_32_PRIME;
	}
	rz_write_le32(dgst, hash);
	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_FNV1A32_DIGEST_SIZE;
	}
	return true;
}
RzHashPlugin rz_hash_plugin_fnv1a32 = {
	.name = "fnv1a32",
	.license = "LGPL-3.0-only",
	.author = "AHMEDSAMI11",
	.description = "FNV-1a 32-bit non-cryptographic hash (common in malware for API hashing)",
	.support_hmac = false,
	.context_new = plugin_fnv1a32_context_new,
	.context_free = plugin_fnv1a32_context_free,
	.digest_size = plugin_fnv1a32_digest_size,
	.block_size = plugin_fnv1a32_block_size,
	.init = plugin_fnv1a32_init,
	.update = plugin_fnv1a32_update,
	.final = plugin_fnv1a32_final,
	.small_block = plugin_fnv1a32_small_block,
};
#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_fnv1a32,
	.version = RZ_VERSION
};
#endif

/* ════════════════════════════════
 *  FNV-1a 64-bit
 * ════════════════════════════════ */
static void *plugin_fnv1a64_context_new() {
	FNV1a64State *s = RZ_NEW0(FNV1a64State);
	return s;
}
static void plugin_fnv1a64_context_free(void *context) {
	free(context);
}
static RzHashSize plugin_fnv1a64_digest_size(void *context) {
	return RZ_HASH_FNV1A64_DIGEST_SIZE;
}
static RzHashSize plugin_fnv1a64_block_size(void *context) {
	return RZ_HASH_FNV1A64_BLOCK_LENGTH;
}
static bool plugin_fnv1a64_init(void *context) {
	rz_return_val_if_fail(context, false);
	FNV1a64State *s = (FNV1a64State *)context;
	s->hash = FNV1A_64_OFFSET_BASIS;
	return true;
}
static bool plugin_fnv1a64_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);
	FNV1a64State *s = (FNV1a64State *)context;
	for (ut64 i = 0; i < size; i++) {
		s->hash ^= (ut64)data[i];
		s->hash *= FNV1A_64_PRIME;
	}
	return true;
}
static bool plugin_fnv1a64_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	FNV1a64State *s = (FNV1a64State *)context;
	rz_write_le64(digest, s->hash);
	return true;
}
static bool plugin_fnv1a64_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_FNV1A64_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}
	ut64 hash = FNV1A_64_OFFSET_BASIS;
	for (ut64 i = 0; i < size; i++) {
		hash ^= (ut64)data[i];
		hash *= FNV1A_64_PRIME;
	}
	rz_write_le64(dgst, hash);
	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_FNV1A64_DIGEST_SIZE;
	}
	return true;
}
RzHashPlugin rz_hash_plugin_fnv1a64 = {
	.name = "fnv1a64",
	.license = "LGPL-3.0-only",
	.author = "AHMEDSAMI11",
	.description = "FNV-1a 64-bit non-cryptographic hash (common in malware for API hashing)",
	.support_hmac = false,
	.context_new = plugin_fnv1a64_context_new,
	.context_free = plugin_fnv1a64_context_free,
	.digest_size = plugin_fnv1a64_digest_size,
	.block_size = plugin_fnv1a64_block_size,
	.init = plugin_fnv1a64_init,
	.update = plugin_fnv1a64_update,
	.final = plugin_fnv1a64_final,
	.small_block = plugin_fnv1a64_small_block,
};
#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_fnv1a64,
	.version = RZ_VERSION
};
#endif
