// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/fletcher/fletcher.h"

#define rz_fletcher_common_plugin_context_new(bits) \
	static void *plugin_fletcher##bits##_context_new() { \
		return RZ_NEW0(RzFletcher##bits); \
	}

#define rz_fletcher_common_plugin_context_free(bits) \
	static void plugin_fletcher##bits##_context_free(void *context) { \
		free(context); \
	}

#define rz_fletcher_common_plugin_digest_size(bits) \
	static RzHashSize plugin_fletcher##bits##_digest_size(void *context) { \
		return RZ_HASH_FLETCHER##bits##_DIGEST_SIZE; \
	}

#define rz_fletcher_common_plugin_init(bits) \
	static bool plugin_fletcher##bits##_init(void *context) { \
		rz_return_val_if_fail(context, false); \
		rz_fletcher##bits##_init((RzFletcher##bits *)context); \
		return true; \
	}

#define rz_fletcher_common_plugin_update(bits) \
	static bool plugin_fletcher##bits##_update(void *context, const ut8 *data, ut64 size) { \
		rz_return_val_if_fail(context && data, false); \
		rz_fletcher##bits##_update((RzFletcher##bits *)context, data, size); \
		return true; \
	}

#define rz_fletcher_common_plugin_final(bits) \
	static bool plugin_fletcher##bits##_final(void *context, ut8 *digest) { \
		rz_return_val_if_fail(context && digest, false); \
		rz_fletcher##bits##_final(digest, (RzFletcher##bits *)context); \
		return true; \
	}

#define rz_fletcher_common_plugin_small_block(bits) \
	static bool plugin_fletcher##bits##_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) { \
		rz_return_val_if_fail(data && digest, false); \
		ut8 *dgst = malloc(RZ_HASH_FLETCHER##bits##_DIGEST_SIZE); \
		if (!dgst) { \
			return false; \
		} \
		RzFletcher##bits ctx; \
		rz_fletcher##bits##_init(&ctx); \
		rz_fletcher##bits##_update(&ctx, data, size); \
		rz_fletcher##bits##_final(dgst, &ctx); \
		*digest = dgst; \
		if (digest_size) { \
			*digest_size = RZ_HASH_FLETCHER##bits##_DIGEST_SIZE; \
		} \
		return true; \
	}

#ifndef RZ_PLUGIN_INCORE
#define rz_lib_fletcher_common(bits) \
	RZ_API RzLibStruct rizin_plugin = { \
		.type = RZ_LIB_TYPE_HASH, \
		.data = &rz_hash_plugin_fletcher##bits, \
		.version = RZ_VERSION \
	}
#else
#define rz_lib_fletcher_common(bits)
#endif

#define rz_fletcher_common_plugin_define_hash_cfg(bits) \
	rz_fletcher_common_plugin_context_new(bits); \
	rz_fletcher_common_plugin_context_free(bits); \
	rz_fletcher_common_plugin_digest_size(bits); \
	rz_fletcher_common_plugin_init(bits); \
	rz_fletcher_common_plugin_update(bits); \
	rz_fletcher_common_plugin_final(bits); \
	rz_fletcher_common_plugin_small_block(bits); \
	RzHashPlugin rz_hash_plugin_fletcher##bits = { \
		.name = "fletcher" #bits, \
		.license = "LGPL3", \
		.author = "deroad", \
		.description = "Fletcher" #bits " checksum", \
		.support_hmac = false, \
		.context_new = plugin_fletcher##bits##_context_new, \
		.context_free = plugin_fletcher##bits##_context_free, \
		.digest_size = plugin_fletcher##bits##_digest_size, \
		.block_size = plugin_fletcher_block_size, \
		.init = plugin_fletcher##bits##_init, \
		.update = plugin_fletcher##bits##_update, \
		.final = plugin_fletcher##bits##_final, \
		.small_block = plugin_fletcher##bits##_small_block, \
	}; \
	rz_lib_fletcher_common(bits)

static RzHashSize plugin_fletcher_block_size(void *context) {
	return RZ_HASH_FLETCHER_BLOCK_LENGTH;
}

rz_fletcher_common_plugin_define_hash_cfg(8);
rz_fletcher_common_plugin_define_hash_cfg(16);
rz_fletcher_common_plugin_define_hash_cfg(32);
rz_fletcher_common_plugin_define_hash_cfg(64);
