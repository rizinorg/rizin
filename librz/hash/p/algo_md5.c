// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_hash_cfg(md5, EVP_md5, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/md5/md5.h"

static void *plugin_md5_context_new() {
	return RZ_NEW0(rz_MD5_CTX);
}

static void plugin_md5_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_md5_digest_size(void *context) {
	return RZ_HASH_MD5_DIGEST_SIZE;
}

static RzHashSize plugin_md5_block_size(void *context) {
	return RZ_HASH_MD5_BLOCK_LENGTH;
}

static bool plugin_md5_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_MD5Init((rz_MD5_CTX *)context);
	return true;
}

static bool plugin_md5_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_MD5Update((rz_MD5_CTX *)context, data, size);
	return true;
}

static bool plugin_md5_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_MD5Final(digest, (rz_MD5_CTX *)context);
	return true;
}

static bool plugin_md5_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_MD5_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	rz_MD5_CTX ctx;
	rz_MD5Init(&ctx);
	rz_MD5Update(&ctx, data, size);
	rz_MD5Final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_MD5_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_md5 = {
	.name = "md5",
	.license = "LGPL2",
	.author = "Alan DeKok",
	.description = "MD5 cryptographic hash",
	.support_hmac = true,
	.context_new = plugin_md5_context_new,
	.context_free = plugin_md5_context_free,
	.digest_size = plugin_md5_digest_size,
	.block_size = plugin_md5_block_size,
	.init = plugin_md5_init,
	.update = plugin_md5_update,
	.final = plugin_md5_final,
	.small_block = plugin_md5_small_block,
};

#endif /* HAVE_LIB_SSL */

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_md5,
	.version = RZ_VERSION
};
#endif
