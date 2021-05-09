// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_msg_digest.h>
#include <rz_util/rz_assert.h>

#if HAVE_LIB_SSL
/**
 * Use OpenSSL lib, not the Rizin implementation
 */

#include "../algorithms/openssl_common.h"
rz_openssl_plugin_define_msg_digest(md5, EVP_md5, true);

#else /* HAVE_LIB_SSL */
/**
 * Use Rizin implementation, not OpenSSL lib
 */

#include "../algorithms/md5/md5.h"

static void *plugin_md5_context_new() {
	return RZ_NEW0(MD5_CTX);
}

static void plugin_md5_context_free(void *context) {
	free(context);
}

static RzMsgDigestSize plugin_md5_digest_size(void *context) {
	return RZ_HASH_MD5_DIGEST_SIZE;
}

static RzMsgDigestSize plugin_md5_block_size(void *context) {
	return RZ_HASH_MD5_BLOCK_LENGTH;
}

static bool plugin_md5_init(void *context) {
	rz_return_val_if_fail(context, false);

	MD5_Init((MD5_CTX *)context);
	return true;
}

static bool plugin_md5_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	MD5_Update((MD5_CTX *)context, data, size);
	return true;
}

static bool plugin_md5_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	MD5_Final(digest, (MD5_CTX *)context);
	return true;
}

static bool plugin_md5_small_block(const ut8 *data, ut64 size, ut8 **digest, RzMsgDigestSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_MD5_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, data, size);
	MD5_Final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_MD5_DIGEST_SIZE;
	}
	return true;
}

RzMsgDigestPlugin rz_msg_digest_plugin_md5 = {
	.name = "md5",
	.license = "RSA-MD",
	.author = "RSA Data Security, Inc.",
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
	.type = RZ_LIB_TYPE_MD,
	.data = &rz_msg_digest_plugin_md5,
	.version = RZ_VERSION
};
#endif
