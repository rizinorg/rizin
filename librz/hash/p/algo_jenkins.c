// SPDX-FileCopyrightText: 2026 shessaanand
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/jenkins/jenkins.h"
#include <rz_lib.h>

#define RZ_HASH_JENKINS_DIGEST_SIZE 4
#define RZ_HASH_JENKINS_BLOCK_LENGTH 0


static void *plugin_jenkins_context_new() {
	return RZ_NEW0(RzJenkins);
}

static void plugin_jenkins_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_jenkins_digest_size(void *context) {
	return RZ_HASH_JENKINS_DIGEST_SIZE;
}

static RzHashSize plugin_jenkins_block_size(void *context) {
	return RZ_HASH_JENKINS_BLOCK_LENGTH;
}

static bool plugin_jenkins_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_jenkins_init((RzJenkins *)context);
	return true;
}

static bool plugin_jenkins_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_jenkins_update((RzJenkins *)context, data, size);
	return true;
}

static bool plugin_jenkins_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_jenkins_final(digest, (RzJenkins *)context);
	return true;
}

static bool plugin_jenkins_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_JENKINS_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzJenkins ctx={ 0 };
	jenkins_init(&ctx);
	jenkins_update(&ctx, data, size);
	jenkins_final(dgst, &ctx);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_JENKINS_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_jenkins = {
	.name = "jenkins",
	.license = "LGPL3",
	.author = "shessaanand",
	.description = "Jenkins one-at-a-time hash",
	.support_hmac = false,
	.context_new = plugin_jenkins_context_new,
	.context_free = plugin_jenkins_context_free,
	.digest_size = plugin_jenkins_digest_size,
	.block_size = plugin_jenkins_block_size,
	.init = plugin_jenkins_init,
	.update = plugin_jenkins_update,
	.final = plugin_jenkins_final,
	.small_block = plugin_jenkins_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_jenkins,
	.version = RZ_VERSION
};
#endif
