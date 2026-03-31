// SPDX-FileCopyrightText: 2025 Seva <little_scamp@yahoo.comt>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/temperature/temperature.h"

static void *plugin_temperature_context_new() {
	return RZ_NEW0(RzTemperature);
}

static void plugin_temperature_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_temperature_digest_size(void *context) {
	return RZ_HASH_TEMPERATURE_DIGEST_SIZE;
}

static RzHashSize plugin_temperature_block_size(void *context) {
	return RZ_HASH_TEMPERATURE_BLOCK_LENGTH;
}

static bool plugin_temperature_init(void *context) {
	rz_return_val_if_fail(context, false);

	rz_temperature_init((RzTemperature *)context);
	return true;
}

static bool plugin_temperature_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	rz_temperature_update((RzTemperature *)context, data, size);
	return true;
}

static bool plugin_temperature_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);

	rz_temperature_final(digest, (RzTemperature *)context, false);
	return true;
}

static bool plugin_temperature_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) {
	rz_return_val_if_fail(data && digest, false);
	ut8 *dgst = malloc(RZ_HASH_TEMPERATURE_DIGEST_SIZE);
	if (!dgst) {
		return false;
	}

	RzTemperature ctx;
	rz_temperature_init(&ctx);
	rz_temperature_update(&ctx, data, size);
	rz_temperature_final(dgst, &ctx, false);

	*digest = dgst;
	if (digest_size) {
		*digest_size = RZ_HASH_TEMPERATURE_DIGEST_SIZE;
	}
	return true;
}

RzHashPlugin rz_hash_plugin_temperature = {
	.name = "temperature",
	.license = "LGPL3",
	.author = "Seva",
	.description = "Binary temperature [0.0-1.0] range",
	.support_hmac = false,
	.context_new = plugin_temperature_context_new,
	.context_free = plugin_temperature_context_free,
	.digest_size = plugin_temperature_digest_size,
	.block_size = plugin_temperature_block_size,
	.init = plugin_temperature_init,
	.update = plugin_temperature_update,
	.final = plugin_temperature_final,
	.small_block = plugin_temperature_small_block,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_HASH,
	.data = &rz_hash_plugin_temperature,
	.version = RZ_VERSION
};
#endif
