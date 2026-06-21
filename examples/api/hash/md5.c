// SPDX-FileCopyrightText: 2025 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <stdio.h>
#include <string.h>

int main(void) {
	RzHash *ctx = rz_hash_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create rz_hash context\n");
		return 1;
	}

	RzHashCfg *cfg = rz_hash_cfg_new_with_algo(ctx, "md5", NULL, 0);
	if (!cfg) {
		fprintf(stderr, "Failed to create md5 config\n");
		rz_hash_free(ctx);
		return 1;
	}

	const char *data = "Hello, world!";
	rz_hash_cfg_update(cfg, (const ut8 *)data, strlen(data));
	rz_hash_cfg_final(cfg);

	char *hex_digest = rz_hash_cfg_get_result_string(cfg, "md5", NULL, false);
	if (hex_digest) {
		printf("%s\n", hex_digest);
		free(hex_digest);
	}

	rz_hash_cfg_free(cfg);
	rz_hash_free(ctx);
	return 0;
}
