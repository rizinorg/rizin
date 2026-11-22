// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-FileCopyrightText: 2024 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <capstone/capstone.h>
#include <capstone/alpha.h>
#include "alpha.h"

static inline bool alpha_setup_cs_handle(RzAsmAlphaContext *ctx, const char *cpu, const char *features, bool big_endian) {
	const cs_mode mode = big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
	if (mode != ctx->mode) {
		cs_close(&ctx->h);
		ctx->h = 0;
		ctx->mode = mode;
	}

	if (ctx->h != 0) {
		return true;
	}
	cs_err err = cs_open(CS_ARCH_ALPHA, mode, &ctx->h);
	if (err) {
		RZ_LOG_ERROR("Failed on cs_open() with error returned: %u\n", err);
		return false;
	}
	err = cs_option(ctx->h, CS_OPT_DETAIL,
		RZ_STR_ISNOTEMPTY(features) || features == NULL ? CS_OPT_ON : CS_OPT_OFF);
	if (err) {
		RZ_LOG_ERROR("Failed on cs_open() with error returned: %u\n", err);
		return false;
	}
	return true;
}
