// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "fletcher.h"
#include <rz_util.h>

// Fletcher 8

bool rz_fletcher8_init(RzFletcher8 *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzFletcher8));
	return true;
}

bool rz_fletcher8_update(RzFletcher8 *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	for (size_t i = 0; i < len; i++) {
		ctx->low += data[i];
		ctx->low = (ctx->low & 0xff) + (ctx->low >> 8);
		ctx->high += ctx->low;
		ctx->high = (ctx->high & 0xff) + (ctx->high >> 8);
	}
	return true;
}

bool rz_fletcher8_final(ut8 *digest, RzFletcher8 *ctx) {
	rz_return_val_if_fail(ctx && digest, false);
	rz_write_le8(digest, (ctx->low & 0xff));
	return true;
}

// Fletcher 16

bool rz_fletcher16_init(RzFletcher16 *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzFletcher16));
	return true;
}

bool rz_fletcher16_update(RzFletcher16 *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	size_t i;
	for (; len >= 5802; len -= 5802) {
		for (i = 0; i < 5802; i++) {
			ctx->low = ctx->low + *data++;
			ctx->high = ctx->high + ctx->low;
		}
		ctx->low %= 0xff;
		ctx->high %= 0xff;
	}
	for (i = 0; i < len; i++) {
		ctx->low += *data++;
		ctx->high += ctx->low;
	}
	return true;
}

bool rz_fletcher16_final(ut8 *digest, RzFletcher16 *ctx) {
	rz_return_val_if_fail(ctx && digest, false);
	ctx->low %= 0xff;
	ctx->high %= 0xff;
	rz_write_le16(digest, (ctx->high << 8 | ctx->low));
	return true;
}

// Fletcher 32

bool rz_fletcher32_init(RzFletcher32 *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzFletcher32));
	return true;
}

bool rz_fletcher32_update(RzFletcher32 *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	size_t i;
	ut8 word[sizeof(ut16)];
	for (; len >= 360; len -= 360) {
		for (i = 0; i < 360; i += 2) {
			size_t left = 360 - i;
			memset(word, 0, sizeof(word));
			memcpy(word, data, RZ_MIN(sizeof(word), left));
			ctx->low += rz_read_le16(word);
			ctx->high += ctx->low;
			data += 2;
		}
		ctx->low %= UT16_MAX;
		ctx->high %= UT16_MAX;
	}
	for (i = 0; i < len; i += 2) {
		size_t left = len - i;
		memset(word, 0, sizeof(word));
		memcpy(word, data, RZ_MIN(sizeof(word), left));
		ctx->low += rz_read_le16(word);
		ctx->high += ctx->low;
		data += 2;
	}
	return true;
}

bool rz_fletcher32_final(ut8 *digest, RzFletcher32 *ctx) {
	rz_return_val_if_fail(ctx && digest, false);
	ctx->low %= UT16_MAX;
	ctx->high %= UT16_MAX;
	rz_write_le32(digest, ctx->high << 16 | ctx->low);
	return true;
}

// Fletcher 64

bool rz_fletcher64_init(RzFletcher64 *ctx) {
	rz_return_val_if_fail(ctx, false);
	memset(ctx, 0, sizeof(RzFletcher64));
	return true;
}

bool rz_fletcher64_update(RzFletcher64 *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);

	ut8 word[sizeof(ut32)];
	for (size_t i = 0; i < len; i += sizeof(ut32)) {
		size_t left = RZ_MIN(sizeof(ut32), len - i);
		memset(word, 0, sizeof(word));
		memcpy(word, &data[i], left);
		ut32 value = rz_read_le32(word);
		ctx->low += value;
		ctx->high += ctx->low;
	}
	return true;
}

bool rz_fletcher64_final(ut8 *digest, RzFletcher64 *ctx) {
	rz_return_val_if_fail(ctx && digest, false);
	rz_write_le64(digest, ((ut64)ctx->high << 32) | ctx->low);
	return true;
}
