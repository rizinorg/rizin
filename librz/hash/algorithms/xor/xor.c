// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "xor.h"
#include <rz_util.h>

bool rz_xor8_init(RzXor8 *ctx) {
	rz_return_val_if_fail(ctx, false);
	*ctx = 0;
	return true;
}

bool rz_xor8_update(RzXor8 *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	ut8 value = *ctx;
	for (size_t i = 0; i < len; ++i) {
		value ^= data[i];
	}
	*ctx = value;
	return true;
}

bool rz_xor8_final(ut8 *digest, RzXor8 *ctx) {
	rz_return_val_if_fail(digest && ctx, false);
	*digest = *ctx;
	return true;
}

bool rz_xor16_init(RzXor16 *ctx) {
	rz_return_val_if_fail(ctx, false);
	*ctx = 0;
	return true;
}

bool rz_xor16_update(RzXor16 *ctx, const ut8 *data, size_t len) {
	rz_return_val_if_fail(ctx && data, false);
	ut16 value = *ctx;
	for (size_t i = 0; i < len; i += sizeof(ut16)) {
		if (len - i > sizeof(ut16)) {
			value ^= rz_read_at_le16(data, i);
		} else {
			value ^= (((ut16)data[i]) << 8);
		}
	}
	*ctx = value;
	return true;
}

bool rz_xor16_final(ut8 *digest, RzXor16 *ctx) {
	rz_return_val_if_fail(digest && ctx, false);
	rz_write_le16(digest, *ctx);
	return true;
}
