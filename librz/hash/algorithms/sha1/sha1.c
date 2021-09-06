// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "sha1.h"
#include <rz_types.h>
#include <rz_endian.h>
#include <rz_util.h>

void rz_sha1_init(RzSHA1 *context) {
	rz_return_if_fail(context);

	context->digest[0] = 0x67452301;
	context->digest[1] = 0xEFCDAB89;
	context->digest[2] = 0x98BADCFE;
	context->digest[3] = 0x10325476;
	context->digest[4] = 0xC3D2E1F0;
	context->index = 0;
	context->len_high = 0;
	context->len_low = 0;
}

static inline ut32 rotate_left_32(ut32 value, ut32 rot) {
	return ((((value) << (rot)) & 0xFFFFFFFF) | ((value) >> (32 - (rot))));
}

static void sha1_digest_block(RzSHA1 *context) {
	ut32 tmp;
	ut32 W[80];
	ut32 A = context->digest[0];
	ut32 B = context->digest[1];
	ut32 C = context->digest[2];
	ut32 D = context->digest[3];
	ut32 E = context->digest[4];

	for (ut32 t = 0; t < 16; ++t) {
		W[t] = rz_read_at_be32(context->block, t * 4);
	}

	for (ut32 t = 16; t < 80; ++t) {
		W[t] = rotate_left_32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
	}

	for (ut32 t = 0; t < 20; ++t) {
		tmp = rotate_left_32(A, 5) + ((B & C) | ((~B) & D)) + E + W[t] + 0x5A827999;
		E = D;
		D = C;
		C = rotate_left_32(B, 30);
		B = A;
		A = tmp;
	}

	for (ut32 t = 20; t < 40; ++t) {
		tmp = rotate_left_32(A, 5) + (B ^ C ^ D) + E + W[t] + 0x6ED9EBA1;
		E = D;
		D = C;
		C = rotate_left_32(B, 30);
		B = A;
		A = tmp;
	}

	for (ut32 t = 40; t < 60; ++t) {
		tmp = rotate_left_32(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[t] + 0x8F1BBCDC;
		E = D;
		D = C;
		C = rotate_left_32(B, 30);
		B = A;
		A = tmp;
	}

	for (ut32 t = 60; t < 80; ++t) {
		tmp = rotate_left_32(A, 5) + (B ^ C ^ D) + E + W[t] + 0xCA62C1D6;
		E = D;
		D = C;
		C = rotate_left_32(B, 30);
		B = A;
		A = tmp;
	}

	context->digest[0] += A;
	context->digest[1] += B;
	context->digest[2] += C;
	context->digest[3] += D;
	context->digest[4] += E;

	context->index = 0;
}

bool rz_sha1_update(RzSHA1 *context, const ut8 *data, ut64 length) {
	rz_return_val_if_fail(context && data, false);
	for (ut64 i = 0; i < length; ++i) {
		context->block[context->index++] = data[i];

		context->len_low += 8;
		if (context->len_low > 0xFFFFFFFFull) {
			context->len_low &= 0xFFFFFFFFull;
			context->len_high++;
			// check if digested data overflows UT64
			if (context->len_high > 0xFFFFFFFFull) {
				return false;
			}
		}

		// digest only 512 bit blocks
		if (context->index == RZ_HASH_SHA1_BLOCK_LENGTH) {
			sha1_digest_block(context);
		}
	}

	return true;
}

void sha1_padding(RzSHA1 *context) {
	if (context->index > 55) {
		context->block[context->index++] = 0x80;
		for (; context->index < RZ_HASH_SHA1_BLOCK_LENGTH;) {
			context->block[context->index++] = 0;
		}

		sha1_digest_block(context);

		for (; context->index < 56;) {
			context->block[context->index++] = 0;
		}
	} else {
		context->block[context->index++] = 0x80;
		for (; context->index < 56;) {
			context->block[context->index++] = 0;
		}
	}

	rz_write_be32(&context->block[56], context->len_high);
	rz_write_be32(&context->block[60], context->len_low);

	sha1_digest_block(context);
}

void rz_sha1_fini(ut8 *hash, RzSHA1 *context) {
	rz_return_if_fail(context && hash);

	sha1_padding(context);

	for (ut32 t = 0; t < 5; ++t) {
		rz_write_at_be32(hash, context->digest[t], t * 4);
	}
}
