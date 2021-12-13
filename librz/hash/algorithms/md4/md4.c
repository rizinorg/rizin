// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "md4.h"
#include <rz_types.h>
#include <rz_endian.h>
#include <rz_util.h>

#define XAX(x, y, z) (z ^ (x & (y ^ z)))
#define AAA(x, y, z) ((x & y) | (x & z) | (y & z))
#define XXX(x, y, z) (x ^ y ^ z)

#define md4_round(m, w, x, y, z, v, s) \
	w += m(x, y, z) + v; \
	w = rotate_left_32(w, s)

void rz_md4_init(RzMD4 *context) {
	rz_return_if_fail(context);

	context->digest[0] = 0x67452301;
	context->digest[1] = 0xEFCDAB89;
	context->digest[2] = 0x98BADCFE;
	context->digest[3] = 0x10325476;
	context->index = 0;
	context->len_high = 0;
	context->len_low = 0;
}

static inline ut32 rotate_left_32(ut32 value, ut32 rot) {
	return ((((value) << (rot)) & 0xFFFFFFFF) | ((value) >> (32 - (rot))));
}

static void md4_digest_block(RzMD4 *context) {
	// printb(context->block, 64);

	ut32 W[16];
	ut32 A = context->digest[0];
	ut32 B = context->digest[1];
	ut32 C = context->digest[2];
	ut32 D = context->digest[3];

	for (ut32 t = 0; t < 16; ++t) {
		W[t] = rz_read_at_le32(context->block, t * 4);
	}

	md4_round(XAX, A, B, C, D, W[/* */ 0], 3);
	md4_round(XAX, D, A, B, C, W[/* */ 1], 7);
	md4_round(XAX, C, D, A, B, W[/* */ 2], 11);
	md4_round(XAX, B, C, D, A, W[/* */ 3], 19);
	md4_round(XAX, A, B, C, D, W[/* */ 4], 3);
	md4_round(XAX, D, A, B, C, W[/* */ 5], 7);
	md4_round(XAX, C, D, A, B, W[/* */ 6], 11);
	md4_round(XAX, B, C, D, A, W[/* */ 7], 19);
	md4_round(XAX, A, B, C, D, W[/* */ 8], 3);
	md4_round(XAX, D, A, B, C, W[/* */ 9], 7);
	md4_round(XAX, C, D, A, B, W[/**/ 10], 11);
	md4_round(XAX, B, C, D, A, W[/**/ 11], 19);
	md4_round(XAX, A, B, C, D, W[/**/ 12], 3);
	md4_round(XAX, D, A, B, C, W[/**/ 13], 7);
	md4_round(XAX, C, D, A, B, W[/**/ 14], 11);
	md4_round(XAX, B, C, D, A, W[/**/ 15], 19);

	md4_round(AAA, A, B, C, D, W[/* */ 0] + 0x5A827999, 3);
	md4_round(AAA, D, A, B, C, W[/* */ 4] + 0x5A827999, 5);
	md4_round(AAA, C, D, A, B, W[/* */ 8] + 0x5A827999, 9);
	md4_round(AAA, B, C, D, A, W[/**/ 12] + 0x5A827999, 13);
	md4_round(AAA, A, B, C, D, W[/* */ 1] + 0x5A827999, 3);
	md4_round(AAA, D, A, B, C, W[/* */ 5] + 0x5A827999, 5);
	md4_round(AAA, C, D, A, B, W[/* */ 9] + 0x5A827999, 9);
	md4_round(AAA, B, C, D, A, W[/**/ 13] + 0x5A827999, 13);
	md4_round(AAA, A, B, C, D, W[/* */ 2] + 0x5A827999, 3);
	md4_round(AAA, D, A, B, C, W[/* */ 6] + 0x5A827999, 5);
	md4_round(AAA, C, D, A, B, W[/**/ 10] + 0x5A827999, 9);
	md4_round(AAA, B, C, D, A, W[/**/ 14] + 0x5A827999, 13);
	md4_round(AAA, A, B, C, D, W[/* */ 3] + 0x5A827999, 3);
	md4_round(AAA, D, A, B, C, W[/* */ 7] + 0x5A827999, 5);
	md4_round(AAA, C, D, A, B, W[/**/ 11] + 0x5A827999, 9);
	md4_round(AAA, B, C, D, A, W[/**/ 15] + 0x5A827999, 13);

	md4_round(XXX, A, B, C, D, W[/* */ 0] + 0x6ED9EBA1, 3);
	md4_round(XXX, D, A, B, C, W[/* */ 8] + 0x6ED9EBA1, 9);
	md4_round(XXX, C, D, A, B, W[/* */ 4] + 0x6ED9EBA1, 11);
	md4_round(XXX, B, C, D, A, W[/**/ 12] + 0x6ED9EBA1, 15);
	md4_round(XXX, A, B, C, D, W[/* */ 2] + 0x6ED9EBA1, 3);
	md4_round(XXX, D, A, B, C, W[/**/ 10] + 0x6ED9EBA1, 9);
	md4_round(XXX, C, D, A, B, W[/* */ 6] + 0x6ED9EBA1, 11);
	md4_round(XXX, B, C, D, A, W[/**/ 14] + 0x6ED9EBA1, 15);
	md4_round(XXX, A, B, C, D, W[/* */ 1] + 0x6ED9EBA1, 3);
	md4_round(XXX, D, A, B, C, W[/* */ 9] + 0x6ED9EBA1, 9);
	md4_round(XXX, C, D, A, B, W[/* */ 5] + 0x6ED9EBA1, 11);
	md4_round(XXX, B, C, D, A, W[/**/ 13] + 0x6ED9EBA1, 15);
	md4_round(XXX, A, B, C, D, W[/* */ 3] + 0x6ED9EBA1, 3);
	md4_round(XXX, D, A, B, C, W[/**/ 11] + 0x6ED9EBA1, 9);
	md4_round(XXX, C, D, A, B, W[/* */ 7] + 0x6ED9EBA1, 11);
	md4_round(XXX, B, C, D, A, W[/**/ 15] + 0x6ED9EBA1, 15);

	context->digest[0] += A;
	context->digest[1] += B;
	context->digest[2] += C;
	context->digest[3] += D;

	context->index = 0;
}

bool rz_md4_update(RzMD4 *context, const ut8 *data, ut64 length) {
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
		if (context->index == RZ_HASH_MD4_BLOCK_LENGTH) {
			md4_digest_block(context);
		}
	}

	return true;
}

void md4_padding(RzMD4 *context) {
	if (context->index > 55) {
		context->block[context->index++] = 0x80;
		for (; context->index < RZ_HASH_MD4_BLOCK_LENGTH;) {
			context->block[context->index++] = 0;
		}

		md4_digest_block(context);

		for (; context->index < 56;) {
			context->block[context->index++] = 0;
		}
	} else {
		context->block[context->index++] = 0x80;
		for (; context->index < 56;) {
			context->block[context->index++] = 0;
		}
	}

	rz_write_le32(&context->block[56], context->len_low);
	rz_write_le32(&context->block[60], context->len_high);

	md4_digest_block(context);
}

void rz_md4_fini(ut8 *hash, RzMD4 *context) {
	rz_return_if_fail(context && hash);

	md4_padding(context);

	for (ut32 t = 0; t < 4; ++t) {
		rz_write_at_le32(hash, context->digest[t], t * 4);
	}
}
