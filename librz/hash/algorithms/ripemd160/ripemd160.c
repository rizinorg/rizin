// SPDX-FileCopyrightText: 2026 Duck
// SPDX-License-Identifier: LGPL-3.0-only

#include "ripemd160.h"
#include "rz_util/rz_assert.h"
#include <rz_types.h>
#include <rz_endian.h>
#include <rz_util.h>

// implementation based on this guide https://laoutaris.cc/blog/ripemd160_guide/ and the python code provided within it

void rz_ripemd160_init(RzRipemd160 *context) {
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

static const ut32 left_constants[5] = { 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
static const ut32 right_constants[5] = { 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

// lookup tables
static const ut8 left_word_order[80] = {
	0,
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	11,
	12,
	13,
	14,
	15,
	7,
	4,
	13,
	1,
	10,
	6,
	15,
	3,
	12,
	0,
	9,
	5,
	2,
	14,
	11,
	8,
	3,
	10,
	14,
	4,
	9,
	15,
	8,
	1,
	2,
	7,
	0,
	6,
	13,
	11,
	5,
	12,
	1,
	9,
	11,
	10,
	0,
	8,
	12,
	4,
	13,
	3,
	7,
	15,
	14,
	5,
	6,
	2,
	4,
	0,
	5,
	9,
	7,
	12,
	2,
	10,
	14,
	1,
	3,
	8,
	11,
	6,
	15,
	13,
};

static const ut8 right_word_order[80] = {
	5,
	14,
	7,
	0,
	9,
	2,
	11,
	4,
	13,
	6,
	15,
	8,
	1,
	10,
	3,
	12,
	6,
	11,
	3,
	7,
	0,
	13,
	5,
	10,
	14,
	15,
	8,
	12,
	4,
	9,
	1,
	2,
	15,
	5,
	1,
	3,
	7,
	14,
	6,
	9,
	11,
	8,
	12,
	2,
	10,
	0,
	4,
	13,
	8,
	6,
	4,
	1,
	3,
	11,
	15,
	0,
	5,
	12,
	2,
	13,
	9,
	7,
	10,
	14,
	12,
	15,
	10,
	4,
	1,
	5,
	8,
	7,
	6,
	2,
	13,
	14,
	0,
	3,
	9,
	11,
};

static const ut8 left_rotations[80] = {
	11,
	14,
	15,
	12,
	5,
	8,
	7,
	9,
	11,
	13,
	14,
	15,
	6,
	7,
	9,
	8,
	7,
	6,
	8,
	13,
	11,
	9,
	7,
	15,
	7,
	12,
	15,
	9,
	11,
	7,
	13,
	12,
	11,
	13,
	6,
	7,
	14,
	9,
	13,
	15,
	14,
	8,
	13,
	6,
	5,
	12,
	7,
	5,
	11,
	12,
	14,
	15,
	14,
	15,
	9,
	8,
	9,
	14,
	5,
	6,
	8,
	6,
	5,
	12,
	9,
	15,
	5,
	11,
	6,
	8,
	13,
	12,
	5,
	12,
	13,
	14,
	11,
	8,
	5,
	6,
};

static const ut8 right_rotations[80] = {
	8,
	9,
	9,
	11,
	13,
	15,
	15,
	5,
	7,
	7,
	8,
	11,
	14,
	14,
	12,
	6,
	9,
	13,
	15,
	7,
	12,
	8,
	9,
	11,
	7,
	7,
	12,
	7,
	6,
	15,
	13,
	11,
	9,
	7,
	15,
	11,
	8,
	6,
	6,
	14,
	12,
	13,
	5,
	14,
	13,
	13,
	7,
	5,
	15,
	5,
	8,
	11,
	14,
	14,
	6,
	14,
	6,
	9,
	12,
	9,
	12,
	5,
	15,
	8,
	8,
	5,
	12,
	9,
	12,
	5,
	14,
	6,
	8,
	13,
	6,
	5,
	15,
	13,
	11,
	11,
};

static inline ut32 rotate_left_32(ut32 value, ut32 rot) {
	return ((((value) << (rot)) & 0xFFFFFFFF) | ((value) >> (32 - (rot))));
}

static inline ut32 ripemd160_boolean_function(ut32 j, ut32 x, ut32 y, ut32 z) {
	if (j < 16) {
		return x ^ y ^ z;
	} else if (j < 32) {
		return (x & y) | (~x & 0xFFFFFFFF & z);
	} else if (j < 48) {
		return (x | (~y & 0xFFFFFFFF)) ^ z;
	} else if (j < 64) {
		return (x & z) | (y & ~z & 0xFFFFFFFF);
	} else {
		return x ^ (y | (~z & 0xFFFFFFFF));
	}
}
static void ripemd160_padding(RzRipemd160 *context) {
	static const ut8 padding[RZ_HASH_RIPEMD160_BLOCK_LENGTH] = { 0x80 };
	ut8 length[8];

	ut64 padding_length;

	if (context->index < 56) {
		padding_length = 56 - context->index;
	} else {
		padding_length = 120 - context->index;
	}

	rz_write_le32(length, context->len_low);
	rz_write_le32(length + 4, context->len_high);
	rz_ripemd160_update(context, padding, padding_length);
	rz_ripemd160_update(context, length, sizeof(length));
}

static void ripemd160_digest_block(RzRipemd160 *context) {
	ut32 words[16];

	for (ut32 i = 0; i < 16; ++i) {
		words[i] = rz_read_at_le32(context->block, i * 4);
	}

	ut32 a = context->digest[0];
	ut32 b = context->digest[1];
	ut32 c = context->digest[2];
	ut32 d = context->digest[3];
	ut32 e = context->digest[4];

	ut32 a2 = a;
	ut32 b2 = b;
	ut32 c2 = c;
	ut32 d2 = d;
	ut32 e2 = e;

	for (ut32 i = 0; i < 80; ++i) {
		ut32 tmp = a + ripemd160_boolean_function(i, b, c, d) + words[left_word_order[i]] + left_constants[i / 16];
		tmp = rotate_left_32(tmp, left_rotations[i]) + e;

		a = e;
		e = d;
		d = rotate_left_32(c, 10);
		c = b;
		b = tmp;

		tmp = a2 + ripemd160_boolean_function(79 - i, b2, c2, d2) + words[right_word_order[i]] + right_constants[i / 16];
		tmp = rotate_left_32(tmp, right_rotations[i]) + e2;

		a2 = e2;
		e2 = d2;
		d2 = rotate_left_32(c2, 10);
		c2 = b2;
		b2 = tmp;
	}

	ut32 tmp = context->digest[1] + c + d2;
	context->digest[1] = context->digest[2] + d + e2;
	context->digest[2] = context->digest[3] + e + a2;
	context->digest[3] = context->digest[4] + a + b2;
	context->digest[4] = context->digest[0] + b + c2;
	context->digest[0] = tmp;

	context->index = 0;
}

bool rz_ripemd160_update(RzRipemd160 *context, const ut8 *data, ut64 length) {
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

		if (context->index == RZ_HASH_RIPEMD160_BLOCK_LENGTH) {
			ripemd160_digest_block(context);
		}
	}
	return true;
}

void rz_ripemd160_fini(ut8 *hash, RzRipemd160 *context) {
	rz_return_if_fail(context && hash);

	ripemd160_padding(context);

	for (ut32 tmp = 0; tmp < 5; ++tmp) {
		rz_write_at_le32(hash, context->digest[tmp], tmp * 4);
	}
}
