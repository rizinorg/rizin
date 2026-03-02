// SPDX-FileCopyrightText: 2026 The Rizin Contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include "ripemd160.h"
#include <rz_endian.h>
#include <string.h>

#define ROL32(value, shift) (((value) << (shift)) | ((value) >> (32 - (shift))))

static const ut8 r_order[80] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

static const ut8 rp_order[80] = {
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

static const ut8 s_shift[80] = {
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

static const ut8 sp_shift[80] = {
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

static inline ut32 f1(ut32 x, ut32 y, ut32 z) {
	return x ^ y ^ z;
}

static inline ut32 f2(ut32 x, ut32 y, ut32 z) {
	return (x & y) | (~x & z);
}

static inline ut32 f3(ut32 x, ut32 y, ut32 z) {
	return (x | ~y) ^ z;
}

static inline ut32 f4(ut32 x, ut32 y, ut32 z) {
	return (x & z) | (y & ~z);
}

static inline ut32 f5(ut32 x, ut32 y, ut32 z) {
	return x ^ (y | ~z);
}

static inline ut32 f_round(ut32 idx, ut32 x, ut32 y, ut32 z) {
	if (idx < 16) {
		return f1(x, y, z);
	}
	if (idx < 32) {
		return f2(x, y, z);
	}
	if (idx < 48) {
		return f3(x, y, z);
	}
	if (idx < 64) {
		return f4(x, y, z);
	}
	return f5(x, y, z);
}

static inline ut32 fp_round(ut32 idx, ut32 x, ut32 y, ut32 z) {
	if (idx < 16) {
		return f5(x, y, z);
	}
	if (idx < 32) {
		return f4(x, y, z);
	}
	if (idx < 48) {
		return f3(x, y, z);
	}
	if (idx < 64) {
		return f2(x, y, z);
	}
	return f1(x, y, z);
}

static inline ut32 round_constant(ut32 idx) {
	if (idx < 16) {
		return 0x00000000;
	}
	if (idx < 32) {
		return 0x5A827999;
	}
	if (idx < 48) {
		return 0x6ED9EBA1;
	}
	if (idx < 64) {
		return 0x8F1BBCDC;
	}
	return 0xA953FD4E;
}

static inline ut32 parallel_round_constant(ut32 idx) {
	if (idx < 16) {
		return 0x50A28BE6;
	}
	if (idx < 32) {
		return 0x5C4DD124;
	}
	if (idx < 48) {
		return 0x6D703EF3;
	}
	if (idx < 64) {
		return 0x7A6D76E9;
	}
	return 0x00000000;
}

static void ripemd160_transform(RzHashRIPEMD160 *context, const ut8 *block) {
	ut32 words[16];
	ut32 a = context->state[0];
	ut32 b = context->state[1];
	ut32 c = context->state[2];
	ut32 d = context->state[3];
	ut32 e = context->state[4];
	ut32 aa = context->state[0];
	ut32 bb = context->state[1];
	ut32 cc = context->state[2];
	ut32 dd = context->state[3];
	ut32 ee = context->state[4];

	for (ut32 i = 0; i < 16; ++i) {
		words[i] = rz_read_at_le32(block, i * sizeof(ut32));
	}

	for (ut32 i = 0; i < 80; ++i) {
		ut32 t = ROL32(a + f_round(i, b, c, d) + words[r_order[i]] + round_constant(i), s_shift[i]) + e;
		a = e;
		e = d;
		d = ROL32(c, 10);
		c = b;
		b = t;

		t = ROL32(
			    aa + fp_round(i, bb, cc, dd) + words[rp_order[i]] + parallel_round_constant(i),
			    sp_shift[i]) +
			ee;
		aa = ee;
		ee = dd;
		dd = ROL32(cc, 10);
		cc = bb;
		bb = t;
	}

	ut32 t = context->state[1] + c + dd;
	context->state[1] = context->state[2] + d + ee;
	context->state[2] = context->state[3] + e + aa;
	context->state[3] = context->state[4] + a + bb;
	context->state[4] = context->state[0] + b + cc;
	context->state[0] = t;
}

void rz_hash_ripemd160_init(RzHashRIPEMD160 *context) {
	rz_return_if_fail(context);

	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->total_length = 0;
	context->block_length = 0;
}

bool rz_hash_ripemd160_update(RzHashRIPEMD160 *context, const ut8 *data, ut64 length) {
	rz_return_val_if_fail(context && (data || !length), false);

	ut64 offset = 0;
	context->total_length += length;

	if (context->block_length > 0) {
		size_t to_copy = RZ_HASH_RIPEMD160_BLOCK_LENGTH - context->block_length;
		if (to_copy > length) {
			to_copy = (size_t)length;
		}
		memcpy(context->block + context->block_length, data, to_copy);
		context->block_length += to_copy;
		offset += to_copy;
		if (context->block_length == RZ_HASH_RIPEMD160_BLOCK_LENGTH) {
			ripemd160_transform(context, context->block);
			context->block_length = 0;
		}
	}

	while ((length - offset) >= RZ_HASH_RIPEMD160_BLOCK_LENGTH) {
		ripemd160_transform(context, data + offset);
		offset += RZ_HASH_RIPEMD160_BLOCK_LENGTH;
	}

	if (offset < length) {
		size_t remain = (size_t)(length - offset);
		memcpy(context->block, data + offset, remain);
		context->block_length = remain;
	}

	return true;
}

void rz_hash_ripemd160_final(ut8 *digest, RzHashRIPEMD160 *context) {
	rz_return_if_fail(context && digest);

	const ut64 bit_length = context->total_length * 8;

	context->block[context->block_length++] = 0x80;
	if (context->block_length > 56) {
		memset(context->block + context->block_length, 0,
			RZ_HASH_RIPEMD160_BLOCK_LENGTH - context->block_length);
		ripemd160_transform(context, context->block);
		context->block_length = 0;
	}

	memset(context->block + context->block_length, 0, 56 - context->block_length);
	rz_write_le64(context->block + 56, bit_length);
	ripemd160_transform(context, context->block);

	for (ut32 i = 0; i < 5; ++i) {
		rz_write_at_le32(digest, context->state[i], i * sizeof(ut32));
	}
}
