// SPDX-FileCopyrightText: 2023 swedenspy <swedenspy@yahoo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "md2.h"
#include <rz_util.h>
#include <rz_endian.h>

#include <string.h>

/*
    implemented according to RFC 1319
*/

const static int block_size = RZ_HASH_MD2_BLOCK_LENGTH;
const static int checksum_size = RZ_HASH_MD2_CHECKSUM_LENGTH;
const static int state_size = RZ_HASH_MD2_STATE_LENGTH;
const static int digest_num_rounds = RZ_HASH_MD2_NUM_ROUNDS;

static void md2_digest_block(RzMD2 *context);

static ut8 PI_SUBST[256] = {
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20
};

static ut8 *PADDING[] = {
	(ut8 *)"",
	(ut8 *)"\001",
	(ut8 *)"\002\002",
	(ut8 *)"\003\003\003",
	(ut8 *)"\004\004\004\004",
	(ut8 *)"\005\005\005\005\005",
	(ut8 *)"\006\006\006\006\006\006",
	(ut8 *)"\007\007\007\007\007\007\007",
	(ut8 *)"\010\010\010\010\010\010\010\010",
	(ut8 *)"\011\011\011\011\011\011\011\011\011",
	(ut8 *)"\012\012\012\012\012\012\012\012\012\012",
	(ut8 *)"\013\013\013\013\013\013\013\013\013\013\013",
	(ut8 *)"\014\014\014\014\014\014\014\014\014\014\014\014",
	(ut8 *)"\015\015\015\015\015\015\015\015\015\015\015\015\015",
	(ut8 *)"\016\016\016\016\016\016\016\016\016\016\016\016\016\016",
	(ut8 *)"\017\017\017\017\017\017\017\017\017\017\017\017\017\017\017",
	(ut8 *)"\020\020\020\020\020\020\020\020\020\020\020\020\020\020\020\020"
};

void rz_md2_init(RzMD2 *context) {
	rz_return_if_fail(context);
	context->index = 0;
	memset(context->state, 0, state_size);
	memset(context->checksum, 0, checksum_size);
}

bool rz_md2_update(RzMD2 *context, const ut8 *data, ut64 length) {
	rz_return_val_if_fail(context && data, false);

	// fill up and digest the current block-buffer if possible
	ut64 data_index = 0;
	int remains_in_buffer = block_size - context->index;
	if (length >= remains_in_buffer) {
		memcpy(&context->block[context->index], data, remains_in_buffer);
		data_index = remains_in_buffer;
		context->index = 0;

		md2_digest_block(context);

		// digest everything before last 16-byte block
		for (; data_index + 16 < length; data_index += 16) {
			memcpy(context->block, &data[data_index], block_size);
			md2_digest_block(context);
		}
	}

	// buffer the last block
	int remains_in_data = length - data_index;
	memcpy(&context->block[context->index], &data[data_index], remains_in_data);
	context->index += remains_in_data;

	return true;
}

void rz_md2_fini(ut8 *hash, RzMD2 *context) {
	rz_return_if_fail(hash && context);

	ut64 n_pad = block_size - context->index;
	rz_md2_update(context, PADDING[n_pad], n_pad);
	rz_md2_update(context, context->checksum, checksum_size);
	memcpy(hash, context->state, block_size);
	memset(context, 0, sizeof(*context));
}

static void md2_digest_block(RzMD2 *context) {
	const ut8 *block = context->block;
	ut8 *checksum = context->checksum;
	ut8 *state = context->state;

	ut8 buf[0x30] = { 0 };

	memcpy(buf, state, state_size);
	memcpy(buf + state_size, block, block_size);

	for (ut64 j = 0; j < block_size; ++j) {
		buf[j + block_size + state_size] = block[j] ^ state[j];
	}

	ut64 t = 0;
	for (ut64 j = 0; j < digest_num_rounds; ++j) {
		for (ut64 k = 0; k < sizeof(buf); ++k) {
			t = buf[k] ^= PI_SUBST[t];
		}
		t = (t + j) & 0xff;
	}

	memcpy(state, buf, state_size);

	t = checksum[checksum_size - 1];
	for (ut64 i = 0; i < checksum_size; i++) {
		t = checksum[i] ^= PI_SUBST[block[i] ^ t];
	}
}