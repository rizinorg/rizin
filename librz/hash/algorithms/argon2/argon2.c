// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include "argon2.h"
#include "blake2b.h"
#include <rz_util/rz_mem.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

void init_block_value(block *b, ut8 in) {
	memset(b->v, in, sizeof(b->v));
}

void copy_block(block *dst, const block *src) {
	memcpy(dst->v, src->v, sizeof(dst->v));
}

void xor_block(block *dst, const block *src) {
	int i;
	for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
		dst->v[i] ^= src->v[i];
	}
}

/* Rotation constants */
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define B2_G(a, b, c, d) \
	do { \
		(a) = (a) + (b) + 2 * (ut64)((ut32)(a)) * (ut64)((ut32)(b)); \
		(d) = ROTR64((d) ^ (a), 32); \
		(c) = (c) + (d) + 2 * (ut64)((ut32)(c)) * (ut64)((ut32)(d)); \
		(b) = ROTR64((b) ^ (c), 24); \
		(a) = (a) + (b) + 2 * (ut64)((ut32)(a)) * (ut64)((ut32)(b)); \
		(d) = ROTR64((d) ^ (a), 16); \
		(c) = (c) + (d) + 2 * (ut64)((ut32)(c)) * (ut64)((ut32)(d)); \
		(b) = ROTR64((b) ^ (c), 63); \
	} while (0)

/* Apply the Blake2b permutation to a 16-word (128-byte) chunk */
static void fill_block(block *state, const block *ref_block, block *next_block, int with_xor) {
	block blockR, block_tmp;
	int i;

	copy_block(&blockR, ref_block);
	xor_block(&blockR, state);
	copy_block(&block_tmp, &blockR);

	if (with_xor) {
		xor_block(&block_tmp, next_block);
	}

	/* Apply Blake2b G to each column of 8x8 matrix */
	for (i = 0; i < 8; ++i) {
		ut64 *v = blockR.v + 16 * i;
		B2_G(v[0], v[4], v[8], v[12]);
		B2_G(v[1], v[5], v[9], v[13]);
		B2_G(v[2], v[6], v[10], v[14]);
		B2_G(v[3], v[7], v[11], v[15]);
		B2_G(v[0], v[5], v[10], v[15]);
		B2_G(v[1], v[6], v[11], v[12]);
		B2_G(v[2], v[7], v[8], v[13]);
		B2_G(v[3], v[4], v[9], v[14]);
	}

	/* Apply Blake2b G to each row of 8x8 matrix */
	for (i = 0; i < 8; ++i) {
		ut64 *v = blockR.v + 2 * i;
		B2_G(v[0], v[1], v[16], v[17]);
		B2_G(v[32], v[33], v[48], v[49]);
		B2_G(v[64], v[65], v[80], v[81]);
		B2_G(v[96], v[97], v[112], v[113]);
		B2_G(v[0], v[33], v[64], v[97]);
		B2_G(v[1], v[48], v[65], v[112]);
		B2_G(v[16], v[49], v[80], v[113]);
		B2_G(v[17], v[32], v[81], v[96]);
	}

	copy_block(next_block, &block_tmp);
	xor_block(next_block, &blockR);
}

void fill_segment(const argon2_instance_t *instance, argon2_position_t position) {
	block *ref_block = NULL, *curr_block = NULL;
	block address_block, input_block, zero_block;
	ut64 pseudo_rand, ref_index, ref_lane;
	ut32 prev_offset, curr_offset;
	ut32 starting_index;
	ut32 i;
	int data_independent_addressing;

	if (!instance) {
		return;
	}

	data_independent_addressing =
		(instance->type == Argon2_i) ||
		(instance->type == Argon2_id && (position.pass == 0) &&
			(position.slice < ARGON2_SYNC_POINTS / 2));

	if (data_independent_addressing) {
		init_block_value(&input_block, 0);
		input_block.v[0] = position.pass;
		input_block.v[1] = position.lane;
		input_block.v[2] = position.slice;
		input_block.v[3] = instance->memory_blocks;
		input_block.v[4] = instance->passes;
		input_block.v[5] = instance->type;
	}

	starting_index = 0;
	if ((0 == position.pass) && (0 == position.slice)) {
		starting_index = 2; /* Skip the first two blocks */
		if (data_independent_addressing) {
			input_block.v[6]++;
			init_block_value(&zero_block, 0);
			init_block_value(&address_block, 0);
			fill_block(&zero_block, &input_block, &address_block, 0);
			fill_block(&zero_block, &address_block, &address_block, 0);
		}
	}

	curr_offset = position.lane * instance->lane_length +
		position.slice * instance->segment_length + starting_index;

	if (0 == curr_offset % instance->lane_length) {
		prev_offset = curr_offset + instance->lane_length - 1;
	} else {
		prev_offset = curr_offset - 1;
	}

	for (i = starting_index; i < instance->segment_length; ++i, ++curr_offset, ++prev_offset) {
		if (curr_offset % instance->lane_length == 1) {
			prev_offset = curr_offset - 1;
		}

		/* Generate pseudo-random value */
		if (data_independent_addressing) {
			if (i % ARGON2_ADDRESSES_IN_BLOCK == 0) {
				input_block.v[6]++;
				init_block_value(&zero_block, 0);
				init_block_value(&address_block, 0);
				fill_block(&zero_block, &input_block, &address_block, 0);
				fill_block(&zero_block, &address_block, &address_block, 0);
			}
			pseudo_rand = address_block.v[i % ARGON2_ADDRESSES_IN_BLOCK];
		} else {
			pseudo_rand = instance->memory[prev_offset].v[0];
		}

		/* Map pseudo_rand to a reference block position */
		ref_lane = ((pseudo_rand >> 32)) % instance->lanes;
		if ((position.pass == 0) && (position.slice == 0)) {
			ref_lane = position.lane;
		}

		position.index = i;
		ref_index = index_alpha(instance, &position, (ut32)(pseudo_rand & 0xFFFFFFFF), ref_lane == position.lane);

		ref_block = instance->memory + instance->lane_length * ref_lane + ref_index;
		curr_block = instance->memory + curr_offset;

		if (instance->version == ARGON2_VERSION_10) {
			fill_block(instance->memory + prev_offset, ref_block, curr_block, 0);
		} else {
			if (position.pass == 0) {
				fill_block(instance->memory + prev_offset, ref_block, curr_block, 0);
			} else {
				fill_block(instance->memory + prev_offset, ref_block, curr_block, 1);
			}
		}
	}
}

void initial_hash(ut8 *blockhash, argon2_context *context, argon2_type type) {
	blake2b_state BlakeHash;
	ut8 value[sizeof(ut32)];

	if (!context || !blockhash) {
		return;
	}

	blake2b_init(&BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);

#define LE32(x) \
	do { \
		value[0] = (ut8)((x) >> 0); \
		value[1] = (ut8)((x) >> 8); \
		value[2] = (ut8)((x) >> 16); \
		value[3] = (ut8)((x) >> 24); \
		blake2b_update(&BlakeHash, value, sizeof value); \
	} while (0)

	LE32(context->lanes);
	LE32(context->outlen);
	LE32(context->m_cost);
	LE32(context->t_cost);
	LE32(context->version);
	LE32((ut32)type);

	LE32(context->pwdlen);
	if (context->pwd) {
		blake2b_update(&BlakeHash, context->pwd, context->pwdlen);
		if (context->flags & ARGON2_FLAG_CLEAR_PASSWORD) {
			clear_internal_memory(context->pwd, context->pwdlen);
			context->pwdlen = 0;
		}
	}

	LE32(context->saltlen);
	if (context->salt) {
		blake2b_update(&BlakeHash, context->salt, context->saltlen);
	}

	LE32(context->secretlen);
	if (context->secret) {
		blake2b_update(&BlakeHash, context->secret, context->secretlen);
		if (context->flags & ARGON2_FLAG_CLEAR_SECRET) {
			clear_internal_memory(context->secret, context->secretlen);
			context->secretlen = 0;
		}
	}

	LE32(context->adlen);
	if (context->ad) {
		blake2b_update(&BlakeHash, context->ad, context->adlen);
	}

#undef LE32

	blake2b_final(&BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
}

void fill_first_blocks(ut8 *blockhash, const argon2_instance_t *instance) {
	ut32 l;
	ut8 blockhash_bytes[ARGON2_BLOCK_SIZE];

	for (l = 0; l < instance->lanes; ++l) {
		ut8 tmp[ARGON2_PREHASH_SEED_LENGTH];
		memcpy(tmp, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
		/* Block 0 */
		tmp[ARGON2_PREHASH_DIGEST_LENGTH + 0] = 0;
		tmp[ARGON2_PREHASH_DIGEST_LENGTH + 1] = 0;
		tmp[ARGON2_PREHASH_DIGEST_LENGTH + 2] = 0;
		tmp[ARGON2_PREHASH_DIGEST_LENGTH + 3] = 0;
		tmp[ARGON2_PREHASH_DIGEST_LENGTH + 4] = (ut8)(l >> 0);
		tmp[ARGON2_PREHASH_DIGEST_LENGTH + 5] = (ut8)(l >> 8);
		tmp[ARGON2_PREHASH_DIGEST_LENGTH + 6] = (ut8)(l >> 16);
		tmp[ARGON2_PREHASH_DIGEST_LENGTH + 7] = (ut8)(l >> 24);
		blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, tmp, ARGON2_PREHASH_SEED_LENGTH);
		memcpy(instance->memory[l * instance->lane_length + 0].v,
			blockhash_bytes, ARGON2_BLOCK_SIZE);

		/* Block 1 */
		tmp[ARGON2_PREHASH_DIGEST_LENGTH + 0] = 1;
		blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, tmp, ARGON2_PREHASH_SEED_LENGTH);
		memcpy(instance->memory[l * instance->lane_length + 1].v,
			blockhash_bytes, ARGON2_BLOCK_SIZE);
	}
	memset(blockhash_bytes, 0, sizeof(blockhash_bytes));
}

int initialize(argon2_instance_t *instance, argon2_context *context) {
	ut8 blockhash[ARGON2_PREHASH_SEED_LENGTH];
	int result;

	if (!instance || !context) {
		return ARGON2_INCORRECT_PARAMETER;
	}

	result = allocate_memory(context, (ut8 **)&instance->memory,
		instance->memory_blocks, sizeof(block));
	if (result != ARGON2_OK) {
		return result;
	}

	initial_hash(blockhash, context, instance->type);
	memset(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0,
		ARGON2_PREHASH_SEED_LENGTH - ARGON2_PREHASH_DIGEST_LENGTH);

	fill_first_blocks(blockhash, instance);
	memset(blockhash, 0, sizeof(blockhash));
	return ARGON2_OK;
}

void finalize(const argon2_context *context, argon2_instance_t *instance) {
	block blockhash;
	ut32 l;

	if (!context || !instance) {
		return;
	}

	copy_block(&blockhash, instance->memory + instance->lane_length - 1);

	/* XOR the last block from every lane */
	for (l = 1; l < instance->lanes; ++l) {
		ut32 last_block_in_lane = l * instance->lane_length + (instance->lane_length - 1);
		xor_block(&blockhash, instance->memory + last_block_in_lane);
	}

	/* Hash the XORed block into the output */
	blake2b_long(context->out, context->outlen,
		(ut8 *)blockhash.v, ARGON2_BLOCK_SIZE);

	/* Clear sensitive data */
	clear_internal_memory(blockhash.v, sizeof(blockhash.v));
	free_memory(context, (ut8 *)instance->memory,
		instance->memory_blocks, sizeof(block));
	instance->memory = NULL;
}

static const char b64chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_byte_to_char(unsigned x) {
	return b64chars[x & 63];
}

static unsigned b64_char_to_byte(int c) {
	if (c >= 'A' && c <= 'Z')
		return (unsigned)(c - 'A');
	if (c >= 'a' && c <= 'z')
		return (unsigned)(c - 'a' + 26);
	if (c >= '0' && c <= '9')
		return (unsigned)(c - '0' + 52);
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return 0xFF; /* invalid */
}

static size_t to_base64(char *dst, size_t dst_len, const void *src, size_t src_len) {
	const ut8 *buf = (const ut8 *)src;
	size_t olen, i;

	olen = (src_len / 3) * 4;
	switch (src_len % 3) {
	case 2: olen += 3; break;
	case 1: olen += 2; break;
	default: break;
	}
	if (dst_len <= olen) {
		return (size_t)-1;
	}

	i = 0;
	while (src_len >= 3) {
		dst[i++] = (char)b64_byte_to_char((buf[0] >> 2) & 0x3F);
		dst[i++] = (char)b64_byte_to_char(((buf[0] & 0x03) << 4) | ((buf[1] >> 4) & 0x0F));
		dst[i++] = (char)b64_byte_to_char(((buf[1] & 0x0F) << 2) | ((buf[2] >> 6) & 0x03));
		dst[i++] = (char)b64_byte_to_char(buf[2] & 0x3F);
		buf += 3;
		src_len -= 3;
	}
	if (src_len == 2) {
		dst[i++] = (char)b64_byte_to_char((buf[0] >> 2) & 0x3F);
		dst[i++] = (char)b64_byte_to_char(((buf[0] & 0x03) << 4) | ((buf[1] >> 4) & 0x0F));
		dst[i++] = (char)b64_byte_to_char((buf[1] & 0x0F) << 2);
	} else if (src_len == 1) {
		dst[i++] = (char)b64_byte_to_char((buf[0] >> 2) & 0x3F);
		dst[i++] = (char)b64_byte_to_char((buf[0] & 0x03) << 4);
	}
	dst[i] = '\0';
	return i;
}

static size_t from_base64(void *dst, size_t *dst_len, const char *src) {
	ut8 *buf = (ut8 *)dst;
	size_t len = 0;
	unsigned acc = 0, acc_len = 0;

	while (*src) {
		unsigned d = b64_char_to_byte((unsigned char)*src);
		if (d == 0xFF)
			break; /* non-base64 char terminates */
		src++;
		acc = (acc << 6) | d;
		acc_len += 6;
		if (acc_len >= 8) {
			acc_len -= 8;
			if (buf)
				buf[len] = (ut8)(acc >> acc_len);
			len++;
		}
	}
	/* Partial final byte means malformed — ignore it */
	*dst_len = len;
	return (size_t)(src - (const char *)dst); /* unused but harmless */
}

/* Encode a decimal uint32 into dst, return updated pointer */
static char *encode_uint32(char *dst, size_t dst_len, ut32 x) {
	char tmp[12];
	size_t k, n;

	n = 0;
	do {
		tmp[n++] = (char)('0' + x % 10);
		x /= 10;
	} while (x && n < sizeof(tmp));

	if (n >= dst_len)
		return NULL;
	for (k = 0; k < n; k++) {
		dst[k] = tmp[n - 1 - k];
	}
	dst[n] = '\0';
	return dst + n;
}

/* Decode a decimal uint32 from src, advance src past it */
static const char *decode_uint32(const char *src, ut32 *v) {
	ut32 acc = 0;
	int has_digit = 0;

	while (*src >= '0' && *src <= '9') {
		ut32 d = (ut32)(*src - '0');
		if (acc > (UINT32_MAX - d) / 10)
			return NULL; /* overflow */
		acc = acc * 10 + d;
		has_digit = 1;
		src++;
	}
	if (!has_digit)
		return NULL;
	*v = acc;
	return src;
}

int encode_string(char *dst, size_t dst_len, argon2_context *ctx, argon2_type type) {
	const char *type_str;
	size_t used;
	char *p = dst;

	if (!dst || !ctx || dst_len == 0)
		return ARGON2_ENCODING_FAIL;

	type_str = argon2_type2string(type, 0);
	if (!type_str)
		return ARGON2_ENCODING_FAIL;

#define WRITE_CHAR(c) \
	do { \
		if ((size_t)(p - dst) >= dst_len - 1) \
			return ARGON2_ENCODING_FAIL; \
		*p++ = (c); \
	} while (0)

#define WRITE_STR(s) \
	do { \
		const char *_s = (s); \
		while (*_s) { \
			WRITE_CHAR(*_s++); \
		} \
	} while (0)

	WRITE_CHAR('$');
	WRITE_STR(type_str);
	WRITE_STR("$v=");
	p = encode_uint32(p, dst_len - (size_t)(p - dst), ctx->version);
	if (!p)
		return ARGON2_ENCODING_FAIL;
	WRITE_STR("$m=");
	p = encode_uint32(p, dst_len - (size_t)(p - dst), ctx->m_cost);
	if (!p)
		return ARGON2_ENCODING_FAIL;
	WRITE_STR(",t=");
	p = encode_uint32(p, dst_len - (size_t)(p - dst), ctx->t_cost);
	if (!p)
		return ARGON2_ENCODING_FAIL;
	WRITE_STR(",p=");
	p = encode_uint32(p, dst_len - (size_t)(p - dst), ctx->lanes);
	if (!p)
		return ARGON2_ENCODING_FAIL;
	WRITE_CHAR('$');

	used = to_base64(p, dst_len - (size_t)(p - dst), ctx->salt, ctx->saltlen);
	if (used == (size_t)-1)
		return ARGON2_ENCODING_FAIL;
	p += used;

	WRITE_CHAR('$');
	used = to_base64(p, dst_len - (size_t)(p - dst), ctx->out, ctx->outlen);
	if (used == (size_t)-1)
		return ARGON2_ENCODING_FAIL;
	p += used;

	*p = '\0';

#undef WRITE_CHAR
#undef WRITE_STR

	return ARGON2_OK;
}

int decode_string(argon2_context *ctx, const char *str, argon2_type type) {
	const char *type_str;
	size_t type_len;
	ut32 version, m_cost, t_cost, lanes;
	size_t saltlen, hashlen;

	if (!ctx || !str)
		return ARGON2_DECODING_FAIL;

	type_str = argon2_type2string(type, 0);
	if (!type_str)
		return ARGON2_DECODING_FAIL;
	type_len = strlen(type_str);

	/* $type */
	if (*str != '$')
		return ARGON2_DECODING_FAIL;
	str++;
	if (strncmp(str, type_str, type_len) != 0)
		return ARGON2_DECODING_FAIL;
	str += type_len;

	/* $v=VERSION */
	if (strncmp(str, "$v=", 3) != 0)
		return ARGON2_DECODING_FAIL;
	str += 3;
	str = decode_uint32(str, &version);
	if (!str)
		return ARGON2_DECODING_FAIL;
	ctx->version = version;

	/* $m=M,t=T,p=P */
	if (strncmp(str, "$m=", 3) != 0)
		return ARGON2_DECODING_FAIL;
	str += 3;
	str = decode_uint32(str, &m_cost);
	if (!str)
		return ARGON2_DECODING_FAIL;
	ctx->m_cost = m_cost;

	if (strncmp(str, ",t=", 3) != 0)
		return ARGON2_DECODING_FAIL;
	str += 3;
	str = decode_uint32(str, &t_cost);
	if (!str)
		return ARGON2_DECODING_FAIL;
	ctx->t_cost = t_cost;

	if (strncmp(str, ",p=", 3) != 0)
		return ARGON2_DECODING_FAIL;
	str += 3;
	str = decode_uint32(str, &lanes);
	if (!str)
		return ARGON2_DECODING_FAIL;
	ctx->lanes = lanes;
	ctx->threads = lanes;

	/* $SALT */
	if (*str != '$')
		return ARGON2_DECODING_FAIL;
	str++;
	{
		const char *salt_end = strchr(str, '$');
		if (!salt_end)
			return ARGON2_DECODING_FAIL;
		saltlen = 0;
		from_base64(ctx->salt, &saltlen, str);
		if (saltlen > ctx->saltlen)
			return ARGON2_DECODING_LENGTH_FAIL;
		ctx->saltlen = (ut32)saltlen;
		str = salt_end;
	}

	/* $HASH */
	if (*str != '$')
		return ARGON2_DECODING_FAIL;
	str++;
	hashlen = 0;
	from_base64(ctx->out, &hashlen, str);
	if (hashlen > ctx->outlen)
		return ARGON2_DECODING_LENGTH_FAIL;
	ctx->outlen = (ut32)hashlen;

	return ARGON2_OK;
}

const char *argon2_type2string(argon2_type type, int uppercase) {
	switch (type) {
	case Argon2_d:
		return uppercase ? "Argon2d" : "argon2d";
	case Argon2_i:
		return uppercase ? "Argon2i" : "argon2i";
	case Argon2_id:
		return uppercase ? "Argon2id" : "argon2id";
	}
	return NULL;
}

int validate_inputs(const argon2_context *context) {
	if (!context) {
		return ARGON2_INCORRECT_PARAMETER;
	}

	if (!context->out) {
		return ARGON2_OUTPUT_PTR_NULL;
	}

	/* Validate output length */
	if (ARGON2_MIN_OUTLEN > context->outlen) {
		return ARGON2_OUTPUT_TOO_SHORT;
	}
	if (ARGON2_MAX_OUTLEN < context->outlen) {
		return ARGON2_OUTPUT_TOO_LONG;
	}

	/* Validate password (optional, but pointer/length must be consistent) */
	if (!context->pwd) {
		if (context->pwdlen != 0) {
			return ARGON2_PWD_PTR_MISMATCH;
		}
	} else {
		if (ARGON2_MIN_PWD_LENGTH > context->pwdlen) {
			return ARGON2_PWD_TOO_SHORT;
		}
		if (ARGON2_MAX_PWD_LENGTH < context->pwdlen) {
			return ARGON2_PWD_TOO_LONG;
		}
	}

	/* Validate salt (required) */
	if (!context->salt) {
		if (context->saltlen != 0) {
			return ARGON2_SALT_PTR_MISMATCH;
		}
	} else {
		if (ARGON2_MIN_SALT_LENGTH > context->saltlen) {
			return ARGON2_SALT_TOO_SHORT;
		}
		if (ARGON2_MAX_SALT_LENGTH < context->saltlen) {
			return ARGON2_SALT_TOO_LONG;
		}
	}

	/* Validate secret (optional) */
	if (!context->secret) {
		if (context->secretlen != 0) {
			return ARGON2_SECRET_PTR_MISMATCH;
		}
	} else {
		if (ARGON2_MIN_SECRET > context->secretlen) {
			return ARGON2_SECRET_TOO_SHORT;
		}
		if (ARGON2_MAX_SECRET < context->secretlen) {
			return ARGON2_SECRET_TOO_LONG;
		}
	}

	/* Validate associated data (optional) */
	if (!context->ad) {
		if (context->adlen != 0) {
			return ARGON2_AD_PTR_MISMATCH;
		}
	} else {
		if (ARGON2_MIN_AD_LENGTH > context->adlen) {
			return ARGON2_AD_TOO_SHORT;
		}
		if (ARGON2_MAX_AD_LENGTH < context->adlen) {
			return ARGON2_AD_TOO_LONG;
		}
	}

	/* Validate memory cost */
	if (ARGON2_MIN_MEMORY > context->m_cost) {
		return ARGON2_MEMORY_TOO_LITTLE;
	}
	if (ARGON2_MAX_MEMORY < context->m_cost) {
		return ARGON2_MEMORY_TOO_MUCH;
	}
	if (context->m_cost < 8 * context->lanes) {
		return ARGON2_MEMORY_TOO_LITTLE;
	}

	/* Validate time cost */
	if (ARGON2_MIN_TIME > context->t_cost) {
		return ARGON2_TIME_TOO_SMALL;
	}
	if (ARGON2_MAX_TIME < context->t_cost) {
		return ARGON2_TIME_TOO_LARGE;
	}

	/* Validate lanes */
	if (ARGON2_MIN_LANES > context->lanes) {
		return ARGON2_LANES_TOO_FEW;
	}
	if (ARGON2_MAX_LANES < context->lanes) {
		return ARGON2_LANES_TOO_MANY;
	}

	/* Validate threads */
	if (ARGON2_MIN_THREADS > context->threads) {
		return ARGON2_THREADS_TOO_FEW;
	}
	if (ARGON2_MAX_THREADS < context->threads) {
		return ARGON2_THREADS_TOO_MANY;
	}

	/* Callback consistency check */
	if (context->allocate_cbk && !context->free_cbk) {
		return ARGON2_FREE_MEMORY_CBK_NULL;
	}
	if (!context->allocate_cbk && context->free_cbk) {
		return ARGON2_ALLOCATE_MEMORY_CBK_NULL;
	}

	return ARGON2_OK;
}

int argon2_ctx(argon2_context *context, argon2_type type) {
	argon2_instance_t instance;
	ut32 memory_blocks, segment_length;
	int result;

	result = validate_inputs(context);
	if (result != ARGON2_OK) {
		return result;
	}

	if (type != Argon2_d && type != Argon2_i && type != Argon2_id) {
		return ARGON2_INCORRECT_TYPE;
	}

	memory_blocks = context->m_cost;
	if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
		memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
	}

	segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
	memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

	instance.version = context->version;
	instance.memory = NULL;
	instance.passes = context->t_cost;
	instance.memory_blocks = memory_blocks;
	instance.segment_length = segment_length;
	instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
	instance.lanes = context->lanes;
	instance.threads = context->threads;
	instance.type = type;
	instance.context_ptr = context;

	if (instance.threads > instance.lanes) {
		instance.threads = instance.lanes;
	}

	result = initialize(&instance, context);
	if (result != ARGON2_OK) {
		return result;
	}

	result = fill_memory_blocks(&instance);
	if (result != ARGON2_OK) {
		return result;
	}

	finalize(context, &instance);
	return ARGON2_OK;
}

int argon2_hash(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	void *hash, size_t hashlen,
	char *encoded, size_t encodedlen,
	argon2_type type, ut32 version) {

	argon2_context context;
	ut8 *out;
	int result;

	if (pwdlen > ARGON2_MAX_PWD_LENGTH) {
		return ARGON2_PWD_TOO_LONG;
	}
	if (saltlen > ARGON2_MAX_SALT_LENGTH) {
		return ARGON2_SALT_TOO_LONG;
	}
	if (hashlen > ARGON2_MAX_OUTLEN) {
		return ARGON2_OUTPUT_TOO_LONG;
	}
	if (hashlen < ARGON2_MIN_OUTLEN) {
		return ARGON2_OUTPUT_TOO_SHORT;
	}

	out = rz_mem_alloc(hashlen);
	if (!out) {
		return ARGON2_MEMORY_ALLOCATION_ERROR;
	}

	context.out = out;
	context.outlen = (ut32)hashlen;
	context.pwd = (ut8 *)pwd;
	context.pwdlen = (ut32)pwdlen;
	context.salt = (ut8 *)salt;
	context.saltlen = (ut32)saltlen;
	context.secret = NULL;
	context.secretlen = 0;
	context.ad = NULL;
	context.adlen = 0;
	context.t_cost = t_cost;
	context.m_cost = m_cost;
	context.lanes = parallelism;
	context.threads = parallelism;
	context.allocate_cbk = NULL;
	context.free_cbk = NULL;
	context.flags = ARGON2_DEFAULT_FLAGS;
	context.version = version;

	result = argon2_ctx(&context, type);
	if (result != ARGON2_OK) {
		clear_internal_memory(out, hashlen);
		free(out);
		return result;
	}

	if (hash) {
		memcpy(hash, out, hashlen);
	}

	if (encoded && encodedlen) {
		if (encode_string(encoded, encodedlen, &context, type) != ARGON2_OK) {
			clear_internal_memory(out, hashlen);
			clear_internal_memory(encoded, encodedlen);
			free(out);
			return ARGON2_ENCODING_FAIL;
		}
	}

	clear_internal_memory(out, hashlen);
	free(out);
	return ARGON2_OK;
}

int argon2i_hash_encoded(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	size_t hashlen, char *encoded, size_t encodedlen) {
	return argon2_hash(t_cost, m_cost, parallelism,
		pwd, pwdlen, salt, saltlen,
		NULL, hashlen, encoded, encodedlen,
		Argon2_i, ARGON2_VERSION_NUMBER);
}

int argon2i_hash_raw(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	void *hash, size_t hashlen) {
	return argon2_hash(t_cost, m_cost, parallelism,
		pwd, pwdlen, salt, saltlen,
		hash, hashlen, NULL, 0,
		Argon2_i, ARGON2_VERSION_NUMBER);
}

int argon2d_hash_encoded(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	size_t hashlen, char *encoded, size_t encodedlen) {
	return argon2_hash(t_cost, m_cost, parallelism,
		pwd, pwdlen, salt, saltlen,
		NULL, hashlen, encoded, encodedlen,
		Argon2_d, ARGON2_VERSION_NUMBER);
}

int argon2d_hash_raw(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	void *hash, size_t hashlen) {
	return argon2_hash(t_cost, m_cost, parallelism,
		pwd, pwdlen, salt, saltlen,
		hash, hashlen, NULL, 0,
		Argon2_d, ARGON2_VERSION_NUMBER);
}

int argon2id_hash_encoded(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	size_t hashlen, char *encoded, size_t encodedlen) {
	return argon2_hash(t_cost, m_cost, parallelism,
		pwd, pwdlen, salt, saltlen,
		NULL, hashlen, encoded, encodedlen,
		Argon2_id, ARGON2_VERSION_NUMBER);
}

int argon2id_hash_raw(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	const void *pwd, size_t pwdlen,
	const void *salt, size_t saltlen,
	void *hash, size_t hashlen) {
	return argon2_hash(t_cost, m_cost, parallelism,
		pwd, pwdlen, salt, saltlen,
		hash, hashlen, NULL, 0,
		Argon2_id, ARGON2_VERSION_NUMBER);
}

static int argon2_compare(const ut8 *b1, const ut8 *b2, size_t len) {
	size_t i;
	ut8 d = 0U;
	for (i = 0U; i < len; i++) {
		d |= b1[i] ^ b2[i];
	}
	return (int)((1 & ((d - 1) >> 8)) - 1);
}

int argon2_verify(const char *encoded, const void *pwd, size_t pwdlen,
	argon2_type type) {

	argon2_context ctx;
	ut8 *desired_result = NULL;
	int ret = ARGON2_OK;
	size_t encoded_len;
	ut32 max_field_len;

	if (pwdlen > ARGON2_MAX_PWD_LENGTH) {
		return ARGON2_PWD_TOO_LONG;
	}
	if (!encoded) {
		return ARGON2_DECODING_FAIL;
	}

	encoded_len = strlen(encoded);
	if (encoded_len > UINT32_MAX) {
		return ARGON2_DECODING_FAIL;
	}

	max_field_len = (ut32)encoded_len;
	ctx.saltlen = max_field_len;
	ctx.outlen = max_field_len;

	ctx.salt = rz_mem_alloc(ctx.saltlen);
	ctx.out = rz_mem_alloc(ctx.outlen);
	if (!ctx.salt || !ctx.out) {
		ret = ARGON2_MEMORY_ALLOCATION_ERROR;
		goto fail;
	}

	ctx.pwd = (ut8 *)pwd;
	ctx.pwdlen = (ut32)pwdlen;

	ret = decode_string(&ctx, encoded, type);
	if (ret != ARGON2_OK) {
		goto fail;
	}

	desired_result = ctx.out;
	ctx.out = rz_mem_alloc(ctx.outlen);
	if (!ctx.out) {
		ret = ARGON2_MEMORY_ALLOCATION_ERROR;
		goto fail;
	}

	ret = argon2_verify_ctx(&ctx, (char *)desired_result, type);

fail:
	free(ctx.salt);
	free(ctx.out);
	free(desired_result);
	return ret;
}

int argon2i_verify(const char *encoded, const void *pwd, size_t pwdlen) {
	return argon2_verify(encoded, pwd, pwdlen, Argon2_i);
}

int argon2d_verify(const char *encoded, const void *pwd, size_t pwdlen) {
	return argon2_verify(encoded, pwd, pwdlen, Argon2_d);
}

int argon2id_verify(const char *encoded, const void *pwd, size_t pwdlen) {
	return argon2_verify(encoded, pwd, pwdlen, Argon2_id);
}

int argon2d_ctx(argon2_context *context) {
	return argon2_ctx(context, Argon2_d);
}

int argon2i_ctx(argon2_context *context) {
	return argon2_ctx(context, Argon2_i);
}

int argon2id_ctx(argon2_context *context) {
	return argon2_ctx(context, Argon2_id);
}

int argon2_verify_ctx(argon2_context *context, const char *hash,
	argon2_type type) {
	int ret = argon2_ctx(context, type);
	if (ret != ARGON2_OK) {
		return ret;
	}
	if (argon2_compare((const ut8 *)hash, context->out, context->outlen)) {
		return ARGON2_VERIFY_MISMATCH;
	}
	return ARGON2_OK;
}

int argon2d_verify_ctx(argon2_context *context, const char *hash) {
	return argon2_verify_ctx(context, hash, Argon2_d);
}

int argon2i_verify_ctx(argon2_context *context, const char *hash) {
	return argon2_verify_ctx(context, hash, Argon2_i);
}

int argon2id_verify_ctx(argon2_context *context, const char *hash) {
	return argon2_verify_ctx(context, hash, Argon2_id);
}

const char *argon2_error_message(int error_code) {
	switch (error_code) {
	case ARGON2_OK: return "OK";
	case ARGON2_OUTPUT_PTR_NULL: return "Output pointer is NULL";
	case ARGON2_OUTPUT_TOO_SHORT: return "Output is too short";
	case ARGON2_OUTPUT_TOO_LONG: return "Output is too long";
	case ARGON2_PWD_TOO_SHORT: return "Password is too short";
	case ARGON2_PWD_TOO_LONG: return "Password is too long";
	case ARGON2_SALT_TOO_SHORT: return "Salt is too short";
	case ARGON2_SALT_TOO_LONG: return "Salt is too long";
	case ARGON2_AD_TOO_SHORT: return "Associated data is too short";
	case ARGON2_AD_TOO_LONG: return "Associated data is too long";
	case ARGON2_SECRET_TOO_SHORT: return "Secret is too short";
	case ARGON2_SECRET_TOO_LONG: return "Secret is too long";
	case ARGON2_TIME_TOO_SMALL: return "Time cost is too small";
	case ARGON2_TIME_TOO_LARGE: return "Time cost is too large";
	case ARGON2_MEMORY_TOO_LITTLE: return "Memory cost is too small";
	case ARGON2_MEMORY_TOO_MUCH: return "Memory cost is too large";
	case ARGON2_LANES_TOO_FEW: return "Too few lanes";
	case ARGON2_LANES_TOO_MANY: return "Too many lanes";
	case ARGON2_PWD_PTR_MISMATCH: return "Password pointer is NULL but password length is not 0";
	case ARGON2_SALT_PTR_MISMATCH: return "Salt pointer is NULL but salt length is not 0";
	case ARGON2_SECRET_PTR_MISMATCH: return "Secret pointer is NULL but secret length is not 0";
	case ARGON2_AD_PTR_MISMATCH: return "Associated data pointer is NULL but ad length is not 0";
	case ARGON2_MEMORY_ALLOCATION_ERROR: return "Memory allocation error";
	case ARGON2_FREE_MEMORY_CBK_NULL: return "The free memory callback is NULL";
	case ARGON2_ALLOCATE_MEMORY_CBK_NULL: return "The allocate memory callback is NULL";
	case ARGON2_INCORRECT_PARAMETER: return "Argon2_Context context is NULL";
	case ARGON2_INCORRECT_TYPE: return "There is no such version of Argon2";
	case ARGON2_OUT_PTR_MISMATCH: return "Output pointer mismatch";
	case ARGON2_THREADS_TOO_FEW: return "Not enough threads";
	case ARGON2_THREADS_TOO_MANY: return "Too many threads";
	case ARGON2_MISSING_ARGS: return "Missing arguments";
	case ARGON2_ENCODING_FAIL: return "Encoding failed";
	case ARGON2_DECODING_FAIL: return "Decoding failed";
	case ARGON2_THREAD_FAIL: return "Threading failure";
	case ARGON2_DECODING_LENGTH_FAIL: return "Some encoded parameters are too long or too short";
	case ARGON2_VERIFY_MISMATCH: return "The password does not match the supplied hash";
	default: return "Unknown error code";
	}
}

static size_t numlen(ut32 n) {
	size_t len = 1;
	while (n >= 10) {
		n /= 10;
		len++;
	}
	return len;
}

static size_t b64len(ut32 len) {
	return ((size_t)len * 4 + 2) / 3;
}

size_t argon2_encodedlen(ut32 t_cost, ut32 m_cost, ut32 parallelism,
	ut32 saltlen, ut32 hashlen, argon2_type type) {
	return strlen("$$v=$m=,t=,p=$$") +
		strlen(argon2_type2string(type, 0)) +
		numlen(t_cost) + numlen(m_cost) + numlen(parallelism) +
		b64len(saltlen) + b64len(hashlen) +
		numlen(ARGON2_VERSION_NUMBER) + 1;
}

int allocate_memory(const argon2_context *context, ut8 **memory,
	size_t num, size_t size) {
	size_t memory_size = num * size;

	if (!memory)
		return ARGON2_MEMORY_ALLOCATION_ERROR;
	if (size != 0 && memory_size / size != num)
		return ARGON2_MEMORY_ALLOCATION_ERROR;

	if (context->allocate_cbk) {
		(context->allocate_cbk)(memory, memory_size);
	} else {
		*memory = rz_mem_alloc(memory_size);
	}

	if (!*memory)
		return ARGON2_MEMORY_ALLOCATION_ERROR;
	return ARGON2_OK;
}

void free_memory(const argon2_context *context, ut8 *memory,
	size_t num, size_t size) {
	size_t memory_size = num * size;
	clear_internal_memory(memory, memory_size);
	if (context->free_cbk) {
		(context->free_cbk)(memory, memory_size);
	} else {
		free(memory);
	}
}

int FLAG_clear_internal_memory = 1;

void clear_internal_memory(void *v, size_t n) {
	if (FLAG_clear_internal_memory && v) {
		rz_mem_memzero(v, n);
	}
}

ut32 index_alpha(const argon2_instance_t *instance,
	const argon2_position_t *position,
	ut32 pseudo_rand, int same_lane) {
	ut32 reference_area_size;
	ut64 relative_position;
	ut32 start_position, absolute_position;

	if (position->pass == 0) {
		if (position->slice == 0) {
			reference_area_size = position->index - 1;
		} else {
			if (same_lane) {
				reference_area_size = position->slice * instance->segment_length +
					position->index - 1;
			} else {
				reference_area_size = position->slice * instance->segment_length +
					((position->index == 0) ? (ut32)-1 : 0);
			}
		}
	} else {
		if (same_lane) {
			reference_area_size = instance->lane_length -
				instance->segment_length + position->index - 1;
		} else {
			reference_area_size = instance->lane_length -
				instance->segment_length +
				((position->index == 0) ? (ut32)-1 : 0);
		}
	}

	relative_position = pseudo_rand;
	relative_position = relative_position * relative_position >> 32;
	relative_position = reference_area_size - 1 -
		(reference_area_size * relative_position >> 32);

	start_position = 0;
	if (position->pass != 0) {
		start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
			? 0
			: (position->slice + 1) * instance->segment_length;
	}

	absolute_position = (start_position + relative_position) % instance->lane_length;
	return absolute_position;
}

static int fill_memory_blocks_st(argon2_instance_t *instance) {
	ut32 r, s, l;
	for (r = 0; r < instance->passes; ++r) {
		for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
			for (l = 0; l < instance->lanes; ++l) {
				argon2_position_t position = { r, l, (ut8)s, 0 };
				fill_segment(instance, position);
			}
		}
	}
	return ARGON2_OK;
}

int fill_memory_blocks(argon2_instance_t *instance) {
	if (!instance || instance->memory_blocks == 0) {
		return ARGON2_INCORRECT_PARAMETER;
	}
	return fill_memory_blocks_st(instance);
}