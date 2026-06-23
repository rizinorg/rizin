// SPDX-FileCopyrightText: 2015 Andrey Jivsov <crypto@brainhub.org>
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "shake.h"

#define SHAKE_CONST(x) x##L

#ifndef SHAKE_ROTL64
#define SHAKE_ROTL64(x, y) \
	(((x) << (y)) | ((x) >> ((sizeof(uint64_t) * 8) - (y))))
#endif

static const uint64_t keccakf_rndc[24] = {
	SHAKE_CONST(0x0000000000000001UL), SHAKE_CONST(0x0000000000008082UL),
	SHAKE_CONST(0x800000000000808aUL), SHAKE_CONST(0x8000000080008000UL),
	SHAKE_CONST(0x000000000000808bUL), SHAKE_CONST(0x0000000080000001UL),
	SHAKE_CONST(0x8000000080008081UL), SHAKE_CONST(0x8000000000008009UL),
	SHAKE_CONST(0x000000000000008aUL), SHAKE_CONST(0x0000000000000088UL),
	SHAKE_CONST(0x0000000080008009UL), SHAKE_CONST(0x000000008000000aUL),
	SHAKE_CONST(0x000000008000808bUL), SHAKE_CONST(0x800000000000008bUL),
	SHAKE_CONST(0x8000000000008089UL), SHAKE_CONST(0x8000000000008003UL),
	SHAKE_CONST(0x8000000000008002UL), SHAKE_CONST(0x8000000000000080UL),
	SHAKE_CONST(0x000000000000800aUL), SHAKE_CONST(0x800000008000000aUL),
	SHAKE_CONST(0x8000000080008081UL), SHAKE_CONST(0x8000000000008080UL),
	SHAKE_CONST(0x0000000080000001UL), SHAKE_CONST(0x8000000080008008UL)
};

static const unsigned keccakf_rotc[24] = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
	18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
	14, 22, 9, 6, 1
};

static void keccakf(uint64_t s[25]) {
	int i, j, round;
	uint64_t t, bc[5];
#define KECCAK_ROUNDS 24

	for (round = 0; round < KECCAK_ROUNDS; round++) {

		/* Theta */
		for (i = 0; i < 5; i++)
			bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ SHAKE_ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				s[j + i] ^= t;
		}

		/* Rho Pi */
		t = s[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = s[j];
			s[j] = SHAKE_ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = s[j + i];
			for (i = 0; i < 5; i++)
				s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		/* Iota */
		s[0] ^= keccakf_rndc[round];
	}
}

void shake_Init128(void *priv) {
	shake_context *ctx = (shake_context *)priv;
	memset(ctx, 0, sizeof(*ctx));
	ctx->capacityWords = 4;
}

void shake_Init256(void *priv) {
	shake_context *ctx = (shake_context *)priv;
	memset(ctx, 0, sizeof(*ctx));
	ctx->capacityWords = 8;
}

void shake_Update(void *priv, void const *bufIn, size_t len) {
	shake_context *ctx = (shake_context *)priv;

	/* 0...7 -- how much is needed to have a word */
	unsigned old_tail = (8 - ctx->byteIndex) & 7;

	size_t words;
	unsigned tail;
	size_t i;

	const uint8_t *buf = bufIn;

	if (len < old_tail) {
		while (len--)
			ctx->saved |= (uint64_t)(*(buf++)) << ((ctx->byteIndex++) * 8);
		return;
	}

	if (old_tail) { /* will have one word to process */
		len -= old_tail;
		while (old_tail--)
			ctx->saved |= (uint64_t)(*(buf++)) << ((ctx->byteIndex++) * 8);

		/* now ready to add saved to the sponge */
		ctx->u.s[ctx->wordIndex] ^= ctx->saved;
		ctx->byteIndex = 0;
		ctx->saved = 0;
		if (++ctx->wordIndex == (SHAKE_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
			keccakf(ctx->u.s);
			ctx->wordIndex = 0;
		}
	}

	/* now work in full words directly from input */

	words = len / sizeof(uint64_t);
	tail = len - words * sizeof(uint64_t);

	for (i = 0; i < words; i++, buf += sizeof(uint64_t)) {
		const uint64_t t = (uint64_t)(buf[0]) |
			((uint64_t)(buf[1]) << 8 * 1) |
			((uint64_t)(buf[2]) << 8 * 2) |
			((uint64_t)(buf[3]) << 8 * 3) |
			((uint64_t)(buf[4]) << 8 * 4) |
			((uint64_t)(buf[5]) << 8 * 5) |
			((uint64_t)(buf[6]) << 8 * 6) |
			((uint64_t)(buf[7]) << 8 * 7);
		ctx->u.s[ctx->wordIndex] ^= t;
		if (++ctx->wordIndex == (SHAKE_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
			keccakf(ctx->u.s);
			ctx->wordIndex = 0;
		}
	}

	/* finally, save the partial word */
	while (tail--) {
		ctx->saved |= (uint64_t)(*(buf++)) << ((ctx->byteIndex++) * 8);
	}
}

void shake_Finalize(void *priv) {
	shake_context *ctx = (shake_context *)priv;
	uint64_t t = (uint64_t)(((uint64_t)0x1f) << (ctx->byteIndex * 8));
	ctx->u.s[ctx->wordIndex] ^= ctx->saved ^ t;
	ctx->u.s[SHAKE_KECCAK_SPONGE_WORDS - ctx->capacityWords - 1] ^=
		SHAKE_CONST(0x8000000000000000UL);
	keccakf(ctx->u.s);
	ctx->byteIndex = 0;
}

void shake_Squeeze(void *priv, uint8_t *output, size_t outlen) {
	shake_context *ctx = (shake_context *)priv;
	size_t rate_bytes = (SHAKE_KECCAK_SPONGE_WORDS - ctx->capacityWords) * 8;
	size_t i;
	for (i = 0; i < outlen; i++) {
		if (ctx->byteIndex >= rate_bytes) {
			keccakf(ctx->u.s);
			ctx->byteIndex = 0;
		}
		unsigned word_idx = ctx->byteIndex / 8;
		unsigned byte_in_word = ctx->byteIndex % 8;
		output[i] = (uint8_t)(ctx->u.s[word_idx] >> (byte_in_word * 8));
		ctx->byteIndex++;
	}
}
