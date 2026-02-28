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

#include "blake2b.h"
#include "argon2.h" /* for clear_internal_memory() */
#include <rz_util/rz_mem.h>
#include <string.h>
#include <stdint.h>

static ut64 load64(const void *src) {
	ut64 w;
	memcpy(&w, src, sizeof w);
	return w;
}

static void store32(void *dst, ut32 w) {
	memcpy(dst, &w, sizeof w);
}

static void store64(void *dst, ut64 w) {
	memcpy(dst, &w, sizeof w);
}

static ut64 rotr64(ut64 x, unsigned n) {
	return (x >> n) | (x << (64 - n));
}

static const ut64 blake2b_IV[8] = {
	UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
	UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
	UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
	UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

static const ut8 blake2b_sigma[12][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

#define G(r, i, a, b, c, d) \
	do { \
		(a) = (a) + (b) + m[blake2b_sigma[r][2 * (i) + 0]]; \
		(d) = rotr64((d) ^ (a), 32); \
		(c) = (c) + (d); \
		(b) = rotr64((b) ^ (c), 24); \
		(a) = (a) + (b) + m[blake2b_sigma[r][2 * (i) + 1]]; \
		(d) = rotr64((d) ^ (a), 16); \
		(c) = (c) + (d); \
		(b) = rotr64((b) ^ (c), 63); \
	} while (0)

#define ROUND(r) \
	do { \
		G(r, 0, v[0], v[4], v[8], v[12]); \
		G(r, 1, v[1], v[5], v[9], v[13]); \
		G(r, 2, v[2], v[6], v[10], v[14]); \
		G(r, 3, v[3], v[7], v[11], v[15]); \
		G(r, 4, v[0], v[5], v[10], v[15]); \
		G(r, 5, v[1], v[6], v[11], v[12]); \
		G(r, 6, v[2], v[7], v[8], v[13]); \
		G(r, 7, v[3], v[4], v[9], v[14]); \
	} while (0)

static void blake2b_compress(blake2b_state *S, const ut8 block[BLAKE2B_BLOCKBYTES]) {
	ut64 m[16];
	ut64 v[16];
	int i;

	for (i = 0; i < 16; ++i) {
		m[i] = load64(block + i * sizeof(ut64));
	}

	for (i = 0; i < 8; ++i) {
		v[i] = S->h[i];
	}

	v[8] = blake2b_IV[0];
	v[9] = blake2b_IV[1];
	v[10] = blake2b_IV[2];
	v[11] = blake2b_IV[3];
	v[12] = blake2b_IV[4] ^ S->t[0];
	v[13] = blake2b_IV[5] ^ S->t[1];
	v[14] = blake2b_IV[6] ^ S->f[0];
	v[15] = blake2b_IV[7] ^ S->f[1];

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);

	for (i = 0; i < 8; ++i) {
		S->h[i] ^= v[i] ^ v[i + 8];
	}
}

#undef G
#undef ROUND

static void blake2b_increment_counter(blake2b_state *S, ut64 inc) {
	S->t[0] += inc;
	S->t[1] += (S->t[0] < inc) ? 1 : 0;
}

static void blake2b_set_lastblock(blake2b_state *S) {
	S->f[0] = UINT64_C(0xFFFFFFFFFFFFFFFF);
}

static int blake2b_is_lastblock(const blake2b_state *S) {
	return S->f[0] != 0;
}

static int blake2b_init_param(blake2b_state *S, const blake2b_param *P) {
	const ut8 *p = (const ut8 *)P;
	int i;

	memset(S, 0, sizeof *S);

	for (i = 0; i < 8; ++i) {
		S->h[i] = blake2b_IV[i];
	}

	for (i = 0; i < 8; ++i) {
		S->h[i] ^= load64(p + sizeof(ut64) * i);
	}

	S->outlen = P->digest_length;
	return 0;
}

int blake2b_init(blake2b_state *S, size_t outlen) {
	blake2b_param P;

	if (!outlen || outlen > BLAKE2B_OUTBYTES) {
		return -1;
	}

	memset(&P, 0, sizeof P);
	P.digest_length = (ut8)outlen;
	P.fanout = 1;
	P.depth = 1;

	return blake2b_init_param(S, &P);
}

int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen) {
	blake2b_param P;
	ut8 block[BLAKE2B_BLOCKBYTES];

	if (!outlen || outlen > BLAKE2B_OUTBYTES)
		return -1;
	if (!key || !keylen || keylen > BLAKE2B_KEYBYTES)
		return -1;

	memset(&P, 0, sizeof P);
	P.digest_length = (ut8)outlen;
	P.key_length = (ut8)keylen;
	P.fanout = 1;
	P.depth = 1;

	if (blake2b_init_param(S, &P) < 0)
		return -1;

	memset(block, 0, BLAKE2B_BLOCKBYTES);
	memcpy(block, key, keylen);
	blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
	clear_internal_memory(block, BLAKE2B_BLOCKBYTES);
	return 0;
}

int blake2b_update(blake2b_state *S, const void *pin, size_t inlen) {
	const ut8 *in = (const ut8 *)pin;

	if (!in && inlen > 0)
		return -1;

	while (inlen > 0) {
		size_t left = S->buflen;
		size_t fill = BLAKE2B_BLOCKBYTES - left;

		if (inlen > fill) {
			/* Fill the buffer and compress */
			memcpy(S->buf + left, in, fill);
			blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
			blake2b_compress(S, S->buf);
			S->buflen = 0;
			in += fill;
			inlen -= fill;
		} else {
			/* Just buffer the remaining bytes */
			memcpy(S->buf + left, in, inlen);
			S->buflen += inlen;
			break;
		}
	}
	return 0;
}

int blake2b_final(blake2b_state *S, void *out, size_t outlen) {
	ut8 buffer[BLAKE2B_OUTBYTES];
	int i;

	if (!out || outlen < S->outlen)
		return -1;
	if (blake2b_is_lastblock(S))
		return -1;

	blake2b_increment_counter(S, S->buflen);
	blake2b_set_lastblock(S);

	/* Pad the remaining buffer with zeros */
	memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
	blake2b_compress(S, S->buf);

	/* Store the result in a temporary buffer */
	for (i = 0; i < 8; ++i) {
		store64(buffer + sizeof(ut64) * i, S->h[i]);
	}

	memcpy(out, buffer, S->outlen);
	clear_internal_memory(buffer, sizeof buffer);
	clear_internal_memory(S, sizeof *S);
	return 0;
}

/* ================================================================== */
/* blake2b_long  — Argon2-specific variable-length hash               */
/*                                                                      */
/* Defined in the Argon2 spec (section 3.2):                           */
/*   if outlen <= 64  -> single Blake2b(outlen, in)                    */
/*   if outlen >  64  -> chain of 32-byte Blake2b digests              */
/* ================================================================== */

int blake2b_long(void *pout, size_t outlen, const void *pin, size_t inlen) {
	ut8 *out = (ut8 *)pout;
	blake2b_state blake_state;
	ut8 outlen_bytes[sizeof(ut32)];
	int ret = -1;

	if (outlen > UINT32_MAX)
		return -1;

	store32(outlen_bytes, (ut32)outlen);

	if (outlen <= BLAKE2B_OUTBYTES) {
		/* Short path: single Blake2b call */
		if (blake2b_init(&blake_state, outlen) < 0)
			goto fail;
		if (blake2b_update(&blake_state, outlen_bytes, sizeof outlen_bytes) < 0)
			goto fail;
		if (blake2b_update(&blake_state, pin, inlen) < 0)
			goto fail;
		if (blake2b_final(&blake_state, out, outlen) < 0)
			goto fail;
	} else {
		/* Long path: produce 32-byte chunks iteratively */
		ut8 A[BLAKE2B_OUTBYTES]; /* current digest */
		ut8 B[BLAKE2B_OUTBYTES]; /* next digest    */
		size_t remaining;
		size_t toproduce;

		/* A_1 = Blake2b(64, outlen || in) */
		if (blake2b_init(&blake_state, BLAKE2B_OUTBYTES) < 0)
			goto fail;
		if (blake2b_update(&blake_state, outlen_bytes, sizeof outlen_bytes) < 0)
			goto fail;
		if (blake2b_update(&blake_state, pin, inlen) < 0)
			goto fail;
		if (blake2b_final(&blake_state, A, BLAKE2B_OUTBYTES) < 0)
			goto fail;

		/* Copy first 32 bytes of A_1 to output */
		memcpy(out, A, BLAKE2B_OUTBYTES / 2);
		out += BLAKE2B_OUTBYTES / 2;
		remaining = outlen - BLAKE2B_OUTBYTES / 2;

		/* Produce subsequent blocks */
		while (remaining > BLAKE2B_OUTBYTES) {
			if (blake2b_init(&blake_state, BLAKE2B_OUTBYTES) < 0)
				goto fail;
			if (blake2b_update(&blake_state, A, BLAKE2B_OUTBYTES) < 0)
				goto fail;
			if (blake2b_final(&blake_state, B, BLAKE2B_OUTBYTES) < 0)
				goto fail;

			memcpy(out, B, BLAKE2B_OUTBYTES / 2);
			out += BLAKE2B_OUTBYTES / 2;
			remaining -= BLAKE2B_OUTBYTES / 2;
			memcpy(A, B, BLAKE2B_OUTBYTES);
		}

		/* Final block: emit all remaining bytes */
		toproduce = remaining;
		if (blake2b_init(&blake_state, toproduce) < 0)
			goto fail;
		if (blake2b_update(&blake_state, A, BLAKE2B_OUTBYTES) < 0)
			goto fail;
		if (blake2b_final(&blake_state, out, toproduce) < 0)
			goto fail;

		clear_internal_memory(A, sizeof A);
		clear_internal_memory(B, sizeof B);
	}

	ret = 0;
fail:
	clear_internal_memory(&blake_state, sizeof blake_state);
	return ret;
}
