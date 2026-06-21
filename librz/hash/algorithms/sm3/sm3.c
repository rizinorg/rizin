// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2017-2023 Free Software Foundation, Inc.
// SPDX-License-Identifier: LGPL-2.1-only

#include "sm3.h"
#include <rz_endian.h>

static void sm3_process_block(const void *buffer, ut64 len, sm3_ctx_t *ctx);

// clang-format off
/* This array contains the bytes used to pad the buffer to the next
   64-byte boundary.  */
static const ut8 fillbuf[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
// clang-format on

/*
  Takes a pointer to a 256 bit block of data (eight 32 bit ints) and
  initializes it to the start constants of the SM3 algorithm.  This
  must be called before using hash in the call to sm3_hash
*/
void sm3_init_ctx(sm3_ctx_t *ctx) {
	memset(ctx, 0, sizeof(sm3_ctx_t));

	ctx->state[0] = 0x7380166fUL;
	ctx->state[1] = 0x4914b2b9UL;
	ctx->state[2] = 0x172442d7UL;
	ctx->state[3] = 0xda8a0600UL;
	ctx->state[4] = 0xa96f30bcUL;
	ctx->state[5] = 0x163138aaUL;
	ctx->state[6] = 0xe38dee4dUL;
	ctx->state[7] = 0xb0fb0e4eUL;
}

/* Put result from CTX in first 32 bytes following RESBUF.  The result
   must be in little endian byte order.  */
static void sm3_read_ctx(const sm3_ctx_t *ctx, void *digest) {
	for (ut64 i = 0; i < 8; i++) {
		ut64 offset = i * sizeof(ut32);
		rz_write_at_be32(digest, ctx->state[i], offset);
	}
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.  */
static void sm3_conclude_ctx(sm3_ctx_t *ctx) {
	/* Take yet unprocessed bytes into account.  */
	ut64 bytes = ctx->buflen;
	ut64 size = (bytes < 56) ? 64 / 4 : 64 * 2 / 4;

	/* Now count remaining bytes.  */
	ctx->total[0] += bytes;
	if (ctx->total[0] < bytes) {
		++ctx->total[1];
	}

	/* Put the 64-bit file length in *bits* at the end of the buffer.
	   Use set_uint32 rather than a simple assignment, to avoid risk of
	   unaligned access.  */
	rz_write_be32(&ctx->buffer[size - 2], (ctx->total[1] << 3) | (ctx->total[0] >> 29));
	rz_write_be32(&ctx->buffer[size - 1], ctx->total[0] << 3);

	memcpy(&((char *)ctx->buffer)[bytes], fillbuf, (size - 2) * 4 - bytes);

	/* Process last bytes.  */
	sm3_process_block(ctx->buffer, size * 4, ctx);
}

void sm3_finish_ctx(sm3_ctx_t *ctx, void *resbuf) {
	sm3_conclude_ctx(ctx);
	sm3_read_ctx(ctx, resbuf);
}

void sm3_process_bytes(const void *buffer, ut64 len, sm3_ctx_t *ctx) {
	/* When we already have some bits in our internal buffer concatenate
	   both inputs first.  */
	if (ctx->buflen != 0) {
		ut64 left_over = ctx->buflen;
		ut64 add = 128 - left_over > len ? len : 128 - left_over;

		memcpy(&((char *)ctx->buffer)[left_over], buffer, add);
		ctx->buflen += add;

		if (ctx->buflen > 64) {
			sm3_process_block(ctx->buffer, ctx->buflen & ~63, ctx);

			ctx->buflen &= 63;
			/* The regions in the following copy operation cannot overlap,
			   because ctx->buflen < 64 â‰¤ (left_over + add) & ~63.  */
			memcpy(ctx->buffer,
				&((char *)ctx->buffer)[(left_over + add) & ~63],
				ctx->buflen);
		}

		buffer = (const char *)buffer + add;
		len -= add;
	}

	/* Process available complete blocks.  */
	if (len >= 64) {
		while (len > 64) {
			sm3_process_block(memcpy(ctx->buffer, buffer, 64), 64, ctx);
			buffer = (const char *)buffer + 64;
			len -= 64;
		}
	}

	/* Move remaining bytes in internal buffer.  */
	if (len > 0) {
		ut64 left_over = ctx->buflen;

		memcpy(&((char *)ctx->buffer)[left_over], buffer, len);
		left_over += len;
		if (left_over >= 64) {
			sm3_process_block(ctx->buffer, 64, ctx);
			left_over -= 64;
			/* The regions in the following copy operation cannot overlap,
			   because left_over â‰¤ 64.  */
			memcpy(ctx->buffer, &ctx->buffer[16], left_over);
		}
		ctx->buflen = left_over;
	}
}

/* --- Code below is the primary difference between sha256.c and sm3.c --- */

/* SM3 round constants */
#define T(j) sm3_round_constants[j]

// clang-format off
static const ut32 sm3_round_constants[64] = {
  0x79cc4519ul, 0xf3988a32ul, 0xe7311465ul, 0xce6228cbul,
  0x9cc45197ul, 0x3988a32ful, 0x7311465eul, 0xe6228cbcul,
  0xcc451979ul, 0x988a32f3ul, 0x311465e7ul, 0x6228cbceul,
  0xc451979cul, 0x88a32f39ul, 0x11465e73ul, 0x228cbce6ul,
  0x9d8a7a87ul, 0x3b14f50ful, 0x7629ea1eul, 0xec53d43cul,
  0xd8a7a879ul, 0xb14f50f3ul, 0x629ea1e7ul, 0xc53d43ceul,
  0x8a7a879dul, 0x14f50f3bul, 0x29ea1e76ul, 0x53d43cecul,
  0xa7a879d8ul, 0x4f50f3b1ul, 0x9ea1e762ul, 0x3d43cec5ul,
  0x7a879d8aul, 0xf50f3b14ul, 0xea1e7629ul, 0xd43cec53ul,
  0xa879d8a7ul, 0x50f3b14ful, 0xa1e7629eul, 0x43cec53dul,
  0x879d8a7aul, 0x0f3b14f5ul, 0x1e7629eaul, 0x3cec53d4ul,
  0x79d8a7a8ul, 0xf3b14f50ul, 0xe7629ea1ul, 0xcec53d43ul,
  0x9d8a7a87ul, 0x3b14f50ful, 0x7629ea1eul, 0xec53d43cul,
  0xd8a7a879ul, 0xb14f50f3ul, 0x629ea1e7ul, 0xc53d43ceul,
  0x8a7a879dul, 0x14f50f3bul, 0x29ea1e76ul, 0x53d43cecul,
  0xa7a879d8ul, 0x4f50f3b1ul, 0x9ea1e762ul, 0x3d43cec5ul,
};
// clang-format on

/* Round functions.  */
#define FF1(X, Y, Z) (X ^ Y ^ Z)
#define FF2(X, Y, Z) ((X & Y) | (X & Z) | (Y & Z))
#define GG1(X, Y, Z) (X ^ Y ^ Z)
#define GG2(X, Y, Z) ((X & Y) | (~X & Z))

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.
   Most of this code comes from David Madore's sha256.c.  */
static void sm3_process_block(const void *buffer, ut64 len, sm3_ctx_t *ctx) {
	const ut32 *words = buffer;
	ut64 nwords = len / sizeof(ut32);
	const ut32 *endp = words + nwords;
	ut32 x[16];
	ut32 a = ctx->state[0];
	ut32 b = ctx->state[1];
	ut32 c = ctx->state[2];
	ut32 d = ctx->state[3];
	ut32 e = ctx->state[4];
	ut32 f = ctx->state[5];
	ut32 g = ctx->state[6];
	ut32 h = ctx->state[7];
	ut32 low_len = len;

	/* First increment the byte count.  GM/T 004-2012 specifies the possible
	   length of the file up to 2^64 bits.  Here we only compute the
	   number of bytes.  Do a double word increment.  */
	ctx->total[0] += low_len;
	ctx->total[1] += (len >> 31 >> 1) + (ctx->total[0] < low_len);

#define rol(x, n) (((x) << ((n) & 31)) | ((x) >> ((32 - (n)) & 31)))
#define P0(x)     ((x) ^ rol(x, 9) ^ rol(x, 17))
#define P1(x)     ((x) ^ rol(x, 15) ^ rol(x, 23))

#define W1(I) (x[I & 0x0f])
#define W2(I) (tw = P1(x[I & 0x0f] ^ x[(I - 9) & 0x0f] ^ rol(x[(I - 3) & 0x0f], 15)) ^ rol(x[(I - 13) & 0x0f], 7) ^ x[(I - 6) & 0x0f], x[I & 0x0f] = tw)

#define R(i, A, B, C, D, E, F, G, H, T, W1, W2) \
	do { \
		ss1 = rol(rol(A, 12) + E + T, 7); \
		ss2 = ss1 ^ rol(A, 12); \
		D += FF##i(A, B, C) + ss2 + (W1 ^ W2); \
		H += GG##i(E, F, G) + ss1 + W1; \
		B = rol(B, 9); \
		F = rol(F, 19); \
		H = P0(H); \
	} while (0)

#define R1(A, B, C, D, E, F, G, H, T, W1, W2) \
	R(1, A, B, C, D, E, F, G, H, T, W1, W2)
#define R2(A, B, C, D, E, F, G, H, T, W1, W2) \
	R(2, A, B, C, D, E, F, G, H, T, W1, W2)

	while (words < endp) {
		ut32 tw = 0;
		ut32 ss1 = 0, ss2 = 0;

		for (ut32 j = 0; j < 16; j++) {
			x[j] = rz_read_be32(words);
			words++;
		}

		R1(a, b, c, d, e, f, g, h, T(0), W1(0), W1(4));
		R1(d, a, b, c, h, e, f, g, T(1), W1(1), W1(5));
		R1(c, d, a, b, g, h, e, f, T(2), W1(2), W1(6));
		R1(b, c, d, a, f, g, h, e, T(3), W1(3), W1(7));
		R1(a, b, c, d, e, f, g, h, T(4), W1(4), W1(8));
		R1(d, a, b, c, h, e, f, g, T(5), W1(5), W1(9));
		R1(c, d, a, b, g, h, e, f, T(6), W1(6), W1(10));
		R1(b, c, d, a, f, g, h, e, T(7), W1(7), W1(11));
		R1(a, b, c, d, e, f, g, h, T(8), W1(8), W1(12));
		R1(d, a, b, c, h, e, f, g, T(9), W1(9), W1(13));
		R1(c, d, a, b, g, h, e, f, T(10), W1(10), W1(14));
		R1(b, c, d, a, f, g, h, e, T(11), W1(11), W1(15));
		R1(a, b, c, d, e, f, g, h, T(12), W1(12), W2(16));
		R1(d, a, b, c, h, e, f, g, T(13), W1(13), W2(17));
		R1(c, d, a, b, g, h, e, f, T(14), W1(14), W2(18));
		R1(b, c, d, a, f, g, h, e, T(15), W1(15), W2(19));
		R2(a, b, c, d, e, f, g, h, T(16), W1(16), W2(20));
		R2(d, a, b, c, h, e, f, g, T(17), W1(17), W2(21));
		R2(c, d, a, b, g, h, e, f, T(18), W1(18), W2(22));
		R2(b, c, d, a, f, g, h, e, T(19), W1(19), W2(23));
		R2(a, b, c, d, e, f, g, h, T(20), W1(20), W2(24));
		R2(d, a, b, c, h, e, f, g, T(21), W1(21), W2(25));
		R2(c, d, a, b, g, h, e, f, T(22), W1(22), W2(26));
		R2(b, c, d, a, f, g, h, e, T(23), W1(23), W2(27));
		R2(a, b, c, d, e, f, g, h, T(24), W1(24), W2(28));
		R2(d, a, b, c, h, e, f, g, T(25), W1(25), W2(29));
		R2(c, d, a, b, g, h, e, f, T(26), W1(26), W2(30));
		R2(b, c, d, a, f, g, h, e, T(27), W1(27), W2(31));
		R2(a, b, c, d, e, f, g, h, T(28), W1(28), W2(32));
		R2(d, a, b, c, h, e, f, g, T(29), W1(29), W2(33));
		R2(c, d, a, b, g, h, e, f, T(30), W1(30), W2(34));
		R2(b, c, d, a, f, g, h, e, T(31), W1(31), W2(35));
		R2(a, b, c, d, e, f, g, h, T(32), W1(32), W2(36));
		R2(d, a, b, c, h, e, f, g, T(33), W1(33), W2(37));
		R2(c, d, a, b, g, h, e, f, T(34), W1(34), W2(38));
		R2(b, c, d, a, f, g, h, e, T(35), W1(35), W2(39));
		R2(a, b, c, d, e, f, g, h, T(36), W1(36), W2(40));
		R2(d, a, b, c, h, e, f, g, T(37), W1(37), W2(41));
		R2(c, d, a, b, g, h, e, f, T(38), W1(38), W2(42));
		R2(b, c, d, a, f, g, h, e, T(39), W1(39), W2(43));
		R2(a, b, c, d, e, f, g, h, T(40), W1(40), W2(44));
		R2(d, a, b, c, h, e, f, g, T(41), W1(41), W2(45));
		R2(c, d, a, b, g, h, e, f, T(42), W1(42), W2(46));
		R2(b, c, d, a, f, g, h, e, T(43), W1(43), W2(47));
		R2(a, b, c, d, e, f, g, h, T(44), W1(44), W2(48));
		R2(d, a, b, c, h, e, f, g, T(45), W1(45), W2(49));
		R2(c, d, a, b, g, h, e, f, T(46), W1(46), W2(50));
		R2(b, c, d, a, f, g, h, e, T(47), W1(47), W2(51));
		R2(a, b, c, d, e, f, g, h, T(48), W1(48), W2(52));
		R2(d, a, b, c, h, e, f, g, T(49), W1(49), W2(53));
		R2(c, d, a, b, g, h, e, f, T(50), W1(50), W2(54));
		R2(b, c, d, a, f, g, h, e, T(51), W1(51), W2(55));
		R2(a, b, c, d, e, f, g, h, T(52), W1(52), W2(56));
		R2(d, a, b, c, h, e, f, g, T(53), W1(53), W2(57));
		R2(c, d, a, b, g, h, e, f, T(54), W1(54), W2(58));
		R2(b, c, d, a, f, g, h, e, T(55), W1(55), W2(59));
		R2(a, b, c, d, e, f, g, h, T(56), W1(56), W2(60));
		R2(d, a, b, c, h, e, f, g, T(57), W1(57), W2(61));
		R2(c, d, a, b, g, h, e, f, T(58), W1(58), W2(62));
		R2(b, c, d, a, f, g, h, e, T(59), W1(59), W2(63));
		R2(a, b, c, d, e, f, g, h, T(60), W1(60), W2(64));
		R2(d, a, b, c, h, e, f, g, T(61), W1(61), W2(65));
		R2(c, d, a, b, g, h, e, f, T(62), W1(62), W2(66));
		R2(b, c, d, a, f, g, h, e, T(63), W1(63), W2(67));

		a = ctx->state[0] ^= a;
		b = ctx->state[1] ^= b;
		c = ctx->state[2] ^= c;
		d = ctx->state[3] ^= d;
		e = ctx->state[4] ^= e;
		f = ctx->state[5] ^= f;
		g = ctx->state[6] ^= g;
		h = ctx->state[7] ^= h;
	}
}
