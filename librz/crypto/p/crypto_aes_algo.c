// SPDX-FileCopyrightText: Karl Malbrain <malbrain@yahoo.com>
// SPDX-License-Identifier: MS-PL

#include "crypto_aes_algo.h"

#define Nb 4 //  number of columns in the state & expanded key
#define Nr 16 // max number of rounds in encryption
#define Nk 8 //  max number of columns in a key

static const ut8 Rcon[30] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
	0x1b, 0x36, 0x6c, 0xc0, 0xab, 0x4d, 0x9a, 0x2f,
	0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
	0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
};

typedef struct {
	ut32 key0[Nr][Nb];
	ut32 key1[Nr][Nb];
} expkey_t;

void aes_expkey(const aes_state_t *st, expkey_t *ek) {
	rz_return_if_fail(st->rounds <= Nr && st->columns <= Nk); // This can't happen

	int round_key_count = 4 * (1 + st->rounds);
	ut32 tk[Nk];

	ut32 tt;
	st32 idx = 0, t = 0;
	const ut8 *key = st->key;
	st32 i, j, r;
	for (i = 0; i <= st->rounds; i++) {
		for (j = 0; j < Nb; j++) {
			ek->key0[i][j] = 0;
		}
	}

	for (i = 0; i <= st->rounds; i++) {
		for (j = 0; j < Nb; j++) {
			ek->key1[i][j] = 0;
		}
	}

	// Copy user material bytes into temporary ints
	for (i = 0; i < st->columns; i++) {
		tk[i] = *key++ << 24;
		tk[i] |= *key++ << 16;
		tk[i] |= *key++ << 8;
		tk[i] |= *key++;
	}

	// Copy values into round key arrays
	for (j = 0; j < st->columns && t < round_key_count; j++, t++) {
		ek->key0[t / Nb][t % Nb] = tk[j];
		ek->key1[st->rounds - (t / Nb)][t % Nb] = tk[j];
	}

	while (t < round_key_count) {
		// Extrapolate using phi (the round key evolution function)
		tt = tk[st->columns - 1];
		tk[0] ^= Sbox[(ut8)(tt >> 16)] << 24 ^ Sbox[(ut8)(tt >> 8)] << 16 ^
			Sbox[(ut8)tt] << 8 ^ Sbox[(ut8)(tt >> 24)] ^ Rcon[idx++] << 24;

		if (st->columns != 8) {
			for (i = 1, j = 0; i < st->columns;) {
				tk[i++] ^= tk[j++];
			}
		} else {
			for (i = 1, j = 0; i < st->columns / 2;) {
				tk[i++] ^= tk[j++];
			}
			tt = tk[st->columns / 2 - 1];
			tk[st->columns / 2] ^= Sbox[(ut8)tt] ^ Sbox[(ut8)(tt >> 8)] << 8 ^
				Sbox[(ut8)(tt >> 16)] << 16 ^
				Sbox[(ut8)(tt >> 24)] << 24;
			for (j = st->columns / 2, i = j + 1; i < st->columns;) {
				tk[i++] ^= tk[j++];
			}
		}

		// Copy values into round key arrays
		for (j = 0; j < st->columns && t < round_key_count; j++, t++) {
			ek->key0[t / Nb][t % Nb] = tk[j];
			ek->key1[st->rounds - (t / Nb)][t % Nb] = tk[j];
		}
	}
	// Inverse MixColumn where needed
	for (r = 1; r < st->rounds; r++) {
		for (j = 0; j < Nb; j++) {
			tt = ek->key1[r][j];
			ek->key1[r][j] = U0[(ut8)(tt >> 24)] ^ U1[(ut8)(tt >> 16)] ^
				U2[(ut8)(tt >> 8)] ^ U3[(ut8)tt];
		}
	}
}

// Convenience method to encrypt exactly one block of plaintext, assuming
// Rijndael's default block size (128-bit).
// in         - The plaintext
// result     - The ciphertext generated from a plaintext using the key
void aes_encrypt(aes_state_t *st, ut8 *in, ut8 *result) {
	expkey_t ek = { 0 };

	aes_expkey(st, &ek);

	ut32 t0, t1, t2, t3, tt;
	ut32 a0, a1, a2, a3, r;

	t0 = *in++ << 24;
	t0 |= *in++ << 16;
	t0 |= *in++ << 8;
	t0 |= *in++;
	t0 ^= ek.key0[0][0];

	t1 = *in++ << 24;
	t1 |= *in++ << 16;
	t1 |= *in++ << 8;
	t1 |= *in++;
	t1 ^= ek.key0[0][1];

	t2 = *in++ << 24;
	t2 |= *in++ << 16;
	t2 |= *in++ << 8;
	t2 |= *in++;
	t2 ^= ek.key0[0][2];

	t3 = *in++ << 24;
	t3 |= *in++ << 16;
	t3 |= *in++ << 8;
	t3 |= *in++;
	t3 ^= ek.key0[0][3];

	// Apply Round Transforms
	for (r = 1; r < st->rounds; r++) {
		a0 = (FT0[(ut8)(t0 >> 24)] ^ FT1[(ut8)(t1 >> 16)] ^ FT2[(ut8)(t2 >> 8)] ^
			FT3[(ut8)t3]);
		a1 = (FT0[(ut8)(t1 >> 24)] ^ FT1[(ut8)(t2 >> 16)] ^ FT2[(ut8)(t3 >> 8)] ^
			FT3[(ut8)t0]);
		a2 = (FT0[(ut8)(t2 >> 24)] ^ FT1[(ut8)(t3 >> 16)] ^ FT2[(ut8)(t0 >> 8)] ^
			FT3[(ut8)t1]);
		a3 = (FT0[(ut8)(t3 >> 24)] ^ FT1[(ut8)(t0 >> 16)] ^ FT2[(ut8)(t1 >> 8)] ^
			FT3[(ut8)t2]);
		t0 = a0 ^ ek.key0[r][0];
		t1 = a1 ^ ek.key0[r][1];
		t2 = a2 ^ ek.key0[r][2];
		t3 = a3 ^ ek.key0[r][3];
	}

	// Last Round is special

	tt = ek.key0[st->rounds][0];
	result[0] = Sbox[(ut8)(t0 >> 24)] ^ (ut8)(tt >> 24);
	result[1] = Sbox[(ut8)(t1 >> 16)] ^ (ut8)(tt >> 16);
	result[2] = Sbox[(ut8)(t2 >> 8)] ^ (ut8)(tt >> 8);
	result[3] = Sbox[(ut8)t3] ^ (ut8)tt;

	tt = ek.key0[st->rounds][1];
	result[4] = Sbox[(ut8)(t1 >> 24)] ^ (ut8)(tt >> 24);
	result[5] = Sbox[(ut8)(t2 >> 16)] ^ (ut8)(tt >> 16);
	result[6] = Sbox[(ut8)(t3 >> 8)] ^ (ut8)(tt >> 8);
	result[7] = Sbox[(ut8)t0] ^ (ut8)tt;

	tt = ek.key0[st->rounds][2];
	result[8] = Sbox[(ut8)(t2 >> 24)] ^ (ut8)(tt >> 24);
	result[9] = Sbox[(ut8)(t3 >> 16)] ^ (ut8)(tt >> 16);
	result[10] = Sbox[(ut8)(t0 >> 8)] ^ (ut8)(tt >> 8);
	result[11] = Sbox[(ut8)t1] ^ (ut8)tt;

	tt = ek.key0[st->rounds][3];
	result[12] = Sbox[(ut8)(t3 >> 24)] ^ (ut8)(tt >> 24);
	result[13] = Sbox[(ut8)(t0 >> 16)] ^ (ut8)(tt >> 16);
	result[14] = Sbox[(ut8)(t1 >> 8)] ^ (ut8)(tt >> 8);
	result[15] = Sbox[(ut8)t2] ^ (ut8)tt;
}

// Convenience method to decrypt exactly one block of plaintext, assuming
// Rijndael's default block size (128-bit).
// in         - The ciphertext.
// result     - The plaintext generated from a ciphertext using the session key.
void aes_decrypt(aes_state_t *st, ut8 *in, ut8 *result) {
	expkey_t ek = { 0 };

	aes_expkey(st, &ek);

	ut32 t0, t1, t2, t3, tt;
	ut32 a0, a1, a2, a3, r;

	t0 = *in++ << 24;
	t0 |= *in++ << 16;
	t0 |= *in++ << 8;
	t0 |= *in++;
	t0 ^= ek.key1[0][0];

	t1 = *in++ << 24;
	t1 |= *in++ << 16;
	t1 |= *in++ << 8;
	t1 |= *in++;
	t1 ^= ek.key1[0][1];

	t2 = *in++ << 24;
	t2 |= *in++ << 16;
	t2 |= *in++ << 8;
	t2 |= *in++;
	t2 ^= ek.key1[0][2];

	t3 = *in++ << 24;
	t3 |= *in++ << 16;
	t3 |= *in++ << 8;
	t3 |= *in++;
	t3 ^= ek.key1[0][3];

	// Apply round transforms
	for (r = 1; r < st->rounds; r++) {
		a0 = (RT0[(ut8)(t0 >> 24)] ^ RT1[(ut8)(t3 >> 16)] ^ RT2[(ut8)(t2 >> 8)] ^ RT3[(ut8)t1]);
		a1 = (RT0[(ut8)(t1 >> 24)] ^ RT1[(ut8)(t0 >> 16)] ^ RT2[(ut8)(t3 >> 8)] ^ RT3[(ut8)t2]);
		a2 = (RT0[(ut8)(t2 >> 24)] ^ RT1[(ut8)(t1 >> 16)] ^ RT2[(ut8)(t0 >> 8)] ^ RT3[(ut8)t3]);
		a3 = (RT0[(ut8)(t3 >> 24)] ^ RT1[(ut8)(t2 >> 16)] ^ RT2[(ut8)(t1 >> 8)] ^ RT3[(ut8)t0]);
		t0 = a0 ^ ek.key1[r][0];
		t1 = a1 ^ ek.key1[r][1];
		t2 = a2 ^ ek.key1[r][2];
		t3 = a3 ^ ek.key1[r][3];
	}

	// Last Round is special
	tt = ek.key1[st->rounds][0];
	result[0] = InvSbox[(ut8)(t0 >> 24)] ^ (ut8)(tt >> 24);
	result[1] = InvSbox[(ut8)(t3 >> 16)] ^ (ut8)(tt >> 16);
	result[2] = InvSbox[(ut8)(t2 >> 8)] ^ (ut8)(tt >> 8);
	result[3] = InvSbox[(ut8)t1] ^ (ut8)tt;

	tt = ek.key1[st->rounds][1];
	result[4] = InvSbox[(ut8)(t1 >> 24)] ^ (ut8)(tt >> 24);
	result[5] = InvSbox[(ut8)(t0 >> 16)] ^ (ut8)(tt >> 16);
	result[6] = InvSbox[(ut8)(t3 >> 8)] ^ (ut8)(tt >> 8);
	result[7] = InvSbox[(ut8)t2] ^ (ut8)tt;

	tt = ek.key1[st->rounds][2];
	result[8] = InvSbox[(ut8)(t2 >> 24)] ^ (ut8)(tt >> 24);
	result[9] = InvSbox[(ut8)(t1 >> 16)] ^ (ut8)(tt >> 16);
	result[10] = InvSbox[(ut8)(t0 >> 8)] ^ (ut8)(tt >> 8);
	result[11] = InvSbox[(ut8)t3] ^ (ut8)tt;

	tt = ek.key1[st->rounds][3];
	result[12] = InvSbox[(ut8)(t3 >> 24)] ^ (ut8)(tt >> 24);
	result[13] = InvSbox[(ut8)(t2 >> 16)] ^ (ut8)(tt >> 16);
	result[14] = InvSbox[(ut8)(t1 >> 8)] ^ (ut8)(tt >> 8);
	result[15] = InvSbox[(ut8)t0] ^ (ut8)tt;
}
