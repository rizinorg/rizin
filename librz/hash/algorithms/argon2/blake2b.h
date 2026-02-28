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

#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <rz_types.h>
#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define BLAKE2B_BLOCKBYTES    128
#define BLAKE2B_OUTBYTES      64
#define BLAKE2B_KEYBYTES      64
#define BLAKE2B_SALTBYTES     16
#define BLAKE2B_PERSONALBYTES 16

#pragma pack(push, 1)
typedef struct blake2b_param_ {
	ut8 digest_length; /* 1 */
	ut8 key_length; /* 2 */
	ut8 fanout; /* 3 */
	ut8 depth; /* 4 */
	ut32 leaf_length; /* 8 */
	ut64 node_offset; /* 16 */
	ut8 node_depth; /* 17 */
	ut8 inner_length; /* 18 */
	ut8 reserved[14]; /* 32 */
	ut8 salt[BLAKE2B_SALTBYTES]; /* 48 */
	ut8 personal[BLAKE2B_PERSONALBYTES]; /* 64 */
} blake2b_param;
#pragma pack(pop)

typedef struct blake2b_state_ {
	ut64 h[8];
	ut64 t[2];
	ut64 f[2];
	ut8 buf[BLAKE2B_BLOCKBYTES];
	size_t buflen;
	size_t outlen;
	ut8 last_node;
} blake2b_state;

/* Initialise state for a digest of outlen bytes (1..64). */
int blake2b_init(blake2b_state *S, size_t outlen);

/* Initialise state with a key (outlen 1..64, keylen 1..64). */
int blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen);

/* Feed data into the state. */
int blake2b_update(blake2b_state *S, const void *in, size_t inlen);

/* Finalise and write digest (exactly S->outlen bytes). */
int blake2b_final(blake2b_state *S, void *out, size_t outlen);

/*
 * blake2b_long — Argon2-specific variable-length hash.
 * Produces outlen bytes of output from inlen bytes of input.
 * outlen may exceed 64 bytes; internally it chains multiple
 * Blake2b invocations as specified in the Argon2 paper.
 */
int blake2b_long(void *out, size_t outlen, const void *in, size_t inlen);

#if defined(__cplusplus)
}
#endif

#endif /* BLAKE2B_H */