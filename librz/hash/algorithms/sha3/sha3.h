// SPDX-FileCopyrightText: 2015. Andrey Jivsov <crypto@brainhub.org>
// SPDX-License-Identifier: MIT

/*
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __SHA3_H__
#define __SHA3_H__
#include <rz_types.h>

#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>

/* -------------------------------------------------------------------------
 *
 * TODO: Implement sha3-224
 * This is  based (copied) of https://github.com/brainhub/SHA3IUF
 *
 * Works when compiled for either 32-bit or 64-bit targets, optimized for
 * 64 bit.
 *
 * Canonical implementation of Init/Update/Finalize for SHA-3 byte input.
 *
 * SHA3-256, SHA3-384, SHA-512 are implemented. SHA-224 can easily be added.
 *
 * Based on code from http://keccak.noekeon.org/ .
 *
 * I place the code that I wrote into public domain, free to use.
 *
 * I would appreciate if you give credits to this work if you used it to
 * write or test * your code.
 *
 * Aug 2015. Andrey Jivsov. crypto@brainhub.org
 * ---------------------------------------------------------------------- */

/* 'Words' here refers to uint64_t */
#define SHA3_KECCAK_SPONGE_WORDS \
	(((1600) / 8 /*bits to byte*/) / sizeof(uint64_t))
typedef struct sha3_context_ {
	uint64_t saved; /* the portion of the input message that we
			 * didn't consume yet */
	union { /* Keccak's state */
		uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
		uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
	} u;
	unsigned byteIndex; /* 0..7--the next byte after the set one
			     * (starts from 0; 0--none are buffered) */
	unsigned wordIndex; /* 0..24--the next word to integrate input
			     * (starts from 0) */
	unsigned capacityWords; /* the double size of the hash output in
				 * words (e.g. 16 for Keccak 512) */
} sha3_context;

enum SHA3_FLAGS {
	SHA3_FLAGS_NONE = 0,
	SHA3_FLAGS_KECCAK = 1
};

enum SHA3_RETURN {
	SHA3_RETURN_OK = 0,
	SHA3_RETURN_BAD_PARAMS = 1
};
typedef enum SHA3_RETURN sha3_return_t;

/* For Init or Reset call these: */
sha3_return_t sha3_Init(void *priv, unsigned bitSize);

RZ_IPI void sha3_Init224(void *priv);
RZ_IPI void sha3_Init256(void *priv);
RZ_IPI void sha3_Init384(void *priv);
RZ_IPI void sha3_Init512(void *priv);

enum SHA3_FLAGS sha3_SetFlags(void *priv, enum SHA3_FLAGS);

RZ_IPI void sha3_Update(void *priv, void const *bufIn, size_t len);
RZ_IPI void const *sha3_Finalize(void *priv);

#endif

#endif
