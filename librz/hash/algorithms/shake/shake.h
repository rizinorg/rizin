// SPDX-FileCopyrightText: 2015 Andrey Jivsov <crypto@brainhub.org>
// SPDX-License-Identifier: MIT

#ifndef __SHAKE_H__
#define __SHAKE_H__

#include <rz_types.h>
#include <stdint.h>

#define SHAKE_KECCAK_SPONGE_WORDS 25

typedef struct shake_context_ {
	uint64_t saved; /* the portion of the input message that we
			 * didn't consume yet */
	union { /* Keccak's state */
		uint64_t s[SHAKE_KECCAK_SPONGE_WORDS];
		uint8_t sb[SHAKE_KECCAK_SPONGE_WORDS * 8];
	} u;
	unsigned byteIndex; /* 0..7--the next byte after the set one
			     * (starts from 0; 0--none are buffered) */
	unsigned wordIndex; /* 0..24--the next word to integrate input
			     * (starts from 0) */
	unsigned capacityWords; /* capacity in words (e.g. 4 for SHAKE-128, 8 for SHAKE-256) */
} shake_context;

RZ_IPI void shake_Init128(void *priv);
RZ_IPI void shake_Init256(void *priv);
RZ_IPI void shake_Update(void *priv, void const *bufIn, size_t len);
RZ_IPI void shake_Finalize(void *priv);
RZ_IPI void shake_Squeeze(void *priv, uint8_t *output, size_t outlen);

#endif
