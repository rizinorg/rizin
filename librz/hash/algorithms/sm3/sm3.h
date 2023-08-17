// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2017-2023 Free Software Foundation, Inc.
// SPDX-License-Identifier: LGPL-2.1-only

#ifndef SM3_H
#define SM3_H

#include <rz_types.h>

#define SM3_DIGEST_SIZE 32
#define SM3_BLOCK_SIZE  64

/* Structure to save state of computation between the single steps.  */
typedef struct sm3_ctx_s {
	ut32 state[8];
	ut32 total[2];
	ut64 buflen; /* >= 0, <= 128 */
	ut32 buffer[32]; /* 128 bytes; the first buflen bytes are in use */
} sm3_ctx_t;

/* Initialize structure containing state of computation. */
void sm3_init_ctx(sm3_ctx_t *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER. */
void sm3_process_bytes(const void *buffer, ut64 len, sm3_ctx_t *ctx);

/* Process the remaining bytes in the buffer and put result from CTX
   in first 32 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.  */
void sm3_finish_ctx(sm3_ctx_t *ctx, void *resbuf);

#endif /* SM3_H */
