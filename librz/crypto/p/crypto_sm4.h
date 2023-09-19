// SPDX-FileCopyrightText: 2023 0xSh4dy <rakshitawasthi17@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CRYPTO_SM4_ALGO_H
#define CRYPTO_SM4_ALGO_H
#include <rz_util.h>

#define SM4_ENCRYPT  1
#define SM4_DECRYPT  2
#define SM4_KEY_SIZE 16

#ifndef GET_UT64
#define GET_UT64(n, b, i) \
	{ \
		(n) = ((unsigned int)(b)[(i)] << 24) | ((unsigned int)(b)[(i) + 1] << 16) | ((unsigned int)(b)[(i) + 2] << 8) | ((unsigned int)(b)[(i) + 3]); \
	}
#endif

typedef struct sm4_ctx {
	int mode;
	ut64 subkeys[32];
} sm4_state;
#endif