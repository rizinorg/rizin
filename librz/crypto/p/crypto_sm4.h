// SPDX-FileCopyrightText: 2023 0xSh4dy <rakshitawasthi17@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CRYPTO_SM4_ALGO_H
#define CRYPTO_SM4_ALGO_H
#include <rz_util.h>

#define SM4_ENCRYPT  1
#define SM4_DECRYPT  2
#define SM4_KEY_SIZE 16

typedef struct {
	int original_len;
	uint32_t round_keys[32];
} sm4_state;
#endif