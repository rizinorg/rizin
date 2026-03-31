// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2023 0xSh4dy <rakshitawasthi17@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CRYPTO_SM4_ALGO_H
#define CRYPTO_SM4_ALGO_H

#include <rz_util.h>

#define SM4_ENCRYPT 1
#define SM4_DECRYPT 2

typedef struct sm4_state {
	int original_len;
	ut32 round_keys[32];
} sm4_state_t;

#endif