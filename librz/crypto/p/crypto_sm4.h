// SPDX-FileCopyrightText: 2023 0xSh4dy <rakshitawasthi17@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CRYPTO_SM4_ALGO_H
#define CRYPTO_SM4_ALGO_H
#include <rz_util.h>

#define SM4_KEY_SIZE 16
typedef struct sm4_ctx {
    ut8 key[SM4_KEY_SIZE];
} sm4_state;
#endif