#ifndef CRYPTO_SM4_ALGO_H
#define CRYPTO_SM4_ALGO_H
#include<rz_util.h>

#define SM4_KEY_SIZE 16
struct sm4_state{
    ut8 key[SM4_KEY_SIZE];
};
#endif