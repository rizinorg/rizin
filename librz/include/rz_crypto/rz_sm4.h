#ifndef RZ_SM4_H
#define RZ_SM4_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_SM4_KEY_SIZE 16

RZ_API ut32 rz_sm4_round_key(ut32 val);

#ifdef __cplusplus
}
#endif

#endif //  RZ_SM4_H
