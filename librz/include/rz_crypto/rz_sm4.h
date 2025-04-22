#ifndef RZ_SM4_H
#define RZ_SM4_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_SM4_KEY_SIZE 16

RZ_API void rz_sm4_extract_master_key(const ut32 word[4], ut8 key_out[RZ_SM4_KEY_SIZE]);
RZ_API ut32 rz_sm4_round_key(ut32 val);

#ifdef __cplusplus
}
#endif

#endif //  RZ_SM4_H
