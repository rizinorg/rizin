#ifndef RZ_MUTUAL_INFO_H
#define RZ_MUTUAL_INFO_H

#include <rz_types.h>

typedef struct rz_mutual_info_t {
    ut64 joint_count[256][256];
    ut64 size;
} RzMutualInfo;

RZ_API bool rz_mutual_info_init(RzMutualInfo *ctx);
RZ_API bool rz_mutual_info_update(RzMutualInfo *ctx, const ut8 *data_a, const ut8 *data_b, size_t len);
RZ_API double rz_mutual_info_final(RzMutualInfo *ctx);

#endif