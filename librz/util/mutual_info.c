// SPDX-FileCopyrightText: 2026 vk3089790-arch <vk3089790@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_mutual_info.h>
#include <math.h>
#include <rz_util/rz_assert.h>
#include <string.h>

RZ_API bool rz_mutual_info_init(RzMutualInfo *ctx) {
    rz_return_val_if_fail(ctx, false);
    memset(ctx, 0, sizeof(RzMutualInfo));
    return true;
}

RZ_API bool rz_mutual_info_update(RzMutualInfo *ctx, const ut8 *data_a, const ut8 *data_b, size_t len) {
    rz_return_val_if_fail(ctx && data_a && data_b, false);
    for (size_t i = 0; i < len; i++) {
        ctx->joint_count[data_a[i]][data_b[i]]++;
    }
    ctx->size += len;
    return true;
}


RZ_API double rz_mutual_info_final(RzMutualInfo *ctx) {
    rz_return_val_if_fail(ctx, 0.0);

    if (ctx->size == 0) {
        return 0.0;
    }


    double marginal_a[256] = { 0 };
    double marginal_b[256] = { 0 };

    // Compute marginal_a[x] = P(A = x), by summing joint counts across all y
    for (int x = 0; x < 256; x++) {
        ut64 sum = 0;
        for (int y = 0; y < 256; y++) {
            sum += ctx->joint_count[x][y];
        }
        marginal_a[x] = (double)sum / ctx->size;
    }

    // Compute marginal_b[y] = P(B = y), by summing joint counts across all x
    for (int y = 0; y < 256; y++) {
        ut64 sum = 0;
        for (int x = 0; x < 256; x++) {
            sum += ctx->joint_count[x][y];
        }
        marginal_b[y] = (double)sum / ctx->size;
    }

    // Sum p(x,y) * log2(p(x,y) / (p(x) * p(y))) over all non-zero joint probabilities
    double mutual_info = 0.0;
    for (int x = 0; x < 256; x++) {
        for (int y = 0; y < 256; y++) {
            double p_xy = (double)ctx->joint_count[x][y] / ctx->size;
            if (p_xy > 0 && marginal_a[x] > 0 && marginal_b[y] > 0) {
                mutual_info += p_xy * log2(p_xy / (marginal_a[x] * marginal_b[y]));
            }
        }
    }

    return mutual_info;
}