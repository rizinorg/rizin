// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BASE32_H
#define RZ_BASE32_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API size_t rz_base32_encode(RZ_OUT RZ_NONNULL char *bout, RZ_NONNULL const ut8 *bin, size_t sz);
RZ_API st64 rz_base32_decode(RZ_OUT RZ_NONNULL ut8 *bout, RZ_NONNULL const char *bin, st64 len);

RZ_API RZ_OWN char *rz_base32_encode_dyn(RZ_NONNULL const ut8 *bin, size_t sz);
RZ_API RZ_OWN ut8 *rz_base32_decode_dyn(RZ_NONNULL const char *in, st64 len);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BASE32_H
