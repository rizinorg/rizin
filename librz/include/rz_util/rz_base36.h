// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BASE36_H
#define RZ_BASE36_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API size_t rz_base36_encode(RZ_OUT RZ_NONNULL char *bout, ut64 val);
RZ_API RZ_OWN char *rz_base36_encode_dyn(ut64 val);

RZ_API st64 rz_base36_decode(RZ_OUT RZ_NONNULL ut64 *bout, RZ_NONNULL const char *bin, st64 len);
RZ_API RZ_OWN ut64 *rz_base36_decode_dyn(RZ_NONNULL const char *bin, const size_t len);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BASE36_H
