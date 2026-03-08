// SPDX-FileCopyrightText: 2025 Ayush Dwivedi <ayushd785@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_RC4_H
#define RZ_RC4_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API void rz_rc4_crypt(RZ_NONNULL const ut8 *key, int keylen, RZ_NONNULL const ut8 *in, RZ_NONNULL ut8 *out, int len);

#ifdef __cplusplus
}
#endif

#endif // RZ_RC4_H
