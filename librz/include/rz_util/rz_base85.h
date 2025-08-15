// SPDX-FileCopyrightText: 2025 Ahmed Ibrahim <a.ibrahim8686@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BASE85_H
#define RZ_BASE85_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API int rz_base85_encode(RZ_OUT RZ_NONNULL char *dest, RZ_NONNULL const char *src, size_t n, int delims, int wrap, int y_abbr);
RZ_API st64 rz_base85_decode(RZ_OUT RZ_NONNULL char *dest, RZ_NONNULL const char *src, st64 len, int delims, int ignore_garbage);

RZ_API RZ_OWN char *rz_base85_encode_dyn(RZ_NONNULL const char *src, size_t n, int delims, int wrap, int y_abbr);
RZ_API RZ_OWN char *rz_base85_decode_dyn(RZ_NONNULL const char *src, st64 len, int delims, int ignore_garbage, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BASE85_H
