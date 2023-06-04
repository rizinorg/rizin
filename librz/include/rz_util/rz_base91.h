// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BASE91_H
#define RZ_BASE91_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API int rz_base91_encode(char *bout, const ut8 *bin, int len);
RZ_API int rz_base91_decode(ut8 *bout, const char *bin, int len);

#ifdef __cplusplus
}
#endif

#endif //  RZ_BASE91_H
