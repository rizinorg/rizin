// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PUNYCODE_H
#define RZ_PUNYCODE_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API char *rz_punycode_encode(const ut8 *src, int srclen, int *dstlen);
RZ_API char *rz_punycode_decode(const char *src, int srclen, int *dstlen);

#ifdef __cplusplus
}
#endif

#endif //  RZ_PUNYCODE_H
