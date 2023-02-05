// SPDX-FileCopyrightText: 2021 keegan
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_AXML_H
#define RZ_AXML_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN char *rz_axml_decode(RZ_NONNULL const ut8 *buffer, const ut64 size);

#ifdef __cplusplus
}
#endif

#endif //  RZ_AXML_H
