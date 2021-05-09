// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LUHN_H
#define RZ_LUHN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_types.h>

RZ_API bool rz_calculate_luhn_value(const char *data, ut64 *result);

#ifdef __cplusplus
}
#endif

#endif /* RZ_LUHN_H */
