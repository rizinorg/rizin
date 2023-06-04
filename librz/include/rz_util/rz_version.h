// SPDX-FileCopyrightText: 2022 Khairul Azhar Kasmiran <kazarmy@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_VERSION_H
#define RZ_VERSION_H

#include "rz_types.h"

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN char *rz_version_gittip();
RZ_API RZ_OWN char *rz_version_str(const char *program);

#ifdef __cplusplus
}
#endif

#endif // RZ_VERSION_H
