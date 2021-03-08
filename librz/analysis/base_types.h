// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BASE_TYPES_H
#define RZ_BASE_TYPES_H

#include "rz_util.h"

#ifdef __cplusplus
extern "C" {
#endif

RZ_IPI void enum_type_case_free(void *e, void *user);
RZ_IPI void struct_type_member_free(void *e, void *user);
RZ_IPI void union_type_member_free(void *e, void *user);

#ifdef __cplusplus
}
#endif
#endif
