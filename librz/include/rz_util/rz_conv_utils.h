// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CONV_UTILS_H
#define RZ_CONV_UTILS_H

#include <rz_list.h>
#include <rz_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_API RZ_OWN RzList /*<void *>*/ *rz_util_copy_pvector_as_list(RZ_NONNULL const RzPVector /*<void *>*/ *pvec);
RZ_API RZ_OWN RzPVector /*<void *>*/ *rz_util_copy_list_as_pvector(RZ_NONNULL const RzList /*<void *>*/ *list);

#ifdef __cplusplus
}
#endif

#endif /* RZ_CONV_UTILS_H */
