// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_QSORT_R_H
#define RZ_QSORT_R_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*RzQsortRCmp)(const void *a, const void *b, void *user);

RZ_API void rz_qsort_r(void *base, size_t nmemb, size_t size,
	RzQsortRCmp cmp, void *user);

#ifdef __cplusplus
}
#endif

#endif // RZ_QSORT_R_H
