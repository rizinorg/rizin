// SPDX-FileCopyrightText: 2020 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2016 Maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_STRPOOL_H
#define RZ_STRPOOL_H

#include <rz_types.h>

#define RZ_STRPOOL_INC 1024

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char *str;
	int len;
	int size;
} RzStrpool;

RZ_API RzStrpool *rz_strpool_new(int sz);
RZ_API char *rz_strpool_alloc(RzStrpool *p, int l);
RZ_API int rz_strpool_memcat(RzStrpool *p, const char *s, int len);
RZ_API int rz_strpool_ansi_chop(RzStrpool *p, int n);
RZ_API int rz_strpool_append(RzStrpool *p, const char *s);
RZ_API void rz_strpool_free(RzStrpool *p);
RZ_API int rz_strpool_fit(RzStrpool *p);
RZ_API char *rz_strpool_get(RzStrpool *p, int index);
RZ_API char *rz_strpool_get_i(RzStrpool *p, int index);
RZ_API int rz_strpool_get_index(RzStrpool *p, const char *s);
RZ_API char *rz_strpool_next(RzStrpool *p, int index);
RZ_API char *rz_strpool_slice(RzStrpool *p, int index);
RZ_API char *rz_strpool_empty(RzStrpool *p);

#ifdef __cplusplus
}
#endif

#endif //  RZ_STRPOOL_H
