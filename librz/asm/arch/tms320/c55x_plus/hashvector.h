// SPDX-FileCopyrightText: 2013-2021 th0rpe <josediazfer@yahoo.es>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef HASHVECTOR_H
#define HASHVECTOR_H

#include <rz_types.h>

typedef struct {
	st32 code;
	st32 (*hash_func)(st32 A1, st32 A2);
} HASHCODE_ENTRY_T;

#endif
