// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef BUILD_BOOL_H
#define BUILD_BOOL_H
#include "common.h"

struct bool_t {
	bool b;
};
typedef struct bool_t *Bool;

RZ_API Bool rz_il_new_bool(bool true_or_false);
RZ_API Bool rz_il_bool_and_(Bool a, Bool b);
RZ_API Bool rz_il_bool_or_(Bool a, Bool b);
RZ_API Bool rz_il_bool_xor_(Bool a, Bool b);
RZ_API Bool rz_il_bool_not_(Bool a);
RZ_API void rz_il_free_bool(Bool bool_var);

#endif //BUILD_BOOL_H
