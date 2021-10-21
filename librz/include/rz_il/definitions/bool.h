// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_BOOL_H
#define RZ_IL_BOOL_H

#include <rz_types.h>
#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bool_t {
	bool b;
};
typedef struct bool_t RzILBool;

RZ_API RzILBool *rz_il_bool_new(bool true_or_false);
RZ_API RzILBool *rz_il_bool_and(RzILBool *a, RzILBool *b);
RZ_API RzILBool *rz_il_bool_or(RzILBool *a, RzILBool *b);
RZ_API RzILBool *rz_il_bool_xor(RzILBool *a, RzILBool *b);
RZ_API RzILBool *rz_il_bool_not(RzILBool *a);
RZ_API void rz_il_bool_free(RzILBool *bool_var);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_BOOL_H
