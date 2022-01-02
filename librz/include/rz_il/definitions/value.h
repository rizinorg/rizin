// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VALUE_H
#define RZ_IL_VALUE_H

#include <rz_il/definitions/variable.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
	RzBitVector *bv;
	RzILBool *b;
} RzValUnion;

/**
 * A concrete value of `'a pure`. Either a bitvector or boolean.
 */
typedef struct rz_il_val_t {
	RzILVarType type; ///< type of value
	RzValUnion data; ///< data pointer
} RzILVal;

RZ_API RZ_OWN RzILVal *rz_il_value_new_bitv(RZ_NONNULL RzBitVector *bv);
RZ_API RZ_OWN RzILVal *rz_il_value_new_bool(RZ_NONNULL RzILBool *b);
#define rz_il_value_new_unk() rz_il_value_new(RZ_IL_VAR_TYPE_UNK)
RZ_API RZ_OWN RzILVal *rz_il_value_new(RzILVarType type);
RZ_API RZ_OWN RzILVal *rz_il_value_dup(RZ_NONNULL RzILVal *val);
RZ_API void rz_il_value_free(RZ_NULLABLE RzILVal *val);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VALUE_H
