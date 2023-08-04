// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VALUE_H
#define RZ_IL_VALUE_H

#include <rz_il/definitions/bool.h>
#include <rz_il/definitions/sort.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
	RzBitVector *bv;
	RzILBool *b;
	RzFloat *f;
} RzValUnion;

/**
 * A concrete value of `'a pure`. Either a bitvector or boolean.
 */
typedef struct rz_il_val_t {
	RzILTypePure type; ///< type of value
	RzValUnion data; ///< data pointer
} RzILVal;

RZ_API RZ_OWN RzILVal *rz_il_value_new_bitv(RZ_NONNULL RzBitVector *bv);
RZ_API RZ_OWN RzILVal *rz_il_value_new_bool(RZ_NONNULL RzILBool *b);
RZ_API RZ_OWN RzILVal *rz_il_value_new_float(RZ_NONNULL RzFloat *f);
RZ_API RZ_OWN RzILVal *rz_il_value_new_zero_of(RzILSortPure sort);
RZ_API RZ_OWN RzILVal *rz_il_value_dup(RZ_NONNULL const RzILVal *val);
RZ_API void rz_il_value_free(RZ_NULLABLE RzILVal *val);
RZ_API RzILSortPure rz_il_value_get_sort(RZ_NONNULL RzILVal *val);
RZ_API RZ_OWN RzBitVector *rz_il_value_to_bv(RZ_NONNULL const RzILVal *val);
RZ_API bool rz_il_value_eq(RZ_NONNULL const RzILVal *a, RZ_NONNULL const RzILVal *b);

RZ_API char *rz_il_value_stringify(RZ_NONNULL const RzILVal *val);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VALUE_H
