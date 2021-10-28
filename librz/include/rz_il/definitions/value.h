// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VALUE_H
#define RZ_IL_VALUE_H

#include <rz_il/definitions/variable.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
	RzILBitVector *bv;
	RzILBool *b;
} RzValUnion;

/**
 *  \struct rz_il_val_t
 *  \brief structure of RzILVal
 */
typedef struct rz_il_val_t {
	RZIL_VAR_TYPE type; ///< type of value
	RzValUnion data; ///< data pointer
} RzILVal;

typedef enum {
	RZIL_TEMP_BV,
	RZIL_TEMP_BOOL,
	RZIL_TEMP_VAL,
	RZIL_TEMP_EFF,

	RZIL_TEMP_EMPTY
} RZIL_TEMP_TYPE;

RZ_API RzILVal *rz_il_value_new(void);
RZ_API RzILVal *rz_il_value_dup(RzILVal *val);
RZ_API void rz_il_value_free(RzILVal *val);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VALUE_H
