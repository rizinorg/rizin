// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VALUE_H
#define RZ_IL_VALUE_H

#include <rz_il/definitions/variable.h>

typedef union {
	RzILBitVector *bv;
	RzILBool *b;
} RzValUnion;

/**
 *  \struct rz_il_val_t
 *  \brief structure of RzILVal
 */
struct rz_il_val_t {
	RZIL_VAR_TYPE type; ///< type of value
	RzValUnion data; ///< data pointer
};
typedef struct rz_il_val_t RzILVal;

typedef enum {
	RZIL_TEMP_BV,
	RZIL_TEMP_BOOL,
	RZIL_TEMP_VAL,
	RZIL_TEMP_EFF,

	RZIL_TEMP_EMPTY
} RZIL_TEMP_TYPE;

RZ_API RzILVal *rz_il_new_value(void);
RZ_API RzILVal *rz_il_dup_value(RzILVal *val);
RZ_API void rz_il_free_value(RzILVal *val);

#endif // RZ_IL_VALUE_H
