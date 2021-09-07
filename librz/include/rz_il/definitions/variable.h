// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VARIABLE_H
#define RZ_IL_VARIABLE_H

#include "bitvector.h"
#include "bool.h"

typedef enum {
	RZIL_VAR_TYPE_BV,
	RZIL_VAR_TYPE_BOOL,
	RZIL_VAR_TYPE_UNK, // Unkown value
} RZIL_VAR_TYPE;

/**
 *  \struct rz_il_var_t
 *  \brief structure of RzILVar
 */
struct rz_il_var_t {
	char *var_name; ///< name of variable
	RZIL_VAR_TYPE type; ///< data type of variable
};
typedef struct rz_il_var_t RzILVar;

RZ_API RzILVar *rz_il_new_variable(char *name);
RZ_API void rz_il_free_variable(RzILVar *var);

#endif // RZ_IL_VARIABLE_H
