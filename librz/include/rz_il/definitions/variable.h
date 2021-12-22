// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VARIABLE_H
#define RZ_IL_VARIABLE_H

#include <rz_util/rz_bitvector.h>
#include <rz_il/definitions/bool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RZIL_VAR_TYPE_BV,
	RZIL_VAR_TYPE_BOOL,
	RZIL_VAR_TYPE_UNK, // Unkown value
} RzILVarType;

/**
 *  \struct rz_il_var_t
 *  \brief structure of RzILVar
 */
typedef struct rz_il_var_t {
	char *var_name; ///< name of variable
	bool is_mutable;
	RzILVarType type; ///< data type of variable
} RzILVar;

RZ_API RZ_OWN RzILVar *rz_il_variable_new(RZ_NONNULL const char *name, RzILVarType type, bool is_mutable);
RZ_API void rz_il_variable_free(RZ_NULLABLE RzILVar *var);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VARIABLE_H
