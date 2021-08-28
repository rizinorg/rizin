// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/variable.h>
#include <string.h>
#include <stdlib.h>

/**
 * New a variable with UNKNOWN TYPE
 * \param name string, name of variable
 * \return var RzILVar, pointer to this variable
 */
RZ_API RzILVar rz_il_new_variable(char *name) {
	RzILVar ret;

	ret = (RzILVar)malloc(sizeof(struct rz_il_var_t));
	if (!ret) {
		return NULL;
	}
	ret->var_name = strdup(name);
	ret->type = RZIL_VAR_TYPE_UNK;

	return ret;
}

/**
 * Free variable
 * \param var RzILVar, pointer to RzILVar
 */
RZ_API void rz_il_free_variable(RzILVar var) {
	if (!var) {
		return;
	}
	free(var->var_name);
	free(var);
}