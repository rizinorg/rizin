// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/variable.h>
#include <string.h>
#include <stdlib.h>

/**
 * New a variable with RzILVarType
 * \param name string, name of variable
 * \return var RzILVar, pointer to this variable
 */
RZ_API RZ_OWN RzILVar *rz_il_variable_new(RZ_NONNULL const char *name, RzILVarType type, bool is_mutable) {
	rz_return_val_if_fail(name, NULL);
	RzILVar *ret = RZ_NEW0(RzILVar);
	if (!ret) {
		return NULL;
	}
	ret->var_name = strdup(name);
	if (!ret->var_name) {
		free(ret);
		return NULL;
	}
	ret->is_mutable = is_mutable;
	ret->type = type;
	return ret;
}

/**
 * Free variable
 * \param var RzILVar, pointer to RzILVar
 */
RZ_API void rz_il_variable_free(RZ_NULLABLE RzILVar *var) {
	if (!var) {
		return;
	}
	free(var->var_name);
	free(var);
}