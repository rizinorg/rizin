// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/variable.h>
#include <string.h>
#include <stdlib.h>

/**
 * Create a new variable description
 */
RZ_API RZ_OWN RzILVar *rz_il_variable_new(RZ_NONNULL const char *name, RzILSortPure sort) {
	rz_return_val_if_fail(name, NULL);
	RzILVar *ret = RZ_NEW0(RzILVar);
	if (!ret) {
		return NULL;
	}
	ret->name = strdup(name);
	if (!ret->name) {
		free(ret);
		return NULL;
	}
	ret->sort = sort;
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
	free(var->name);
	free(var);
}

// Variable Set

/**
 * Initialize \p vs as an empty variable set
 *
 * This makes sure that if a failure occurs, the contents are still zeroed out,
 * so it is safe (but not required) to call rz_il_var_set_fini(), even if the init failed.
 *
 * \return whether the initialization succeeded
 */
RZ_API bool rz_il_var_set_init(RzILVarSet *vs) {
	rz_return_val_if_fail(vs, false);
	memset(vs, 0, sizeof(*vs));
	vs->vars = ht_sp_new(HT_STR_DUP, NULL, (HtPPFreeValue)rz_il_variable_free);
	if (!vs->vars) {
		return false;
	}
	vs->contents = ht_sp_new(HT_STR_DUP, NULL, (HtPPFreeValue)rz_il_value_free);
	if (!vs->contents) {
		ht_sp_free(vs->vars);
		vs->vars = NULL;
		return false;
	}
	return true;
}

RZ_API void rz_il_var_set_fini(RzILVarSet *vs) {
	ht_sp_free(vs->vars);
	ht_sp_free(vs->contents);
}

RZ_API void rz_il_var_set_reset(RzILVarSet *vs) {
	rz_il_var_set_fini(vs);
	rz_il_var_set_init(vs);
}

/**
 * Create a new variable of the given name and sort.
 * If a variable of this name already exists, nothing happens.
 */
RZ_API RZ_BORROW RzILVar *rz_il_var_set_create_var(RzILVarSet *vs, const char *name, RzILSortPure sort) {
	rz_return_val_if_fail(vs && name, NULL);
	if (ht_sp_find(vs->vars, name, NULL)) {
		return NULL;
	}
	RzILVar *var = rz_il_variable_new(name, sort);
	if (!var) {
		return NULL;
	}
	ht_sp_insert(vs->vars, name, var);
	return var;
}

/**
 * Remove a variable, if it exists
 * \return the variable's variable, to be freed by the caller
 */
RZ_API RZ_OWN RZ_NULLABLE RzILVal *rz_il_var_set_remove_var(RzILVarSet *vs, const char *name) {
	rz_return_val_if_fail(vs && name, NULL);
	ht_sp_delete(vs->vars, name);
	HtSPKv *kv = ht_sp_find_kv(vs->contents, name, NULL);
	if (!kv) {
		return NULL;
	}
	RzILVal *r = kv->value;
	kv->value = NULL;
	ht_sp_delete(vs->contents, name);
	return r;
}

/**
 * Set the contents of the variable called \p name to \p val
 *
 * In order for this to succeed, a variable called \p name must already exist
 * and the sort of \p val must match the variable's sort. Checking this is done
 * inside this function, so calling it with invalid args in that sense is fine.
 *
 * \return whether the value was successfully bound
 */
RZ_API bool rz_il_var_set_bind(RzILVarSet *vs, const char *name, RZ_OWN RzILVal *val) {
	rz_return_val_if_fail(vs && name && val, false);
	RzILVar *var = ht_sp_find(vs->vars, name, NULL);
	if (!var || !rz_il_sort_pure_eq(var->sort, rz_il_value_get_sort(val))) {
		if (!var) {
			RZ_LOG_ERROR("Attempted to bind value to non-existent variable \"%s\"\n", name);
		} else {
			RZ_LOG_ERROR("Attempted to bind mis-sorted value to variable \"%s\"\n", name);
		}
		rz_il_value_free(val);
		return false;
	}
	ht_sp_update(vs->contents, name, val);
	return true;
}

/**
 * Get the definition of the variable called \p name
 */
RZ_API RZ_BORROW RzILVar *rz_il_var_set_get(RzILVarSet *vs, const char *name) {
	return ht_sp_find(vs->vars, name, NULL);
}

static bool vars_collect_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	rz_pvector_push(user, (void *)v);
	return true;
}

/**
 * Get a list of all variable definitions in the given set
 */
RZ_API RZ_OWN RzPVector /*<RzILVar *>*/ *rz_il_var_set_get_all(RzILVarSet *vs) {
	rz_return_val_if_fail(vs, NULL);
	RzPVector *r = rz_pvector_new(NULL);
	if (!r) {
		return NULL;
	}
	ht_sp_foreach(vs->vars, vars_collect_cb, r);
	return r;
}

/**
 * Get the current value of the variable called \p name
 */
RZ_API RZ_BORROW RzILVal *rz_il_var_set_get_value(RzILVarSet *vs, const char *name) {
	rz_return_val_if_fail(vs && name, NULL);
	return ht_sp_find(vs->contents, name, NULL);
}

/**
 * Get a readable string representation of \p kind
 */
const char *rz_il_var_kind_name(RzILVarKind kind) {
	switch (kind) {
	case RZ_IL_VAR_KIND_GLOBAL:
		return "global";
	case RZ_IL_VAR_KIND_LOCAL:
		return "local";
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		return "local pure";
	default:
		return "invalid";
	}
}
