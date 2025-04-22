// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VARIABLE_H
#define RZ_IL_VARIABLE_H

#include <rz_util/rz_bitvector.h>
#include <rz_util/ht_sp.h>
#include <rz_il/definitions/value.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  \brief Definition of a variable inside the vm
 */
typedef struct rz_il_var_t {
	char *name;
	RzILSortPure sort; ///< "type" of the variable
} RzILVar;

RZ_API RZ_OWN RzILVar *rz_il_variable_new(RZ_NONNULL const char *name, RzILSortPure sort);
RZ_API void rz_il_variable_free(RZ_NULLABLE RzILVar *var);

/**
 * \brief Holds a set of variable definitions and their current contents
 * This is meant only as a low-level container to be used in RzILVM.
 */
typedef struct rz_il_var_set_t {
	HtSP /*<char *, RzILVar *>*/ *vars;
	HtSP /*<char *, RzILVal *>*/ *contents;
} RzILVarSet;

RZ_API bool rz_il_var_set_init(RzILVarSet *vs);
RZ_API void rz_il_var_set_fini(RzILVarSet *vs);
RZ_API void rz_il_var_set_reset(RzILVarSet *vs);
RZ_API RZ_BORROW RzILVar *rz_il_var_set_create_var(RzILVarSet *vs, const char *name, RzILSortPure sort);
RZ_API RZ_OWN RZ_NULLABLE RzILVal *rz_il_var_set_remove_var(RzILVarSet *vs, const char *name);
RZ_API bool rz_il_var_set_bind(RzILVarSet *vs, const char *name, RZ_OWN RzILVal *val);
RZ_API RZ_BORROW RzILVar *rz_il_var_set_get(RzILVarSet *vs, const char *name);
RZ_API RZ_OWN RzPVector /*<RzILVar *>*/ *rz_il_var_set_get_all(RzILVarSet *vs);
RZ_API RZ_BORROW RzILVal *rz_il_var_set_get_value(RzILVarSet *vs, const char *name);

typedef enum {
	RZ_IL_VAR_KIND_GLOBAL, ///< global var, usually bound to a physical representation like a register.
	RZ_IL_VAR_KIND_LOCAL, ///< local var, defined and assigned by set ops, mutable and useable across effects.
	RZ_IL_VAR_KIND_LOCAL_PURE ///< local pure var, bound only by let expressions, scope is limited to the let's pure body, thus it's immutable.
} RzILVarKind;

const char *rz_il_var_kind_name(RzILVarKind kind);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VARIABLE_H
