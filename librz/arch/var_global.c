// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_list.h>

/**
 * \brief Create a new instance of global variable
 *
 * \param name variable name
 * \param addr variable address
 * \return RzAnalysisVarGlobal *
 */
RZ_API RZ_OWN RzAnalysisVarGlobal *rz_analysis_var_global_new(RZ_NONNULL const char *name, ut64 addr) {
	rz_return_val_if_fail(name, NULL);
	RzAnalysisVarGlobal *glob = RZ_NEW0(RzAnalysisVarGlobal);
	if (!glob) {
		return NULL;
	}
	glob->name = strdup(name);
	glob->addr = addr;
	glob->analysis = NULL;

	return glob;
}

static int global_var_node_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 ia = *(ut64 *)incoming;
	ut64 ta = container_of(in_tree, const RzAnalysisVarGlobal, rb)->addr;
	if (ia < ta) {
		return -1;
	} else if (ia > ta) {
		return 1;
	}
	return 0;
}

static void global_var_set_type(RzAnalysisVarGlobal *glob, RzType *type) {
	glob->type = type;

	RzFlagItem *flag = rz_analysis_var_global_get_flag_item(glob);
	if (flag) {
		flag->size = rz_type_db_get_bitsize(glob->analysis->typedb, glob->type) / 8;
	}
}

/**
 * \brief Add the global variable into hashtable
 *
 * \param analysis RzAnalysis
 * \param global_var Global variable instance
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_add(RzAnalysis *analysis, RZ_NONNULL RzAnalysisVarGlobal *global_var) {
	rz_return_val_if_fail(analysis && global_var, false);

	RzAnalysisVarGlobal *existing_glob = NULL;
	if ((existing_glob = rz_analysis_var_global_get_byaddr_in(analysis, global_var->addr))) {
		RZ_LOG_ERROR("Global variable %s at 0x%" PFMT64x " already exists!\n", existing_glob->name, existing_glob->addr);
		return false;
	}
	if ((existing_glob = rz_analysis_var_global_get_byname(analysis, global_var->name))) {
		RZ_LOG_ERROR("Global variable %s at 0x%" PFMT64x " already exists!\n", existing_glob->name, existing_glob->addr);
		return false;
	}
	if (!ht_sp_insert(analysis->ht_global_var, global_var->name, global_var)) {
		return false;
	}
	if (!rz_rbtree_aug_insert(&analysis->global_var_tree, &global_var->addr, &global_var->rb, global_var_node_cmp, NULL, NULL)) {
		return false;
	}

	global_var->analysis = analysis;
	rz_flag_space_push(global_var->analysis->flb.f, "globals");
	rz_flag_set(global_var->analysis->flb.f, global_var->name, global_var->addr, rz_type_db_get_bitsize(global_var->analysis->typedb, global_var->type) / 8);
	rz_flag_space_pop(global_var->analysis->flb.f);

	return true;
}

/**
 * \brief Create the global variable and add into hashtable
 *
 * \param analysis RzAnalysis
 * \param name Global variable name
 * \param type Global variable type
 * \param addr Global variable address
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_create(RzAnalysis *analysis, RZ_NONNULL const char *name, RZ_NONNULL RZ_BORROW RzType *type, ut64 addr) {
	rz_return_val_if_fail(analysis && name && type, false);

	RzAnalysisVarGlobal *glob = rz_analysis_var_global_new(name, addr);
	if (!glob) {
		return false;
	}

	global_var_set_type(glob, type);

	if (!rz_analysis_var_global_add(analysis, glob)) {
		rz_analysis_var_global_free(glob);
		return false;
	}

	return true;
}

/**
 * \brief Free the global variable instance
 *
 * \param glob Global variable instance
 * \return void
 */
RZ_API void rz_analysis_var_global_free(RzAnalysisVarGlobal *glob) {
	if (!glob) {
		return;
	}
	RzFlagItem *flag = rz_analysis_var_global_get_flag_item(glob);
	if (flag) {
		rz_flag_unset(glob->analysis->flb.f, flag);
	}
	RZ_FREE(glob->name);
	rz_type_free(glob->type);
	rz_vector_fini(&glob->constraints);
	RZ_FREE(glob);
}

/**
 * \brief Get the flag item corresponding to the given variable
 *
 * This will search for the matching flag that has been created along with the global variable.
 * It can happen that the flag has manually been deleted, in which case this returns NULL.
 *
 * \return a flag item or NULL
 */
RZ_API RZ_NULLABLE RzFlagItem *rz_analysis_var_global_get_flag_item(RzAnalysisVarGlobal *glob) {
	rz_return_val_if_fail(glob, NULL);
	RzAnalysis *a = glob->analysis;
	if (!a) {
		return NULL;
	}
	RzFlagItem *r = rz_flag_get(a->flb.f, glob->name);
	if (r && r->offset != glob->addr) {
		return NULL;
	}
	return r;
}

/**
 * \brief Delete and free the global variable
 *
 * \param analysis RzAnalysis
 * \param glob global variable to be deleted
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_delete(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisVarGlobal *glob) {
	rz_return_val_if_fail(analysis && glob, false);

	// We need to delete RBTree first because ht_pp_delete will free its member
	bool deleted = rz_rbtree_delete(&analysis->global_var_tree, &glob->addr, global_var_node_cmp, NULL, NULL, NULL);
	return deleted ? ht_sp_delete(analysis->ht_global_var, glob->name) : deleted;
}

/**
 * \brief Delete and free the global variable by its name
 *
 * \param analysis RzAnalysis
 * \param name Global Variable name
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_delete_byname(RzAnalysis *analysis, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(analysis && name, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(analysis, name);
	if (!glob) {
		RZ_LOG_ERROR("No global variable found having name %s\n", name);
		return false;
	}

	return rz_analysis_var_global_delete(analysis, glob);
}

/**
 * \brief Same as rz_analysis_var_global_delete_byname at the address
 *
 * \param analysis RzAnalysis
 * \param addr Global Variable address
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_delete_byaddr_at(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byaddr_at(analysis, addr);
	if (!glob) {
		RZ_LOG_ERROR("No global variable found at 0x%" PFMT64x "\n", addr);
		return false;
	}

	return rz_analysis_var_global_delete(analysis, glob);
}

/**
 * \brief Same as rz_analysis_var_global_delete_byname in the address
 *
 * \param analysis RzAnalysis
 * \param addr Global Variable address
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_delete_byaddr_in(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byaddr_in(analysis, addr);
	if (!glob) {
		RZ_LOG_ERROR("No global variable found in 0x%" PFMT64x "\n", addr);
		return false;
	}

	return rz_analysis_var_global_delete(analysis, glob);
}

/**
 * \brief Get the instance of global variable by its name
 *
 * \param analysis RzAnalysis
 * \param name Global variable name
 * \return RzAnalysisVarGlobal *
 */
RZ_API RZ_BORROW RzAnalysisVarGlobal *rz_analysis_var_global_get_byname(RzAnalysis *analysis, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(analysis && name, NULL);
	return (RzAnalysisVarGlobal *)ht_sp_find(analysis->ht_global_var, name, NULL);
}

struct list_addr {
	RzList /*<RzAnalysisVarGlobal *>*/ *list;
	ut64 addr;
};

/**
 * \brief Get the instance of global variable at the address
 *
 * \param analysis RzAnalysis
 * \param addr Global variable address
 * \return RzAnalysisVarGlobal *
 */
RZ_API RZ_BORROW RzAnalysisVarGlobal *rz_analysis_var_global_get_byaddr_at(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);

	RBNode *node = rz_rbtree_find(analysis->global_var_tree, &addr, global_var_node_cmp, NULL);
	if (!node) {
		return NULL;
	}
	RzAnalysisVarGlobal *var = (RzAnalysisVarGlobal *)container_of(node, RzAnalysisVarGlobal, rb);
	if (!var) {
		return NULL;
	}
	return var;
}

/**
 * \brief Get the instance of global variable contains the address
 *
 * \param analysis RzAnalysis
 * \param addr Global variable address
 * \return RzAnalysisVarGlobal *
 */
RZ_API RZ_BORROW RzAnalysisVarGlobal *rz_analysis_var_global_get_byaddr_in(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);

	RBNode *node = rz_rbtree_upper_bound(analysis->global_var_tree, &addr, global_var_node_cmp, NULL);
	if (!node) {
		return NULL;
	}
	RzAnalysisVarGlobal *var = (RzAnalysisVarGlobal *)container_of(node, RzAnalysisVarGlobal, rb);
	if (!var) {
		return NULL;
	}
	ut64 size = rz_type_db_get_bitsize(analysis->typedb, var->type) / 8;
	if (addr >= var->addr + size) {
		return NULL;
	}
	return var;
}

static bool global_var_collect_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	RzList *l = user;
	RzAnalysisVarGlobal *glob = (RzAnalysisVarGlobal *)v;
	rz_list_append(l, glob);
	return true;
}

/**
 * \brief Get all of the added global variables
 *
 * \param analysis RzAnalysis
 * \return RzList *
 */
RZ_API RZ_OWN RzList /*<RzAnalysisVarGlobal *>*/ *rz_analysis_var_global_get_all(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzList *globals = rz_list_new();
	if (!globals) {
		return NULL;
	}
	ht_sp_foreach_cb(analysis->ht_global_var, global_var_collect_cb, globals);
	return globals;
}

/**
 * \brief Rename the global variable
 *
 * \param analysis RzAnalysis
 * \param old_name The old name of the global variable
 * \param newname The new name of the global variable
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_rename(RzAnalysis *analysis, RZ_NONNULL const char *old_name, RZ_NONNULL const char *newname) {
	rz_return_val_if_fail(analysis && old_name && newname, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(analysis, old_name);
	if (!glob) {
		RZ_LOG_ERROR("Global variable '%s' does not exist!\n", old_name);
		return false;
	}

	RzFlagItem *flag = rz_analysis_var_global_get_flag_item(glob);
	if (flag) {
		rz_flag_rename(analysis->flb.f, flag, newname);
	}

	RZ_FREE(glob->name);
	glob->name = strdup(newname);
	return ht_sp_update_key(analysis->ht_global_var, old_name, newname);
}

/**
 * \brief Set the type of the global variable
 *
 * \param glob Global variable instance
 * \param type The type to set. RzType*
 * \return void
 */
RZ_API void rz_analysis_var_global_set_type(RzAnalysisVarGlobal *glob, RZ_NONNULL RZ_BORROW RzType *type) {
	rz_return_if_fail(glob && type);
	rz_type_free(glob->type);

	global_var_set_type(glob, type);
}

/**
 * \brief Add a constaint to global variable
 *
 * \param glob Global variable instance
 * \param constraint RzTypeConstraint
 * \return void
 */
RZ_API void rz_analysis_var_global_add_constraint(RzAnalysisVarGlobal *glob, RzTypeConstraint *constraint) {
	rz_return_if_fail(glob && constraint);
	rz_vector_push(&glob->constraints, constraint);
}

/**
 * \brief Get the pritable string of global variable constraints
 *
 * \param glob Global variable instance
 * \return char *
 */
RZ_API RZ_OWN char *rz_analysis_var_global_get_constraints_readable(RzAnalysisVarGlobal *glob) {
	size_t n = glob->constraints.len;
	if (!n) {
		return NULL;
	}
	bool low = false, high = false;
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	size_t i;
	for (i = 0; i < n; i += 1) {
		RzTypeConstraint *constr = rz_vector_index_ptr(&glob->constraints, i);
		switch (constr->cond) {
		case RZ_TYPE_COND_LE:
			if (high) {
				rz_strbuf_append(&sb, " && ");
			}
			rz_strbuf_appendf(&sb, "<= 0x%" PFMT64x "", constr->val);
			low = true;
			break;
		case RZ_TYPE_COND_LT:
			if (high) {
				rz_strbuf_append(&sb, " && ");
			}
			rz_strbuf_appendf(&sb, "< 0x%" PFMT64x "", constr->val);
			low = true;
			break;
		case RZ_TYPE_COND_GE:
			rz_strbuf_appendf(&sb, ">= 0x%" PFMT64x "", constr->val);
			high = true;
			break;
		case RZ_TYPE_COND_GT:
			rz_strbuf_appendf(&sb, "> 0x%" PFMT64x "", constr->val);
			high = true;
			break;
		default:
			break;
		}
		if (low && high && i != n - 1) {
			rz_strbuf_append(&sb, " || ");
			low = false;
			high = false;
		}
	}
	return rz_strbuf_drain_nofree(&sb);
}

/**
 * \brief Get the list of x-references to the global variable
 *
 * \param analysis RzAnalysis
 * \param glob Global variable
 * \return RzList *
 */
RZ_API RZ_OWN RzList /*<RzAnalysisXRef *>*/ *rz_analysis_var_global_xrefs(RzAnalysis *analysis, RZ_NONNULL const RzAnalysisVarGlobal *glob) {
	rz_return_val_if_fail(analysis && glob, NULL);
	return rz_analysis_xrefs_get_to(analysis, glob->addr);
}
