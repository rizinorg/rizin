// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_list.h>
#include <rz_core.h>

/**
 * \brief Create a new instance of global variable
 * 
 * \param name variable name
 * \param addr variable address
 * \param comment variable comment
 * \param flags flag list of current core instance
 * \return RzAnalysisVarGlobal *
 */
RZ_API RZ_OWN RzAnalysisVarGlobal *rz_analysis_var_global_new(RZ_NONNULL const char *name, ut64 addr, RzFlag *flags) {
	rz_return_val_if_fail(name, NULL);
	RzAnalysisVarGlobal *glob = RZ_NEW0(RzAnalysisVarGlobal);
	if (!glob) {
		return NULL;
	}
	glob->name = strdup(name);
	glob->addr = addr;
	glob->flag = NULL;

	if (!flags) {
		return glob;
	}

	RzFlagItem *glob_flag_item = rz_flag_set(flags, glob->name, glob->addr, 0);
	if (!glob_flag_item) {
		RZ_LOG_ERROR("Unable to create flag item for global variable %s at 0x%" PFMT64x "\n", glob->name, glob->addr);
		return glob;
	}
	glob->flag = glob_flag_item;

	return glob;
}

int global_var_node_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 ia = *(ut64 *)incoming;
	ut64 ta = container_of(in_tree, const RzAnalysisVarGlobal, rb)->addr;
	if (ia < ta) {
		return -1;
	} else if (ia > ta) {
		return 1;
	}
	return 0;
}

/**
 * \brief Add the global variable into hashtable
 * 
 * \param analysis RzAnalysis
 * \param global_var Global variable instance
 * \return true if succeed
 */
RZ_API RZ_OWN bool rz_analysis_var_global_add(RzAnalysis *analysis, RZ_NONNULL RzAnalysisVarGlobal *global_var) {
	rz_return_val_if_fail(analysis && global_var, false);
	if (rz_analysis_var_global_get_byaddr_in(analysis, global_var->addr)) {
		RZ_LOG_ERROR("Global variable %s at 0x%" PFMT64x " already exists!\n", global_var->name, global_var->addr);
		return false;
	}
	if (!ht_pp_insert(analysis->ht_global_var, global_var->name, global_var)) {
		return false;
	}
	if (!rz_rbtree_aug_insert(&analysis->global_var_tree, &global_var->addr, &global_var->rb, global_var_node_cmp, NULL, NULL)) {
		return false;
	}
	return true;
}

/**
 * \brief Free the global variable instance except the flag
 * 
 * \param glob Global variable instance
 * \return void
 */
RZ_API void rz_analysis_var_global_free_except_flag(RZ_NONNULL RzAnalysisVarGlobal *glob) {
	if (!glob) {
		return;
	}

	RZ_FREE(glob->name);
	rz_type_free(glob->type);
	rz_vector_fini(&glob->constraints);
	RZ_FREE(glob);
}

/**
 * \brief Free the global variable instance
 * 
 * \param glob Global variable instance
 * \param flags flag list of current core instance
 * \return void
 */
RZ_API void rz_analysis_var_global_free(RZ_NONNULL RzAnalysisVarGlobal *glob, RZ_NONNULL RzFlag *flags) {
	if (!glob) {
		return;
	}
	rz_return_if_fail(flags);

	RZ_FREE(glob->name);
	rz_type_free(glob->type);
	rz_vector_fini(&glob->constraints);

	if (!rz_flag_unset(flags, glob->flag)) {
		RZ_LOG_ERROR("Failed to unset flag for global variable %s at 0x%" PFMT64x "\n", glob->name, glob->addr);
	}
	glob->flag = NULL;
	RZ_FREE(glob);
}

/**
 * \brief Delete and free the global variable
 * 
 * \param analysis RzAnalysis
 * \param glob global variable to be deleted
 * \param flags flag list of current core instance
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_delete(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisVarGlobal *glob, RzFlag *flags) {
	rz_return_val_if_fail(analysis && glob, false);

	bool ret = false;

	// We need to delete RBTree first because ht_pp_delete will free its member
	bool deleted = rz_rbtree_delete(&analysis->global_var_tree, &glob->addr, global_var_node_cmp, NULL, NULL, NULL);
	ret = deleted ? ht_pp_delete(analysis->ht_global_var, glob->name) : deleted;

	if (!flags || !glob->flag) {
		glob->flag = NULL;
		return ret;
	}

	if (!rz_flag_unset(flags, glob->flag)) {
		RZ_LOG_ERROR("Failed to unset flag for global variable %s at 0x%" PFMT64x "\n", glob->name, glob->addr);
	}

	glob->flag = NULL;
	return ret;
}

/**
 * \brief Delete and free the global variable by its name
 * 
 * \param analysis RzAnalysis
 * \param name Global Variable name
 * \param flags flag list of current core instance
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_delete_byname(RzAnalysis *analysis, RZ_NONNULL const char *name, RzFlag *flags) {
	rz_return_val_if_fail(analysis && name, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(analysis, name);
	if (!glob) {
		return false;
	}

	return rz_analysis_var_global_delete(analysis, glob, flags);
}

/**
 * \brief Same as rz_analysis_var_global_delete_byname at the address
 * 
 * \param analysis RzAnalysis
 * \param addr Global Variable address
 * \param flags flag list of current core instance
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_delete_byaddr_at(RzAnalysis *analysis, ut64 addr, RzFlag *flags) {
	rz_return_val_if_fail(analysis, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byaddr_at(analysis, addr);
	if (!glob) {
		return false;
	}

	return rz_analysis_var_global_delete(analysis, glob, flags);
}

/**
 * \brief Same as rz_analysis_var_global_delete_byname in the address
 * 
 * \param analysis RzAnalysis
 * \param addr Global Variable address
 * \param flags flag list of current core instance
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_delete_byaddr_in(RzAnalysis *analysis, ut64 addr, RzFlag *flags) {
	rz_return_val_if_fail(analysis, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byaddr_in(analysis, addr);
	if (!glob) {
		return false;
	}

	return rz_analysis_var_global_delete(analysis, glob, flags);
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
	return (RzAnalysisVarGlobal *)ht_pp_find(analysis->ht_global_var, name, NULL);
}

struct list_addr {
	RzList /* <RzAnalysisVarGlobal> */ *list;
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

static bool global_var_collect_cb(void *user, const void *k, const void *v) {
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
RZ_API RZ_OWN RzList *rz_analysis_var_global_get_all(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzList *globals = rz_list_new();
	if (!globals) {
		return NULL;
	}
	ht_pp_foreach(analysis->ht_global_var, global_var_collect_cb, globals);
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
	RZ_FREE(glob->name);
	glob->name = strdup(newname);

	if (glob->flag) {
		if (glob->flag->realname != glob->flag->name) {
			RZ_FREE(glob->flag->realname);
		}
		RZ_FREE(glob->flag->name);

		glob->flag->realname = strdup(newname);
		glob->flag->name = strdup(newname);
	}

	return ht_pp_update_key(analysis->ht_global_var, old_name, newname);
}

/**
 * \brief Set the type of the global variable
 * 
 * \param glob Global variable instance
 * \param type The type to set. RzType*
 * \param typedb RzTypeDB for the current analysis instance
 * \return void
 */
RZ_API void rz_analysis_var_global_set_type(RzAnalysisVarGlobal *glob, RZ_NONNULL RZ_BORROW RzType *type, const RzTypeDB *typedb) {
	rz_return_if_fail(glob && type);
	rz_type_free(glob->type);
	glob->type = type;

	if (typedb) {
		glob->flag->size = rz_type_db_get_bitsize(typedb, glob->type) / 8;
	}
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
