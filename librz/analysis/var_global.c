// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_list.h>

/**
 * \brief Create a new instance of global variable
 * 
 * \param name variable name
 * \param addr variable address
 * \param comment variable comment
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
	if (rz_analysis_var_global_get_byaddr(analysis, global_var->addr)) {
		RZ_LOG_ERROR("Global variable %s at 0x%" PFMT64x " already exists!\n", global_var->name, global_var->addr);
		return false;
	}
	if (!ht_pp_insert(analysis->ht_global_var, global_var->name, global_var)) {
		return false;
	}
	if (global_var->type) {
		global_var->size = rz_type_db_get_bitsize(analysis->typedb, global_var->type) / 8;
	}
	if (!rz_rbtree_aug_insert(&analysis->global_var_tree, &global_var->addr, &global_var->rb, global_var_node_cmp, NULL, NULL)) {
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

	RZ_FREE(glob->name);
	rz_type_free(glob->type);
	rz_vector_fini(&glob->constraints);
	RZ_FREE(glob);
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
		return false;
	}
	// We need to delete RBTree first because ht_pp_delete will free its member
	bool deleted = rz_rbtree_delete(&analysis->global_var_tree, &glob->addr, global_var_node_cmp, NULL, NULL, NULL);
	return deleted ? ht_pp_delete(analysis->ht_global_var, name) : deleted;
}

/**
 * \brief Same as rz_analysis_var_global_delete_byname but by its address
 * 
 * \param analysis RzAnalysis
 * \param addr Global Variable address
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_delete_byaddr(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byaddr(analysis, addr);
	if (!glob) {
		return false;
	}
	// We need to delete RBTree first because ht_pp_delete will free its member
	bool deleted = rz_rbtree_delete(&analysis->global_var_tree, &glob->addr, global_var_node_cmp, NULL, NULL, NULL);
	return deleted ? ht_pp_delete(analysis->ht_global_var, glob->name) : deleted;
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
 * \brief Same as rz_analysis_var_global_get_byname but by its address
 * 
 * \param analysis RzAnalysis
 * \param addr Global variable address
 * \return RzAnalysisVarGlobal *
 */
RZ_API RZ_BORROW RzAnalysisVarGlobal *rz_analysis_var_global_get_byaddr(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	RBIter it;
	RzAnalysisVarGlobal *node, *tmp = NULL;
	rz_rbtree_foreach (analysis->global_var_tree, it, node, RzAnalysisVarGlobal, rb) {
		if (node->addr > addr) { // get the highest variable
			break;
		}
		if (addr <= node->addr + node->size - 1) { // check if the givin address is in the global variable
			tmp = node;
		}
	}
	if (!tmp) {
		return NULL;
	}
	return tmp;
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
		return false;
	}
	RZ_FREE(glob->name);
	glob->name = strdup(newname);
	return ht_pp_update_key(analysis->ht_global_var, old_name, newname);
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
	glob->type = type;
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
 * \brief Print out the global variables
 * 
 * \param analysis RzAnalysis
 * \param state RzCmdStateOutput *
 * \param name Which one to print
 * \return void
 */
RZ_API void rz_analysis_var_global_list_show(RzAnalysis *analysis, RzCmdStateOutput *state, RZ_NULLABLE const char *name) {
	rz_return_if_fail(analysis && state);
	RzList *global_vars = NULL;
	RzAnalysisVarGlobal *glob = NULL;
	if (name) {
		global_vars = rz_list_new();
		if (!global_vars) {
			return;
		}
		glob = rz_analysis_var_global_get_byname(analysis, name);
		if (!glob) {
			return;
		}
		rz_list_append(global_vars, glob);
	} else {
		global_vars = rz_analysis_var_global_get_all(analysis);
	}

	RzListIter *it = NULL;
	char *var_type = NULL;
	bool json = state->mode == RZ_OUTPUT_MODE_JSON;
	PJ *pj = json ? state->d.pj : NULL;
	// to use rz_cmd_state_output_array_start we need to set RzCore as the dependency of RzAnalysis, which is impossible
	if (json) {
		pj_a(pj);
	}
	if (!global_vars && json) {
		pj_end(pj);
		return;
	}
	rz_list_foreach (global_vars, it, glob) {
		var_type = rz_type_as_string(analysis->typedb, glob->type);
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			analysis->cb_printf("global %s %s @ 0x%" PFMT64x "\n",
				var_type, glob->name, glob->addr);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ks(pj, "name", glob->name);
			pj_ks(pj, "type", var_type);
			pj_ks(pj, "addr", rz_str_newf("0x%" PFMT64x, glob->addr));
			pj_end(pj);
			break;
		default:
			break;
		}
	}
	if (json) {
		pj_end(pj);
	}
	rz_list_free(global_vars);
}
