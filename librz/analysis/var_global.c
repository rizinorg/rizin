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
RZ_API RZ_OWN RzAnalysisVarGlobal *rz_analysis_var_global_new(RZ_NONNULL const char *name, ut64 addr, RZ_NULLABLE const char *comment) {
	rz_return_val_if_fail(name && addr, NULL);
	RzAnalysisVarGlobal *glob = RZ_NEW0(RzAnalysisVarGlobal);
	if (!glob) {
		return NULL;
	}
	glob->name = strdup(name);
	glob->addr = addr;
	if (comment) {
		glob->comment = strdup(comment);
	}
	return glob;
}

typedef struct {
	RBNode rb;
	ut64 addr;
	ut64 size;
} GlobalVarNode;

int global_var_node_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 ia = *(ut64 *)incoming;
	ut64 ta = container_of(in_tree, const GlobalVarNode, rb)->addr;
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
RZ_API RZ_OWN bool rz_analysis_var_global_add(RzAnalysis *analysis, RzAnalysisVarGlobal *global_var) {
	rz_return_val_if_fail(analysis && global_var, false);
	if (rz_analysis_var_global_get_byaddr(analysis, global_var->addr)) {
		RZ_LOG_ERROR("Global variable %s at 0x%" PFMT64x " already exists!\n", global_var->name, global_var->addr);
		return false;
	} else if (ht_pp_find(analysis->ht_global_var, global_var->name, NULL)) {
		RZ_LOG_ERROR("Global variable %s already exists!\n", global_var->name);
		return false;
	}
	if (!ht_pp_insert(analysis->ht_global_var, global_var->name, global_var)) {
		return false;
	}
	GlobalVarNode *node = RZ_NEW0(GlobalVarNode);
	node->addr = global_var->addr;
	node->size = 0;
	if (global_var->type) {
		node->size = rz_type_db_get_bitsize(analysis->typedb, global_var->type) / 8;
	}
	if (!rz_rbtree_aug_insert(&analysis->global_var_tree, &node->addr, &node->rb, global_var_node_cmp, NULL, NULL)) {
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
	RZ_FREE(glob->comment);
	rz_type_free(glob->type);
	rz_analysis_var_global_clear_accesses(glob);
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
RZ_API bool rz_analysis_var_global_delete_byname(RzAnalysis *analysis, const char *name) {
	rz_return_val_if_fail(analysis && name, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(analysis, name);
	if (!glob) {
		RZ_LOG_ERROR("No such global variable!\n");
		return false;
	}
	rz_analysis_var_global_free(glob);
	rz_rbtree_delete(&analysis->global_var_tree, &glob->addr, global_var_node_cmp, NULL, NULL, NULL);
	return ht_pp_delete(analysis->ht_global_var, name);
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
		RZ_LOG_ERROR("No such global variable!\n");
		return false;
	}
	bool deleted = ht_pp_delete(analysis->ht_global_var, glob->name);
	if (deleted) {
		rz_rbtree_delete(&analysis->global_var_tree, &glob->addr, global_var_node_cmp, NULL, NULL, NULL);
		rz_analysis_var_global_free(glob);
	}
	return deleted;
}

/**
 * \brief Get the instance of global variable by its name
 * 
 * \param analysis RzAnalysis
 * \param name Global variable name
 * \return RzAnalysisVarGlobal *
 */
RZ_API RZ_BORROW RzAnalysisVarGlobal *rz_analysis_var_global_get_byname(RzAnalysis *analysis, const char *name) {
	rz_return_val_if_fail(analysis && name, NULL);
	return (RzAnalysisVarGlobal *)ht_pp_find(analysis->ht_global_var, name, NULL);
}

struct list_addr {
	RzList /* <RzAnalysisVarGlobal> */ *list;
	ut64 addr;
};

static bool global_var_collect_addr_cb(void *user, const void *k, const void *v) {
	struct list_addr *l = user;
	RzAnalysisVarGlobal *glob = (RzAnalysisVarGlobal *)v;
	if (glob->addr == l->addr) {
		rz_list_append(l->list, glob);
	}
	return true;
}

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
	GlobalVarNode *node, *tmp = NULL;
	rz_rbtree_foreach (analysis->global_var_tree, it, node, GlobalVarNode, rb) {
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

	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	struct list_addr l = { list, tmp->addr };
	ht_pp_foreach(analysis->ht_global_var, global_var_collect_addr_cb, &l);
	if (rz_list_length(list) != 1) {
		rz_list_free(list);
		return NULL;
	}
	RzAnalysisVarGlobal *glob = (RzAnalysisVarGlobal *)rz_list_first(list);
	rz_list_free(list);
	return glob;
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
RZ_API bool rz_analysis_var_global_rename(RzAnalysis *analysis, const char *old_name, RZ_NONNULL const char *newname) {
	rz_return_val_if_fail(analysis && old_name && newname, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(analysis, old_name);
	if (!glob) {
		RZ_LOG_ERROR("No such global variable!\n");
		return false;
	}
	RZ_FREE(glob->name);
	glob->name = strdup(newname);
	return ht_pp_update_key(analysis->ht_global_var, old_name, newname);
}

/**
 * \brief Set the comment of the global variable
 * 
 * \param analysis RzAnalysis
 * \param name The name of the global variable to set
 * \param comment The comment to set
 * \return true if succeed
 */
RZ_API bool rz_analysis_var_global_set_comment(RzAnalysis *analysis, const char *name, RZ_NONNULL const char *comment) {
	rz_return_val_if_fail(analysis && name && comment, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(analysis, name);
	if (!glob) {
		RZ_LOG_ERROR("No such global variable!\n");
		return false;
	}
	RZ_FREE(glob->comment);
	glob->comment = strdup(comment);
	return true;
}

/**
 * \brief Set the type of the global variable
 * 
 * \param glob Global variable instance
 * \param type The type to set. RzType*
 * \return void
 */
RZ_API void rz_analysis_var_global_set_type(RzAnalysisVarGlobal *glob, RzType *type) {
	rz_return_if_fail(glob && type);
	glob->type = type;
}

static st64 var_access_cmp(st64 x, char *y) {
	return x - (st64)((RzAnalysisVarGlobal *)y)->addr;
}

/**
 * \brief Set the accesses of the global variable
 * 
 * \param analysis RzAnalysis
 * \param glob Global variable instance
 * \param reg Register
 * \param access_addr Address of access
 * \param access_type Type of access
 * \param stackptr Stack pointer
 * \return void
 */
RZ_API void rz_analysis_var_global_set_access(RzAnalysis *analysis, RzAnalysisVarGlobal *glob, const char *reg, ut64 access_addr, int access_type, st64 stackptr) {
	rz_return_if_fail(glob);
	st64 offset = (st64)access_addr - (st64)glob->addr;

	// accesses are stored ordered by offset, use binary search to get the matching existing or the index to insert a new one
	size_t index;
	rz_vector_lower_bound(&glob->accesses, offset, index, var_access_cmp);
	RzAnalysisVarAccess *acc = NULL;
	if (index < glob->accesses.len) {
		acc = rz_vector_index_ptr(&glob->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		acc = rz_vector_insert(&glob->accesses, index, NULL);
		if (!acc) {
			return;
		}
		acc->offset = offset;
		acc->type = 0;
	}

	acc->type |= (ut8)access_type;
	acc->stackptr = stackptr;
	acc->reg = rz_str_constpool_get(&analysis->constpool, reg);
}

/**
 * \brief Remove the access at the address of global variable
 * 
 * \param glob Global variable instance
 * \param address Where to delete
 * \return void
 */
RZ_API void rz_analysis_var_global_remove_access_at(RzAnalysisVarGlobal *glob, ut64 address) {
	rz_return_if_fail(glob);
	st64 offset = (st64)address - (st64)glob->addr;
	size_t index;
	rz_vector_lower_bound(&glob->accesses, offset, index, var_access_cmp);
	if (index >= glob->accesses.len) {
		return;
	}
	RzAnalysisVarAccess *acc = rz_vector_index_ptr(&glob->accesses, index);
	if (acc && acc->offset == offset) {
		rz_vector_remove_at(&glob->accesses, index, NULL);
	}
}

/**
 * \brief Clear all the accesses of global variable
 * 
 * \param glob Global variable instance
 * \return void
 */
RZ_API void rz_analysis_var_global_clear_accesses(RzAnalysisVarGlobal *glob) {
	rz_return_if_fail(glob);
	rz_vector_clear(&glob->accesses);
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
RZ_API char *rz_analysis_var_global_get_constraints_readable(RzAnalysisVarGlobal *glob) {
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
	char *comment = NULL;
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
		if (!glob->comment) {
			comment = "";
		} else {
			comment = glob->comment;
		}
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			analysis->cb_printf("global %s %s @ 0x%" PFMT64x " ;%s\n",
				var_type, glob->name,
				glob->addr, comment);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ks(pj, "name", glob->name);
			pj_ks(pj, "type", var_type);
			pj_ks(pj, "addr", rz_str_newf("0x%" PFMT64x, glob->addr));
			pj_ks(pj, "comment", comment);
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
