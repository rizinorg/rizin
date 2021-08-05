// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_list.h>

RZ_API RzAnalysisVarGlobal *rz_analysis_var_global_new(char *name, ut64 addr, char *comment) {
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

RZ_API bool rz_analysis_var_global_add(RzAnalysis *analysis, RzAnalysisVarGlobal *global_var) {
	rz_return_val_if_fail(analysis && global_var, false);
	if (rz_analysis_var_global_get_byaddr(analysis, global_var->addr)) {
		eprintf("Global variable at 0x%" PFMT64x " is already exist!\n", global_var->addr);
		return false;
	}
	return ht_pp_insert(analysis->ht_global_var, global_var->name, global_var);
}

RZ_API void rz_analysis_var_global_free(RzAnalysisVarGlobal *glob) {
	rz_return_if_fail(glob);
	RZ_FREE(glob->name);
	if (glob->comment) {
		RZ_FREE(glob->comment);
	}
	rz_type_free(glob->type);
	rz_analysis_var_global_clear_accesses(glob);
	rz_vector_fini(&glob->constraints);
	RZ_FREE(glob);
}

RZ_API bool rz_analysis_var_global_delete_byname(RzAnalysis *analysis, char *name) {
	rz_return_val_if_fail(analysis && name, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(analysis, name);
	if (!glob) {
		eprintf("No such global variable!\n");
		return true;
	}
	rz_analysis_var_global_free(glob);
	return ht_pp_delete(analysis->ht_global_var, name);
}

RZ_API bool rz_analysis_var_global_delete_byaddr(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byaddr(analysis, addr);
	if (!glob) {
		eprintf("No such global variable!\n");
		return true;
	}
	bool deleted = ht_pp_delete(analysis->ht_global_var, glob->name);
	rz_analysis_var_global_free(glob);
	return deleted ? true : false;
}

RZ_API void rz_analysis_var_global_delete_all(RzAnalysis *analysis) {
	rz_return_if_fail(analysis);
	RzList *globals = rz_analysis_var_global_get_all(analysis);
	if (!globals) {
		return;
	}
	RzListIter *it;
	RzAnalysisVarGlobal *glob;
	rz_list_foreach (globals, it, glob) {
		ht_pp_delete(analysis->ht_global_var, glob->name);
		rz_analysis_var_global_free(glob);
	}
}

RZ_API RzAnalysisVarGlobal *rz_analysis_var_global_get_byname(RzAnalysis *analysis, char *name) {
	rz_return_val_if_fail(analysis && name, NULL);
	RzAnalysisVarGlobal *glob;
	bool found;
	glob = ht_pp_find(analysis->ht_global_var, name, &found);
	return found ? glob : NULL;
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

RZ_API RzAnalysisVarGlobal *rz_analysis_var_global_get_byaddr(RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	RzList *list = rz_list_new();
	struct list_addr l = { list, addr };
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

RZ_API RzList *rz_analysis_var_global_get_all(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzList *globals = rz_list_new();
	ht_pp_foreach(analysis->ht_global_var, global_var_collect_cb, globals);
	return globals;
}

RZ_API bool rz_analysis_var_global_rename(RzAnalysis *analysis, char *old_name, char *newname) {
	rz_return_val_if_fail(analysis && old_name && newname, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(analysis, old_name);
	if (!glob) {
		eprintf("No such global variable!\n");
		return false;
	}
	RZ_FREE(glob->name);
	glob->name = strdup(newname);
	return ht_pp_update_key(analysis->ht_global_var, old_name, newname);
}

RZ_API bool rz_analysis_var_global_set_comment(RzAnalysis *analysis, char *name, char *comment) {
	rz_return_val_if_fail(analysis && name && comment, false);
	RzAnalysisVarGlobal *glob = rz_analysis_var_global_get_byname(analysis, name);
	if (!glob) {
		return false;
	}
	if (glob->comment) {
		RZ_FREE(glob->comment);
	}
	glob->comment = strdup(comment);
	return true;
}

RZ_API void rz_analysis_var_global_set_type(RzAnalysisVarGlobal *glob, RzType *type) {
	rz_return_if_fail(glob && type);
	glob->type = type;
}

static st64 var_access_cmp(ut64 x, char *y) {
	return x - (ut64)((RzAnalysisVarGlobal *)y)->addr;
}

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
		acc->offset = offset;
		acc->type = 0;
	}

	acc->type |= (ut8)access_type;
	acc->stackptr = stackptr;
	acc->reg = rz_str_constpool_get(&analysis->constpool, reg);
}

RZ_API void rz_analysis_var_global_remove_access_at(RzAnalysisVarGlobal *glob, ut64 address) {
	rz_return_if_fail(glob);
	st64 offset = (st64)address - (st64)glob->addr;
	size_t index;
	rz_vector_lower_bound(&glob->accesses, offset, index, var_access_cmp);
	if (index >= glob->accesses.len) {
		return;
	}
	RzAnalysisVarAccess *acc = rz_vector_index_ptr(&glob->accesses, index);
	if (acc->offset == offset) {
		rz_vector_remove_at(&glob->accesses, index, NULL);
	}
}

RZ_API void rz_analysis_var_global_clear_accesses(RzAnalysisVarGlobal *glob) {
	rz_return_if_fail(glob);
	rz_vector_clear(&glob->accesses);
}

RZ_API void rz_analysis_var_global_add_constraint(RzAnalysisVarGlobal *glob, RzTypeConstraint *constraint) {
	rz_return_if_fail(glob && constraint);
	rz_vector_push(&glob->constraints, constraint);
}

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

RZ_API void rz_analysis_var_global_list_show(RzAnalysis *analysis, RzCmdStateOutput *state, char *name) {
	rz_return_if_fail(analysis && state);
	RzList *global_vars = NULL;
	RzAnalysisVarGlobal *glob = NULL;
	if (name) {
		global_vars = rz_list_new();
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
			analysis->cb_printf("global %s %s @ 0x%" PFMT64x " %s\n",
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
