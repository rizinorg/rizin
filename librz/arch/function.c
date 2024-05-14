// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2019 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

static bool get_functions_block_cb(RzAnalysisBlock *block, void *user) {
	RzList *list = user;
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (block->fcns, iter, fcn) {
		if (rz_list_contains(list, fcn)) {
			continue;
		}
		rz_list_push(list, fcn);
	}
	return true;
}

RZ_API RzList /*<RzAnalysisFunction *>*/ *rz_analysis_get_functions_in(RzAnalysis *analysis, ut64 addr) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	rz_analysis_blocks_foreach_in(analysis, addr, get_functions_block_cb, list);
	return list;
}

static bool get_function_block_cb(RzAnalysisBlock *block, void *user) {
	RzAnalysisFunction **pfcn = user;
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (block->fcns, iter, fcn) {
		*pfcn = fcn;
		break;
	}
	return true;
}

/**
 * \brief Returns the first function that have a basic block containing the given address \p addr
 *
 * \param analysis A pointer to the `RzAnalysis` object used for analysis.
 * \param addr The address to find the function in.
 *
 * \return RzAnalysisFunction* Pointer to the `RzAnalysisFunction` object if found, otherwise NULL.
 */
RZ_API RZ_BORROW RzAnalysisFunction *rz_analysis_first_function_in(RZ_NONNULL RZ_BORROW RzAnalysis *analysis, ut64 addr) {
	rz_return_val_if_fail(analysis, NULL);
	RzAnalysisFunction *fcn = NULL;
	rz_analysis_blocks_foreach_in(analysis, addr, get_function_block_cb, &fcn);
	return fcn;
}

// check if name is already registered
static bool function_name_exists(RzAnalysis *analysis, const char *name, ut64 addr) {
	bool found = false;
	if (addr == UT64_MAX) {
		RZ_LOG_ERROR("Invalid function address (-1) '%s'\n", name);
		return true;
	}
	if (!name) {
		RZ_LOG_INFO("Empty function name, we must auto generate one\n");
		return true;
	}
	RzAnalysisFunction *f = ht_sp_find(analysis->ht_name_fun, name, &found);
	if (f && found) {
		return true;
	}
	return false;
}

// check if there's a function already in the given address
static bool function_already_defined_at(RzAnalysis *analysis, const char *name, ut64 addr) {
	bool found = false;
	RzAnalysisFunction *f = ht_up_find(analysis->ht_addr_fun, addr, &found);
	if (f && found) {
		return true;
	}
	return false;
}

RZ_API RzAnalysisFunction *rz_analysis_function_new(RzAnalysis *analysis) {
	RzAnalysisFunction *fcn = RZ_NEW0(RzAnalysisFunction);
	if (!fcn) {
		return NULL;
	}
	fcn->analysis = analysis;
	fcn->addr = UT64_MAX;
	fcn->cc = rz_str_constpool_get(&analysis->constpool, rz_analysis_cc_default(analysis));
	fcn->bits = analysis->bits;
	fcn->bbs = rz_pvector_new(NULL);
	fcn->has_changed = true;
	fcn->bp_frame = true;
	fcn->is_noreturn = false;
	fcn->meta._min = UT64_MAX;
	rz_pvector_init(&fcn->vars, (RzPVectorFree)rz_analysis_var_free);
	fcn->inst_vars = ht_up_new(NULL, (HtUPFreeValue)rz_pvector_free);
	fcn->labels = ht_up_new(NULL, free);
	fcn->label_addrs = ht_sp_new(HT_STR_DUP, NULL, free);
	return fcn;
}

RZ_API void rz_analysis_function_free(void *_fcn) {
	RzAnalysisFunction *fcn = _fcn;
	if (!_fcn) {
		return;
	}

	RzAnalysisBlock *block;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		block = (RzAnalysisBlock *)*it;
		rz_list_delete_data(block->fcns, fcn);
		rz_analysis_block_unref(block);
	}
	rz_pvector_free(fcn->bbs);

	RzAnalysis *analysis = fcn->analysis;
	if (ht_up_find(analysis->ht_addr_fun, fcn->addr, NULL) == _fcn) {
		ht_up_delete(analysis->ht_addr_fun, fcn->addr);
	}
	if (ht_sp_find(analysis->ht_name_fun, fcn->name, NULL) == _fcn) {
		ht_sp_delete(analysis->ht_name_fun, fcn->name);
	}

	rz_pvector_fini(&fcn->vars);
	ht_up_free(fcn->inst_vars);
	ht_up_free(fcn->labels);
	ht_sp_free(fcn->label_addrs);
	rz_type_free(fcn->ret_type);
	free(fcn->name);
	rz_list_free(fcn->imports);
	free(fcn);
}

/**
 * \brief Adds a new function to the analysis
 *
 * \param analysis The current RzAnalysis.
 * \param fcn The RzAnalysisFunction to add.
 *
 * \return True in case of success or false if it already exists.
 */
RZ_API bool rz_analysis_add_function(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(analysis && fcn, false);
	if (function_name_exists(analysis, fcn->name, fcn->addr)) {
		RZ_LOG_WARN("Function name '%s' already exists\n", fcn->name);
		return false;
	}
	if (function_already_defined_at(analysis, fcn->name, fcn->addr)) {
		RZ_LOG_WARN("Function '%s' already defined at specified address 0x%08" PFMT64x "\n",
			fcn->name, fcn->addr);
		return false;
	}
	if (analysis->cb.on_fcn_new) {
		analysis->cb.on_fcn_new(analysis, analysis->core, fcn);
	}
	if (analysis->flg_fcn_set) {
		analysis->flg_fcn_set(analysis->flb.f, fcn->name, fcn->addr, rz_analysis_function_size_from_entry(fcn));
	}
	fcn->is_noreturn = rz_analysis_noreturn_at_addr(analysis, fcn->addr);
	rz_list_append(analysis->fcns, fcn);
	return ht_sp_insert(analysis->ht_name_fun, fcn->name, fcn) && ht_up_insert(analysis->ht_addr_fun, fcn->addr, fcn);
}

RZ_API RzAnalysisFunction *rz_analysis_create_function(RzAnalysis *analysis, const char *name, ut64 addr, RzAnalysisFcnType type) {
	RzAnalysisFunction *fcn = rz_analysis_function_new(analysis);
	if (!fcn) {
		return NULL;
	}
	fcn->addr = addr;
	fcn->type = type;
	fcn->cc = rz_str_constpool_get(&analysis->constpool, rz_analysis_cc_default(analysis));
	fcn->bits = analysis->bits;
	if (name) {
		free(fcn->name);
		fcn->name = strdup(name);
	} else {
		const char *fcnprefix = analysis->coreb.cfgGet ? analysis->coreb.cfgGet(analysis->coreb.core, "analysis.fcnprefix") : NULL;
		if (RZ_STR_ISEMPTY(fcnprefix)) {
			fcnprefix = "fcn";
		}
		fcn->name = rz_str_newf("%s.%08" PFMT64x, fcnprefix, fcn->addr);
	}
	if (!rz_analysis_add_function(analysis, fcn)) {
		rz_analysis_function_free(fcn);
		return NULL;
	}
	return fcn;
}

RZ_API bool rz_analysis_function_delete(RzAnalysisFunction *fcn) {
	return rz_list_delete_data(fcn->analysis->fcns, fcn);
}

/**
 * \brief Returns the function which has its entrypoint at \p addr or NULL if non was found.
 *
 * \param analysis The current RzAnalysis.
 * \param addr The address of the function to get.
 *
 * \return The function with an entrypoint at \p addr or NULL if non was found.
 */
RZ_API RzAnalysisFunction *rz_analysis_get_function_at(const RzAnalysis *analysis, ut64 addr) {
	bool found = false;
	RzAnalysisFunction *f = ht_up_find(analysis->ht_addr_fun, addr, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

typedef struct {
	HtUP *inst_vars_new;
	st64 delta;
} InstVarsRelocateCtx;

static bool inst_vars_relocate_cb(void *user, const ut64 k, const void *v) {
	InstVarsRelocateCtx *ctx = user;
	ht_up_insert(ctx->inst_vars_new, k - ctx->delta, (void *)v);
	return true;
}

RZ_API bool rz_analysis_function_relocate(RzAnalysisFunction *fcn, ut64 addr) {
	if (fcn->addr == addr) {
		return true;
	}
	if (rz_analysis_get_function_at(fcn->analysis, addr)) {
		return false;
	}
	ht_up_delete(fcn->analysis->ht_addr_fun, fcn->addr);

	// relocate the var accesses (their addrs are relative to the function addr)
	st64 delta = (st64)addr - (st64)fcn->addr;
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		RzAnalysisVarAccess *acc;
		rz_vector_foreach (&var->accesses, acc) {
			acc->offset -= delta;
		}
	}
	InstVarsRelocateCtx ctx = {
		.inst_vars_new = ht_up_new(NULL, (HtUPFreeValue)rz_pvector_free),
		.delta = delta
	};
	if (ctx.inst_vars_new) {
		ht_up_foreach(fcn->inst_vars, inst_vars_relocate_cb, &ctx);
		// Do not free the elements of the Ht, because they were moved to ctx.inst_vars_new
		fcn->inst_vars->opt.finiKV = NULL;
		ht_up_free(fcn->inst_vars);
		fcn->inst_vars = ctx.inst_vars_new;
	}

	fcn->addr = addr;
	ht_up_insert(fcn->analysis->ht_addr_fun, addr, fcn);
	return true;
}

RZ_API bool rz_analysis_function_rename(RzAnalysisFunction *fcn, const char *name) {
	RzAnalysis *analysis = fcn->analysis;
	RzAnalysisFunction *existing = ht_sp_find(analysis->ht_name_fun, name, NULL);
	if (existing) {
		if (existing == fcn) {
			// fcn->name == name, nothing to do
			return true;
		}
		return false;
	}
	char *newname = strdup(name);
	if (!newname) {
		return false;
	}
	bool in_tree = ht_sp_delete(analysis->ht_name_fun, fcn->name);
	free(fcn->name);
	fcn->name = newname;
	if (in_tree) {
		// only re-insert if it really was in the tree before
		ht_sp_insert(analysis->ht_name_fun, fcn->name, fcn);
	}
	return true;
}

RZ_API void rz_analysis_function_add_block(RzAnalysisFunction *fcn, RzAnalysisBlock *bb) {
	if (rz_list_contains(bb->fcns, fcn)) {
		return;
	}
	rz_list_append(bb->fcns, fcn); // associate the given fcn with this bb
	rz_analysis_block_ref(bb);
	rz_pvector_push(fcn->bbs, bb);

	if (fcn->meta._min != UT64_MAX) {
		if (bb->addr + bb->size > fcn->meta._max) {
			fcn->meta._max = bb->addr + bb->size;
		}
		if (bb->addr < fcn->meta._min) {
			fcn->meta._min = bb->addr;
		}
	}

	if (fcn->analysis->cb.on_fcn_bb_new) {
		fcn->analysis->cb.on_fcn_bb_new(fcn->analysis, fcn->analysis->core, fcn, bb);
	}
}

RZ_API void rz_analysis_function_remove_block(RzAnalysisFunction *fcn, RzAnalysisBlock *bb) {
	rz_list_delete_data(bb->fcns, fcn);

	if (fcn->meta._min != UT64_MAX && (fcn->meta._min == bb->addr || fcn->meta._max == bb->addr + bb->size)) {
		// If a block is removed at the beginning or end, updating min/max is not trivial anymore, just invalidate
		fcn->meta._min = UT64_MAX;
	}

	rz_pvector_remove_data(fcn->bbs, bb);
	rz_analysis_block_unref(bb);
}

static void ensure_fcn_range(RzAnalysisFunction *fcn) {
	if (fcn->meta._min != UT64_MAX) { // recalculate only if invalid
		return;
	}
	ut64 minval = UT64_MAX;
	ut64 maxval = UT64_MIN;
	RzAnalysisBlock *block;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		block = (RzAnalysisBlock *)*it;
		if (block->addr < minval) {
			minval = block->addr;
		}
		if (block->addr + block->size > maxval) {
			maxval = block->addr + block->size;
		}
	}
	fcn->meta._min = minval;
	fcn->meta._max = minval == UT64_MAX ? UT64_MAX : maxval;
}

RZ_API ut64 rz_analysis_function_linear_size(RzAnalysisFunction *fcn) {
	ensure_fcn_range(fcn);
	return fcn->meta._max - fcn->meta._min;
}

RZ_API ut64 rz_analysis_function_min_addr(RzAnalysisFunction *fcn) {
	ensure_fcn_range(fcn);
	return fcn->meta._min;
}

RZ_API ut64 rz_analysis_function_max_addr(RzAnalysisFunction *fcn) {
	ensure_fcn_range(fcn);
	return fcn->meta._max;
}

RZ_API ut64 rz_analysis_function_size_from_entry(RzAnalysisFunction *fcn) {
	ensure_fcn_range(fcn);
	return fcn->meta._min == UT64_MAX ? 0 : fcn->meta._max - fcn->addr;
}

RZ_API ut64 rz_analysis_function_realsize(const RzAnalysisFunction *fcn) {
	ut64 realsize = 0;
	RzAnalysisBlock *block;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		block = (RzAnalysisBlock *)*it;
		realsize += block->size;
	}
	return realsize;
}

static bool fcn_in_cb(RzAnalysisBlock *block, void *user) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;
	rz_list_foreach (block->fcns, iter, fcn) {
		if (fcn == user) {
			return false;
		}
	}
	return true;
}

RZ_API bool rz_analysis_function_contains(RzAnalysisFunction *fcn, ut64 addr) {
	// fcn_in_cb breaks with false if it finds the fcn
	return !rz_analysis_blocks_foreach_in(fcn->analysis, addr, fcn_in_cb, fcn);
}

RZ_API bool rz_analysis_function_was_modified(RZ_NONNULL RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(fcn, false);
	RzAnalysisBlock *block;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		block = (RzAnalysisBlock *)*it;
		if (rz_analysis_block_was_modified(block)) {
			return true;
		}
	}
	return false;
}

RZ_API RZ_BORROW RzList /*<RzAnalysisFunction *>*/ *rz_analysis_function_list(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	return analysis->fcns;
}

#define MIN_MATCH_LEN 4

static RZ_OWN char *function_name_try_guess(RzTypeDB *typedb, RZ_NONNULL char *name) {
	if (strlen(name) < MIN_MATCH_LEN) {
		return NULL;
	}
	if (rz_type_func_exist(typedb, name)) {
		return strdup(name);
	}
	return NULL;
}

static inline bool is_auto_named(char *func_name, size_t slen) {
	return slen > 4 && (rz_str_startswith(func_name, "fcn.") || rz_str_startswith(func_name, "loc."));
}

static inline bool has_rz_prefixes(char *func_name, int offset, size_t slen) {
	return slen > 4 && (offset + 3 < slen) && func_name[offset + 3] == '.';
}

static char *strip_rz_prefixes(char *func_name, size_t slen) {
	// strip rizin prefixes (sym, sym.imp, etc')
	int offset = 0;
	while (has_rz_prefixes(func_name, offset, slen)) {
		offset += 4;
	}
	return func_name + offset;
}

static char *strip_common_prefixes_stdlib(char *func_name) {
	// strip common prefixes from standard lib functions
	if (rz_str_startswith(func_name, "__isoc99_")) {
		func_name += 9;
	} else if (rz_str_startswith(func_name, "__libc_") && !strstr(func_name, "_main")) {
		func_name += 7;
	} else if (rz_str_startswith(func_name, "__GI_")) {
		func_name += 5;
	}
	return func_name;
}

static char *strip_dll_prefix(char *func_name) {
	char *tmp = strstr(func_name, "dll_");
	if (tmp) {
		return tmp + 3;
	}
	return func_name;
}

static void clean_function_name(char *func_name) {
	char *last = (char *)rz_str_lchr(func_name, '_');
	if (!last || !rz_str_isnumber(last + 1)) {
		return;
	}
	*last = '\0';
}

/**
 * \brief Checks if the function name was generated by Rizin automatically
 */
RZ_API bool rz_analysis_function_is_autonamed(RZ_NONNULL char *name) {
	size_t len = strlen(name);
	return (len >= MIN_MATCH_LEN) && (is_auto_named(name, len) || has_rz_prefixes(name, 0, len));
}

/**
 * \brief Checks if varions function name variations present in the database
 *
 * Tries to remove different prefixes from the Rizin autonames,
 * standard libraries prefixes, various Windows-specific prefixes and checks
 * every attempt in the function database. If there is a match - returns it.
 *
 * \param typedb RzTypeDB instance
 * \param name Function name to check
 */
RZ_API RZ_OWN char *rz_analysis_function_name_guess(RzTypeDB *typedb, RZ_NONNULL char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	char *str = name;
	char *result = NULL;

	size_t slen = strlen(str);
	if (slen < MIN_MATCH_LEN || is_auto_named(str, slen)) {
		return NULL;
	}

	str = strip_rz_prefixes(str, slen);
	str = strip_common_prefixes_stdlib(str);
	str = strip_dll_prefix(str);

	if ((result = function_name_try_guess(typedb, str))) {
		return result;
	}

	str = strdup(str);
	clean_function_name(str);

	if (*str == '_' && (result = function_name_try_guess(typedb, str + 1))) {
		free(str);
		return result;
	}

	free(str);
	return result;
}
