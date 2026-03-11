// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_regex.h>
#include <rz_analysis.h>
#include <rz_parse.h>
#include <rz_util.h>
#include <rz_list.h>
#include <basic_block_analysis.h>

#define SDB_KEY_BB "bb.0x%" PFMT64x ".0x%" PFMT64x

#define BB_ALIGN 0x10

#define DB             a->sdb_fcns
#define EXISTS(x, ...) snprintf(key, sizeof(key) - 1, x, ##__VA_ARGS__), sdb_exists(DB, key)
#define SETKEY(x, ...) snprintf(key, sizeof(key) - 1, x, ##__VA_ARGS__);

typedef struct fcn_tree_iter_t {
	int len;
	RBNode *cur;
	RBNode *path[RZ_RBTREE_MAX_HEIGHT];
} FcnTreeIter;

RZ_API const char *rz_analysis_fcntype_tostring(int type) {
	switch (type) {
	case RZ_ANALYSIS_FCN_TYPE_NULL: return "null";
	case RZ_ANALYSIS_FCN_TYPE_FCN: return "fcn";
	case RZ_ANALYSIS_FCN_TYPE_LOC: return "loc";
	case RZ_ANALYSIS_FCN_TYPE_SYM: return "sym";
	case RZ_ANALYSIS_FCN_TYPE_IMP: return "imp";
	case RZ_ANALYSIS_FCN_TYPE_INT: return "int"; // interrupt
	case RZ_ANALYSIS_FCN_TYPE_ROOT: return "root";
	}
	return "unk";
}

RZ_API int rz_analysis_function_resize(RzAnalysisFunction *fcn, int newsize) {
	rz_return_val_if_fail(fcn, false);
	if (newsize < 1) {
		return false;
	}

	RzAnalysis *analysis = fcn->analysis;

	// XXX this is something we should probably do for all the archs
	bool is_arm = analysis->cur->arch && !strncmp(analysis->cur->arch, "arm", 3);
	if (is_arm) {
		return true;
	}

	ut64 eof = fcn->addr + newsize;

	// in this loop we remove basic blocks and since we modify the
	// pvector size we cannot loop normally.
	size_t count = rz_pvector_len(fcn->bbs);
	for (size_t i = 0; i < count;) {
		RzAnalysisBlock *bb = (RzAnalysisBlock *)rz_pvector_at(fcn->bbs, i);
		if (bb->addr >= eof) {
			rz_analysis_function_remove_block(fcn, bb);
			// the size of the pvector is changed, so we update count.
			count = rz_pvector_len(fcn->bbs);
			continue;
		}
		if (bb->addr + bb->size >= eof) {
			rz_analysis_block_set_size(bb, eof - bb->addr);
			rz_analysis_block_update_hash(bb);
		}
		if (bb->jump != UT64_MAX && bb->jump >= eof) {
			bb->jump = UT64_MAX;
		}
		if (bb->fail != UT64_MAX && bb->fail >= eof) {
			bb->fail = UT64_MAX;
		}
		i++;
	}

	return true;
}

static bool purity_checked(HtUP *ht, RzAnalysisFunction *fcn) {
	bool checked;
	ht_up_find(ht, fcn->addr, &checked);
	return checked;
}

/*
 * Checks whether a given function is pure and sets its 'is_pure' field.
 * This function marks fcn 'not pure' if fcn, or any function called by fcn, accesses data
 * from outside, even if it only READS it.
 * Probably worth changing it in the future, so that it marks fcn 'impure' only when it
 * (or any function called by fcn) MODIFIES external data.
 */
static void check_purity(HtUP *ht, RzAnalysisFunction *fcn) {
	RzListIter *iter;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	RzAnalysisXRef *xref;
	ht_up_insert(ht, fcn->addr, NULL);
	fcn->is_pure = true;
	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_CALL || xref->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
			RzAnalysisFunction *called_fcn = rz_analysis_get_fcn_in(fcn->analysis, xref->to, 0);
			if (!called_fcn) {
				continue;
			}
			if (!purity_checked(ht, called_fcn)) {
				check_purity(ht, called_fcn);
			}
			if (!called_fcn->is_pure) {
				fcn->is_pure = false;
				break;
			}
		}
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_DATA) {
			fcn->is_pure = false;
			break;
		}
	}
	rz_list_free(xrefs);
}

/**
 * \brief Analyses the given task item \p item for branches.
 *
 * Analysis starts for all instructions from \p item->start_address. If a branch is
 * encountered a new task item is added to the list \p tasks.
 * If an end of a basic function block is encountered (e.g. an invalid instruction),
 * the cause for it is returned.
 *
 * \param item The task item with the parent function and start address to start analysing from.
 * \param tasks The task list to append the new task items to.
 * \return RzAnalysisBBEndCause Cause a basic block ended.
 */
static RzAnalysisBBEndCause run_basic_block_analysis(RzAnalysisTaskItem *item, RzVector /*<RzAnalysisTaskItem>*/ *tasks) {
	BasicBlockAnalysisCtx ctx;
	if (!init_basic_block(&ctx, item, tasks)) {
		return ctx.ret; // failure
	}
	ctx.ret = analysis_basic_block(&ctx, item, tasks);
	cleanup_basic_block(&ctx);
	return ctx.ret;
}

/**
 * \brief Adds a new task item to the `tasks` parameter.
 *
 * Used to create a new item to the `tasks` parameter
 * that can be worked on later by the `rz_analysis_run_tasks` function.
 *
 * \param analysis Pointer to RzAnalysis instance.
 * \param tasks Pointer to RzVector to add a new RzAnalysisTaskItem to.
 * \param fcn Pointer to RzAnalysisFunction in which analysis will be performed on.
 * \param block Pointer to RzAnalysisBlock in which analysis will be performed on. If null, analysis will take care of block creation.
 * \param address Address where analysis will start from
 * \param sp Tracked stack pointer value at \p address
 */
RZ_API bool rz_analysis_task_item_new(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzVector /*<RzAnalysisTaskItem>*/ *tasks, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NULLABLE RzAnalysisBlock *block, ut64 address, RzStackAddr sp) {
	rz_return_val_if_fail(analysis && tasks && fcn, false);
	RzAnalysisTaskItem item = { fcn, block, sp, address };
	RzAnalysisTaskItem *it;
	rz_vector_foreach (tasks, it) {
		if (item.start_address == it->start_address) {
			return true;
		}
	}
	return rz_vector_push(tasks, &item);
}

/**
 * \brief Runs analysis on the task items.
 *
 * Runs control-flow and variable usage analysis on each of the task items until tasks vector becomes empty.
 * Items are removed from the tasks vector as they are processed.
 * Items are added to the tasks vector as new basic blocks are found to be analyzed.
 *
 * \param tasks Pointer to RzVector of RzAnalysisTaskItem to be performed analysis on.
 */
RZ_API int rz_analysis_run_tasks(RZ_NONNULL RzVector /*<RzAnalysisTaskItem>*/ *tasks) {
	rz_return_val_if_fail(tasks, RZ_ANALYSIS_RET_ERROR);
	int ret = RZ_ANALYSIS_RET_ERROR;
	while (!rz_vector_empty(tasks)) {
		RzAnalysisTaskItem item;
		rz_vector_pop(tasks, &item);
		int r = run_basic_block_analysis(&item, tasks);
		switch (r) {
		case RZ_ANALYSIS_RET_BRANCH:
		case RZ_ANALYSIS_RET_COND:
			continue;
		case RZ_ANALYSIS_RET_NOP:
		case RZ_ANALYSIS_RET_ERROR:
			if (ret != RZ_ANALYSIS_RET_END) {
				ret = r;
			}
			break;
		case RZ_ANALYSIS_RET_END:
		default:
			ret = r;
			break;
		}
		if (rz_cons_is_breaked()) {
			break;
		}
	}
	return ret;
}

RZ_API bool rz_analysis_check_fcn(RzAnalysis *analysis, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high) {
	RzAnalysisOp op = { 0 };
	int i, oplen, opcnt = 0, pushcnt = 0, movcnt = 0, brcnt = 0;
	if (rz_analysis_is_prelude(analysis, buf, bufsz)) {
		return true;
	}
	for (i = 0; i < bufsz && opcnt < 10; i += oplen, opcnt++) {
		rz_analysis_op_init(&op);
		if ((oplen = rz_analysis_op(analysis, &op, addr + i, buf + i, bufsz - i, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT)) < 1) {
			rz_analysis_op_fini(&op);
			return false;
		}
		switch (op.type) {
		case RZ_ANALYSIS_OP_TYPE_PUSH:
		case RZ_ANALYSIS_OP_TYPE_UPUSH:
		case RZ_ANALYSIS_OP_TYPE_RPUSH:
			pushcnt++;
			break;
		case RZ_ANALYSIS_OP_TYPE_MOV:
		case RZ_ANALYSIS_OP_TYPE_CMOV:
			movcnt++;
			break;
		case RZ_ANALYSIS_OP_TYPE_JMP:
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_CALL:
			if (op.jump < low || op.jump >= high) {
				rz_analysis_op_fini(&op);
				return false;
			}
			brcnt++;
			break;
		case RZ_ANALYSIS_OP_TYPE_UNK:
			rz_analysis_op_fini(&op);
			return false;
		default:
			break;
		}
		rz_analysis_op_fini(&op);
	}
	return (pushcnt + movcnt + brcnt > 5);
}

RZ_API void rz_analysis_trim_jmprefs(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzAnalysisXRef *xref;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	RzListIter *iter;
	const bool is_x86 = analysis->cur->arch && !strcmp(analysis->cur->arch, "x86"); // HACK

	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_CODE && rz_analysis_function_contains(fcn, xref->to) && (!is_x86 || !rz_analysis_function_contains(fcn, xref->from))) {
			rz_analysis_xrefs_deln(analysis, xref->from, xref->to, xref->type);
		}
	}
	rz_list_free(xrefs);
}

RZ_API void rz_analysis_del_jmprefs(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzAnalysisXRef *xref;
	RzList *xrefs = rz_analysis_function_get_xrefs_from(fcn);
	RzListIter *iter;

	rz_list_foreach (xrefs, iter, xref) {
		if (xref->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
			rz_analysis_xrefs_deln(analysis, xref->from, xref->to, xref->type);
		}
	}
	rz_list_free(xrefs);
}

/* Does NOT invalidate read-ahead cache. */
RZ_API int rz_analysis_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr, ut64 len, int reftype) {
	RzPVector *metas = rz_meta_get_all_in(analysis, addr, RZ_META_TYPE_ANY);
	void **it;
	rz_pvector_foreach (metas, it) {
		RzAnalysisMetaItem *meta = ((RzIntervalNode *)*it)->data;
		switch (meta->type) {
		case RZ_META_TYPE_DATA:
		case RZ_META_TYPE_STRING:
		case RZ_META_TYPE_FORMAT:
			rz_pvector_free(metas);
			return 0;
		default:
			break;
		}
	}
	rz_pvector_free(metas);
	if (analysis->opt.norevisit) {
		if (!analysis->visited) {
			analysis->visited = rz_set_u_new();
		}
		if (rz_set_u_contains(analysis->visited, addr)) {
			RZ_LOG_DEBUG("rz_analysis_fcn: analysis.norevisit at 0x%08" PFMT64x " %c\n", addr, reftype);
			return RZ_ANALYSIS_RET_END;
		}
		rz_set_u_add(analysis->visited, addr);
	} else {
		if (analysis->visited) {
			rz_set_u_free(analysis->visited);
			analysis->visited = NULL;
		}
	}
	/* defines fcn. or loc. prefix */
	fcn->type = (reftype == RZ_ANALYSIS_XREF_TYPE_CODE) ? RZ_ANALYSIS_FCN_TYPE_LOC : RZ_ANALYSIS_FCN_TYPE_FCN;
	if (fcn->addr == UT64_MAX) {
		fcn->addr = addr;
	}
	fcn->maxstack = 0;
	RzVector tasks;
	rz_vector_init(&tasks, sizeof(RzAnalysisTaskItem), NULL, NULL);
	rz_analysis_task_item_new(analysis, &tasks, fcn, NULL, addr, 0);
	int ret = rz_analysis_run_tasks(&tasks);
	rz_vector_fini(&tasks);
	return ret;
}

// XXX deprecate
RZ_API int rz_analysis_fcn_del_locs(RzAnalysis *analysis, ut64 addr) {
	RzListIter *iter, *iter2;
	RzAnalysisFunction *fcn, *f = rz_analysis_get_fcn_in(analysis, addr, RZ_ANALYSIS_FCN_TYPE_ROOT);
	if (!f) {
		return false;
	}
	rz_list_foreach_safe (analysis->fcns, iter, iter2, fcn) {
		if (fcn->type != RZ_ANALYSIS_FCN_TYPE_LOC) {
			continue;
		}
		if (rz_analysis_function_contains(fcn, addr)) {
			rz_analysis_function_delete(fcn);
		}
	}
	rz_analysis_fcn_del(analysis, addr);
	return true;
}

RZ_API int rz_analysis_fcn_del(RzAnalysis *a, ut64 addr) {
	RzAnalysisFunction *fcn;
	RzListIter *iter, *iter_tmp;
	rz_list_foreach_safe (a->fcns, iter, iter_tmp, fcn) {
		RZ_LOG_DEBUG("removing function at %" PFMT64x " %" PFMT64x "\n", fcn->addr, addr);
		if (fcn->addr == addr) {
			rz_analysis_function_delete(fcn);
		}
	}
	return true;
}

RZ_DEPRECATE RZ_API RzAnalysisFunction *rz_analysis_get_fcn_in(RzAnalysis *analysis, ut64 addr, int type) {
	RzList *list = rz_analysis_get_functions_in(analysis, addr);
	RzAnalysisFunction *ret = NULL;
	if (list && !rz_list_empty(list)) {
		if (type == RZ_ANALYSIS_FCN_TYPE_ROOT) {
			RzAnalysisFunction *fcn;
			RzListIter *iter;
			rz_list_foreach (list, iter, fcn) {
				if (fcn->addr == addr) {
					ret = fcn;
					break;
				}
			}
		} else {
			ret = rz_list_first_val(list);
		}
	}
	rz_list_free(list);
	return ret;
}

RZ_DEPRECATE RZ_API RzAnalysisFunction *rz_analysis_get_fcn_in_bounds(RzAnalysis *analysis, ut64 addr, int type) {
	RzAnalysisFunction *fcn, *ret = NULL;
	RzListIter *iter;
	if (type == RZ_ANALYSIS_FCN_TYPE_ROOT) {
		rz_list_foreach (analysis->fcns, iter, fcn) {
			if (addr == fcn->addr) {
				return fcn;
			}
		}
		return NULL;
	}
	rz_list_foreach (analysis->fcns, iter, fcn) {
		if (!type || (fcn && fcn->type & type)) {
			if (rz_analysis_function_contains(fcn, addr)) {
				return fcn;
			}
		}
	}
	return ret;
}

/**
 * \brief Returns function if exists given the \p name
 */
RZ_API RzAnalysisFunction *rz_analysis_get_function_byname(RzAnalysis *a, const char *name) {
	bool found = false;
	RzAnalysisFunction *f = ht_sp_find(a->ht_name_fun, name, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

/* rename RzAnalysisFunctionBB.add() */
RZ_API bool rz_analysis_fcn_add_bb(RzAnalysis *a, RzAnalysisFunction *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail) {
	if (size == 0) {
		RZ_LOG_ERROR("Empty basic block at 0x%08" PFMT64x " (not allowed).\n", addr);
		rz_warn_if_reached();
		return false;
	}
	if (size > a->opt.bb_max_size) {
		RZ_LOG_ERROR("Cannot allocate such big bb of %" PFMT64d " bytes at 0x%08" PFMT64x "\n", (st64)size, addr);
		rz_warn_if_reached();
		return false;
	}

	RzAnalysisBlock *block = rz_analysis_get_block_at(a, addr);
	if (block) {
		rz_analysis_delete_block(block);
		block = NULL;
	}

	block = rz_analysis_create_block(a, addr, size);
	if (!block) {
		return false;
	}

	rz_analysis_block_analyze_ops(block);
	rz_analysis_function_add_block(fcn, block);

	block->jump = jump;
	block->fail = fail;
	rz_analysis_block_unref(block);
	return true;
}

/**
 * \brief Returns the amount of loops located in the \p fcn function
 */
RZ_API ut32 rz_analysis_function_loops(RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	ut32 loops = 0;

	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (bb->jump != UT64_MAX && bb->jump < bb->addr) {
			loops++;
		}
		if (bb->fail != UT64_MAX && bb->fail < bb->addr) {
			loops++;
		}
	}
	return loops;
}

/**
 * \brief Returns cyclomatic complexity of the function
 *
 * It calculated using this formula:
 *
 * CC = E - N + 2P
 * where
 * E is the number of edges of the graph.
 * N is the number of nodes of the graph.
 * P is the number of connected components (exit nodes).
 *
 */
RZ_API ut32 rz_analysis_function_complexity(RzAnalysisFunction *fcn) {
	RzAnalysis *analysis = fcn->analysis;
	ut32 E = 0, N = 0, P = 0;
	RzAnalysisBlock *bb;

	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		N++; // nodes
		if (!analysis && bb->jump == UT64_MAX && bb->fail != UT64_MAX) {
			RZ_LOG_DEBUG("invalid bb jump/fail pair at 0x%08" PFMT64x " (fcn 0x%08" PFMT64x "\n", bb->addr, fcn->addr);
		}
		if (bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			P++; // exit nodes
		} else {
			E++; // edges
			if (bb->fail != UT64_MAX) {
				E++;
			}
		}
		if (bb->switch_op && bb->switch_op->cases) {
			E += rz_list_length(bb->switch_op->cases);
		}
	}

	return E - N + (2 * P);
}

/**
 * \brief Gets the RzCallable's arg count for the given function
 *
 * Derives the RzCallable type for the given function,
 * saves it if it exists, and returns its arguments count.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API int rz_analysis_function_get_arg_count(RzAnalysis *analysis, RzAnalysisFunction *f) {
	RzCallable *callable = rz_analysis_function_derive_type(analysis, f);
	if (!callable) {
		return -1;
	}
	rz_type_func_save(analysis->typedb, callable);
	return rz_pvector_len(callable->args);
}

// tfj and afsj call this function
RZ_API RZ_OWN char *rz_analysis_function_get_json(RzAnalysisFunction *function) {
	char *tmp = NULL;
	RzAnalysis *a = function->analysis;
	PJ *pj = pj_new();
	char *ret_type_str = NULL;
	RzType *ret_type = rz_type_func_ret(a->typedb, function->name);
	if (ret_type) {
		ret_type_str = rz_type_as_string(a->typedb, ret_type);
	}
	int argc = rz_analysis_function_get_arg_count(a, function);

	pj_o(pj);
	pj_ks(pj, "name", function->name);
	const bool no_return = rz_analysis_noreturn_at_addr(a, function->addr);
	pj_kb(pj, "noreturn", no_return);
	pj_ks(pj, "ret", ret_type_str ? ret_type_str : "void");
	if (function->cc) {
		pj_ks(pj, "cc", function->cc);
	}
	pj_k(pj, "args");
	pj_a(pj);
	for (int i = 0; i < argc; i++) {
		pj_o(pj);
		const char *arg_name = rz_type_func_args_name(a->typedb, function->name, i);
		RzType *arg_type = rz_type_func_args_type(a->typedb, function->name, i);
		tmp = rz_type_as_string(a->typedb, arg_type);
		pj_ks(pj, "name", arg_name);
		pj_ks(pj, "type", tmp);
		free(tmp);
		tmp = rz_str_newf("A%d", i);
		const char *cc_arg = rz_reg_get_name(a->reg, rz_reg_get_name_idx(tmp));
		free(tmp);
		if (cc_arg) {
			pj_ks(pj, "cc", cc_arg);
		}
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);
	free(ret_type_str);
	return pj_drain(pj);
}

/**
 * \brief Returns type signature (prototype) of the function
 *
 * If the type is presented in the type database it uses it,
 * otherwise it tries to derive the type from the analysis data
 */
RZ_API RZ_OWN char *rz_analysis_function_get_signature(RZ_NONNULL RzAnalysisFunction *function) {
	rz_return_val_if_fail(function, NULL);
	RzAnalysis *a = function->analysis;

	RzCallable *callable = rz_analysis_function_derive_type(a, function);
	if (!callable) {
		return NULL;
	}
	char *signature = rz_type_callable_as_string(a->typedb, callable);
	rz_type_callable_free(callable);
	char *result = rz_str_newf("%s;", signature);
	free(signature);
	return result;
}

/**
 * \brief Sets the RzCallable type for the given function
 *
 * Overwrites all arguments, the return type, calling convention and noreturn property of \p f to
 * match the contents of \p callable. This is done according to the calling convention in
 * \p callable, or \p f if it is not defined in \p callable.
 *
 * \param a RzAnalysis instance
 * \param f Function to update
 * \param callable A function type to apply to \p f
 */
RZ_API void rz_analysis_function_set_type(RzAnalysis *a, RZ_NONNULL RzAnalysisFunction *f, RZ_NONNULL RzCallable *callable) {
	rz_return_if_fail(a && f && callable);
	// Set the cc first, it will be used further down.
	if (callable->cc) {
		f->cc = rz_str_constpool_get(&a->constpool, callable->cc);
	}
	// All args will be overwritten
	rz_analysis_function_delete_arg_vars(f);
	RzStackAddr stack_off = rz_type_db_pointer_size(a->typedb) / 8; // return val
	if (f->cc) {
		stack_off += rz_analysis_cc_shadow_store(a, f->cc);
	}
	size_t args_count = rz_pvector_len(callable->args);
	for (size_t index = 0; index < args_count; index++) {
		RzCallableArg *arg = rz_pvector_at(callable->args, index);
		if (!arg || !arg->type) {
			continue;
		}
		RzAnalysisVarStorage stor = { 0 };
		const char *loc = f->cc ? rz_analysis_cc_arg(a, f->cc, index) : "stack";
		if (!loc || rz_str_startswith(loc, "stack")) {
			stor.type = RZ_ANALYSIS_VAR_STORAGE_STACK;
			stor.stack_off = stack_off;
			stack_off += (rz_type_db_get_bitsize(a->typedb, arg->type) + 7) / 8;
		} else {
			stor.type = RZ_ANALYSIS_VAR_STORAGE_REG;
			stor.reg = rz_str_constpool_get(&a->constpool, loc);
		}
		rz_analysis_function_set_var(f, &stor, arg->type, 0, arg->name);
	}
	f->is_noreturn = callable->noret;
	rz_type_free(f->ret_type);
	f->ret_type = callable->ret ? rz_type_clone(callable->ret) : NULL;
}

/**
 * \brief Parses the function type and sets it for the given function
 *
 * Checks if the type is defined already for this function, if yes -
 * it removes the existing one and parses the one defined in the signature.
 * The function type should be valid C syntax supplied with name, like
 * int *func(char arg0, const int *arg1, float foo[]);
 *
 * \param a RzAnalysis instance
 * \param f Function to update
 * \param sig A function type ("signature" or "prototype")
 */
RZ_API bool rz_analysis_function_set_type_str(RzAnalysis *a, RZ_NONNULL RzAnalysisFunction *f, RZ_NONNULL const char *sig) {
	rz_return_val_if_fail(a && f && sig, false);
	char *error_msg = NULL;
	// At first we should check if the type is already presented in the types database
	// and remove it if exists
	if (rz_type_func_exist(a->typedb, f->name)) {
		rz_type_func_delete(a->typedb, f->name);
	}
	// Then we create a new one by parsing the string
	RzType *result = rz_type_parse_string_declaration_single(a->typedb->parser, sig, &error_msg);
	if (!result) {
		if (error_msg) {
			RZ_LOG_ERROR("%s", error_msg);
			free(error_msg);
		}
		RZ_LOG_ERROR("Cannot parse callable type\n");
		return false;
	}
	// Parsed result should be RzCallable
	if (result->kind != RZ_TYPE_KIND_CALLABLE) {
		RZ_LOG_ERROR("Parsed function signature should be RzCallable\n");
		return false;
	}
	if (!result->callable) {
		RZ_LOG_ERROR("Parsed function signature should not be NULL\n");
		return false;
	}
	rz_analysis_function_set_type(a, f, result->callable);
	return true;
}

/**
 * \brief Sets the calling convention for the given function
 *
 * Sets the calling convention (\p cc) for the function \p fcn. The calling convention
 * must exist in the analysis instance. If \p cc is NULL or empty, the calling convention
 * is cleared (set to NULL).
 *
 * \param analysis RzAnalysis instance
 * \param fcn Function to update
 * \param cc Calling convention name, or NULL to clear
 * \return true on success, false if the calling convention doesn't exist
 */
RZ_API bool rz_analysis_function_set_cc(RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NULLABLE const char *cc) {
	rz_return_val_if_fail(analysis && fcn, false);

	if (RZ_STR_ISEMPTY(cc)) {
		fcn->cc = NULL;
		return true;
	}
	if (!rz_analysis_cc_exist(analysis, cc)) {
		RZ_LOG_ERROR("analysis: calling convention '%s' does not exist\n", cc);
		return false;
	}
	fcn->cc = rz_str_constpool_get(&analysis->constpool, cc);
	return true;
}

RZ_API RzAnalysisFunction *rz_analysis_fcn_next(RzAnalysis *analysis, ut64 addr) {
	RzAnalysisFunction *fcni;
	RzListIter *iter;
	RzAnalysisFunction *closer = NULL;
	rz_list_foreach (analysis->fcns, iter, fcni) {
		// if (fcni->addr == addr)
		if (fcni->addr > addr && (!closer || fcni->addr < closer->addr)) {
			closer = fcni;
		}
	}
	return closer;
}

RZ_API ut32 rz_analysis_fcn_count(RzAnalysis *analysis, ut64 from, ut64 to) {
	ut32 n = 0;
	RzAnalysisFunction *fcni;
	RzListIter *iter;
	rz_list_foreach (analysis->fcns, iter, fcni) {
		if (fcni->addr >= from && fcni->addr < to) {
			n++;
		}
	}
	return n;
}

/* return the basic block in fcn found at the given address.
 * NULL is returned if such basic block doesn't exist. */
RZ_API RzAnalysisBlock *rz_analysis_fcn_bbget_in(const RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr) {
	rz_return_val_if_fail(analysis && fcn, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	bool can_jmpmid = false;
	if (analysis->cur->arch) {
		bool is_x86 = !strncmp(analysis->cur->arch, "x86", 3);
		bool is_dalvik = !strncmp(analysis->cur->arch, "dalvik", 6);
		can_jmpmid = analysis->opt.jmpmid && (is_dalvik || is_x86);
	}
	RzAnalysisBlock *bb;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (addr >= bb->addr && addr < (bb->addr + bb->size) && (!can_jmpmid || rz_analysis_block_op_starts_at(bb, addr))) {
			return bb;
		}
	}
	return NULL;
}

RZ_API RzAnalysisBlock *rz_analysis_fcn_bbget_at(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr) {
	rz_return_val_if_fail(fcn && addr != UT64_MAX, NULL);
	RzAnalysisBlock *b = rz_analysis_get_block_at(analysis, addr);
	if (b) {
		return b;
	}
	RzAnalysisBlock *bb;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (addr == bb->addr) {
			return bb;
		}
	}
	return NULL;
}

// compute the cyclomatic cost
RZ_API ut32 rz_analysis_function_cost(RzAnalysisFunction *fcn) {
	RzAnalysisBlock *bb;
	RzAnalysisOp op = { 0 };
	ut32 totalCycles = 0;
	if (!fcn) {
		return 0;
	}
	RzAnalysis *analysis = fcn->analysis;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc(bb->size);
		if (!buf) {
			continue;
		}
		(void)analysis->iob.read_at(analysis->iob.io, bb->addr, (ut8 *)buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			rz_analysis_op_init(&op);
			(void)rz_analysis_op(analysis, &op, at, buf + idx, bb->size - idx, RZ_ANALYSIS_OP_MASK_BASIC);
			if (op.size < 1) {
				op.size = 1;
			}
			idx += op.size;
			at += op.size;
			totalCycles += op.cycles;
			rz_analysis_op_fini(&op);
		}
		free(buf);
	}
	return totalCycles;
}

RZ_API ut32 rz_analysis_function_count_edges(const RzAnalysisFunction *fcn, RZ_NULLABLE int *ebbs) {
	rz_return_val_if_fail(fcn, 0);
	RzAnalysisBlock *bb;
	ut32 edges = 0;
	if (ebbs) {
		*ebbs = 0;
	}
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		if (ebbs && bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			*ebbs = *ebbs + 1;
		} else {
			if (bb->jump != UT64_MAX) {
				edges++;
			}
			if (bb->fail != UT64_MAX) {
				edges++;
			}
		}
	}
	return edges;
}

/**
 * \brief Returns if the function pure - accesses any external resources or not
 */
RZ_API bool rz_analysis_function_purity(RzAnalysisFunction *fcn) {
	if (fcn->has_changed) {
		HtUP *ht = ht_up_new(NULL, NULL);
		if (ht) {
			check_purity(ht, fcn);
			ht_up_free(ht);
		}
	}
	return fcn->is_pure;
}

static bool can_affect_bp(RzAnalysis *analysis, RzAnalysisOp *op) {
	RzAnalysisValue *dst = op->dst;
	RzAnalysisValue *src = op->src[0];
	const char *opdreg = (dst && dst->reg) ? dst->reg->name : NULL;
	const char *opsreg = (src && src->reg) ? src->reg->name : NULL;
	const char *bp_name = analysis->reg->name[RZ_REG_NAME_BP];
	bool is_bp_dst = opdreg && !dst->memref && !strcmp(opdreg, bp_name);
	bool is_bp_src = opsreg && !src->memref && !strcmp(opsreg, bp_name);
	if (op->type == RZ_ANALYSIS_OP_TYPE_XCHG) {
		return is_bp_src || is_bp_dst;
	}
	return is_bp_dst;
}

/*
 * This function checks whether any operation in a given function may change bp (excluding "mov bp, sp"
 * and "pop bp" at the end).
 */
static void __analysis_fcn_check_bp_use(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	if (!fcn) {
		return;
	}
	RzAnalysisOp op = { 0 };
	RzAnalysisBlock *bb;
	void **it;
	rz_pvector_foreach (fcn->bbs, it) {
		bb = (RzAnalysisBlock *)*it;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc(bb->size);
		if (!buf) {
			continue;
		}
		(void)analysis->iob.read_at(analysis->iob.io, bb->addr, (ut8 *)buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			rz_analysis_op_init(&op);
			rz_analysis_op(analysis, &op, at, buf + idx, bb->size - idx, RZ_ANALYSIS_OP_MASK_VAL);
			if (op.size < 1) {
				op.size = 1;
			}
			switch (op.type) {
			case RZ_ANALYSIS_OP_TYPE_MOV:
			case RZ_ANALYSIS_OP_TYPE_LEA:
				if (can_affect_bp(analysis, &op) && op.src[0] && op.src[0]->reg && op.src[0]->reg->name && strcmp(op.src[0]->reg->name, analysis->reg->name[RZ_REG_NAME_SP])) {
					fcn->bp_frame = false;
					rz_analysis_op_fini(&op);
					free(buf);
					return;
				}
				break;
			case RZ_ANALYSIS_OP_TYPE_ADD:
			case RZ_ANALYSIS_OP_TYPE_AND:
			case RZ_ANALYSIS_OP_TYPE_CMOV:
			case RZ_ANALYSIS_OP_TYPE_NOT:
			case RZ_ANALYSIS_OP_TYPE_OR:
			case RZ_ANALYSIS_OP_TYPE_ROL:
			case RZ_ANALYSIS_OP_TYPE_ROR:
			case RZ_ANALYSIS_OP_TYPE_SAL:
			case RZ_ANALYSIS_OP_TYPE_SAR:
			case RZ_ANALYSIS_OP_TYPE_SHR:
			case RZ_ANALYSIS_OP_TYPE_SUB:
			case RZ_ANALYSIS_OP_TYPE_XOR:
			case RZ_ANALYSIS_OP_TYPE_SHL:
			case RZ_ANALYSIS_OP_TYPE_XCHG:
				if (can_affect_bp(analysis, &op)) {
					fcn->bp_frame = false;
					rz_analysis_op_fini(&op);
					free(buf);
					return;
				}
				break;
			default:
				break;
			}
			idx += op.size;
			at += op.size;
			rz_analysis_op_fini(&op);
		}
		free(buf);
	}
}

/**
 *  \brief This function checks whether any operation in a given function may change BP
 *
 *  Excludes pattern like "mov bp, sp" and "pop sp, bp" for saving stack pointer value
 */
RZ_API void rz_analysis_function_check_bp_use(RzAnalysisFunction *fcn) {
	rz_return_if_fail(fcn);
	__analysis_fcn_check_bp_use(fcn->analysis, fcn);
}

typedef struct {
	RzAnalysisFunction *fcn;
	HtUP *visited;
} BlockRecurseCtx;

static bool mark_as_visited(RzAnalysisBlock *bb, void *user) {
	BlockRecurseCtx *ctx = user;
	ht_up_insert(ctx->visited, bb->addr, NULL);
	return true;
}

static bool analize_addr_cb(ut64 addr, void *user) {
	BlockRecurseCtx *ctx = user;
	RzAnalysis *analysis = ctx->fcn->analysis;
	RzAnalysisBlock *existing_bb = rz_analysis_get_block_at(analysis, addr);
	if (!existing_bb || !rz_pvector_contains(ctx->fcn->bbs, existing_bb)) {
		size_t old_len = rz_pvector_len(ctx->fcn->bbs);
		analyze_function_locally(ctx->fcn->analysis, ctx->fcn, addr);
		if (old_len != rz_pvector_len(ctx->fcn->bbs)) {
			rz_analysis_block_recurse(rz_analysis_get_block_at(analysis, addr), mark_as_visited, user);
		}
	}
	ht_up_insert(ctx->visited, addr, NULL);
	return true;
}

static bool analize_descendents(RzAnalysisBlock *bb, void *user) {
	return rz_analysis_block_successor_addrs_foreach(bb, analize_addr_cb, user);
}

static void update_vars_analysis(RzAnalysisFunction *fcn, RzAnalysisBlock *block, int align, ut64 from, ut64 to) {
	RzAnalysis *analysis = fcn->analysis;
	ut64 cur_addr;
	int opsz;
	from = align ? from - (from % align) : from;
	to = align ? RZ_ROUND(to, align) : to;
	if (UT64_SUB_OVFCHK(to, from)) {
		return;
	}
	ut64 len = to - from;
	ut8 *buf = malloc(len);
	if (!buf) {
		return;
	}
	if (analysis->iob.read_at(analysis->iob.io, from, buf, len) < len) {
		return;
	}
	RzAnalysisOp op = { 0 };
	for (cur_addr = from; cur_addr < to; cur_addr += opsz, len -= opsz) {
		rz_analysis_op_init(&op);
		int ret = rz_analysis_op(analysis->coreb.core, &op, cur_addr, buf, len, RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_VAL);
		if (ret < 1 || op.size < 1) {
			rz_analysis_op_fini(&op);
			break;
		}
		opsz = op.size;
		rz_analysis_extract_vars(analysis, fcn, &op, rz_analysis_block_get_sp_at(block, cur_addr));
		rz_analysis_op_fini(&op);
	}
	free(buf);
}

// Clear function variable acesses inside in a block
static void clear_bb_vars(RzAnalysisFunction *fcn, RzAnalysisBlock *bb, ut64 from, ut64 to) {
	int i;
	if (rz_pvector_empty(&fcn->vars)) {
		return;
	}
	for (i = 0; i < bb->ninstr; i++) {
		const ut64 addr = rz_analysis_block_get_op_addr(bb, i);
		if (addr < from) {
			continue;
		}
		if (addr >= to || addr == UT64_MAX) {
			break;
		}
		RzPVector *vars = rz_analysis_function_get_vars_used_at(fcn, addr);
		if (vars) {
			RzPVector *vars_clone = rz_pvector_clone(vars);
			void **v;
			rz_pvector_foreach (vars_clone, v) {
				rz_analysis_var_remove_access_at((RzAnalysisVar *)*v, addr);
			}
			rz_pvector_clear(vars_clone);
		}
	}
}

static void update_analysis(RzAnalysis *analysis, RzList /*<RzAnalysisFunction *>*/ *fcns, HtUP *reachable) {
	RzListIter *it;
	RzAnalysisFunction *fcn;
	bool old_jmpmid = analysis->opt.jmpmid;
	analysis->opt.jmpmid = true;
	rz_list_foreach (fcns, it, fcn) {
		// Recurse through blocks of function, mark reachable,
		// analyze edges that don't have a block
		RzAnalysisBlock *bb = rz_analysis_get_block_at(analysis, fcn->addr);
		if (!bb) {
			analyze_function_locally(analysis, fcn, fcn->addr);
			bb = rz_analysis_get_block_at(analysis, fcn->addr);
			if (!bb) {
				continue;
			}
		}
		HtUP *ht = ht_up_new(NULL, NULL);
		ht_up_insert(ht, bb->addr, NULL);
		BlockRecurseCtx ctx = { fcn, ht };
		rz_analysis_block_recurse(bb, analize_descendents, &ctx);

		// in this loop we remove non-reachable basic blocks and since
		// we modify the pvector size we cannot loop normally.
		size_t count = rz_pvector_len(fcn->bbs);
		for (size_t i = 0; i < count;) {
			bb = (RzAnalysisBlock *)rz_pvector_at(fcn->bbs, i);
			if (ht_up_find_kv(ht, bb->addr, NULL)) {
				i++;
				continue;
			}
			HtUP *o_visited = ht_up_find(reachable, fcn->addr, NULL);
			if (!ht_up_find_kv(o_visited, bb->addr, NULL)) {
				// Avoid removing blocks that were already not reachable
				i++;
				continue;
			}
			fcn->ninstr -= bb->ninstr;
			rz_analysis_function_remove_block(fcn, bb);
			count = rz_pvector_len(fcn->bbs);
		}

		RzPVector *dup_bbs = rz_pvector_clone(fcn->bbs);
		rz_analysis_block_automerge(dup_bbs);
		rz_analysis_function_delete_unused_vars(fcn);
		rz_pvector_free(dup_bbs);
	}
	analysis->opt.jmpmid = old_jmpmid;
}

static void calc_reachable_and_remove_block(RzList /*<RzAnalysisFunction *>*/ *fcns, RzAnalysisFunction *fcn, RzAnalysisBlock *bb, HtUP *reachable) {
	clear_bb_vars(fcn, bb, bb->addr, bb->addr + bb->size);
	if (!rz_list_contains(fcns, fcn)) {
		rz_list_append(fcns, fcn);

		// Calculate reachable blocks from the start of function
		HtUP *ht = ht_up_new(NULL, NULL);
		BlockRecurseCtx ctx = { fcn, ht };
		rz_analysis_block_recurse(rz_analysis_get_block_at(fcn->analysis, fcn->addr), mark_as_visited, &ctx);
		ht_up_insert(reachable, fcn->addr, ht);
	}
	fcn->ninstr -= bb->ninstr;
	rz_analysis_function_remove_block(fcn, bb);
}

RZ_API void rz_analysis_update_analysis_range(RzAnalysis *analysis, ut64 addr, int size) {
	rz_return_if_fail(analysis);
	RzListIter *it, *it2, *tmp;
	RzAnalysisBlock *bb;
	RzAnalysisFunction *fcn;
	RzList *blocks = rz_analysis_get_blocks_intersect(analysis, addr, size);
	if (rz_list_empty(blocks)) {
		rz_list_free(blocks);
		return;
	}
	RzList *fcns = rz_list_new();
	HtUP *reachable = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);
	const int align = rz_analysis_archinfo(analysis, RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN);
	const ut64 end_write = addr + size;

	rz_list_foreach (blocks, it, bb) {
		if (!rz_analysis_block_was_modified(bb)) {
			continue;
		}
		rz_list_foreach_safe (bb->fcns, it2, tmp, fcn) {
			if (align > 1) {
				if ((end_write < rz_analysis_block_get_op_addr(bb, bb->ninstr - 1)) && (!bb->switch_op || end_write < bb->switch_op->addr)) {
					// Special case when instructions are aligned and we don't
					// need to worry about a write messing with the jump instructions
					clear_bb_vars(fcn, bb, addr > bb->addr ? addr : bb->addr, end_write);
					update_vars_analysis(fcn, bb, align, addr > bb->addr ? addr : bb->addr, end_write);
					rz_analysis_function_delete_unused_vars(fcn);
					continue;
				}
			}
			calc_reachable_and_remove_block(fcns, fcn, bb, reachable);
		}
	}
	rz_list_free(blocks); // This will call rz_analysis_block_unref to actually remove blocks from RzAnalysis
	update_analysis(analysis, fcns, reachable);
	ht_up_free(reachable);
	rz_list_free(fcns);
}

RZ_API void rz_analysis_function_update_analysis(RzAnalysisFunction *fcn) {
	rz_return_if_fail(fcn);
	RzListIter *it, *tmp;
	RzAnalysisBlock *bb;
	RzAnalysisFunction *f;
	RzList *fcns = rz_list_new();
	HtUP *reachable = ht_up_new(NULL, (HtUPFreeValue)ht_up_free);

	// in this loop we modify the pvector size we cannot loop normally.
	size_t count = rz_pvector_len(fcn->bbs);
	for (size_t i = 0; i < count;) {
		bb = (RzAnalysisBlock *)rz_pvector_at(fcn->bbs, i);
		if (!rz_analysis_block_was_modified(bb)) {
			i++;
			continue;
		}
		rz_list_foreach_safe (bb->fcns, it, tmp, f) {
			calc_reachable_and_remove_block(fcns, f, bb, reachable);
		}
		count = rz_pvector_len(fcn->bbs);
	}
	update_analysis(fcn->analysis, fcns, reachable);
	ht_up_free(reachable);
	rz_list_free(fcns);
}

/**
 * \brief Returns vector of all function arguments
 *
 * \param a RzAnalysis instance
 * \param fcn Function
 */
RZ_API RZ_OWN RzPVector /*<RzAnalysisVar *>*/ *rz_analysis_function_args(RzAnalysis *a, RzAnalysisFunction *fcn) {
	if (!a || !fcn) {
		return NULL;
	}
	RzPVector *tmp = rz_pvector_new(NULL);
	if (!tmp) {
		return NULL;
	}
	RzAnalysisVar *var;
	void **it;
	int rarg_idx = 0;
	// Resort the pvector to order "reg_arg - stack_arg"
	rz_pvector_foreach (&fcn->vars, it) {
		var = *it;
		if (var->storage.type == RZ_ANALYSIS_VAR_STORAGE_REG) {
			rz_pvector_insert(tmp, rarg_idx++, var);
		} else {
			rz_pvector_push(tmp, var);
		}
	}

	RzPVector *args = rz_pvector_new(NULL);
	if (!args) {
		rz_pvector_free(tmp);
		return NULL;
	}
	rz_pvector_foreach (tmp, it) {
		var = *it;
		if (rz_analysis_var_is_arg(var)) {
			int argnum;
			if (var->storage.type == RZ_ANALYSIS_VAR_STORAGE_REG) {
				argnum = rz_analysis_var_get_argnum(var);
				if (argnum < 0) {
					RZ_LOG_INFO("%s : arg \"%s\" has wrong position: %d\n", fcn->name, var->name, argnum);
					continue;
				}
			} else {
				argnum = fcn->argnum;
			}
			// pvector api is a bit ugly here, essentially we make a (possibly sparse) array
			// where each var is assigned at its argnum
			if (argnum >= rz_pvector_len(args)) {
				if (!rz_pvector_reserve(args, argnum + 1)) {
					goto cleanup;
				}
				while (argnum >= rz_pvector_len(args)) {
					rz_pvector_push(args, NULL);
				}
			}
			rz_pvector_set(args, argnum, var);
			fcn->argnum++;
		}
	}
cleanup:
	rz_pvector_free(tmp);
	return args;
}

/**
 * \brief Returns vector of all function variables without arguments
 *
 * \param a RzAnalysis instance
 * \param fcn Function
 */
RZ_API RZ_OWN RzPVector /*<RzAnalysisVar *>*/ *rz_analysis_function_vars(RZ_NONNULL RzAnalysis *a, RZ_NONNULL RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(a && fcn, NULL);
	RzAnalysisVar *var;
	void **it;
	RzPVector *vars = rz_pvector_new(NULL);
	if (!vars) {
		return NULL;
	}
	rz_pvector_foreach (&fcn->vars, it) {
		var = *it;
		if (!rz_analysis_var_is_arg(var)) {
			rz_pvector_push(vars, var);
		}
	}
	return vars;
}

/**
 * \brief Gets the argument given its index
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_get_arg_idx(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *f, size_t index) {
	rz_return_val_if_fail(analysis && f, NULL);
	int argnum = rz_analysis_function_get_arg_count(analysis, f);
	if (argnum < 1) {
		return NULL;
	}
	if (index >= argnum) {
		RZ_LOG_VERBOSE("Function %s has less arguments (%d) than requested (%zu)\n",
			f->name, argnum, index);
	}
	RzPVector *args = rz_analysis_function_args(analysis, f);
	if (!args) {
		RZ_LOG_VERBOSE("Function %s has no arguments\n", f->name);
		return NULL;
	}
	if (rz_pvector_len(args) < index) {
		RZ_LOG_VERBOSE("Function %s has less arguments (%zu) than requested (%zu)\n",
			f->name, rz_pvector_len(args), index);
		return NULL;
	}
	return rz_pvector_at(args, index);
}

static int typecmp(const void *a, const void *b, void *user) {
	const RzType *t1 = a;
	const RzType *t2 = b;
	return !rz_types_equal(t1, t2);
}

/**
 * \brief Returns vector of all unique types used in a function
 *
 * Accounts for all types used in both arguments and variables, excluding return value type
 */
RZ_API RZ_OWN RzList /*<RzType *>*/ *rz_analysis_types_from_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzList *type_used = rz_list_new();
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		rz_list_append(type_used, var->type);
	}
	RzList *uniq = rz_list_uniq(type_used, typecmp, NULL);
	rz_list_free(type_used);
	return uniq;
}

/**
 * \brief Clones the RzCallable type for the given function
 *
 * Searches the types database for the given function and
 * returns a clone of the RzCallable type.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_OWN RzCallable *rz_analysis_function_clone_type(RzAnalysis *analysis, const RzAnalysisFunction *f) {
	rz_return_val_if_fail(analysis && f, NULL);
	// Check first if there is a match with some pre-existing RzCallable type in the database
	char *shortname = rz_analysis_function_name_guess(analysis->typedb, f->name);
	if (!shortname) {
		shortname = rz_str_dup(f->name);
	}
	// At this point the `callable` pointer is *borrowed*
	RzCallable *callable = rz_type_func_get(analysis->typedb, shortname);
	free(shortname);
	if (callable) {
		// TODO: Decide what to do if there is a mismatch between type
		// stored in the RzTypeDB database and the actual type of the
		// RzAnalysisFunction
		return rz_type_callable_clone(callable);
	}
	return NULL;
}

/**
 * \brief Creates the RzCallable type for the given function
 *
 * Creates the RzCallable type for the given function
 * by searching in the types database and returning it.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_OWN RzCallable *rz_analysis_function_create_type(RzAnalysis *analysis, RzAnalysisFunction *f) {
	// TODO: Figure out if we should use shortname or a fullname here
	RzCallable *callable = rz_type_func_new(analysis->typedb, f->name, NULL);
	if (!callable) {
		return NULL;
	}
	return callable;
}

/**
 * \brief Sets the RzCallable return type for the given function
 *
 * Checks if the given function's return type exists
 * and adds it to RzCallable by cloning it.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 * \param callable A function type
 */
RZ_API void rz_analysis_function_derive_return_type(RzAnalysisFunction *f, RzCallable **callable) {
	if (f->ret_type) {
		(*callable)->ret = rz_type_clone(f->ret_type);
	}
}

/**
 * \brief Sets the RzCallable args for the given function
 *
 * Gets the given function's arguments (names and types)
 * and if it has none it simply returns. Otherwise, it
 * creates RzCallableArgs and adds them to RzCallable.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 * \param callable A function type
 */
RZ_API bool rz_analysis_function_derive_args(RzAnalysis *analysis, RzAnalysisFunction *f, RzCallable **callable) {
	RzPVector *args = rz_analysis_function_args(analysis, f);
	if (!args || rz_pvector_empty(args)) {
		rz_pvector_free(args);
		return true;
	}
	void **it;
	rz_pvector_foreach (args, it) {
		RzAnalysisVar *var = *it;
		if (!var) {
			// TODO: maybe create a stub void arg here?
			continue;
		}
		RzType *cloned_type = rz_type_clone(var->type);
		if (!cloned_type) {
			rz_pvector_free(args);
			rz_type_callable_free(*callable);
			RZ_LOG_ERROR("Cannot parse function's argument type\n");
			return false;
		}
		RzCallableArg *arg = rz_type_callable_arg_new(analysis->typedb, var->name, cloned_type);
		if (!arg) {
			rz_pvector_free(args);
			rz_type_callable_free(*callable);
			RZ_LOG_ERROR("Cannot create callable argument\n");
			return false;
		}
		rz_type_callable_arg_add(*callable, arg);
	}
	rz_pvector_free(args);
	return true;
}

/**
 * \brief Derives the RzCallable type for the given function
 *
 * Checks if the type is defined already for this function, if yes -
 * it returns pointer to the one stored in the types database.
 * If not - it creates a new RzCallable instance based on the function name,
 * its arguments' names and types.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_OWN RzCallable *rz_analysis_function_derive_type(RzAnalysis *analysis, RzAnalysisFunction *f) {
	RzCallable *callable = rz_analysis_function_clone_type(analysis, f);
	if (!callable) {
		// If there is no match - create a new one.
		callable = rz_analysis_function_create_type(analysis, f);
		if (!callable) {
			return NULL;
		}
		// Derive retvar and args from that function
		rz_analysis_function_derive_return_type(f, &callable);
		if (!rz_analysis_function_derive_args(analysis, f, &callable)) {
			return NULL;
		}
	}
	return callable;
}

/**
 * \brief Determines if the given function is a memory allocating function (malloc, calloc etc.).
 *
 * The current methods of detection (tested in order):
 * - Name matches regex ".*\.([mc]|(re))?alloc.*"
 *
 * \param fcn The function to test.
 *
 * \return true If the function \p fcn is considered a memory allocating.
 * \return false Otherwise.
 */
RZ_API bool rz_analysis_function_is_malloc(const RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(fcn, false);
	// TODO We need more metrics here. Just the name is pretty naive.
	// E.g. we should compare it to signatures and other characterisitics.
	return rz_regex_contains(".*\\.([mc]|(re))?alloc.*", fcn->name, RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT);
}
