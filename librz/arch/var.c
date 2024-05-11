// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2010-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_list.h>

#define ACCESS_CMP(x, y) ((st64)((ut64)(x) - (ut64)((RzAnalysisVarAccess *)y)->offset))

/**
 * \brief Compare two RzAnalysisVarAccess objects.
 * \param a RzAnalysisVarStorage object.
 * \param b RzAnalysisVarStorage object.
 * \return 0 if equal, negative if a < b, positive if a > b.
 */
RZ_API int rz_analysis_var_storage_cmp(
	RZ_NONNULL const RzAnalysisVarStorage *a,
	RZ_NONNULL const RzAnalysisVarStorage *b) {
	rz_return_val_if_fail(a && b, 0);
	if (a->type != b->type) {
		return -(int)a->type + (int)b->type;
	}
	switch (a->type) {
	case RZ_ANALYSIS_VAR_STORAGE_REG:
		// Hint: this strcmp could be optimized to pointer comparison if we add the requirement that a->reg and b->reg
		// must come from the RzAnalysis.contpool.
		return strcmp(a->reg, b->reg);
	case RZ_ANALYSIS_VAR_STORAGE_STACK:
		return a->stack_off - b->stack_off;
	case RZ_ANALYSIS_VAR_STORAGE_COMPOSITE: {
		RzAnalysisVarStoragePiece *ap = NULL;
		ut32 i = 0;
		rz_vector_enumerate (a->composite, ap, i) {
			RzAnalysisVarStoragePiece *bp = rz_vector_index_ptr(b->composite, i);
			int xcmp = ap->offset_in_bits - bp->offset_in_bits;
			if (xcmp != 0) {
				return xcmp;
			}
			xcmp = ap->size_in_bits - bp->size_in_bits;
			if (xcmp != 0) {
				return xcmp;
			}
			xcmp = rz_analysis_var_storage_cmp(ap->storage, bp->storage);
			if (xcmp != 0) {
				return xcmp;
			}
		}
		return 0;
	}
	case RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING:
		return -1;
	default:
		rz_warn_if_reached();
		return -1;
	}
}

/**
 * \brief Check if two RzAnalysisVarStorage objects are equal.
 * \see rz_analysis_var_storage_cmp
 * \param a RzAnalysisVarStorage object.
 * \param b RzAnalysisVarStorage object.
 * \return true if equal, false otherwise.
 */
RZ_API bool rz_analysis_var_storage_equals(
	RZ_NONNULL const RzAnalysisVarStorage *a,
	RZ_NONNULL const RzAnalysisVarStorage *b) {
	rz_return_val_if_fail(a && b, 0);
	return rz_analysis_var_storage_cmp(a, b) == 0;
}

static const char *var_storage_strings[] = {
	[RZ_ANALYSIS_VAR_STORAGE_REG] = "reg",
	[RZ_ANALYSIS_VAR_STORAGE_STACK] = "stack",
	[RZ_ANALYSIS_VAR_STORAGE_COMPOSITE] = "composite",
	[RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING] = "eval_pending",
};

RZ_API const char *rz_analysis_var_storage_type_to_string(RzAnalysisVarStorageType type) {
	if (type > RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING || type < 0) {
		return NULL;
	}
	return var_storage_strings[type];
}

RZ_API bool rz_analysis_var_storage_type_from_string(
	RZ_NONNULL const char *type_str,
	RZ_NONNULL RZ_BORROW RZ_OUT RzAnalysisVarStorageType *type) {
	rz_return_val_if_fail(type_str && type, false);
	for (int i = 0; i <= RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING; ++i) {
		if (RZ_STR_EQ(type_str, var_storage_strings[i])) {
			*type = i;
			return true;
		}
	}
	return false;
}

static void strbuf_append_sign_hex(RzStrBuf *sb, st64 x) {
	const char sign = x >= 0 ? '+' : '-';
	rz_strbuf_appendf(sb, " %c 0x%" PFMT64x, sign, RZ_ABS(x));
}

RZ_API void rz_analysis_var_storage_dump(
	RZ_NONNULL RZ_BORROW RzAnalysis *a,
	RZ_NONNULL RZ_BORROW RZ_OUT RzStrBuf *sb,
	RZ_NULLABLE RZ_BORROW const RzAnalysisVar *var,
	RZ_NONNULL RZ_BORROW const RzAnalysisVarStorage *storage) {
	rz_return_if_fail(a && sb && storage);
	switch (storage->type) {
	case RZ_ANALYSIS_VAR_STORAGE_REG: {
		rz_strbuf_append(sb, storage->reg);
		break;
	}
	case RZ_ANALYSIS_VAR_STORAGE_STACK: {
		rz_strbuf_append(sb, var_storage_strings[storage->type]);
		strbuf_append_sign_hex(sb, storage->stack_off);
		break;
	}
	case RZ_ANALYSIS_VAR_STORAGE_COMPOSITE: {
		rz_strbuf_append(sb, "COMPOSITE");
		break;
	}
	case RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING:
		/// Omit storage information
		if (var && var->origin.kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF &&
			var->origin.dw_var && var->origin.dw_var->location &&
			var->origin.dw_var->location->kind == RzBinDwarfLocationKind_LOCLIST) {
			rz_strbuf_append(sb, "LOCLIST");
		} else {
			rz_strbuf_append(sb, "...");
		}
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_API RZ_OWN char *rz_analysis_var_storage_to_string(
	RZ_NONNULL RZ_BORROW RzAnalysis *a,
	RZ_NULLABLE RZ_BORROW const RzAnalysisVar *var,
	RZ_NONNULL RZ_BORROW const RzAnalysisVarStorage *storage) {
	rz_return_val_if_fail(a && storage, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	rz_analysis_var_storage_dump(a, sb, var, storage);
	return rz_strbuf_drain(sb);
}

static void composite_dump_pj(
	RZ_NONNULL RZ_BORROW RZ_OUT PJ *pj,
	RZ_NONNULL RZ_BORROW const RzAnalysisVar *var,
	RZ_NONNULL RZ_BORROW const RzVector /*<RzAnalysisVarStoragePiece>*/ *composite) {
	pj_a(pj);
	RzAnalysisVarStoragePiece *piece = NULL;
	rz_vector_foreach (composite, piece) {
		pj_o(pj);
		pj_kn(pj, "offset_in_bits", piece->offset_in_bits);
		pj_kn(pj, "size_in_bits", piece->size_in_bits);
		rz_analysis_var_storage_dump_pj(pj, var, piece->storage);
		pj_end(pj);
	}
	pj_end(pj);
}

RZ_API void rz_analysis_var_storage_dump_pj(
	RZ_NONNULL RZ_BORROW RZ_OUT PJ *pj,
	RZ_NONNULL RZ_BORROW const RzAnalysisVar *var,
	RZ_NONNULL RZ_BORROW const RzAnalysisVarStorage *storage) {
	rz_return_if_fail(pj && var && storage);
	const char *type = rz_analysis_var_storage_type_to_string(storage->type);
	pj_k(pj, "storage");
	pj_o(pj);
	pj_ks(pj, "type", rz_str_get_null(type));
	if (type) {
		pj_k(pj, type);
		switch (storage->type) {
		case RZ_ANALYSIS_VAR_STORAGE_STACK:
			pj_N(pj, storage->stack_off);
			break;
		case RZ_ANALYSIS_VAR_STORAGE_REG:
			pj_s(pj, storage->reg);
			break;
		case RZ_ANALYSIS_VAR_STORAGE_COMPOSITE:
			composite_dump_pj(pj, var, storage->composite);
			break;
		case RZ_ANALYSIS_VAR_STORAGE_EVAL_PENDING:
			if (var->origin.kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF) {
				pj_n(pj, var->origin.dw_var->offset);
			} else {
				rz_warn_if_reached();
			}
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	pj_end(pj);
}

/**
 * Ensure that the register name in \p stor comes from the const pool
 */
RZ_API void rz_analysis_var_storage_poolify(
	RZ_NONNULL RZ_BORROW RzAnalysis *analysis,
	RZ_NONNULL RZ_BORROW RZ_OUT RzAnalysisVarStorage *stor) {
	rz_return_if_fail(analysis && stor);
	if (stor->type == RZ_ANALYSIS_VAR_STORAGE_REG) {
		stor->reg = rz_str_constpool_get(&analysis->constpool, stor->reg);
	} else if (stor->type == RZ_ANALYSIS_VAR_STORAGE_COMPOSITE) {
		if (!stor->composite) {
			return;
		}
		RzAnalysisVarStoragePiece *piece = NULL;
		rz_vector_foreach (stor->composite, piece) {
			rz_analysis_var_storage_poolify(analysis, piece->storage);
		}
	}
}

static void RzVector_RzAnalysisVarStoragePiece_fini(void *e, void *u) {
	rz_analysis_var_storage_piece_fini(e);
}

RZ_API void rz_analysis_var_storage_init_composite(RzAnalysisVarStorage *sto) {
	rz_return_if_fail(sto);
	sto->type = RZ_ANALYSIS_VAR_STORAGE_COMPOSITE;
	sto->composite = rz_vector_new(
		sizeof(RzAnalysisVarStoragePiece), RzVector_RzAnalysisVarStoragePiece_fini, NULL);
}

RZ_API void rz_analysis_var_storage_piece_fini(RzAnalysisVarStoragePiece *p) {
	if (!p) {
		return;
	}
	rz_analysis_var_storage_free(p->storage);
}

RZ_API void rz_analysis_var_storage_fini(RzAnalysisVarStorage *sto) {
	if (!sto) {
		return;
	}
	if (sto->type == RZ_ANALYSIS_VAR_STORAGE_COMPOSITE) {
		rz_vector_free(sto->composite);
		sto->composite = NULL;
	}
}

RZ_API void rz_analysis_var_storage_free(RzAnalysisVarStorage *sto) {
	if (!sto) {
		return;
	}
	rz_analysis_var_storage_fini(sto);
	free(sto);
}

static const char *__int_type_from_size(int size) {
	switch (size) {
	case 1: return "int8_t";
	case 2: return "int16_t";
	case 4: return "int32_t";
	case 8: return "int64_t";
	default: return NULL;
	}
}

static RZ_OWN RzType *var_type_default(RzAnalysis *analysis, int size) {
	const char *typestr = __int_type_from_size(size);
	if (!typestr) {
		typestr = __int_type_from_size(analysis->bits);
	}
	if (!typestr) {
		typestr = "int32_t";
	}
	RzType *type = RZ_NEW0(RzType);
	if (!type) {
		return NULL;
	}
	type->kind = RZ_TYPE_KIND_IDENTIFIER;
	type->identifier.name = strdup(typestr);
	if (!type->identifier.name) {
		free(type);
		return NULL;
	}
	type->identifier.kind = RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED;
	return type;
}

/**
 * Given a stack variable, delete all other vars that have their addresses inside of its storage.
 */
RZ_API void rz_analysis_var_resolve_overlaps(RzAnalysisVar *var) {
	// We do not touch variables that are not stack-based
	// or arguments
	if (rz_analysis_var_is_arg(var) || var->storage.type != RZ_ANALYSIS_VAR_STORAGE_STACK) {
		return;
	}
	// We ignore overlaps between atomic types because current
	// detection of the variable default type is suboptimal.
	// The default type is `intXX_t` where XX is the bitness of the platform
	// But some binaries can use variables of the smaller size by default
	// and Rizin doesn't detect bitwidth perfectly. Thus, we skip ATOMIC
	// types in the overlap detection.
	if (rz_type_is_strictly_atomic(var->fcn->analysis->typedb, var->type)) {
		return;
	}
	ut64 varsize = rz_type_db_get_bitsize(var->fcn->analysis->typedb, var->type) / 8;
	if (!varsize) {
		return;
	}
	ut64 varoff = var->storage.stack_off;
	// delete variables which are overlaid by the variable type
	RzPVector *cloned_vars = rz_pvector_clone(&var->fcn->vars);
	cloned_vars->v.free = NULL;
	cloned_vars->v.free_user = NULL;
	void **it;
	rz_pvector_foreach (cloned_vars, it) {
		RzAnalysisVar *other = *it;
		if (!other || other->storage.type != RZ_ANALYSIS_VAR_STORAGE_STACK) {
			continue;
		}
		st64 otheroff = other->storage.stack_off;
		if (strcmp(var->name, other->name) && otheroff > varoff && otheroff < varoff + varsize) {
			rz_analysis_var_delete(other);
		}
	}
	rz_pvector_free(cloned_vars);
}

/**
 * Add or update a variable at the given storage location \p stor.
 * Both the variable's type and name are set according to the parameters given.
 *
 * \param fcn the function which the variable will belong to
 * \param stor storage for the new variable to create, or for identifying an existing one if it exists
 * \param type explicit type to assign to the variable. If NULL, a default type will be selected according to \p size
 * \param size if \p type is NULL, some default type of this size will be assigned to the variable
 * \param name a new name to assign to the variable
 * \return the created or updated variable, or NULL if the operation could not be completed
 */
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_set_var(
	RzAnalysisFunction *fcn,
	RZ_NONNULL RzAnalysisVarStorage *stor,
	RZ_BORROW RZ_NULLABLE const RzType *type,
	int size,
	RZ_NONNULL const char *name) {
	rz_return_val_if_fail(fcn && name, NULL);
	RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
	if (var) {
		if (!rz_analysis_var_storage_equals(&var->storage, stor)) {
			// var name already exists at a different kind+delta
			RZ_LOG_INFO("var name %s already exists at a different kind+delta\n", name);
			return NULL;
		} else {
			// We already have a variable with the same name and storage.
			return NULL;
		}
	}
	var = rz_analysis_function_get_var_at(fcn, stor);
	if (!var) {
		var = rz_analysis_var_new();
		var->fcn = fcn;
		rz_pvector_push(&fcn->vars, var);
	} else {
		RZ_FREE(var->name);
	}

	var->name = strdup(name);
	var->storage = *stor;
	rz_analysis_var_storage_poolify(fcn->analysis, &var->storage);
	if (type) {
		if (var->type != type) {
			rz_type_free(var->type);
			var->type = rz_type_clone(type);
		}
	} else {
		if (!var->type) {
			var->type = var_type_default(fcn->analysis, size);
		}
	}

	rz_analysis_var_resolve_overlaps(var);
	return var;
}

static bool var_clean(RzAnalysisVar *var) {
	void **it;
	RzPVector *remove_plan = rz_pvector_new((RzPVectorFree)rz_analysis_var_delete);
	rz_pvector_foreach (&var->fcn->vars, it) {
		RzAnalysisVar *p = *it;
		if (p->origin.kind == var->origin.kind) {
			if (RZ_STR_EQ(p->name, var->name) && rz_analysis_var_storage_equals(&p->storage, &var->storage)) {
				goto beach;
			}
		} else {
			if (RZ_STR_EQ(p->name, var->name) || rz_analysis_var_storage_equals(&p->storage, &var->storage)) {
				rz_pvector_push(remove_plan, p);
			}
		}
	}
	rz_pvector_free(remove_plan);
	return true;
beach:
	rz_analysis_var_free(var);
	remove_plan->v.free_user = NULL;
	rz_pvector_free(remove_plan);
	return false;
}

/**
 * \brief Add or update a variable \p var to the given function \p fcn.
 *
 * For the variable information in DWARF, there may be some variables whose location information is the same
 * but other information may be completely different.
 * The current approach to this situation is to add all FORMAL_PARAMETER variables first, and then add the others
 * but don't overwrite any already added variables from DWARF. This assumes that for all FORMAL_PARAMETER variables
 * of a function, there is no overlap in their locations.
 *
 * \param fcn the function which the variable will belong to
 * \param var the variable to add or update
 * \return the created or updated variable, or NULL if the operation could not be completed
 */
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_add_var(
	RzAnalysisFunction *fcn, RZ_OWN RzAnalysisVar *var) {
	rz_return_val_if_fail(fcn && var && var->name && var->type, NULL);
	if (!var_clean(var)) {
		return NULL;
	}
	rz_pvector_push(&fcn->vars, var);
	rz_analysis_var_storage_poolify(fcn->analysis, &var->storage);
	rz_analysis_var_resolve_overlaps(var);
	return var;
}

/**
 * \brief Updates the type of the variable
 *
 * Frees the old type of the variable and sets a new one.
 * After that it checks if the size of the variable has changed
 * and tries to resolve overlaps if \p resolve_overlaps is set
 *
 * \param var variable to check
 * \param type new type of the variable
 * \param resolve_overlaps resolves overlaps if set
 */
RZ_API void rz_analysis_var_set_type(RzAnalysisVar *var, RZ_OWN RzType *type, bool resolve_overlaps) {
	rz_return_if_fail(var && type);
	rz_type_free(var->type);
	var->type = type;
	if (resolve_overlaps) {
		rz_analysis_var_resolve_overlaps(var);
	}
}

RZ_API void rz_analysis_var_init(RZ_BORROW RzAnalysisVar *var) {
	rz_return_if_fail(var);
	memset(var, 0, sizeof(RzAnalysisVar));
	rz_vector_init(&var->accesses, sizeof(RzAnalysisVarAccess), NULL, NULL);
	rz_vector_init(&var->constraints, sizeof(RzTypeConstraint), NULL, NULL);
}

RZ_API void rz_analysis_var_fini(RZ_OWN RzAnalysisVar *var) {
	rz_return_if_fail(var);
	rz_analysis_var_clear_accesses(var);
	RZ_FREE_CUSTOM(var->type, rz_type_free);
	rz_vector_fini(&var->constraints);
	RZ_FREE(var->name);
	RZ_FREE(var->comment);
	rz_analysis_var_storage_fini(&var->storage);
}

RZ_API RZ_OWN RzAnalysisVar *rz_analysis_var_new() {
	RzAnalysisVar *var = RZ_NEW(RzAnalysisVar);
	rz_analysis_var_init(var);
	return var;
}

RZ_API void rz_analysis_var_free(RZ_OWN RzAnalysisVar *var) {
	if (!var) {
		return;
	}
	rz_analysis_var_fini(var);
	free(var);
}

RZ_API void rz_analysis_var_delete(RzAnalysisVar *var) {
	rz_return_if_fail(var && var->fcn);
	rz_pvector_remove_data(&var->fcn->vars, var);
	rz_analysis_var_free(var);
}

/**
 * Delete all variables from \p fcn that have the storage type \p stor
 */
RZ_API void rz_analysis_function_delete_vars_by_storage_type(RzAnalysisFunction *fcn, RzAnalysisVarStorageType stor) {
	rz_return_if_fail(fcn);
	size_t i;
	for (i = 0; i < rz_pvector_len(&fcn->vars);) {
		RzAnalysisVar *var = rz_pvector_at(&fcn->vars, i);
		if (var->storage.type == stor) {
			rz_pvector_remove_at(&fcn->vars, i);
			rz_analysis_var_free(var);
			continue;
		}
		i++;
	}
}

/**
 * Delete all variables from \p fcn that are arguments
 */
RZ_API void rz_analysis_function_delete_arg_vars(RzAnalysisFunction *fcn) {
	rz_return_if_fail(fcn);
	size_t i;
	for (i = 0; i < rz_pvector_len(&fcn->vars);) {
		RzAnalysisVar *var = rz_pvector_at(&fcn->vars, i);
		if (rz_analysis_var_is_arg(var)) {
			rz_pvector_remove_at(&fcn->vars, i);
			rz_analysis_var_free(var);
			continue;
		}
		i++;
	}
}

/**
 * Delete all variables from \p fcn function - both arguments and local variables
 */
RZ_API void rz_analysis_function_delete_all_vars(RzAnalysisFunction *fcn) {
	rz_pvector_fini(&fcn->vars);
	fcn->argnum = 0;
}

/**
 * Delete all unused (without any read or write access) variables from \p fcn function
 */
RZ_API void rz_analysis_function_delete_unused_vars(RzAnalysisFunction *fcn) {
	void **v;
	RzPVector *vars_clone = rz_pvector_clone(&fcn->vars);
	rz_pvector_foreach (vars_clone, v) {
		RzAnalysisVar *var = *v;
		if (rz_vector_empty(&var->accesses)) {
			rz_analysis_function_delete_var(fcn, var);
		}
	}
	rz_pvector_free(vars_clone);
}

/**
 * Delete variable \p var from \p fcn
 */
RZ_API void rz_analysis_function_delete_var(RzAnalysisFunction *fcn, RzAnalysisVar *var) {
	rz_return_if_fail(fcn && var);
	rz_pvector_remove_data(&fcn->vars, var);
	rz_analysis_var_free(var);
}

/**
 * Search variable by \p name in \p fcn, return first match
 */
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_get_var_byname(RzAnalysisFunction *fcn, const char *name) {
	rz_return_val_if_fail(fcn && name, NULL);
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (!strcmp(var->name, name)) {
			return var;
		}
	}
	return NULL;
}

/**
 * \return the variable that is located exactly at \p stor, or NULL if no such variable exists
 */
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_get_var_at(RzAnalysisFunction *fcn, RZ_NONNULL RzAnalysisVarStorage *stor) {
	rz_return_val_if_fail(fcn && stor, NULL);
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (rz_analysis_var_storage_equals(&var->storage, stor)) {
			return var;
		}
	}
	return NULL;
}

/**
 * \return the stack variable that is located exactly at \p stack_off, or NULL if no such variable exists.
 */
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_get_stack_var_at(RzAnalysisFunction *fcn, RzStackAddr stack_off) {
	rz_return_val_if_fail(fcn, NULL);
	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_stack(&stor, stack_off);
	return rz_analysis_function_get_var_at(fcn, &stor);
}

/**
 * Get the stack variable with the highest address less than or equal to \p stack_off
 * The variable size (i.e. size of its type) is not checked here, so the given offset might be beyond
 * the returned variable already.
 */
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_get_stack_var_in(RzAnalysisFunction *fcn, RzStackAddr stack_off) {
	rz_return_val_if_fail(fcn, NULL);
	RzAnalysisVar *best = NULL;
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (var->storage.type != RZ_ANALYSIS_VAR_STORAGE_STACK) {
			continue;
		}
		if (var->storage.stack_off == stack_off) {
			// exact match is always the end result
			return var;
		}
		if (var->storage.stack_off > stack_off) {
			continue;
		}
		if (!best || var->storage.stack_off > best->storage.stack_off) {
			best = var;
		}
	}
	return best;
}

/**
 * \return the register variable in \p reg, or NULL if no such variable exists.
 */
RZ_API RZ_BORROW RzAnalysisVar *rz_analysis_function_get_reg_var_at(RzAnalysisFunction *fcn, RZ_NONNULL const char *reg) {
	rz_return_val_if_fail(fcn && reg, NULL);
	RzAnalysisVarStorage stor;
	rz_analysis_var_storage_init_reg(&stor, reg);
	return rz_analysis_function_get_var_at(fcn, &stor);
}

/**
 * Determine which stack variable the expression reg+reg_addend points to at the given address
 * using stored RzAnalysisVarAccess info.
 * Due to the nature of RzAnalysisVarAccess, a variable is only returned here if reg+reg_addend points
 * exactly to the start of it. var_use_from_stack can also handle pointers inside of variables.
 */
static RzAnalysisVar *var_use_from_accesses(RzAnalysisFunction *fcn, ut64 addr, const char *reg, st64 reg_addend) {
	RzPVector *vars = rz_analysis_function_get_vars_used_at(fcn, addr);
	if (!vars) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (vars, it) {
		RzAnalysisVar *var = *it;
		RzAnalysisVarAccess *acc = rz_analysis_var_get_access_at(var, addr);
		if (!acc) {
			continue;
		}
		if (!strcmp(acc->reg, reg) && acc->reg_addend == reg_addend) {
			return var;
		}
	}
	return NULL;
}

/**
 * Determine which stack variable the expression reg+reg_addend falls into at the given address
 * using stored tracked stack pointer info.
 * \param offset_out returns the offset into the returned variable that reg+reg_addend points to
 */
static RzAnalysisVar *var_use_from_stack(RzAnalysisFunction *fcn, ut64 addr, const char *reg, st64 reg_addend, ut64 *offset_out) {
	RzAnalysis *analysis = fcn->analysis;
	const char *sp_name = rz_reg_get_name(analysis->reg, RZ_REG_NAME_SP);
	const char *bp_name = rz_reg_get_name(analysis->reg, RZ_REG_NAME_BP);
	RzStackAddr stack_addr;
	if (sp_name && !rz_str_casecmp(sp_name, reg)) {
		// sp-based access
		RzAnalysisBlock *block = rz_analysis_fcn_bbget_in(analysis, fcn, addr);
		if (!block) {
			return NULL;
		}
		stack_addr = rz_analysis_block_get_sp_at(block, addr);
		if (stack_addr == RZ_STACK_ADDR_INVALID) {
			return NULL;
		}
		stack_addr += reg_addend;
	} else if (bp_name && !rz_str_casecmp(bp_name, reg)) {
		// bp-based access
		stack_addr = reg_addend - fcn->bp_off;
	} else {
		// some other reg we can't relate to the stack here
		return NULL;
	}
	RzAnalysisVar *ret = rz_analysis_function_get_stack_var_in(fcn, stack_addr);
	if (!ret) {
		return NULL;
	}
	rz_return_val_if_fail(ret->storage.type == RZ_ANALYSIS_VAR_STORAGE_STACK, NULL);
	*offset_out = stack_addr - ret->storage.stack_off;
	return ret;
}

/**
 * Generate a readable description for the (stack) address formed by the value of \p reg + \p reg_addend
 * for disassembly at \p addr, in terms of variables.
 *
 * Example:
 * for disassembly
 *     0x00001152      mov   dword [rsp + 0xc], 4
 * the call
 *     rz_analysis_function_var_expr_for_reg_access_at(fcn, 0x00001152, "rsp", 0xc)
 * may find that rsp + 0xc at this place will point to an existing variable called "myvar" and
 * return its name, enabling the following substitution:
 *     0x00001152      mov   dword [myvar], 4
 *
 * Example outputs:
 * * "myvar" when \p reg + \p reg_addend points exactly to the start of myvar
 * * "myvar.somemember" when \p reg + \p reg_addend points exactly to some a member of myvar
 * * "myvar + 0x4" when \p reg + \p reg_addend points somewhere inside myvar, but not exactly at a known member
 * * NULL when no var has been found
 */
RZ_API RZ_NULLABLE char *rz_analysis_function_var_expr_for_reg_access_at(RzAnalysisFunction *fcn, ut64 addr, RZ_NONNULL const char *reg, st64 reg_addend) {
	rz_return_val_if_fail(fcn && reg, NULL);
	// Try concrete saved accesses first, these are especially important for accesses using registers other than sp/bp,
	// which are created by esil analysis.
	RzAnalysisVar *var = var_use_from_accesses(fcn, addr, reg, reg_addend);
	ut64 var_offset = 0; // accesses always point to the beginning of vars
	if (!var) {
		// For accesses inside of variables or when no accesses are available, search by address on the stack.
		var = var_use_from_stack(fcn, addr, reg, reg_addend, &var_offset);
		if (!var) {
			return NULL;
		}
	}
	// var found, create string
	RzList *paths = rz_type_path_by_offset(fcn->analysis->typedb, var->type, var_offset, 1);
	if (paths && !rz_list_empty(paths)) {
		RzTypePath *path = rz_list_first(paths);
		char *r = rz_str_newf("%s%s", var->name, path->path);
		rz_list_free(paths);
		return r;
	}
	rz_list_free(paths);
	if (var_offset) {
		return rz_str_newf("%s + 0x%" PFMT64x, var->name, var_offset);
	} else {
		return strdup(var->name);
	}
}

RZ_API bool rz_analysis_var_check_name(const char *name) {
	return !isdigit(*name) && strcspn(name, "., =/");
}

RZ_API bool rz_analysis_var_rename(RzAnalysisVar *var, const char *new_name, bool verbose) {
	rz_return_val_if_fail(var, false);
	if (!rz_analysis_var_check_name(new_name)) {
		return false;
	}
	RzAnalysisVar *v1 = rz_analysis_function_get_var_byname(var->fcn, new_name);
	if (v1) {
		if (verbose) {
			RZ_LOG_WARN("variable or arg with name `%s` already exist\n", new_name);
		}
		return false;
	}
	char *nn = strdup(new_name);
	if (!nn) {
		return false;
	}
	free(var->name);
	var->name = nn;
	return true;
}

/**
 * Returns the argument number if the variable \p is argument of some function
 * and matches the calling convention
 */
RZ_API int rz_analysis_var_get_argnum(RzAnalysisVar *var) {
	rz_return_val_if_fail(var, -1);
	RzAnalysis *analysis = var->fcn->analysis;
	if (!rz_analysis_var_is_arg(var) || var->storage.type != RZ_ANALYSIS_VAR_STORAGE_REG) { // TODO: support bp and sp too
		return -1;
	}
	RzRegItem *reg = rz_reg_get(analysis->reg, var->storage.reg, -1);
	if (!reg) {
		return -1;
	}
	int arg_max = 0;
	if (RZ_STR_ISNOTEMPTY(var->fcn->cc)) {
		arg_max = rz_analysis_cc_max_arg(analysis, var->fcn->cc);
	}
	for (int i = 0; i < arg_max; i++) {
		const char *reg_arg = rz_analysis_cc_arg(analysis, var->fcn->cc, i);
		if (reg_arg && !strcmp(reg->name, reg_arg)) {
			return i;
		}
	}
	return -1;
}

RZ_API RZ_BORROW RzPVector /*<RzAnalysisVar *>*/ *rz_analysis_function_get_vars_used_at(RzAnalysisFunction *fcn, ut64 op_addr) {
	rz_return_val_if_fail(fcn, NULL);
	return ht_up_find(fcn->inst_vars, (st64)op_addr - (st64)fcn->addr, NULL);
}

RZ_DEPRECATE RZ_API RzAnalysisVar *rz_analysis_get_used_function_var(RzAnalysis *analysis, ut64 addr) {
	RzList *fcns = rz_analysis_get_functions_in(analysis, addr);
	if (!fcns) {
		return NULL;
	}
	RzAnalysisVar *var = NULL;
	RzListIter *it;
	RzAnalysisFunction *fcn;
	rz_list_foreach (fcns, it, fcn) {
		RzPVector *used_vars = rz_analysis_function_get_vars_used_at(fcn, addr);
		if (used_vars && !rz_pvector_empty(used_vars)) {
			var = rz_pvector_at(used_vars, 0);
			break;
		}
	}
	rz_list_free(fcns);
	return var;
}

RZ_API RzAnalysisVar *rz_analysis_var_get_dst_var(RzAnalysisVar *var) {
	rz_return_val_if_fail(var, NULL);
	RzAnalysisVarAccess *acc;
	rz_vector_foreach (&var->accesses, acc) {
		if (!(acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_READ)) {
			continue;
		}
		ut64 addr = var->fcn->addr + acc->offset;
		RzPVector *used_vars = rz_analysis_function_get_vars_used_at(var->fcn, addr);
		void **it;
		rz_pvector_foreach (used_vars, it) {
			RzAnalysisVar *used_var = *it;
			if (used_var == var) {
				continue;
			}
			RzAnalysisVarAccess *other_acc = rz_analysis_var_get_access_at(used_var, addr);
			if (other_acc && other_acc->type & RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE) {
				return used_var;
			}
		}
	}
	return NULL;
}

RZ_API void rz_analysis_var_set_access(RzAnalysisVar *var, const char *reg, ut64 access_addr, int access_type, st64 reg_addend) {
	rz_return_if_fail(var);
	st64 offset = (st64)access_addr - (st64)var->fcn->addr;

	// accesses are stored ordered by offset, use binary search to get the matching existing or the index to insert a new one
	size_t index;
	rz_vector_lower_bound(&var->accesses, offset, index, ACCESS_CMP);
	RzAnalysisVarAccess *acc = NULL;
	if (index < var->accesses.len) {
		acc = rz_vector_index_ptr(&var->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		acc = rz_vector_insert(&var->accesses, index, NULL);
		acc->offset = offset;
		acc->type = 0;
	}

	acc->type |= (ut8)access_type;
	acc->reg_addend = reg_addend;
	acc->reg = rz_str_constpool_get(&var->fcn->analysis->constpool, reg);

	// add the inverse reference from the instruction to the var
	RzPVector *inst_accesses = ht_up_find(var->fcn->inst_vars, (ut64)offset, NULL);
	if (!inst_accesses) {
		inst_accesses = rz_pvector_new(NULL);
		if (!inst_accesses) {
			return;
		}
		ht_up_insert(var->fcn->inst_vars, (ut64)offset, inst_accesses, NULL);
	}
	if (!rz_pvector_contains(inst_accesses, var)) {
		rz_pvector_push(inst_accesses, var);
	}
}

RZ_API void rz_analysis_var_remove_access_at(RzAnalysisVar *var, ut64 address) {
	rz_return_if_fail(var);
	st64 offset = (st64)address - (st64)var->fcn->addr;
	size_t index;
	rz_vector_lower_bound(&var->accesses, offset, index, ACCESS_CMP);
	if (index >= var->accesses.len) {
		return;
	}
	RzAnalysisVarAccess *acc = rz_vector_index_ptr(&var->accesses, index);
	if (acc->offset == offset) {
		rz_vector_remove_at(&var->accesses, index, NULL);
		RzPVector *inst_accesses = ht_up_find(var->fcn->inst_vars, (ut64)offset, NULL);
		rz_pvector_remove_data(inst_accesses, var);
	}
}

RZ_API void rz_analysis_var_clear_accesses(RzAnalysisVar *var) {
	rz_return_if_fail(var);
	RzAnalysisFunction *fcn = var->fcn;
	if (fcn->inst_vars) {
		// remove all inverse references to the var's accesses
		RzAnalysisVarAccess *acc;
		rz_vector_foreach (&var->accesses, acc) {
			RzPVector *inst_accesses = ht_up_find(fcn->inst_vars, (ut64)acc->offset, NULL);
			if (!inst_accesses) {
				continue;
			}
			rz_pvector_remove_data(inst_accesses, var);
		}
	}
	rz_vector_clear(&var->accesses);
}

RZ_API RzAnalysisVarAccess *rz_analysis_var_get_access_at(RzAnalysisVar *var, ut64 addr) {
	rz_return_val_if_fail(var, NULL);
	st64 offset = (st64)addr - (st64)var->fcn->addr;
	size_t index;
	rz_vector_lower_bound(&var->accesses, offset, index, ACCESS_CMP);
	if (index >= var->accesses.len) {
		return NULL;
	}
	RzAnalysisVarAccess *acc = rz_vector_index_ptr(&var->accesses, index);
	if (acc->offset == offset) {
		return acc;
	}
	return NULL;
}

/**
 * \brief Adds a type constraint \p constraint to a \p var variables
 */
RZ_API void rz_analysis_var_add_constraint(RzAnalysisVar *var, RZ_BORROW RzTypeConstraint *constraint) {
	rz_vector_push(&var->constraints, constraint);
}

/**
 * \brief Get all type constraints of a \p var variable in the text form
 */
RZ_API char *rz_analysis_var_get_constraints_readable(RzAnalysisVar *var) {
	size_t n = var->constraints.len;
	if (!n) {
		return NULL;
	}
	bool low = false, high = false;
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	size_t i;
	for (i = 0; i < n; i += 1) {
		RzTypeConstraint *constr = rz_vector_index_ptr(&var->constraints, i);
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

static bool stack_offset_is_arg(RzAnalysisFunction *fcn, st64 stack_off) {
	RzStackAddr shadow = fcn->cc ? rz_analysis_cc_shadow_store(fcn->analysis, fcn->cc) : 0;
	return stack_off >= shadow;
}

static bool reg_is_fcn_arg(RzAnalysisFunction *fcn, const char *regname) {
	if (RZ_STR_ISEMPTY(fcn->cc) || RZ_STR_ISEMPTY(regname)) {
		return false;
	}
	int n = rz_analysis_cc_max_arg(fcn->analysis, fcn->cc);
	for (int i = 0; i < n; ++i) {
		const char *x = rz_analysis_cc_arg(fcn->analysis, fcn->cc, i);
		if (!x) {
			continue;
		}
		if (strcmp(x, regname) == 0) {
			return true;
		}
	}
	return false;
}

/**
 * \brief Check if a variable is a function argument
 *
 * \param var variable to check
 * \return {return} true if the variable is a function argument
 */
RZ_API bool rz_analysis_var_is_arg(RZ_NONNULL RzAnalysisVar *var) {
	rz_return_val_if_fail(var, false);
	switch (var->kind) {
	case RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER:
		return true;
	case RZ_ANALYSIS_VAR_KIND_VARIABLE:
		return false;
	case RZ_ANALYSIS_VAR_KIND_INVALID: {
		/**
		 * If we already have some function arguments from debug information,
		 * then we don't consider the function arguments of the call convention anymore
		 */
		if (var->fcn->has_debuginfo) {
			return false;
		}
		break;
	}
	default: break;
	}

	switch (var->storage.type) {
	case RZ_ANALYSIS_VAR_STORAGE_REG:
		return reg_is_fcn_arg(var->fcn, var->storage.reg);
	case RZ_ANALYSIS_VAR_STORAGE_STACK:
		return stack_offset_is_arg(var->fcn, var->storage.stack_off);
	default:
		return false;
	}
}

static size_t count_vars(RZ_NONNULL RzAnalysisFunction *fcn, bool args) {
	rz_return_val_if_fail(fcn, 0);
	size_t count = 0;
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (rz_analysis_var_is_arg(var) == args) {
			count++;
		}
	}
	return count;
}

/**
 * \brief Count the local (non-argument) variables in the given function
 */
RZ_API size_t rz_analysis_var_local_count(RZ_NONNULL RzAnalysisFunction *fcn) {
	return count_vars(fcn, false);
}

/**
 * \brief Count the argument variables in the given function
 */
RZ_API size_t rz_analysis_arg_count(RZ_NONNULL RzAnalysisFunction *fcn) {
	return count_vars(fcn, true);
}

static const char *get_regname(RzAnalysis *analysis, RzAnalysisValue *value) {
	const char *name = NULL;
	if (value && value->reg && value->reg->name) {
		name = value->reg->name;
		RzRegItem *ri = rz_reg_get(analysis->reg, value->reg->name, -1);
		if (ri && (ri->size == 32) && (analysis->bits == 64)) {
			name = rz_reg_32_to_64(analysis->reg, value->reg->name);
		}
	}
	return name;
}

static inline bool is_not_read_nor_write(const RzAnalysisOpDirection direction) {
	return direction != RZ_ANALYSIS_OP_DIR_READ && direction != RZ_ANALYSIS_OP_DIR_WRITE;
}

/**
 * \brief Try to extract any args from a single op
 *
 * \param reg name of the register to look at for accesses
 * \param from_sp whether \p reg is the sp or bp
 */
static void extract_stack_var(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op, const char *reg, const char *sign, bool is_sp, RzStackAddr sp, RzStackAddr shadow_store) {
	rz_return_if_fail(analysis && fcn && op && reg);
	st64 addend = 0;
	bool found_addend = false;
	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(op->src); i++) {
		if (!op->src[i] || !op->src[i]->reg || !op->src[i]->reg->name) {
			continue;
		}
		if (strcmp(reg, op->src[i]->reg->name)) {
			continue;
		}
		st64 delta = op->src[i]->delta;
		if ((delta < 0 && *sign == '+') || (delta >= 0 && *sign == '-')) {
			continue;
		}
		if (!delta && is_not_read_nor_write(op->direction)) {
			// avoid creating variables for just `mov rbp, rsp`, which would otherwise detect a var at rsp+0
			// so for delta == 0, we only consider actual memory operations for now
			continue;
		}
		addend = delta;
		found_addend = true;
		break;
	}

	char *esil_buf = NULL;
	if (!found_addend) {
		const char *op_esil = rz_strbuf_get(&op->esil);
		if (!op_esil) {
			return;
		}
		esil_buf = strdup(op_esil);
		if (!esil_buf) {
			return;
		}
		char *tmp = rz_str_newf(",%s,%s,", reg, sign);
		char *ptr_end = tmp ? strstr(esil_buf, tmp) : NULL;
		free(tmp);
		if (!ptr_end) {
			free(esil_buf);
			return;
		}
		*ptr_end = 0;
		char *addr = ptr_end;
		while ((addr[0] != '0' || addr[1] != 'x') && addr >= esil_buf + 1 && *addr != ',') {
			addr--;
		}
		if (strncmp(addr, "0x", 2)) {
			// XXX: This is a workaround for inconsistent esil
			if (!op->stackop && op->dst) {
				const char *sp = rz_reg_get_name(analysis->reg, RZ_REG_NAME_SP);
				const char *bp = rz_reg_get_name(analysis->reg, RZ_REG_NAME_BP);
				const char *rn = op->dst->reg ? op->dst->reg->name : NULL;
				if (rn && ((bp && !strcmp(bp, rn)) || (sp && !strcmp(sp, rn)))) {
					RZ_LOG_DEBUG("Analysis didn't fill op->stackop for instruction that alters stack at 0x%" PFMT64x ".\n", op->addr);
					goto beach;
				}
			}
			if (*addr == ',') {
				addr++;
			}
			if (!op->stackop && op->type != RZ_ANALYSIS_OP_TYPE_PUSH && op->type != RZ_ANALYSIS_OP_TYPE_POP && op->type != RZ_ANALYSIS_OP_TYPE_RET && rz_str_isnumber(addr)) {
				addend = (st64)rz_num_get(NULL, addr);
				if (addend && op->src[0] && addend == op->src[0]->imm) {
					goto beach;
				}
			} else if ((op->stackop == RZ_ANALYSIS_STACK_SET) || (op->stackop == RZ_ANALYSIS_STACK_GET)) {
				if (op->ptr % 4) {
					goto beach;
				}
				addend = op->ptr;
			} else {
				goto beach;
			}
		} else {
			addend = (st64)rz_num_get(NULL, addr);
		}
		if (*sign == '-') {
			addend = -addend;
		}
		if (addend == 0 && is_not_read_nor_write(op->direction)) {
			// avoid creating variables for just `mov rbp, rsp`, which would otherwise detect a var at rsp+0
			// so for addend == 0, we only consider actual memory operations for now
			goto beach;
		}
	}

	if (!op->src[0] || !op->dst) {
		RZ_LOG_DEBUG("Analysis didn't fill op->src/dst at 0x%" PFMT64x ".\n", op->addr);
	}

	RzStackAddr stack_off;
	if (is_sp) {
		stack_off = addend - fcn->stack;
	} else {
		stack_off = addend - fcn->bp_off;
	}
	if (!stack_off) {
		// Do not create a var/arg for the return address
		free(esil_buf);
		return;
	}

	int rw = (op->direction == RZ_ANALYSIS_OP_DIR_WRITE) ? RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE : RZ_ANALYSIS_VAR_ACCESS_TYPE_READ;
	if (*sign == '+') {
		const bool isarg = stack_offset_is_arg(fcn, stack_off);
		const char *pfx = isarg ? ARGPREFIX : VARPREFIX;
		RzAnalysisVar *var = rz_analysis_function_get_stack_var_at(fcn, stack_off);
		if (var) {
			rz_analysis_var_set_access(var, reg, op->addr, rw, addend);
			goto beach;
		}
		char *varname = NULL;
		RzType *vartype = NULL;
		if (isarg) {
			const char *place = fcn->cc ? rz_analysis_cc_arg(analysis, fcn->cc, ST32_MAX) : NULL;
			bool stack_rev = place ? !strcmp(place, "stack_rev") : false;
			char *fname = rz_analysis_function_name_guess(analysis->typedb, fcn->name);
			if (fname) {
				ut64 sum_sz = 0;
				size_t from, to, i;
				if (stack_rev) {
					const size_t cnt = rz_type_func_args_count(analysis->typedb, fname);
					from = cnt ? cnt - 1 : cnt;
					to = fcn->cc ? rz_analysis_cc_max_arg(analysis, fcn->cc) : 0;
				} else {
					from = fcn->cc ? rz_analysis_cc_max_arg(analysis, fcn->cc) : 0;
					to = rz_type_func_args_count(analysis->typedb, fname);
				}
				const int bytes = (fcn->bits ? fcn->bits : analysis->bits) / 8;
				if (!strcmp(analysis->cur->arch, "x86")) {
					sum_sz += bytes; // move past the return address
				}
				for (i = from; stack_rev ? i >= to : i < to; stack_rev ? i-- : i++) {
					RzType *tp = rz_type_func_args_type(analysis->typedb, fname, i);
					if (!tp) {
						break;
					}
					if (sum_sz == stack_off) {
						vartype = tp;
						varname = strdup(rz_type_func_args_name(analysis->typedb, fname, i));
						break;
					}
					ut64 bit_sz = rz_type_db_get_bitsize(analysis->typedb, tp);
					sum_sz += bit_sz ? bit_sz / 8 : bytes;
					sum_sz = RZ_ROUND(sum_sz, bytes);
				}
				free(fname);
			}
		}
		if (!varname) {
			varname = rz_str_newf("%s_%" PFMT64x "h", pfx, RZ_ABS(stack_off));
		}
		if (varname) {
			RzAnalysisVarStorage stor;
			rz_analysis_var_storage_init_stack(&stor, stack_off);
			RzAnalysisVar *var = rz_analysis_function_set_var(fcn, &stor, vartype, rz_analysis_guessed_mem_access_width(analysis), varname);
			if (var) {
				rz_analysis_var_set_access(var, reg, op->addr, rw, addend);
			}
			free(varname);
		}
	} else {
		RzAnalysisVarStorage stor;
		rz_analysis_var_storage_init_stack(&stor, stack_off);
		RzAnalysisVar *var = rz_analysis_function_get_stack_var_at(fcn, stor.stack_off);
		if (var) {
			rz_analysis_var_set_access(var, reg, op->addr, rw, addend);
			goto beach;
		}
		char *varname = rz_str_newf("%s_%" PFMT64x "h", VARPREFIX, RZ_ABS(stor.stack_off));
		if (varname) {
			RzAnalysisVar *var = rz_analysis_function_set_var(fcn, &stor, NULL, rz_analysis_guessed_mem_access_width(analysis), varname);
			if (var) {
				rz_analysis_var_set_access(var, reg, op->addr, rw, addend);
			}
			free(varname);
		}
	}
beach:
	free(esil_buf);
}

static bool is_reg_in_src(const char *regname, RzAnalysis *analysis, RzAnalysisOp *op);

static inline bool op_affect_dst(RzAnalysisOp *op) {
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_MUL:
	case RZ_ANALYSIS_OP_TYPE_DIV:
	case RZ_ANALYSIS_OP_TYPE_SHR:
	case RZ_ANALYSIS_OP_TYPE_SHL:
	case RZ_ANALYSIS_OP_TYPE_SAL:
	case RZ_ANALYSIS_OP_TYPE_SAR:
	case RZ_ANALYSIS_OP_TYPE_OR:
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_NOR:
	case RZ_ANALYSIS_OP_TYPE_NOT:
	case RZ_ANALYSIS_OP_TYPE_ROR:
	case RZ_ANALYSIS_OP_TYPE_ROL:
	case RZ_ANALYSIS_OP_TYPE_CAST:
		return true;
	default:
		return false;
	}
}

#define STR_EQUAL(s1, s2) (s1 && s2 && !strcmp(s1, s2))

static inline bool arch_destroys_dst(const char *arch) {
	return (STR_EQUAL(arch, "arm") || STR_EQUAL(arch, "riscv") || STR_EQUAL(arch, "ppc"));
}

static bool is_used_like_arg(const char *regname, const char *opsreg, const char *opdreg, RzAnalysisOp *op, RzAnalysis *analysis) {
	RzAnalysisValue *dst = op->dst;
	RzAnalysisValue *src = op->src[0];
	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_POP:
		return false;
	case RZ_ANALYSIS_OP_TYPE_MOV:
		return (is_reg_in_src(regname, analysis, op)) || (STR_EQUAL(opdreg, regname) && dst->memref);
	case RZ_ANALYSIS_OP_TYPE_CMOV:
		if (STR_EQUAL(opdreg, regname)) {
			return false;
		}
		if (is_reg_in_src(regname, analysis, op)) {
			return true;
		}
		return false;
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		if (is_reg_in_src(regname, analysis, op)) {
			return true;
		}
		if (STR_EQUAL(opdreg, regname)) {
			return false;
		}
		return false;
	case RZ_ANALYSIS_OP_TYPE_XOR:
		if (STR_EQUAL(opsreg, opdreg) && !src->memref && !dst->memref) {
			return false;
		}
		// fallthrough
	default:
		if (op_affect_dst(op) && arch_destroys_dst(analysis->cur->arch)) {
			if (is_reg_in_src(regname, analysis, op)) {
				return true;
			}
			return false;
		}
		return ((STR_EQUAL(opdreg, regname)) || (is_reg_in_src(regname, analysis, op)));
	}
}

static bool is_reg_in_src(const char *regname, RzAnalysis *analysis, RzAnalysisOp *op) {
	const char *opsreg0 = op->src[0] ? get_regname(analysis, op->src[0]) : NULL;
	const char *opsreg1 = op->src[1] ? get_regname(analysis, op->src[1]) : NULL;
	const char *opsreg2 = op->src[2] ? get_regname(analysis, op->src[2]) : NULL;
	return (STR_EQUAL(regname, opsreg0)) || (STR_EQUAL(regname, opsreg1)) || (STR_EQUAL(regname, opsreg2));
}

static size_t count_reg_arg_vars(RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(fcn, 0);
	size_t count = 0;
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (var->storage.type == RZ_ANALYSIS_VAR_STORAGE_REG && rz_analysis_var_is_arg(var)) {
			count++;
		}
	}
	return count;
}

RZ_API void rz_analysis_extract_rarg(RzAnalysis *analysis, RzAnalysisOp *op, RzAnalysisFunction *fcn, int *reg_set, int *count) {
	int i, argc = 0;
	rz_return_if_fail(analysis && op && fcn);
	const char *opsreg = op->src[0] ? get_regname(analysis, op->src[0]) : NULL;
	const char *opdreg = op->dst ? get_regname(analysis, op->dst) : NULL;
	const int size = (fcn->bits ? fcn->bits : analysis->bits) / 8;
	if (!fcn->cc) {
		RZ_LOG_DEBUG("No calling convention for function '%s' to extract register arguments\n", fcn->name);
		return;
	}
	char *fname = rz_analysis_function_name_guess(analysis->typedb, fcn->name);
	int max_count = rz_analysis_cc_max_arg(analysis, fcn->cc);
	if (!max_count || (*count >= max_count)) {
		free(fname);
		return;
	}
	if (fname) {
		argc = rz_type_func_args_count(analysis->typedb, fname);
	}

	bool is_call = (op->type & 0xf) == RZ_ANALYSIS_OP_TYPE_CALL || (op->type & 0xf) == RZ_ANALYSIS_OP_TYPE_UCALL;
	if (is_call && *count < max_count) {
		RzList *callee_rargs_l = NULL;
		size_t callee_rargs = 0;
		char *callee = NULL;
		ut64 offset = op->jump == UT64_MAX ? op->ptr : op->jump;
		RzAnalysisFunction *f = rz_analysis_get_function_at(analysis, offset);
		if (!f) {
			RzCore *core = (RzCore *)analysis->coreb.core;
			RzFlagItem *flag = rz_flag_get_by_spaces(core->flags, offset, RZ_FLAGS_FS_IMPORTS, NULL);
			if (flag) {
				callee = rz_analysis_function_name_guess(analysis->typedb, flag->name);
				if (callee) {
					const char *cc = rz_analysis_cc_func(analysis, callee);
					if (cc && !strcmp(fcn->cc, cc)) {
						callee_rargs = RZ_MIN(max_count, rz_type_func_args_count(analysis->typedb, callee));
					}
				}
			}
		} else if (!f->is_variadic && !strcmp(fcn->cc, f->cc)) {
			callee = rz_analysis_function_name_guess(analysis->typedb, f->name);
			if (callee) {
				callee_rargs = RZ_MIN(max_count, rz_type_func_args_count(analysis->typedb, callee));
			}
			callee_rargs = callee_rargs ? callee_rargs : count_reg_arg_vars(f);
			callee_rargs_l = rz_analysis_var_list(f, RZ_ANALYSIS_VAR_STORAGE_REG);
		}
		size_t i;
		for (i = 0; i < callee_rargs; i++) {
			if (reg_set[i]) {
				continue;
			}
			const char *vname = NULL;
			RzType *type = NULL;
			char *name = NULL;
			const char *regname = rz_analysis_cc_arg(analysis, fcn->cc, i);
			if (!regname) {
				continue;
			}
			if (fname) {
				type = rz_type_func_args_type(analysis->typedb, fname, i);
				vname = rz_type_func_args_name(analysis->typedb, fname, i);
			}
			if (!vname && callee) {
				type = rz_type_func_args_type(analysis->typedb, callee, i);
				vname = rz_type_func_args_name(analysis->typedb, callee, i);
			}
			if (vname) {
				reg_set[i] = 1;
			} else {
				RzListIter *it;
				RzAnalysisVar *arg, *found_arg = NULL;
				rz_list_foreach (callee_rargs_l, it, arg) {
					if (rz_analysis_var_get_argnum(arg) == i) {
						found_arg = arg;
						break;
					}
				}
				if (found_arg) {
					type = found_arg->type;
					vname = name = strdup(found_arg->name);
				}
			}
			if (!vname) {
				name = rz_str_newf("arg%zu", i + 1);
				vname = name;
			}
			RzAnalysisVarStorage stor;
			rz_analysis_var_storage_init_reg(&stor, regname);
			rz_analysis_function_set_var(fcn, &stor, type, size, vname);
			(*count)++;
			free(name);
		}
		free(callee);
		rz_list_free(callee_rargs_l);
		free(fname);
		return;
	}

	for (i = 0; i < max_count; i++) {
		const char *regname = rz_analysis_cc_arg(analysis, fcn->cc, i);
		if (!regname) {
			continue;
		}
		RzAnalysisVar *var = NULL;
		bool is_used_like_an_arg = is_used_like_arg(regname, opsreg, opdreg, op, analysis);
		if (reg_set[i] == 1 && is_used_like_an_arg) {
			var = rz_analysis_function_get_reg_var_at(fcn, regname);
		} else if (reg_set[i] != 2 && is_used_like_an_arg) {
			const char *vname = NULL;
			RzType *type = NULL;
			char *name = NULL;
			if ((i < argc) && fname) {
				type = rz_type_func_args_type(analysis->typedb, fname, i);
				vname = rz_type_func_args_name(analysis->typedb, fname, i);
			}
			if (!vname) {
				name = rz_str_newf("arg%d", i + 1);
				vname = name;
			}
			RzAnalysisVarStorage stor;
			rz_analysis_var_storage_init_reg(&stor, regname);
			var = rz_analysis_function_set_var(fcn, &stor, type, size, vname);
			free(name);
			(*count)++;
		} else {
			if (is_reg_in_src(regname, analysis, op) || STR_EQUAL(opdreg, regname)) {
				reg_set[i] = 2;
			}
			continue;
		}
		if (is_reg_in_src(regname, analysis, op) || STR_EQUAL(regname, opdreg)) {
			reg_set[i] = 1;
		}
		if (var) {
			rz_analysis_var_set_access(var, regname, op->addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 0);
			rz_meta_set_string(analysis, RZ_META_TYPE_VARTYPE, op->addr, var->name);
		}
	}

	const char *selfreg = rz_analysis_cc_self(analysis, fcn->cc);
	if (selfreg) {
		bool is_used_like_an_arg = is_used_like_arg(selfreg, opsreg, opdreg, op, analysis);
		if (reg_set[i] != 2 && is_used_like_an_arg) {
			char *vname = strdup("self");
			RzAnalysisVarStorage stor;
			rz_analysis_var_storage_init_reg(&stor, selfreg);
			RzAnalysisVar *newvar = rz_analysis_function_set_var(fcn, &stor, NULL, size, vname);
			if (newvar) {
				rz_analysis_var_set_access(newvar, selfreg, op->addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 0);
			}
			rz_meta_set_string(analysis, RZ_META_TYPE_VARTYPE, op->addr, vname);
			free(vname);
			(*count)++;
		} else {
			if (is_reg_in_src(selfreg, analysis, op) || STR_EQUAL(opdreg, selfreg)) {
				reg_set[i] = 2;
			}
		}
		i++;
	}

	const char *errorreg = rz_analysis_cc_error(analysis, fcn->cc);
	if (errorreg) {
		if (reg_set[i] == 0 && STR_EQUAL(opdreg, errorreg)) {
			char *vname = strdup("error");
			RzAnalysisVarStorage stor;
			rz_analysis_var_storage_init_reg(&stor, errorreg);
			RzAnalysisVar *newvar = rz_analysis_function_set_var(fcn, &stor, NULL, size, vname);
			if (newvar) {
				rz_analysis_var_set_access(newvar, errorreg, op->addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 0);
			}
			rz_meta_set_string(analysis, RZ_META_TYPE_VARTYPE, op->addr, vname);
			free(vname);
			(*count)++;
			reg_set[i] = 2;
		}
	}
	free(fname);
}

/**
 * Analyze \p op for variable-like accesses to the stack and create variables
 * \p sp value of the stack pointer before \p op is executed in the context of \p fcn
 */
RZ_API void rz_analysis_extract_vars(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op, RzStackAddr sp) {
	rz_return_if_fail(analysis && fcn && op);
	RzStackAddr shadow_store = fcn->cc ? rz_analysis_cc_shadow_store(analysis, fcn->cc) : 0;
	const char *BP = rz_reg_get_name(analysis->reg, RZ_REG_NAME_BP);
	const char *SP = rz_reg_get_name(analysis->reg, RZ_REG_NAME_SP);
	if (BP) {
		extract_stack_var(analysis, fcn, op, BP, "+", false, sp, shadow_store);
		extract_stack_var(analysis, fcn, op, BP, "-", false, sp, shadow_store);
	}
	if (SP) {
		extract_stack_var(analysis, fcn, op, SP, "+", true, sp, shadow_store);
	}
}

/**
 * \brief      Returns a list of vars (RzAnalysisVar) of the requrested kind
 *
 * \param      fcn   The function to use to retrieve the list of vars
 * \param[in]  kind  The kind of the vars to retrieve
 *
 * \return     On success a list of RzAnalysisVar pointers (can be empty), otherwise NULL.
 */
RZ_API RZ_OWN RzList /*<RzAnalysisVar *>*/ *rz_analysis_var_list(RZ_NONNULL RzAnalysisFunction *fcn, RzAnalysisVarStorageType kind) {
	rz_return_val_if_fail(fcn, NULL);

	RzList *list = rz_list_new();
	if (!list) {
		RZ_LOG_ERROR("analysis: Cannot allocate RzList for RzAnalysisVar\n");
		return NULL;
	}

	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (var->storage.type != kind) {
			continue;
		}
		rz_list_append(list, var);
	}
	return list;
}

static int regvar_comparator(const RzAnalysisVar *a, const RzAnalysisVar *b) {
	return (a && b) ? (a->argnum > b->argnum) - (a->argnum < b->argnum) : 0;
}

static int var_comparator(const RzAnalysisVar *a, const RzAnalysisVar *b, void *user) {
	if (a->origin.kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF && b->origin.kind == RZ_ANALYSIS_VAR_ORIGIN_DWARF) {
		return (int)a->origin.dw_var->offset - b->origin.dw_var->offset;
	}
	if (a->origin.kind != b->origin.kind) {
		return (int)a->origin.kind - b->origin.kind;
	}
	bool aa = rz_analysis_var_is_arg((RzAnalysisVar *)a);
	bool bb = rz_analysis_var_is_arg((RzAnalysisVar *)a);
	if ((aa && bb) || (!aa && !bb)) {
		if (a->storage.type == RZ_ANALYSIS_VAR_STORAGE_REG && b->storage.type == RZ_ANALYSIS_VAR_STORAGE_REG) {
			return regvar_comparator(a, b);
		}
		return rz_analysis_var_storage_cmp(&a->storage, &b->storage);
	}
	return aa ? -1 : 1;
}

/**
 * Populate \p cache with the variables from \p fcn and sort them according to their storage
 */
RZ_API void rz_analysis_fcn_vars_cache_init(
	RZ_NONNULL RZ_BORROW RzAnalysis *analysis,
	RZ_NONNULL RZ_BORROW RZ_OUT RzAnalysisFcnVarsCache *cache,
	RZ_NONNULL RZ_BORROW RzAnalysisFunction *fcn) {
	rz_return_if_fail(analysis && cache && fcn);
	cache->sorted_vars = rz_list_new_from_array((const void **)rz_pvector_data(&fcn->vars), rz_pvector_len(&fcn->vars));
	cache->arg_vars = rz_list_new();
	RzListIter *it;
	RzAnalysisVar *var;
	rz_list_foreach (cache->sorted_vars, it, var) {
		var->argnum = rz_analysis_var_get_argnum(var);
		if (rz_analysis_var_is_arg(var)) {
			rz_list_append(cache->arg_vars, var);
		}
	}
	rz_list_sort(cache->sorted_vars, (RzListComparator)var_comparator, NULL);
	rz_list_sort(cache->arg_vars, (RzListComparator)var_comparator, NULL);
}

/**
 * \brief Create variable cache with the variables from \p fcn and sort them according to their storage
 * \param analysis The RzAnalysis instance
 * \param fcn The RzAnalysis
 * \return RzAnalysisFcnVarsCache or NULL
 */
RZ_API RZ_OWN RzAnalysisFcnVarsCache *rz_analysis_fcn_vars_cache_from_fcn(
	RZ_NONNULL RZ_BORROW RzAnalysis *analysis,
	RZ_NONNULL RZ_BORROW RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(analysis && fcn, NULL);
	RzAnalysisFcnVarsCache *cache = RZ_NEW0(RzAnalysisFcnVarsCache);
	if (!cache) {
		return NULL;
	}
	rz_analysis_fcn_vars_cache_init(analysis, cache, fcn);
	return cache;
}

RZ_API void rz_analysis_fcn_vars_cache_fini(RzAnalysisFcnVarsCache *cache) {
	if (!cache) {
		return;
	}
	rz_list_free(cache->sorted_vars);
	rz_list_free(cache->arg_vars);
}

static char *sig_from_debuginfo(RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, char *fcn_name, const char *fcn_name_pre, const char *fcn_name_post) {
	if (!fcn->has_debuginfo || !rz_str_startswith(fcn_name, "dbg."))
		return NULL;

	RzCallable *callable = rz_type_func_get(analysis->typedb, fcn_name + 4);
	if (!callable) {
		return NULL;
	}
	return rz_type_callable_as_string(analysis->typedb, callable);
}

/**
 * \brief Returns a string representing the signature of the function \p fcn
 *
 * \param analysis The analysis context
 * \param fcn The function to use to retrieve the signature
 * \param fcn_name The name of the function to use to retrieve the signature
 * \param reuse_cache The function variable cache to speed up the process
 * \param fcn_name_pre The prefix to use to highlight the function name
 * \param fcn_name_post The suffix to use to highlight the function name
 * \return {return}
 */
RZ_API char *rz_analysis_fcn_format_sig(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NULLABLE char *fcn_name,
	RZ_NULLABLE RzAnalysisFcnVarsCache *reuse_cache, RZ_NULLABLE const char *fcn_name_pre, RZ_NULLABLE const char *fcn_name_post) {
	fcn_name = !fcn_name ? fcn->name : fcn_name;
	if (!fcn_name) {
		return NULL;
	}

	char *sig = sig_from_debuginfo(analysis, fcn, fcn_name, fcn_name_pre, fcn_name_post);
	if (RZ_STR_ISNOTEMPTY(sig)) {
		return sig;
	}

	RzStrBuf *buf = rz_strbuf_new(NULL);
	if (!buf) {
		return NULL;
	}

	RzAnalysisFcnVarsCache *cache = reuse_cache;
	if (!cache) {
		cache = rz_analysis_fcn_vars_cache_from_fcn(analysis, fcn);
		if (!cache) {
			return NULL;
		}
	}

	char *type_fcn_name = rz_analysis_function_name_guess(analysis->typedb, fcn_name);
	if (type_fcn_name && rz_type_func_exist(analysis->typedb, type_fcn_name)) {
		RzType *ret_type = rz_type_func_ret(analysis->typedb, type_fcn_name);
		if (ret_type) {
			char *ret_type_str = rz_type_as_string(analysis->typedb, ret_type);
			if (ret_type_str) {
				const char *sp = ret_type->kind == RZ_TYPE_KIND_POINTER ? "" : " ";
				rz_strbuf_appendf(buf, "%s%s", ret_type_str, sp);
				free(ret_type_str);
			}
		}
	}

	if (fcn_name_pre) {
		rz_strbuf_append(buf, fcn_name_pre);
	}
	rz_strbuf_append(buf, fcn_name);
	if (fcn_name_post) {
		rz_strbuf_append(buf, fcn_name_post);
	}
	rz_strbuf_append(buf, "(");

	if (type_fcn_name && rz_type_func_exist(analysis->typedb, type_fcn_name)) {
		int i, argc = rz_type_func_args_count(analysis->typedb, type_fcn_name);
		bool comma = true;
		// This avoids false positives present in argument recovery
		// and straight away print arguments fetched from types db
		for (i = 0; i < argc; i++) {
			RzType *type = rz_type_func_args_type(analysis->typedb, type_fcn_name, i);
			const char *name = rz_type_func_args_name(analysis->typedb, type_fcn_name, i);
			if (!type || !name) {
				RZ_LOG_ERROR("Missing type for %s\n", type_fcn_name);
				goto beach;
			}
			char *type_str = rz_type_as_string(analysis->typedb, type);
			if (i == argc - 1) {
				comma = false;
			}
			const char *sp = type->kind == RZ_TYPE_KIND_POINTER ? "" : " ";
			rz_strbuf_appendf(buf, "%s%s%s%s", type_str, sp, name, comma ? ", " : "");
			free(type_str);
		}
		goto beach;
	}
	RZ_FREE(type_fcn_name);

	RzAnalysisVar *var;
	RzListIter *iter;
	rz_list_foreach (cache->arg_vars, iter, var) {
		char *vartype = rz_type_as_string(analysis->typedb, var->type);
		size_t tmp_len = strlen(vartype);
		rz_strbuf_appendf(buf, "%s%s%s%s", vartype,
			tmp_len && vartype[tmp_len - 1] == '*' ? "" : " ",
			var->name, rz_list_iter_has_next(iter) ? ", " : "");
		free(vartype);
	}

beach:
	RZ_FREE(type_fcn_name);
	if (!reuse_cache && cache) {
		// !reuse_cache => we created our own cache
		rz_analysis_fcn_vars_cache_fini(cache);
		free(cache);
	}
	rz_strbuf_append(buf, ");");
	return rz_strbuf_drain(buf);
}

/**
 * \brief Updates the types database for function arguments
 *
 * Searches if the types database has the function with the same name.
 * if there is a match - updates the RzCallable type of the function
 * by adding the new function arguments' types.
 *
 * \param analysis RzAnalysis instance
 * \param fcn Function which arguments we should save into the types database
 */
RZ_API void rz_analysis_fcn_vars_add_types(RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn) {
	rz_return_if_fail(analysis && fcn && fcn->name);

	// Do not syncronize types if the function already exist in the types database
	if (rz_type_func_exist(analysis->typedb, fcn->name)) {
		return;
	}

	// Avoid saving the autonamed functions into the types database
	if (rz_analysis_function_is_autonamed(fcn->name)) {
		return;
	}

	RzAnalysisFcnVarsCache cache;
	rz_analysis_fcn_vars_cache_init(analysis, &cache, fcn);

	// TODO: Save also the return type
	RzCallable *callable = rz_type_func_new(analysis->typedb, fcn->name, NULL);

	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (rz_analysis_var_is_arg(var)) {
			// Since we create a new argument type we should clone it here
			RzType *cloned = rz_type_clone(var->type);
			RzCallableArg *arg = rz_type_callable_arg_new(analysis->typedb, var->name, cloned);
			if (arg) {
				rz_type_callable_arg_add(callable, arg);
			} else {
				rz_type_free(cloned);
			}
		}
	}
	rz_type_func_save(analysis->typedb, callable);
	rz_analysis_fcn_vars_cache_fini(&cache);
}

/**
 * \brief Calculates the size of a variable
 *
 * Gets the type (RzType) of a variable and calculates its size
 *
 * \param analysis RzAnalysis instance
 * \param var Variable to check
 * \return The variable size in bits or `UT64_MAX` in case of failure
 */
RZ_API ut64 rz_analysis_var_size(const RzAnalysis *analysis, RZ_NONNULL RzAnalysisVar *var) {
	rz_return_val_if_fail(analysis && var, UT64_MAX);
	return rz_type_db_get_bitsize(analysis->typedb, var->type);
}
