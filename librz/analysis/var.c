// SPDX-FileCopyrightText: 2010-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2010-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_list.h>

#define ACCESS_CMP(x, y) ((st64)((ut64)(x) - (ut64)((RzAnalysisVarAccess *)y)->offset))

static const char *__int_type_from_size(int size) {
	switch (size) {
	case 1: return "int8_t";
	case 2: return "int16_t";
	case 4: return "int32_t";
	case 8: return "int64_t";
	default: return NULL;
	}
}

RZ_API bool rz_analysis_function_rebase_vars(RzAnalysis *a, RzAnalysisFunction *fcn) {
	rz_return_val_if_fail(a && fcn, false);
	RzListIter *it;
	RzAnalysisVar *var;
	RzList *var_list = rz_analysis_var_all_list(a, fcn);
	rz_return_val_if_fail(var_list, false);

	rz_list_foreach (var_list, it, var) {
		// Resync delta in case the registers list changed
		if (var->isarg && var->kind == 'r') {
			RzRegItem *reg = rz_reg_get(a->reg, var->regname, -1);
			if (reg) {
				if (var->delta != reg->index) {
					var->delta = reg->index;
				}
			}
		}
	}

	rz_list_free(var_list);
	return true;
}

// If the type of var is a struct,
// remove all other vars that are overlapped by var and are at the offset of one of its struct members
static void shadow_var_struct_members(RzAnalysisVar *var) {
	if (var->type->kind == RZ_TYPE_KIND_POINTER || var->type->kind == RZ_TYPE_KIND_CALLABLE) {
		// Pointers don't shadow anything
		return;
	}
	if (var->type->kind == RZ_TYPE_KIND_ARRAY) {
		// TODO: support arrays
		return;
	}
	// In other cases we check the type by name
	const char *tname = var->type->identifier.name;
	RzBaseType *btype = rz_type_db_get_base_type(var->fcn->analysis->typedb, tname);
	if (!btype) {
		return;
	}

	if (btype->kind != RZ_BASE_TYPE_KIND_STRUCT) {
		rz_type_base_type_free(btype);
		return;
	}

	if (rz_vector_empty(&btype->struct_data.members)) {
		rz_type_base_type_free(btype);
		return;
	}
	RzTypeStructMember *member;
	rz_vector_foreach(&btype->struct_data.members, member) {
		if (member->offset != 0) { // delete variables which are overlaid by structure
			RzAnalysisVar *other = rz_analysis_function_get_var(var->fcn, var->kind, var->delta + member->offset);
			if (other && other != var) {
				rz_analysis_var_delete(other);
			}
		}
	}
	rz_type_base_type_free(btype);
}

RZ_API RzAnalysisVar *rz_analysis_function_set_var(RzAnalysisFunction *fcn, int delta, char kind, RZ_NULLABLE RzType *type, int size, bool isarg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(fcn && name, NULL);
	RzAnalysisVar *existing = rz_analysis_function_get_var_byname(fcn, name);
	if (existing && (existing->kind != kind || existing->delta != delta)) {
		// var name already exists at a different kind+delta
		return NULL;
	}
	RzRegItem *reg = NULL;
	if (!kind) {
		kind = RZ_ANALYSIS_VAR_KIND_BPV;
	}
	if (!type) {
		const char *typestr = __int_type_from_size(size);
		if (!typestr) {
			typestr = __int_type_from_size(fcn->analysis->bits);
		}
		if (!typestr) {
			typestr = "int32_t";
		}
		type = rz_type_parse(fcn->analysis->typedb->parser, typestr, NULL);
	}
	switch (kind) {
	case RZ_ANALYSIS_VAR_KIND_BPV: // base pointer var/args
	case RZ_ANALYSIS_VAR_KIND_SPV: // stack pointer var/args
	case RZ_ANALYSIS_VAR_KIND_REG: // registers args
		break;
	default:
		eprintf("Invalid var kind '%c'\n", kind);
		return NULL;
	}
	if (kind == RZ_ANALYSIS_VAR_KIND_REG) {
		reg = rz_reg_index_get(fcn->analysis->reg, RZ_ABS(delta));
		if (!reg) {
			eprintf("Register wasn't found at the given delta\n");
			return NULL;
		}
	}
	RzAnalysisVar *var = rz_analysis_function_get_var(fcn, kind, delta);
	if (!var) {
		var = RZ_NEW0(RzAnalysisVar);
		if (!var) {
			return NULL;
		}
		rz_pvector_push(&fcn->vars, var);
		var->fcn = fcn;
		rz_vector_init(&var->accesses, sizeof(RzAnalysisVarAccess), NULL, NULL);
		rz_vector_init(&var->constraints, sizeof(RzAnalysisVarConstraint), NULL, NULL);
	} else {
		free(var->name);
		free(var->regname);
		free(var->type);
	}
	var->name = strdup(name);
	var->regname = reg ? strdup(reg->name) : NULL; // TODO: no strdup here? pool? or not keep regname at all?
	var->type = rz_type_parse(fcn->analysis->typedb->parser, type, NULL);
	var->kind = kind;
	var->isarg = isarg;
	var->delta = delta;
	shadow_var_struct_members(var);
	return var;
}

RZ_API void rz_analysis_var_set_type(RzAnalysisVar *var, const char *type) {
	char *nt = strdup(type);
	if (!nt) {
		return;
	}
	free(var->type);
	var->type = nt;
	shadow_var_struct_members(var);
}

static void var_free(RzAnalysisVar *var) {
	if (!var) {
		return;
	}
	rz_analysis_var_clear_accesses(var);
	rz_vector_fini(&var->constraints);
	free(var->name);
	free(var->regname);
	free(var->type);
	free(var->comment);
	free(var);
}

RZ_API void rz_analysis_var_delete(RzAnalysisVar *var) {
	rz_return_if_fail(var);
	RzAnalysisFunction *fcn = var->fcn;
	size_t i;
	for (i = 0; i < rz_pvector_len(&fcn->vars); i++) {
		RzAnalysisVar *v = rz_pvector_at(&fcn->vars, i);
		if (v == var) {
			rz_pvector_remove_at(&fcn->vars, i);
			var_free(v);
			return;
		}
	}
}

RZ_API void rz_analysis_function_delete_vars_by_kind(RzAnalysisFunction *fcn, RzAnalysisVarKind kind) {
	rz_return_if_fail(fcn);
	size_t i;
	for (i = 0; i < rz_pvector_len(&fcn->vars);) {
		RzAnalysisVar *var = rz_pvector_at(&fcn->vars, i);
		if (var->kind == kind) {
			rz_pvector_remove_at(&fcn->vars, i);
			var_free(var);
			continue;
		}
		i++;
	}
}

RZ_API void rz_analysis_function_delete_all_vars(RzAnalysisFunction *fcn) {
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		var_free(*it);
	}
	rz_pvector_clear(&fcn->vars);
}

RZ_API void rz_analysis_function_delete_unused_vars(RzAnalysisFunction *fcn) {
	void **v;
	RzPVector *vars_clone = (RzPVector *)rz_vector_clone((RzVector *)&fcn->vars);
	rz_pvector_foreach (vars_clone, v) {
		RzAnalysisVar *var = *v;
		if (rz_vector_empty(&var->accesses)) {
			rz_analysis_function_delete_var(fcn, var);
		}
	}
	rz_pvector_free(vars_clone);
}

RZ_API void rz_analysis_function_delete_var(RzAnalysisFunction *fcn, RzAnalysisVar *var) {
	rz_return_if_fail(fcn && var);
	rz_pvector_remove_data(&fcn->vars, var);
	var_free(var);
}

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

RZ_API RzAnalysisVar *rz_analysis_function_get_var(RzAnalysisFunction *fcn, char kind, int delta) {
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (var->kind == kind && var->delta == delta) {
			return var;
		}
	}
	return NULL;
}

RZ_API ut64 rz_analysis_var_addr(RzAnalysisVar *var) {
	rz_return_val_if_fail(var, UT64_MAX);
	RzAnalysis *analysis = var->fcn->analysis;
	const char *regname = NULL;
	if (var->kind == RZ_ANALYSIS_VAR_KIND_BPV) {
		regname = rz_reg_get_name(analysis->reg, RZ_REG_NAME_BP);
		return rz_reg_getv(analysis->reg, regname) + var->delta + var->fcn->bp_off;
	} else if (var->kind == RZ_ANALYSIS_VAR_KIND_SPV) {
		regname = rz_reg_get_name(analysis->reg, RZ_REG_NAME_SP);
		return rz_reg_getv(analysis->reg, regname) + var->delta;
	}
	return 0;
}

RZ_API st64 rz_analysis_function_get_var_stackptr_at(RzAnalysisFunction *fcn, st64 delta, ut64 addr) {
	st64 offset = (st64)addr - (st64)fcn->addr;
	RzPVector *inst_accesses = ht_up_find(fcn->inst_vars, offset, NULL);
	if (!inst_accesses) {
		return ST64_MAX;
	}
	RzAnalysisVar *var = NULL;
	void **it;
	rz_pvector_foreach (inst_accesses, it) {
		RzAnalysisVar *v = *it;
		if (v->delta == delta) {
			var = v;
			break;
		}
	}
	if (!var) {
		return ST64_MAX;
	}
	size_t index;
	rz_vector_lower_bound(&var->accesses, offset, index, ACCESS_CMP);
	RzAnalysisVarAccess *acc = NULL;
	if (index < var->accesses.len) {
		acc = rz_vector_index_ptr(&var->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		return ST64_MAX;
	}
	return acc->stackptr;
}

RZ_API const char *rz_analysis_function_get_var_reg_at(RzAnalysisFunction *fcn, st64 delta, ut64 addr) {
	st64 offset = (st64)addr - (st64)fcn->addr;
	RzPVector *inst_accesses = ht_up_find(fcn->inst_vars, offset, NULL);
	if (!inst_accesses) {
		return NULL;
	}
	RzAnalysisVar *var = NULL;
	void **it;
	rz_pvector_foreach (inst_accesses, it) {
		RzAnalysisVar *v = *it;
		if (v->delta == delta) {
			var = v;
			break;
		}
	}
	if (!var) {
		return NULL;
	}
	size_t index;
	rz_vector_lower_bound(&var->accesses, offset, index, ACCESS_CMP);
	RzAnalysisVarAccess *acc = NULL;
	if (index < var->accesses.len) {
		acc = rz_vector_index_ptr(&var->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		return NULL;
	}
	return acc->reg;
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
			eprintf("variable or arg with name `%s` already exist\n", new_name);
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

RZ_API int rz_analysis_var_get_argnum(RzAnalysisVar *var) {
	rz_return_val_if_fail(var, -1);
	RzAnalysis *analysis = var->fcn->analysis;
	if (!var->isarg || var->kind != RZ_ANALYSIS_VAR_KIND_REG) { // TODO: support bp and sp too
		return -1;
	}
	if (!var->regname) {
		return -1;
	}
	RzRegItem *reg = rz_reg_get(analysis->reg, var->regname, -1);
	if (!reg) {
		return -1;
	}
	int i;
	int arg_max = var->fcn->cc ? rz_analysis_cc_max_arg(analysis, var->fcn->cc) : 0;
	for (i = 0; i < arg_max; i++) {
		const char *reg_arg = rz_analysis_cc_arg(analysis, var->fcn->cc, i);
		if (reg_arg && !strcmp(reg->name, reg_arg)) {
			return i;
		}
	}
	return -1;
}

RZ_API RZ_BORROW RzPVector *rz_analysis_function_get_vars_used_at(RzAnalysisFunction *fcn, ut64 op_addr) {
	rz_return_val_if_fail(fcn, NULL);
	return ht_up_find(fcn->inst_vars, (st64)op_addr - (st64)fcn->addr, NULL);
}

RZ_API RZ_DEPRECATE RzAnalysisVar *rz_analysis_get_used_function_var(RzAnalysis *analysis, ut64 addr) {
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
	rz_vector_foreach(&var->accesses, acc) {
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

RZ_API void rz_analysis_var_set_access(RzAnalysisVar *var, const char *reg, ut64 access_addr, int access_type, st64 stackptr) {
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
	acc->stackptr = stackptr;
	acc->reg = rz_str_constpool_get(&var->fcn->analysis->constpool, reg);

	// add the inverse reference from the instruction to the var
	RzPVector *inst_accesses = ht_up_find(var->fcn->inst_vars, (ut64)offset, NULL);
	if (!inst_accesses) {
		inst_accesses = rz_pvector_new(NULL);
		if (!inst_accesses) {
			return;
		}
		ht_up_insert(var->fcn->inst_vars, (ut64)offset, inst_accesses);
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
		rz_vector_foreach(&var->accesses, acc) {
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

RZ_API void rz_analysis_var_add_constraint(RzAnalysisVar *var, RZ_BORROW RzAnalysisVarConstraint *constraint) {
	rz_vector_push(&var->constraints, constraint);
}

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
		RzAnalysisVarConstraint *constr = rz_vector_index_ptr(&var->constraints, i);
		switch (constr->cond) {
		case RZ_ANALYSIS_COND_LE:
			if (high) {
				rz_strbuf_append(&sb, " && ");
			}
			rz_strbuf_appendf(&sb, "<= 0x%" PFMT64x "", constr->val);
			low = true;
			break;
		case RZ_ANALYSIS_COND_LT:
			if (high) {
				rz_strbuf_append(&sb, " && ");
			}
			rz_strbuf_appendf(&sb, "< 0x%" PFMT64x "", constr->val);
			low = true;
			break;
		case RZ_ANALYSIS_COND_GE:
			rz_strbuf_appendf(&sb, ">= 0x%" PFMT64x "", constr->val);
			high = true;
			break;
		case RZ_ANALYSIS_COND_GT:
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

RZ_API int rz_analysis_var_count(RzAnalysis *a, RzAnalysisFunction *fcn, int kind, int type) {
	// type { local: 0, arg: 1 };
	RzList *list = rz_analysis_var_list(a, fcn, kind);
	RzAnalysisVar *var;
	RzListIter *iter;
	int count[2] = {
		0
	};
	rz_list_foreach (list, iter, var) {
		if (kind == RZ_ANALYSIS_VAR_KIND_REG) {
			count[1]++;
			continue;
		}
		count[var->isarg]++;
	}
	rz_list_free(list);
	return count[type];
}

static bool var_add_structure_fields_to_list(RzAnalysis *a, RzAnalysisVar *av, RzList *list) {
	RzBaseType *btype = rz_type_db_get_base_type(a->typedb, av->type);
	if (!btype || btype->kind != RZ_BASE_TYPE_KIND_STRUCT) {
		return false;
	}
	if (rz_vector_empty(&btype->struct_data.members)) {
		return false;
	}
	RzTypeStructMember *member;
	rz_vector_foreach(&btype->struct_data.members, member) {
		char *new_name = rz_str_newf("%s.%s", av->name, member->name);
		RzAnalysisVarField *field = RZ_NEW0(RzAnalysisVarField);
		field->name = new_name;
		field->delta = av->delta + member->offset;
		field->field = true;
		rz_list_append(list, field);
	}
	return false;
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

RZ_API RZ_OWN char *rz_analysis_function_autoname_var(RzAnalysisFunction *fcn, char kind, const char *pfx, int ptr) {
	void **it;
	const ut32 uptr = RZ_ABS(ptr);
	char *varname = rz_str_newf("%s_%xh", pfx, uptr);
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (!strcmp(varname, var->name)) {
			if (var->kind != kind) {
				const char *k = kind == RZ_ANALYSIS_VAR_KIND_SPV ? "sp" : "bp";
				free(varname);
				varname = rz_str_newf("%s_%s_%xh", pfx, k, uptr);
				return varname;
			}
			int i = 2;
			do {
				free(varname);
				varname = rz_str_newf("%s_%xh_%u", pfx, uptr, i++);
			} while (rz_analysis_function_get_var_byname(fcn, varname));
			return varname;
		}
	}
	return varname;
}

static RzAnalysisVar *get_stack_var(RzAnalysisFunction *fcn, int delta) {
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		bool is_stack = var->kind == RZ_ANALYSIS_VAR_KIND_SPV || var->kind == RZ_ANALYSIS_VAR_KIND_BPV;
		if (is_stack && var->delta == delta) {
			return var;
		}
	}
	return NULL;
}

static void extract_arg(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op, const char *reg, const char *sign, char type) {
	st64 ptr = 0;
	char *addr, *esil_buf = NULL;

	rz_return_if_fail(analysis && fcn && op && reg);

	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(op->src); i++) {
		if (op->src[i] && op->src[i]->reg && op->src[i]->reg->name) {
			if (!strcmp(reg, op->src[i]->reg->name)) {
				st64 delta = op->src[i]->delta;
				if ((delta > 0 && *sign == '+') || (delta < 0 && *sign == '-')) {
					ptr = RZ_ABS(op->src[i]->delta);
					break;
				}
			}
		}
	}

	if (!ptr) {
		const char *op_esil = rz_strbuf_get(&op->esil);
		if (!op_esil) {
			return;
		}
		esil_buf = strdup(op_esil);
		if (!esil_buf) {
			return;
		}
		char *ptr_end = strstr(esil_buf, sdb_fmt(",%s,%s,", reg, sign));
		if (!ptr_end) {
			free(esil_buf);
			return;
		}
		*ptr_end = 0;
		addr = ptr_end;
		while ((addr[0] != '0' || addr[1] != 'x') && addr >= esil_buf + 1 && *addr != ',') {
			addr--;
		}
		if (strncmp(addr, "0x", 2)) {
			//XXX: This is a workaround for inconsistent esil
			if (!op->stackop && op->dst) {
				const char *sp = rz_reg_get_name(analysis->reg, RZ_REG_NAME_SP);
				const char *bp = rz_reg_get_name(analysis->reg, RZ_REG_NAME_BP);
				const char *rn = op->dst->reg ? op->dst->reg->name : NULL;
				if (rn && ((bp && !strcmp(bp, rn)) || (sp && !strcmp(sp, rn)))) {
					if (analysis->verbose) {
						eprintf("Warning: Analysis didn't fill op->stackop for instruction that alters stack at 0x%" PFMT64x ".\n", op->addr);
					}
					goto beach;
				}
			}
			if (*addr == ',') {
				addr++;
			}
			if (!op->stackop && op->type != RZ_ANALYSIS_OP_TYPE_PUSH && op->type != RZ_ANALYSIS_OP_TYPE_POP && op->type != RZ_ANALYSIS_OP_TYPE_RET && rz_str_isnumber(addr)) {
				ptr = (st64)rz_num_get(NULL, addr);
				if (ptr && op->src[0] && ptr == op->src[0]->imm) {
					goto beach;
				}
			} else if ((op->stackop == RZ_ANALYSIS_STACK_SET) || (op->stackop == RZ_ANALYSIS_STACK_GET)) {
				if (op->ptr % 4) {
					goto beach;
				}
				ptr = RZ_ABS(op->ptr);
			} else {
				goto beach;
			}
		} else {
			ptr = (st64)rz_num_get(NULL, addr);
		}
	}

	if (analysis->verbose && (!op->src[0] || !op->dst)) {
		eprintf("Warning: Analysis didn't fill op->src/dst at 0x%" PFMT64x ".\n", op->addr);
	}

	int rw = (op->direction == RZ_ANALYSIS_OP_DIR_WRITE) ? RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE : RZ_ANALYSIS_VAR_ACCESS_TYPE_READ;
	if (*sign == '+') {
		const bool isarg = type == RZ_ANALYSIS_VAR_KIND_SPV ? ptr >= fcn->stack : ptr >= fcn->bp_off;
		const char *pfx = isarg ? ARGPREFIX : VARPREFIX;
		st64 frame_off;
		if (type == RZ_ANALYSIS_VAR_KIND_SPV) {
			frame_off = ptr - fcn->stack;
		} else {
			frame_off = ptr - fcn->bp_off;
		}
		RzAnalysisVar *var = get_stack_var(fcn, frame_off);
		if (var) {
			rz_analysis_var_set_access(var, reg, op->addr, rw, ptr);
			goto beach;
		}
		char *varname = NULL, *vartype = NULL;
		if (isarg) {
			const char *place = fcn->cc ? rz_analysis_cc_arg(analysis, fcn->cc, ST32_MAX) : NULL;
			bool stack_rev = place ? !strcmp(place, "stack_rev") : false;
			char *fname = rz_type_func_guess(analysis->typedb, fcn->name);
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
				for (i = from; stack_rev ? i >= to : i < to; stack_rev ? i-- : i++) {
					char *tp = rz_type_func_args_type(analysis->typedb, fname, i);
					if (!tp) {
						break;
					}
					if (sum_sz == frame_off) {
						vartype = tp;
						varname = strdup(rz_type_func_args_name(analysis->typedb, fname, i));
						break;
					}
					ut64 bit_sz = rz_type_db_get_bitsize(analysis->typedb, tp);
					sum_sz += bit_sz ? bit_sz / 8 : bytes;
					sum_sz = RZ_ROUND(sum_sz, bytes);
					free(tp);
				}
				free(fname);
			}
		}
		if (!varname) {
			if (analysis->opt.varname_stack) {
				varname = rz_str_newf("%s_%" PFMT64x "h", pfx, RZ_ABS(frame_off));
			} else {
				varname = rz_analysis_function_autoname_var(fcn, type, pfx, ptr);
			}
		}
		if (varname) {
			RzAnalysisVar *var = rz_analysis_function_set_var(fcn, frame_off, type, vartype, analysis->bits / 8, isarg, varname);
			if (var) {
				rz_analysis_var_set_access(var, reg, op->addr, rw, ptr);
			}
			free(varname);
		}
		free(vartype);
	} else {
		st64 frame_off = -(ptr + fcn->bp_off);
		RzAnalysisVar *var = get_stack_var(fcn, frame_off);
		if (var) {
			rz_analysis_var_set_access(var, reg, op->addr, rw, -ptr);
			goto beach;
		}
		char *varname = analysis->opt.varname_stack
			? rz_str_newf("%s_%" PFMT64x "h", VARPREFIX, RZ_ABS(frame_off))
			: rz_analysis_function_autoname_var(fcn, type, VARPREFIX, -ptr);
		if (varname) {
			RzAnalysisVar *var = rz_analysis_function_set_var(fcn, frame_off, type, NULL, analysis->bits / 8, false, varname);
			if (var) {
				rz_analysis_var_set_access(var, reg, op->addr, rw, -ptr);
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
		//fallthrough
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
	char *fname = rz_type_func_guess(analysis->typedb, fcn->name);
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
		int callee_rargs = 0;
		char *callee = NULL;
		ut64 offset = op->jump == UT64_MAX ? op->ptr : op->jump;
		RzAnalysisFunction *f = rz_analysis_get_function_at(analysis, offset);
		if (!f) {
			RzCore *core = (RzCore *)analysis->coreb.core;
			RzFlagItem *flag = rz_flag_get_by_spaces(core->flags, offset, RZ_FLAGS_FS_IMPORTS, NULL);
			if (flag) {
				callee = rz_type_func_guess(analysis->typedb, flag->name);
				if (callee) {
					const char *cc = rz_analysis_cc_func(analysis, callee);
					if (cc && !strcmp(fcn->cc, cc)) {
						callee_rargs = RZ_MIN(max_count, rz_type_func_args_count(analysis->typedb, callee));
					}
				}
			}
		} else if (!f->is_variadic && !strcmp(fcn->cc, f->cc)) {
			callee = rz_type_func_guess(analysis->typedb, f->name);
			if (callee) {
				callee_rargs = RZ_MIN(max_count, rz_type_func_args_count(analysis->typedb, callee));
			}
			callee_rargs = callee_rargs
				? callee_rargs
				: rz_analysis_var_count(analysis, f, RZ_ANALYSIS_VAR_KIND_REG, 1);
			callee_rargs_l = rz_analysis_var_list(analysis, f, RZ_ANALYSIS_VAR_KIND_REG);
		}
		size_t i;
		for (i = 0; i < callee_rargs; i++) {
			if (reg_set[i]) {
				continue;
			}
			const char *vname = NULL;
			char *type = NULL;
			char *name = NULL;
			int delta = 0;
			const char *regname = rz_analysis_cc_arg(analysis, fcn->cc, i);
			RzRegItem *ri = rz_reg_get(analysis->reg, regname, -1);
			if (ri) {
				delta = ri->index;
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
					const char *argtype = rz_type_as_string(analysis->typedb, found_arg->type);
					type = argtype;
					vname = name = strdup(found_arg->name);
				}
			}
			if (!vname) {
				name = rz_str_newf("arg%zu", i + 1);
				vname = name;
			}
			rz_analysis_function_set_var(fcn, delta, RZ_ANALYSIS_VAR_KIND_REG, type, size, true, vname);
			(*count)++;
			free(name);
			free(type);
		}
		free(callee);
		rz_list_free(callee_rargs_l);
		free(fname);
		return;
	}

	for (i = 0; i < max_count; i++) {
		const char *regname = rz_analysis_cc_arg(analysis, fcn->cc, i);
		if (regname) {
			int delta = 0;
			RzRegItem *ri = NULL;
			RzAnalysisVar *var = NULL;
			bool is_used_like_an_arg = is_used_like_arg(regname, opsreg, opdreg, op, analysis);
			if (reg_set[i] != 2 && is_used_like_an_arg) {
				ri = rz_reg_get(analysis->reg, regname, -1);
				if (ri) {
					delta = ri->index;
				}
			}
			if (reg_set[i] == 1 && is_used_like_an_arg) {
				var = rz_analysis_function_get_var(fcn, RZ_ANALYSIS_VAR_KIND_REG, delta);
			} else if (reg_set[i] != 2 && is_used_like_an_arg) {
				const char *vname = NULL;
				char *type = NULL;
				char *name = NULL;
				if ((i < argc) && fname) {
					type = rz_type_func_args_type(analysis->typedb, fname, i);
					vname = rz_type_func_args_name(analysis->typedb, fname, i);
				}
				if (!vname) {
					name = rz_str_newf("arg%d", i + 1);
					vname = name;
				}
				var = rz_analysis_function_set_var(fcn, delta, RZ_ANALYSIS_VAR_KIND_REG, type, size, true, vname);
				free(name);
				free(type);
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
				rz_analysis_var_set_access(var, var->regname, op->addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 0);
				rz_meta_set_string(analysis, RZ_META_TYPE_VARTYPE, op->addr, var->name);
			}
		}
	}

	const char *selfreg = rz_analysis_cc_self(analysis, fcn->cc);
	if (selfreg) {
		bool is_used_like_an_arg = is_used_like_arg(selfreg, opsreg, opdreg, op, analysis);
		if (reg_set[i] != 2 && is_used_like_an_arg) {
			int delta = 0;
			char *vname = strdup("self");
			RzRegItem *ri = rz_reg_get(analysis->reg, selfreg, -1);
			if (ri) {
				delta = ri->index;
			}
			RzAnalysisVar *newvar = rz_analysis_function_set_var(fcn, delta, RZ_ANALYSIS_VAR_KIND_REG, 0, size, true, vname);
			if (newvar) {
				rz_analysis_var_set_access(newvar, newvar->regname, op->addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 0);
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
			int delta = 0;
			char *vname = strdup("error");
			RzRegItem *ri = rz_reg_get(analysis->reg, errorreg, -1);
			if (ri) {
				delta = ri->index;
			}
			RzAnalysisVar *newvar = rz_analysis_function_set_var(fcn, delta, RZ_ANALYSIS_VAR_KIND_REG, 0, size, true, vname);
			if (newvar) {
				rz_analysis_var_set_access(newvar, newvar->regname, op->addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 0);
			}
			rz_meta_set_string(analysis, RZ_META_TYPE_VARTYPE, op->addr, vname);
			free(vname);
			(*count)++;
			reg_set[i] = 2;
		}
	}
	free(fname);
}

RZ_API void rz_analysis_extract_vars(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisOp *op) {
	rz_return_if_fail(analysis && fcn && op);

	const char *BP = analysis->reg->name[RZ_REG_NAME_BP];
	const char *SP = analysis->reg->name[RZ_REG_NAME_SP];
	if (BP) {
		extract_arg(analysis, fcn, op, BP, "+", RZ_ANALYSIS_VAR_KIND_BPV);
		extract_arg(analysis, fcn, op, BP, "-", RZ_ANALYSIS_VAR_KIND_BPV);
	}
	extract_arg(analysis, fcn, op, SP, "+", RZ_ANALYSIS_VAR_KIND_SPV);
}

static RzList *var_generate_list(RzAnalysis *a, RzAnalysisFunction *fcn, int kind) {
	if (!a || !fcn) {
		return NULL;
	}
	RzList *list = rz_list_new();
	if (kind < 1) {
		kind = RZ_ANALYSIS_VAR_KIND_BPV; // by default show vars
	}
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (var->kind == kind) {
			rz_list_push(list, var);
		}
	}
	return list;
}

RZ_API RzList *rz_analysis_var_all_list(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	// rz_analysis_var_list if there are not vars with that kind returns a list with
	// zero element.. which is an unnecessary loss of cpu time
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	RzList *reg_vars = rz_analysis_var_list(analysis, fcn, RZ_ANALYSIS_VAR_KIND_REG);
	RzList *bpv_vars = rz_analysis_var_list(analysis, fcn, RZ_ANALYSIS_VAR_KIND_BPV);
	RzList *spv_vars = rz_analysis_var_list(analysis, fcn, RZ_ANALYSIS_VAR_KIND_SPV);
	rz_list_join(list, reg_vars);
	rz_list_join(list, bpv_vars);
	rz_list_join(list, spv_vars);
	rz_list_free(reg_vars);
	rz_list_free(bpv_vars);
	rz_list_free(spv_vars);
	return list;
}

RZ_API RzList *rz_analysis_var_list(RzAnalysis *a, RzAnalysisFunction *fcn, int kind) {
	return var_generate_list(a, fcn, kind);
}

static void var_field_free(RzAnalysisVarField *field) {
	if (!field) {
		return;
	}
	free(field->name);
	free(field);
}

RZ_API RzList *rz_analysis_function_get_var_fields(RzAnalysisFunction *fcn, int kind) {
	if (!fcn) {
		return NULL;
	}
	RzList *list = rz_list_newf((RzListFree)var_field_free);
	if (kind < 1) {
		kind = RZ_ANALYSIS_VAR_KIND_BPV; // by default show vars
	}
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		if (var->kind != kind) {
			continue;
		}
		if (var_add_structure_fields_to_list(fcn->analysis, var, list)) {
			// this var is a struct and var_add_structure_fields_to_list added all the fields
			continue;
		}
		RzAnalysisVarField *field = RZ_NEW0(RzAnalysisVarField);
		if (!field) {
			break;
		}
		field->name = strdup(var->name);
		if (!field->name) {
			var_field_free(field);
			break;
		}
		field->delta = var->delta;
		rz_list_push(list, field);
	}
	return list;
}

static int var_comparator(const RzAnalysisVar *a, const RzAnalysisVar *b) {
	// avoid NULL dereference
	return (a && b) ? (a->delta > b->delta) - (a->delta < b->delta) : 0;
}

static int regvar_comparator(const RzAnalysisVar *a, const RzAnalysisVar *b) {
	// avoid NULL dereference
	return (a && b) ? (a->argnum > b->argnum) - (a->argnum < b->argnum) : 0;
}

RZ_API void rz_analysis_var_list_show(RzAnalysis *analysis, RzAnalysisFunction *fcn, int kind, int mode, PJ *pj) {
	RzAnalysisVar *var;
	RzListIter *iter;
	if (!pj && mode == 'j') {
		return;
	}
	if (mode == 'j') {
		pj_a(pj);
	}
	RzList *list = rz_analysis_var_list(analysis, fcn, kind);
	if (!list) {
		if (mode == 'j') {
			pj_end(pj);
		}
		return;
	}
	rz_list_sort(list, (RzListComparator)var_comparator);
	rz_list_foreach (list, iter, var) {
		if (var->kind != kind) {
			continue;
		}
		switch (mode) {
		case '*': {
			// we can't express all type info here :(
			const char *vartype = rz_type_as_string(analysis->typedb, var->type);
			if (kind == RZ_ANALYSIS_VAR_KIND_REG) { // registers
				RzRegItem *i = rz_reg_index_get(analysis->reg, var->delta);
				if (!i) {
					eprintf("Register not found");
					break;
				}
				analysis->cb_printf("afv%c %s %s %s @ 0x%" PFMT64x "\n",
					kind, i->name, var->name, vartype, fcn->addr);
			} else {
				int delta = kind == RZ_ANALYSIS_VAR_KIND_BPV
					? var->delta + fcn->bp_off
					: var->delta;
				analysis->cb_printf("afv%c %d %s %s @ 0x%" PFMT64x "\n",
					kind, delta, var->name, vartype,
					fcn->addr);
			}
			break;
		}
		case 'j':
			switch (var->kind) {
			case RZ_ANALYSIS_VAR_KIND_BPV: {
				const char *vartype = rz_type_as_string(analysis->typedb, var->type);
				st64 delta = (st64)var->delta + fcn->bp_off;
				pj_o(pj);
				pj_ks(pj, "name", var->name);
				if (var->isarg) {
					pj_ks(pj, "kind", "arg");
				} else {
					pj_ks(pj, "kind", "var");
				}
				pj_ks(pj, "type", vartype);
				pj_k(pj, "ref");
				pj_o(pj);
				pj_ks(pj, "base", analysis->reg->name[RZ_REG_NAME_BP]);
				pj_kN(pj, "offset", delta);
				pj_end(pj);
				pj_end(pj);
			} break;
			case RZ_ANALYSIS_VAR_KIND_REG: {
				RzRegItem *i = rz_reg_index_get(analysis->reg, var->delta);
				if (!i) {
					eprintf("Register not found");
					break;
				}
				const char *vartype = rz_type_as_string(analysis->typedb, var->type);
				pj_o(pj);
				pj_ks(pj, "name", var->name);
				pj_ks(pj, "kind", "reg");
				pj_ks(pj, "type", vartype);
				pj_ks(pj, "ref", i->name);
				pj_end(pj);
			} break;
			case RZ_ANALYSIS_VAR_KIND_SPV: {
				st64 delta = (st64)var->delta + fcn->maxstack;
				pj_o(pj);
				pj_ks(pj, "name", var->name);
				if (var->isarg) {
					pj_ks(pj, "kind", "arg");
				} else {
					pj_ks(pj, "kind", "var");
				}
				const char *vartype = rz_type_as_string(analysis->typedb, var->type);
				pj_ks(pj, "type", vartype);
				pj_k(pj, "ref");
				pj_o(pj);
				pj_ks(pj, "base", analysis->reg->name[RZ_REG_NAME_SP]);
				pj_kN(pj, "offset", delta);
				pj_end(pj);
				pj_end(pj);
			} break;
			}
			break;
		default:
			switch (kind) {
			case RZ_ANALYSIS_VAR_KIND_BPV: {
				int delta = var->delta + fcn->bp_off;
				const char *vartype = rz_type_as_string(analysis->typedb, var->type);
				if (var->isarg) {
					analysis->cb_printf("arg %s %s @ %s+0x%x\n",
						vartype, var->name,
						analysis->reg->name[RZ_REG_NAME_BP],
						delta);
				} else {
					char sign = (-var->delta <= fcn->bp_off) ? '+' : '-';
					analysis->cb_printf("var %s %s @ %s%c0x%x\n",
						vartype, var->name,
						analysis->reg->name[RZ_REG_NAME_BP],
						sign, RZ_ABS(delta));
				}
			} break;
			case RZ_ANALYSIS_VAR_KIND_REG: {
				RzRegItem *i = rz_reg_index_get(analysis->reg, var->delta);
				if (!i) {
					eprintf("Register not found");
					break;
				}
				const char *vartype = rz_type_as_string(analysis->typedb, var->type);
				analysis->cb_printf("arg %s %s @ %s\n",
					vartype, var->name, i->name);
			} break;
			case RZ_ANALYSIS_VAR_KIND_SPV: {
				int delta = fcn->maxstack + var->delta;
				const char *vartype = rz_type_as_string(analysis->typedb, var->type);
				if (!var->isarg) {
					char sign = (-var->delta <= fcn->maxstack) ? '+' : '-';
					analysis->cb_printf("var %s %s @ %s%c0x%x\n",
						vartype, var->name,
						analysis->reg->name[RZ_REG_NAME_SP],
						sign, RZ_ABS(delta));
				} else {
					analysis->cb_printf("arg %s %s @ %s+0x%x\n",
						vartype, var->name,
						analysis->reg->name[RZ_REG_NAME_SP],
						delta);
				}
			} break;
			}
		}
	}
	if (mode == 'j') {
		pj_end(pj);
	}
	rz_list_free(list);
}

RZ_API void rz_analysis_fcn_vars_cache_init(RzAnalysis *analysis, RzAnalysisFcnVarsCache *cache, RzAnalysisFunction *fcn) {
	cache->bvars = rz_analysis_var_list(analysis, fcn, RZ_ANALYSIS_VAR_KIND_BPV);
	cache->rvars = rz_analysis_var_list(analysis, fcn, RZ_ANALYSIS_VAR_KIND_REG);
	cache->svars = rz_analysis_var_list(analysis, fcn, RZ_ANALYSIS_VAR_KIND_SPV);
	rz_list_sort(cache->bvars, (RzListComparator)var_comparator);
	RzListIter *it;
	RzAnalysisVar *var;
	rz_list_foreach (cache->rvars, it, var) {
		var->argnum = rz_analysis_var_get_argnum(var);
	}
	rz_list_sort(cache->rvars, (RzListComparator)regvar_comparator);
	rz_list_sort(cache->svars, (RzListComparator)var_comparator);
}

RZ_API void rz_analysis_fcn_vars_cache_fini(RzAnalysisFcnVarsCache *cache) {
	if (!cache) {
		return;
	}
	rz_list_free(cache->bvars);
	rz_list_free(cache->rvars);
	rz_list_free(cache->svars);
}

RZ_API char *rz_analysis_fcn_format_sig(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NULLABLE char *fcn_name,
	RZ_NULLABLE RzAnalysisFcnVarsCache *reuse_cache, RZ_NULLABLE const char *fcn_name_pre, RZ_NULLABLE const char *fcn_name_post) {
	RzAnalysisFcnVarsCache *cache = NULL;

	if (!fcn_name) {
		fcn_name = fcn->name;
		if (!fcn_name) {
			return NULL;
		}
	}

	RzStrBuf *buf = rz_strbuf_new(NULL);
	if (!buf) {
		return NULL;
	}

	char *type_fcn_name = rz_type_func_guess(analysis->typedb, fcn_name);
	if (type_fcn_name && rz_type_func_exist(analysis->typedb, type_fcn_name)) {
		const char *fcn_type = rz_type_func_ret(analysis->typedb, type_fcn_name);
		if (fcn_type) {
			const char *sp = " ";
			if (*fcn_type && (fcn_type[strlen(fcn_type) - 1] == '*')) {
				sp = "";
			}
			rz_strbuf_appendf(buf, "%s%s", fcn_type, sp);
		}
	}

	if (fcn_name_pre) {
		rz_strbuf_append(buf, fcn_name_pre);
	}
	rz_strbuf_append(buf, fcn_name);
	if (fcn_name_post) {
		rz_strbuf_append(buf, fcn_name_post);
	}
	rz_strbuf_append(buf, " (");

	if (type_fcn_name && rz_type_func_exist(analysis->typedb, type_fcn_name)) {
		int i, argc = rz_type_func_args_count(analysis->typedb, type_fcn_name);
		bool comma = true;
		// This avoids false positives present in argument recovery
		// and straight away print arguments fetched from types db
		for (i = 0; i < argc; i++) {
			char *type = rz_type_func_args_type(analysis->typedb, type_fcn_name, i);
			const char *name = rz_type_func_args_name(analysis->typedb, type_fcn_name, i);
			if (!type || !name) {
				eprintf("Missing type for %s\n", type_fcn_name);
				goto beach;
			}
			if (i == argc - 1) {
				comma = false;
			}
			size_t len = strlen(type);
			const char *tc = len > 0 && type[len - 1] == '*' ? "" : " ";
			rz_strbuf_appendf(buf, "%s%s%s%s", type, tc, name, comma ? ", " : "");
			free(type);
		}
		goto beach;
	}
	RZ_FREE(type_fcn_name);

	cache = reuse_cache;
	if (!cache) {
		cache = RZ_NEW0(RzAnalysisFcnVarsCache);
		if (!cache) {
			type_fcn_name = NULL;
			goto beach;
		}
		rz_analysis_fcn_vars_cache_init(analysis, cache, fcn);
	}

	bool comma = true;
	bool arg_bp = false;
	size_t tmp_len;
	RzAnalysisVar *var;
	RzListIter *iter;

	rz_list_foreach (cache->rvars, iter, var) {
		// assume self, error are always the last
		if (!strcmp(var->name, "self") || !strcmp(var->name, "error")) {
			rz_strbuf_slice(buf, 0, rz_strbuf_length(buf) - 2);
			break;
		}
		const char *vartype = rz_type_as_string(analysis->typedb, var->type);
		tmp_len = strlen(vartype);
		rz_strbuf_appendf(buf, "%s%s%s%s", vartype,
			tmp_len && vartype[tmp_len - 1] == '*' ? "" : " ",
			var->name, iter->n ? ", " : "");
	}

	rz_list_foreach (cache->bvars, iter, var) {
		if (var->isarg) {
			if (!rz_list_empty(cache->rvars) && comma) {
				rz_strbuf_append(buf, ", ");
				comma = false;
			}
			arg_bp = true;
			const char *vartype = rz_type_as_string(analysis->typedb, var->type);
			tmp_len = strlen(vartype);
			rz_strbuf_appendf(buf, "%s%s%s%s", vartype,
				tmp_len && vartype[tmp_len - 1] == '*' ? "" : " ",
				var->name, iter->n ? ", " : "");
		}
	}

	comma = true;
	const char *maybe_comma = ", ";
	rz_list_foreach (cache->svars, iter, var) {
		if (var->isarg) {
			if (!*maybe_comma || ((arg_bp || !rz_list_empty(cache->rvars)) && comma)) {
				comma = false;
				rz_strbuf_append(buf, ", ");
			}
			const char *vartype = rz_type_as_string(analysis->typedb, var->type);
			tmp_len = strlen(vartype);
			if (iter->n && ((RzAnalysisVar *)iter->n->data)->isarg) {
				maybe_comma = ", ";
			} else {
				maybe_comma = "";
			}
			rz_strbuf_appendf(buf, "%s%s%s%s", vartype,
				tmp_len && vartype[tmp_len - 1] == '*' ? "" : " ",
				var->name, maybe_comma);
		}
	}

beach:
	rz_strbuf_append(buf, ");");
	RZ_FREE(type_fcn_name);
	if (!reuse_cache) {
		// !reuse_cache => we created our own cache
		rz_analysis_fcn_vars_cache_fini(cache);
		free(cache);
	}
	return rz_strbuf_drain(buf);
}

// function argument types and names into analysis/types
RZ_API void rz_analysis_fcn_vars_add_types(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzAnalysisFcnVarsCache cache;
	rz_analysis_fcn_vars_cache_init(analysis, &cache, fcn);
	RzListIter *iter;
	RzAnalysisVar *var;
	int arg_count = 0;

	RzList *all_vars = cache.rvars;
	rz_list_join(all_vars, cache.bvars);
	rz_list_join(all_vars, cache.svars);

	rz_list_foreach (all_vars, iter, var) {
		if (var->isarg) {
			rz_type_func_arg_set(analysis->typedb, fcn->name, arg_count, var->name, var->type);
			arg_count++;
		}
	}
	if (arg_count > 0) {
		rz_type_func_arg_count_set(analysis->typedb, fcn->name, arg_count);
	}
	rz_analysis_fcn_vars_cache_fini(&cache);
}
