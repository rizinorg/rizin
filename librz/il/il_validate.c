// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_validate.h>
#include <rz_util/ht_uu.h>

/////////////////////////////////////////////////////////
// ---------------------- context -----------------------

/**
 * Global (immutable) context
 */
struct rz_il_validate_global_context_t {
	HtSP /*<const char *, RzILSortPure *>*/ *global_vars;
	HtUU /*<RzILMemIndex, ut32:ut32>*/ *mems;
	ut32 pc_len;
}; /* RzILValidateGlobalContext */

/**
 * Create a new global context for validation
 * Vars and mems can be added manually with rz_il_validate_global_context_add_* functions.
 */
RZ_API RzILValidateGlobalContext *rz_il_validate_global_context_new_empty(ut32 pc_len) {
	rz_return_val_if_fail(pc_len, NULL);
	RzILValidateGlobalContext *ctx = RZ_NEW0(RzILValidateGlobalContext);
	if (!ctx) {
		return NULL;
	}
	ctx->pc_len = pc_len;
	ctx->global_vars = ht_sp_new(HT_STR_DUP, NULL, free);
	if (!ctx->global_vars) {
		free(ctx);
		return NULL;
	}
	ctx->mems = ht_uu_new();
	if (!ctx->mems) {
		ht_sp_free(ctx->global_vars);
		free(ctx);
		return NULL;
	}
	return ctx;
}

/**
 * Define a new global variable in \p ctx
 */
RZ_API void rz_il_validate_global_context_add_var(RzILValidateGlobalContext *ctx, RZ_NONNULL const char *name, RzILSortPure sort) {
	rz_return_if_fail(ctx && name);
	RzILSortPure *hts = RZ_NEW(RzILSortPure);
	if (!hts) {
		return;
	}
	*hts = sort;
	ht_sp_update(ctx->global_vars, name, hts);
}

/**
 * Define a new memory in \p ctx
 */
RZ_API void rz_il_validate_global_context_add_mem(RzILValidateGlobalContext *ctx, RzILMemIndex idx, ut32 key_len, ut32 val_len) {
	rz_return_if_fail(ctx && key_len && val_len);
	ht_uu_update(ctx->mems, idx, ((ut64)key_len << 32) | (ut64)val_len);
}

/**
 * Create a new context for IL validation based on the global vars and mems in \p vm
 */
RZ_API RzILValidateGlobalContext *rz_il_validate_global_context_new_from_vm(RZ_NONNULL RzILVM *vm) {
	rz_return_val_if_fail(vm, NULL);
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(rz_il_vm_get_pc_len(vm));
	RzPVector *vars = rz_il_vm_get_all_vars(vm, RZ_IL_VAR_KIND_GLOBAL);
	if (vars) {
		void **it;
		rz_pvector_foreach (vars, it) {
			RzILVar *var = *it;
			rz_il_validate_global_context_add_var(ctx, var->name, var->sort);
		}
		rz_pvector_free(vars);
	}
	for (size_t i = 0; i < rz_pvector_len(&vm->vm_memory); i++) {
		RzILMem *mem = rz_pvector_at(&vm->vm_memory, i);
		if (!mem) {
			continue;
		}
		rz_il_validate_global_context_add_mem(ctx, (RzILMemIndex)i, rz_il_mem_key_len(mem), rz_il_mem_value_len(mem));
	}
	return ctx;
}

RZ_API void rz_il_validate_global_context_free(RzILValidateGlobalContext *ctx) {
	if (!ctx) {
		return;
	}
	ht_sp_free(ctx->global_vars);
	ht_uu_free(ctx->mems);
	free(ctx);
}

typedef struct {
	const RzILValidateGlobalContext *global_ctx;

	/**
	 * all vars' types that were encountered somewhere before, for enforcing vars always have the
	 * same type, even if they are not available anymore.
	 * This must always be a superset of `local_vars_available`.
	 * This owns all values, local_vars_available borrows them.
	 */
	HtSP /*<const char *, RzILSortPure *>*/ *local_vars_known;

	HtSP /*<const char *, RzILSortPure *>*/ *local_vars_available; ///< vars that can be accessed right now
} LocalContext;

static bool local_context_init(LocalContext *ctx, const RzILValidateGlobalContext *global_ctx) {
	ctx->global_ctx = global_ctx;
	ctx->local_vars_known = ht_sp_new(HT_STR_DUP, NULL, free);
	if (!ctx->local_vars_known) {
		return false;
	}
	ctx->local_vars_available = ht_sp_new(HT_STR_DUP, NULL, NULL);
	if (!ctx->local_vars_available) {
		ht_sp_free(ctx->local_vars_known);
		ctx->local_vars_known = NULL;
		return false;
	}
	return true;
}

static void local_context_fini(LocalContext *ctx) {
	ht_sp_free(ctx->local_vars_known);
	ht_sp_free(ctx->local_vars_available);
	ctx->local_vars_known = NULL;
	ctx->local_vars_available = NULL;
}

static bool local_var_copy_known_cb(RZ_NONNULL void *user, const char *k, const void *v) {
	LocalContext *dst = user;
	RzILSortPure *sort = RZ_NEW(RzILSortPure);
	if (!sort) {
		return false;
	}
	*sort = *(RzILSortPure *)v;
	ht_sp_update(dst->local_vars_known, k, sort);
	return true;
}

static bool local_var_copy_avail_cb(RZ_NONNULL void *user, const char *k, const void *v) {
	LocalContext *dst = user;
	RzILSortPure *sort = ht_sp_find(dst->local_vars_known, k, NULL);
	// known is superset of avail, so we can assert this:
	rz_return_val_if_fail(sort && rz_il_sort_pure_eq(*sort, *(RzILSortPure *)v), false);
	ht_sp_update(dst->local_vars_available, k, sort);
	return true;
}

static bool local_context_copy(LocalContext *dst, LocalContext *src) {
	if (!local_context_init(dst, src->global_ctx)) {
		return false;
	}
	ht_sp_foreach(src->local_vars_known, local_var_copy_known_cb, dst);
	ht_sp_foreach(src->local_vars_available, local_var_copy_avail_cb, dst);
	return true;
}

typedef struct {
	bool failed;
	RzStrBuf *report_builder;
	const char *op_name;
	LocalContext *dst;
	LocalContext *src;
} LocalContextMeet;

// called on src, take the union of the known types or fail if they don't agree
static bool local_var_meet_known_cb(RZ_NONNULL void *user, const char *k, const void *v) {
	LocalContextMeet *meet = user;
	RzILSortPure src_sort = *(RzILSortPure *)v;
	RzILSortPure *dst_sort = ht_sp_find(meet->dst->local_vars_known, k, NULL);
	if (dst_sort && !rz_il_sort_pure_eq(src_sort, *dst_sort)) {
		char *src_sort_s = rz_il_sort_pure_stringify(src_sort);
		char *dst_sort_s = rz_il_sort_pure_stringify(*dst_sort);
		rz_strbuf_appendf(meet->report_builder, "Control flow paths from %s op do not agree on the type of local variable \"%s\": %s vs. %s.\n",
			meet->op_name, (const char *)k, src_sort_s, dst_sort_s);
		free(src_sort_s);
		free(dst_sort_s);
		meet->failed = true;
		return false;
	}
	if (!dst_sort) {
		dst_sort = RZ_NEW(RzILSortPure);
		if (!dst_sort) {
			meet->failed = true;
			return false;
		}
		*dst_sort = src_sort;
		ht_sp_update(meet->dst->local_vars_known, k, dst_sort);
	}
	return true;
}

// called on dst, remove all vars from dst that do not appear in src (intersection)
static bool local_var_meet_avail_cb(RZ_NONNULL void *user, const char *k, const void *v) {
	LocalContextMeet *meet = user;
	RzILSortPure *src_sort = ht_sp_find(meet->src->local_vars_available, k, NULL);
	if (!src_sort) {
		ht_sp_delete(meet->dst->local_vars_available, k);
	}
	return true;
}

/**
 * Meet (intersection) of two contexts, usually when two control flow paths meet.
 * Known types for local vars are always kept from both, to ensure they always have the
 * same type in the entire expression.
 * Available local vars are intersected.
 * This fails when \p a and \p b both know about a local var, but don't agree about its type.
 *
 * \p a First input operand, this will also be modified in-place to contain the result.
 * \p b Second input operand, will not be modified.
 * \p report_builder On failure, will be appended with an error message
 * \p op_name Name of the op in which the meet is being performed, for the error message
 * \return whether the meet succeeded
 */
static bool local_context_meet(RZ_INOUT LocalContext *a, RZ_IN LocalContext *b, RzStrBuf *report_builder, const char *op_name) {
	LocalContextMeet meet = {
		.failed = false,
		.report_builder = report_builder,
		.op_name = op_name,
		.dst = a,
		.src = b
	};
	ht_sp_foreach(b->local_vars_known, local_var_meet_known_cb, &meet);
	if (meet.failed) {
		return false;
	}
	ht_sp_foreach(a->local_vars_available, local_var_meet_avail_cb, &meet);
	return true;
}

/////////////////////////////////////////////////////////
/**
 * \name Pure
 * @{
 */

/**
 * Linked list (stack) of let-bound vars
 *
 * While descending, new var definitions are pushed, thus shadowing other vars
 * of the same name when searching from the head.
 */
typedef struct local_pure_var_t {
	const char *name;
	RzILSortPure sort;
	struct local_pure_var_t *next;
} LocalPureVar;

// clang-format off
#define VALIDATOR_PURE_ARGS \
	RZ_NULLABLE RzILOpPure *op, \
	RZ_NONNULL RzILSortPure *sort_out, \
	RZ_NONNULL RzStrBuf *report_builder, \
	RZ_NONNULL const LocalContext *ctx, \
	RZ_NULLABLE LocalPureVar *local_pure_var_stack
// clang-format on

static bool validate_pure(VALIDATOR_PURE_ARGS);
typedef bool (*ValidatePureFn)(VALIDATOR_PURE_ARGS);

#define VALIDATOR_PURE_NAME(op) validate_pure_##op
#define VALIDATOR_PURE(op)      static bool VALIDATOR_PURE_NAME(op)(VALIDATOR_PURE_ARGS)
#define VALIDATOR_ASSERT(condition, ...) \
	do { \
		if (!(condition)) { \
			rz_warn_if_reached(); \
			rz_strbuf_appendf(report_builder, __VA_ARGS__); \
			return false; \
		} \
	} while (0)
#define VALIDATOR_DESCEND(op, sort) \
	do { \
		if (!validate_pure(op, sort, report_builder, ctx, local_pure_var_stack)) { \
			return false; \
		} \
	} while (0)

VALIDATOR_PURE(var) {
	RzILOpArgsVar *args = &op->op.var;
	VALIDATOR_ASSERT(args->v, "Var name of var op is NULL.\n");
	switch (args->kind) {
	case RZ_IL_VAR_KIND_GLOBAL: {
		RzILSortPure *sort = ht_sp_find(ctx->global_ctx->global_vars, args->v, NULL);
		VALIDATOR_ASSERT(sort, "Global variable \"%s\" referenced by var op does not exist.\n", args->v);
		*sort_out = *sort;
		return true;
	}
	case RZ_IL_VAR_KIND_LOCAL: {
		RzILSortPure *sort = ht_sp_find(ctx->local_vars_available, args->v, NULL);
		VALIDATOR_ASSERT(sort, "Local variable \"%s\" is not available at var op.\n", args->v);
		*sort_out = *sort;
		return true;
	}
	case RZ_IL_VAR_KIND_LOCAL_PURE: {
		for (LocalPureVar *loc = local_pure_var_stack; loc; loc = loc->next) {
			if (!strcmp(loc->name, args->v)) {
				*sort_out = loc->sort;
				return true;
			}
		}
		VALIDATOR_ASSERT(false, "Local pure variable \"%s\" unbound at var op.\n", args->v);
		return false;
	}
	default:
		VALIDATOR_ASSERT(false, "Var op has invalid kind.\n");
	}
	return true;
}

VALIDATOR_PURE(bool_const) {
	*sort_out = rz_il_sort_pure_bool();
	return true;
}

VALIDATOR_PURE(bitv) {
	RzBitVector *bv = op->op.bitv.value;
	if (!bv) {
		rz_strbuf_appendf(report_builder, "Bitvector in constant bitvector op is NULL.\n");
		return false;
	}
	*sort_out = rz_il_sort_pure_bv(rz_bv_len(bv));
	return true;
}

/**
 * 'a bitv -> 'a bitv -> 'a bitv ops
 * e.g. add, sub, mul, div, ...
 */
VALIDATOR_PURE(bitv_binop) {
	RzILOpPure *x = op->op.add.x; // just add is fine, all ops in here use the same struct
	RzILOpPure *y = op->op.add.y;
	RzILSortPure sx;
	VALIDATOR_DESCEND(x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BITVECTOR, "Left operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	RzILSortPure sy;
	VALIDATOR_DESCEND(y, &sy);
	VALIDATOR_ASSERT(sy.type == RZ_IL_TYPE_PURE_BITVECTOR, "Right operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	VALIDATOR_ASSERT(sx.props.bv.length == sy.props.bv.length, "Operand sizes of %s op do not agree: %u vs. %u.\n",
		rz_il_op_pure_code_stringify(op->code), (unsigned int)sx.props.bv.length, (unsigned int)sy.props.bv.length);
	*sort_out = sx;
	return true;
}

VALIDATOR_PURE(ite) {
	RzILOpArgsIte *args = &op->op.ite;
	RzILSortPure sc;
	VALIDATOR_DESCEND(args->condition, &sc);
	VALIDATOR_ASSERT(sc.type == RZ_IL_TYPE_PURE_BOOL, "Condition of ite op is not boolean.\n");
	RzILSortPure sx;
	VALIDATOR_DESCEND(args->x, &sx);
	RzILSortPure sy;
	VALIDATOR_DESCEND(args->y, &sy);
	if (!rz_il_sort_pure_eq(sx, sy)) {
		char *sxs = rz_il_sort_pure_stringify(sx);
		char *sys = rz_il_sort_pure_stringify(sy);
		rz_strbuf_appendf(report_builder, "Types of ite branches do not agree: %s vs. %s.\n",
			rz_str_get_null(sxs), rz_str_get_null(sys));
		free(sxs);
		free(sys);
		return false;
	}
	*sort_out = sx;
	return true;
}

VALIDATOR_PURE(let) {
	RzILOpArgsLet *args = &op->op.let;
	VALIDATOR_ASSERT(args->name, "Var name of let op is NULL.\n");
	VALIDATOR_ASSERT(args->exp, "Expression of let op is NULL.\n");
	VALIDATOR_ASSERT(args->body, "Body of let op is NULL.\n");
	RzILSortPure sort;
	VALIDATOR_DESCEND(args->exp, &sort);
	LocalPureVar var = {
		.name = args->name,
		.sort = sort,
		.next = local_pure_var_stack
	};
	return validate_pure(args->body, sort_out, report_builder, ctx, &var);
}

VALIDATOR_PURE(inv) {
	RzILOpArgsBoolInv *args = &op->op.boolinv;
	RzILSortPure sort;
	VALIDATOR_DESCEND(args->x, &sort);
	VALIDATOR_ASSERT(sort.type == RZ_IL_TYPE_PURE_BOOL, "Operand of boolean inv op is not boolean.\n");
	*sort_out = rz_il_sort_pure_bool();
	return true;
}

/**
 * bool -> bool -> bool ops
 * e.g. and, or, ...
 */
VALIDATOR_PURE(bool_binop) {
	RzILOpPure *x = op->op.booland.x; // just booland is fine, all ops in here use the same struct
	RzILOpPure *y = op->op.booland.y;
	RzILSortPure sx;
	VALIDATOR_DESCEND(x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BOOL, "Left operand of %s op is not bool.\n", rz_il_op_pure_code_stringify(op->code));
	RzILSortPure sy;
	VALIDATOR_DESCEND(y, &sy);
	VALIDATOR_ASSERT(sy.type == RZ_IL_TYPE_PURE_BOOL, "Right operand of %s op is not bool.\n", rz_il_op_pure_code_stringify(op->code));
	*sort_out = rz_il_sort_pure_bool();
	return true;
}

/**
 * 'a bitv -> bool ops
 * e.g. msb, lsb
 */
VALIDATOR_PURE(bitv_bool_unop) {
	RzILOpPure *x = op->op.msb.bv; // just msb is fine, all ops in here use the same struct
	RzILSortPure sx;
	VALIDATOR_DESCEND(x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BITVECTOR, "Operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	*sort_out = rz_il_sort_pure_bool();
	return true;
}

/**
 * 'a bitv -> 'a bitv ops
 * e.g. bitwise negation
 */
VALIDATOR_PURE(bitv_unop) {
	RzILOpPure *x = op->op.lognot.bv; // just lognot is fine, all ops in here use the same struct
	RzILSortPure sx;
	VALIDATOR_DESCEND(x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BITVECTOR, "Operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	*sort_out = sx;
	return true;
}

VALIDATOR_PURE(shift) {
	RzILOpArgsShiftLeft *args = &op->op.shiftl;
	RzILSortPure sf;
	VALIDATOR_DESCEND(args->fill_bit, &sf);
	VALIDATOR_ASSERT(sf.type == RZ_IL_TYPE_PURE_BOOL, "Fill operand of %s op is not bool.\n", rz_il_op_pure_code_stringify(op->code));
	RzILSortPure sx;
	VALIDATOR_DESCEND(args->x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BITVECTOR, "Value operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	RzILSortPure sy;
	VALIDATOR_DESCEND(args->y, &sy);
	VALIDATOR_ASSERT(sy.type == RZ_IL_TYPE_PURE_BITVECTOR, "Distance operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	*sort_out = sx;
	return true;
}

VALIDATOR_PURE(cmp) {
	RzILOpArgsEq *args = &op->op.eq;
	RzILSortPure sx;
	VALIDATOR_DESCEND(args->x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BITVECTOR, "Left operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	RzILSortPure sy;
	VALIDATOR_DESCEND(args->y, &sy);
	VALIDATOR_ASSERT(sy.type == RZ_IL_TYPE_PURE_BITVECTOR, "Right operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	VALIDATOR_ASSERT(sx.props.bv.length == sy.props.bv.length, "Operand sizes of %s op do not agree: %u vs. %u.\n",
		rz_il_op_pure_code_stringify(op->code), (unsigned int)sx.props.bv.length, (unsigned int)sy.props.bv.length);
	*sort_out = rz_il_sort_pure_bool();
	return true;
}

VALIDATOR_PURE(cast) {
	RzILOpArgsCast *args = &op->op.cast;
	VALIDATOR_ASSERT(args->length, "Length of cast op is 0.\n");
	RzILSortPure sf;
	VALIDATOR_DESCEND(args->fill, &sf);
	VALIDATOR_ASSERT(sf.type == RZ_IL_TYPE_PURE_BOOL, "Fill operand of cast op is not bool.\n");
	RzILSortPure sx;
	VALIDATOR_DESCEND(args->val, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BITVECTOR, "Value operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	*sort_out = rz_il_sort_pure_bv(args->length);
	return true;
}

VALIDATOR_PURE(append) {
	RzILOpPure *x = op->op.append.high;
	RzILOpPure *y = op->op.append.low;
	RzILSortPure sx;
	VALIDATOR_DESCEND(x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BITVECTOR, "High operand of append op is not a bitvector.\n");
	RzILSortPure sy;
	VALIDATOR_DESCEND(y, &sy);
	VALIDATOR_ASSERT(sy.type == RZ_IL_TYPE_PURE_BITVECTOR, "Low operand of append op is not a bitvector.\n");
	*sort_out = rz_il_sort_pure_bv(sx.props.bv.length + sy.props.bv.length);
	return true;
}

VALIDATOR_PURE(load) {
	RzILOpArgsLoad *args = &op->op.load;
	bool found = false;
	ut64 htm = ht_uu_find(ctx->global_ctx->mems, args->mem, &found);
	VALIDATOR_ASSERT(found, "Mem %u referenced by load op does not exist.\n", (unsigned int)args->mem);
	ut32 key_len = htm >> 32;
	ut32 val_len = htm & UT32_MAX;
	RzILSortPure sk;
	VALIDATOR_DESCEND(args->key, &sk);
	VALIDATOR_ASSERT(sk.type == RZ_IL_TYPE_PURE_BITVECTOR, "Key operand of load op is not a bitvector.\n");
	VALIDATOR_ASSERT(sk.props.bv.length == key_len, "Length of key operand (%u) of load op is not equal to key length %u of mem %u.\n",
		(unsigned int)sk.props.bv.length, (unsigned int)key_len, (unsigned int)args->mem);
	*sort_out = rz_il_sort_pure_bv(val_len);
	return true;
}

VALIDATOR_PURE(loadw) {
	RzILOpArgsLoadW *args = &op->op.loadw;
	VALIDATOR_ASSERT(args->n_bits, "Length of loadw op is 0.\n");
	bool found = false;
	ut64 htm = ht_uu_find(ctx->global_ctx->mems, args->mem, &found);
	VALIDATOR_ASSERT(found, "Mem %u referenced by loadw op does not exist.\n", (unsigned int)args->mem);
	ut32 key_len = htm >> 32;
	RzILSortPure sk;
	VALIDATOR_DESCEND(args->key, &sk);
	VALIDATOR_ASSERT(sk.type == RZ_IL_TYPE_PURE_BITVECTOR, "Key operand of loadw op is not a bitvector.\n");
	VALIDATOR_ASSERT(sk.props.bv.length == key_len, "Length of key operand (%u) of loadw op is not equal to key length %u of mem %u.\n",
		(unsigned int)sk.props.bv.length, (unsigned int)key_len, (unsigned int)args->mem);
	*sort_out = rz_il_sort_pure_bv(args->n_bits);
	return true;
}

VALIDATOR_PURE(float) {
	RzILOpArgsFloat *args = &op->op.float_;
	RzILSortPure sort;

	VALIDATOR_DESCEND(args->bv, &sort);
	VALIDATOR_ASSERT(sort.type == RZ_IL_TYPE_PURE_BITVECTOR, "Float bv operand is not bitvector.\n");
	*sort_out = rz_il_sort_pure_float(args->r);
	return true;
}

VALIDATOR_PURE(fbits) {
	RzILOpArgsFbits *args = &op->op.fbits;
	RzILSortPure sort;

	VALIDATOR_DESCEND(args->f, &sort);
	VALIDATOR_ASSERT(sort.type == RZ_IL_TYPE_PURE_FLOAT, "operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));
	*sort_out = rz_il_sort_pure_bv(rz_float_get_format_info(sort.props.f.format, RZ_FLOAT_INFO_TOTAL_LEN));
	return true;
}

// float -> bool
VALIDATOR_PURE(float_bool_uop) {
	RzILOpArgsIsFinite *args = &op->op.is_finite;
	RzILSortPure sort;

	VALIDATOR_DESCEND(args->f, &sort);
	VALIDATOR_ASSERT(sort.type == RZ_IL_TYPE_PURE_FLOAT, "operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));
	*sort_out = rz_il_sort_pure_bool();
	return true;
}

VALIDATOR_PURE(float_uop) {
	RzILOpArgsFneg *args = &op->op.fneg;
	RzILSortPure sort;

	VALIDATOR_DESCEND(args->f, &sort);
	VALIDATOR_ASSERT(sort.type == RZ_IL_TYPE_PURE_FLOAT, "operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));
	*sort_out = sort;
	return true;
}

VALIDATOR_PURE(fcast_to_int) {
	RzILOpArgsFCastint *args = &op->op.fcast_int;
	RzILSortPure sort;

	VALIDATOR_DESCEND(args->f, &sort);
	VALIDATOR_ASSERT(sort.type == RZ_IL_TYPE_PURE_FLOAT, "operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));
	VALIDATOR_ASSERT(args->length != 0, "length of casted bitvector should not be 0.\n");
	*sort_out = rz_il_sort_pure_bv(args->length);
	return true;
}

VALIDATOR_PURE(icast_to_float) {
	RzILOpArgsFCastfloat *args = &op->op.fcast_float;
	RzILSortPure sort;

	VALIDATOR_DESCEND(args->bv, &sort);
	VALIDATOR_ASSERT(sort.type == RZ_IL_TYPE_PURE_BITVECTOR, "operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));

	*sort_out = rz_il_sort_pure_float(args->format);
	return true;
}

VALIDATOR_PURE(fconvert) {
	RzILOpArgsFconvert *args = &op->op.fconvert;
	RzILSortPure sort;

	VALIDATOR_DESCEND(args->f, &sort);
	VALIDATOR_ASSERT(sort.type == RZ_IL_TYPE_PURE_FLOAT, "operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));

	*sort_out = rz_il_sort_pure_float(args->format);
	return true;
}

VALIDATOR_PURE(forder) {
	RzILOpArgsForder *args = &op->op.forder;
	RzILSortPure sx, sy;

	VALIDATOR_DESCEND(args->x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_FLOAT, "Left operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));

	VALIDATOR_DESCEND(args->y, &sy);
	VALIDATOR_ASSERT(sy.type == RZ_IL_TYPE_PURE_FLOAT, "Right operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));

	// flatten validator assert
	if (!(sx.props.f.format == sy.props.f.format)) {
		char *ssx = rz_il_sort_pure_stringify(sx);
		char *ssy = rz_il_sort_pure_stringify(sy);

		rz_strbuf_appendf(report_builder, "Op %s formats of left operand (%s) and right operand (%s) do not agree.\n",
			rz_il_op_pure_code_stringify(op->code), ssx, ssy);
		free(ssx);
		free(ssy);
		return false;
	}

	*sort_out = rz_il_sort_pure_bool();
	return true;
}

VALIDATOR_PURE(frequal) {
	*sort_out = rz_il_sort_pure_bool();
	return true;
}

VALIDATOR_PURE(float_uop_with_round) {
	RzILOpArgsFround *args = &op->op.fround;
	RzILSortPure sort;

	VALIDATOR_DESCEND(args->f, &sort);
	VALIDATOR_ASSERT(sort.type == RZ_IL_TYPE_PURE_FLOAT, "operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));

	*sort_out = sort;
	return true;
}

VALIDATOR_PURE(float_binop_with_round) {
	RzILOpArgsFadd *args = &op->op.fadd;
	RzILSortPure sx, sy;

	VALIDATOR_DESCEND(args->x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_FLOAT, "Left operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));
	VALIDATOR_DESCEND(args->y, &sy);
	VALIDATOR_ASSERT(sy.type == RZ_IL_TYPE_PURE_FLOAT, "Right operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));

	// flatten validator assert
	if (!(sx.props.f.format == sy.props.f.format)) {
		char *ssx = rz_il_sort_pure_stringify(sx);
		char *ssy = rz_il_sort_pure_stringify(sy);

		rz_strbuf_appendf(report_builder, "Op %s formats of left operand (%s) and right operand (%s) do not agree.\n",
			rz_il_op_pure_code_stringify(op->code), ssx, ssy);

		free(ssx);
		free(ssy);
		return false;
	}

	*sort_out = sx;
	return true;
}

VALIDATOR_PURE(float_terop_with_round) {
	RzILOpArgsFmad *args = &op->op.fmad;
	RzILSortPure sx, sy, sz;

	VALIDATOR_DESCEND(args->x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_FLOAT, "1st operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));

	VALIDATOR_DESCEND(args->y, &sy);
	VALIDATOR_ASSERT(sy.type == RZ_IL_TYPE_PURE_FLOAT, "2nd operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));

	VALIDATOR_DESCEND(args->z, &sz);
	VALIDATOR_ASSERT(sz.type == RZ_IL_TYPE_PURE_FLOAT, "3rd operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));

	if (!((sx.props.f.format == sy.props.f.format) &&
		    (sx.props.f.format == sz.props.f.format))) {
		char *ssx = rz_il_sort_pure_stringify(sx);
		char *ssy = rz_il_sort_pure_stringify(sy);
		char *ssz = rz_il_sort_pure_stringify(sz);

		rz_strbuf_appendf(report_builder,
			"types of operand in op %s do not agree: operand1 (%s) operand2 (%s) operand3 (%s)",
			rz_il_op_pure_code_stringify(op->code),
			ssx, ssy, ssz);

		free(ssx);
		free(ssy);
		free(ssz);
		return false;
	}

	*sort_out = sx;
	return true;
}

VALIDATOR_PURE(float_hybridop_with_round) {
	RzILOpArgsFcompound *args = &op->op.fcompound;
	RzILSortPure fs, bs;

	VALIDATOR_DESCEND(args->f, &fs);
	VALIDATOR_ASSERT(fs.type == RZ_IL_TYPE_PURE_FLOAT, "1st operand of %s op is not a float.\n", rz_il_op_pure_code_stringify(op->code));
	VALIDATOR_DESCEND(args->n, &bs);
	VALIDATOR_ASSERT(bs.type == RZ_IL_TYPE_PURE_BITVECTOR, "2nd operand of %s op is not a bitv. \n", rz_il_op_pure_code_stringify(op->code));

	*sort_out = fs;
	return true;
}

static ValidatePureFn validate_pure_table[RZ_IL_OP_PURE_MAX] = {
	[RZ_IL_OP_VAR] = VALIDATOR_PURE_NAME(var),
	[RZ_IL_OP_ITE] = VALIDATOR_PURE_NAME(ite),
	[RZ_IL_OP_LET] = VALIDATOR_PURE_NAME(let),
	[RZ_IL_OP_B0] = VALIDATOR_PURE_NAME(bool_const),
	[RZ_IL_OP_B1] = VALIDATOR_PURE_NAME(bool_const),
	[RZ_IL_OP_INV] = VALIDATOR_PURE_NAME(inv),
	[RZ_IL_OP_AND] = VALIDATOR_PURE_NAME(bool_binop),
	[RZ_IL_OP_OR] = VALIDATOR_PURE_NAME(bool_binop),
	[RZ_IL_OP_XOR] = VALIDATOR_PURE_NAME(bool_binop),
	[RZ_IL_OP_BITV] = VALIDATOR_PURE_NAME(bitv),
	[RZ_IL_OP_MSB] = VALIDATOR_PURE_NAME(bitv_bool_unop),
	[RZ_IL_OP_LSB] = VALIDATOR_PURE_NAME(bitv_bool_unop),
	[RZ_IL_OP_IS_ZERO] = VALIDATOR_PURE_NAME(bitv_bool_unop),
	[RZ_IL_OP_NEG] = VALIDATOR_PURE_NAME(bitv_unop),
	[RZ_IL_OP_LOGNOT] = VALIDATOR_PURE_NAME(bitv_unop),
	[RZ_IL_OP_ADD] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_SUB] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_MUL] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_DIV] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_MOD] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_SDIV] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_SMOD] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_LOGAND] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_LOGOR] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_LOGXOR] = VALIDATOR_PURE_NAME(bitv_binop),
	[RZ_IL_OP_SHIFTR] = VALIDATOR_PURE_NAME(shift),
	[RZ_IL_OP_SHIFTL] = VALIDATOR_PURE_NAME(shift),
	[RZ_IL_OP_EQ] = VALIDATOR_PURE_NAME(cmp),
	[RZ_IL_OP_SLE] = VALIDATOR_PURE_NAME(cmp),
	[RZ_IL_OP_ULE] = VALIDATOR_PURE_NAME(cmp),
	[RZ_IL_OP_CAST] = VALIDATOR_PURE_NAME(cast),
	[RZ_IL_OP_APPEND] = VALIDATOR_PURE_NAME(append),
	[RZ_IL_OP_LOAD] = VALIDATOR_PURE_NAME(load),
	[RZ_IL_OP_LOADW] = VALIDATOR_PURE_NAME(loadw),
	[RZ_IL_OP_FLOAT] = VALIDATOR_PURE_NAME(float),
	[RZ_IL_OP_FBITS] = VALIDATOR_PURE_NAME(fbits),
	[RZ_IL_OP_IS_FINITE] = VALIDATOR_PURE_NAME(float_bool_uop),
	[RZ_IL_OP_IS_NAN] = VALIDATOR_PURE_NAME(float_bool_uop),
	[RZ_IL_OP_IS_INF] = VALIDATOR_PURE_NAME(float_bool_uop),
	[RZ_IL_OP_IS_FZERO] = VALIDATOR_PURE_NAME(float_bool_uop),
	[RZ_IL_OP_IS_FNEG] = VALIDATOR_PURE_NAME(float_bool_uop),
	[RZ_IL_OP_IS_FPOS] = VALIDATOR_PURE_NAME(float_bool_uop),
	[RZ_IL_OP_FNEG] = VALIDATOR_PURE_NAME(float_uop),
	[RZ_IL_OP_FABS] = VALIDATOR_PURE_NAME(float_uop),
	[RZ_IL_OP_FREQUAL] = VALIDATOR_PURE_NAME(frequal),
	[RZ_IL_OP_FSUCC] = VALIDATOR_PURE_NAME(float_uop),
	[RZ_IL_OP_FPRED] = VALIDATOR_PURE_NAME(float_uop),
	[RZ_IL_OP_FORDER] = VALIDATOR_PURE_NAME(forder),
	[RZ_IL_OP_FROUND] = VALIDATOR_PURE_NAME(float_uop_with_round),
	[RZ_IL_OP_FSQRT] = VALIDATOR_PURE_NAME(float_uop_with_round),
	[RZ_IL_OP_FRSQRT] = VALIDATOR_PURE_NAME(float_uop_with_round),
	[RZ_IL_OP_FADD] = VALIDATOR_PURE_NAME(float_binop_with_round),
	[RZ_IL_OP_FSUB] = VALIDATOR_PURE_NAME(float_binop_with_round),
	[RZ_IL_OP_FMUL] = VALIDATOR_PURE_NAME(float_binop_with_round),
	[RZ_IL_OP_FDIV] = VALIDATOR_PURE_NAME(float_binop_with_round),
	[RZ_IL_OP_FMOD] = VALIDATOR_PURE_NAME(float_binop_with_round),
	[RZ_IL_OP_FMAD] = VALIDATOR_PURE_NAME(float_terop_with_round),
	[RZ_IL_OP_FCAST_INT] = VALIDATOR_PURE_NAME(fcast_to_int),
	[RZ_IL_OP_FCAST_SINT] = VALIDATOR_PURE_NAME(fcast_to_int),
	[RZ_IL_OP_FCAST_FLOAT] = VALIDATOR_PURE_NAME(icast_to_float),
	[RZ_IL_OP_FCAST_SFLOAT] = VALIDATOR_PURE_NAME(icast_to_float),
	[RZ_IL_OP_FCONVERT] = VALIDATOR_PURE_NAME(fconvert),

	// unimplemented
	[RZ_IL_OP_FHYPOT] = VALIDATOR_PURE_NAME(float_binop_with_round),
	[RZ_IL_OP_FPOW] = VALIDATOR_PURE_NAME(float_binop_with_round),
	[RZ_IL_OP_FROOTN] = VALIDATOR_PURE_NAME(float_hybridop_with_round),
	[RZ_IL_OP_FPOWN] = VALIDATOR_PURE_NAME(float_hybridop_with_round),
	[RZ_IL_OP_FCOMPOUND] = VALIDATOR_PURE_NAME(float_hybridop_with_round),
};

static bool validate_pure(VALIDATOR_PURE_ARGS) {
	VALIDATOR_ASSERT(op, "Encountered NULL for pure op.\n");
	ValidatePureFn validator = validate_pure_table[op->code];
	rz_return_val_if_fail(validator, false);
	return validator(op, sort_out, report_builder, ctx, local_pure_var_stack);
}

/**
 * Run validation (type-checking and other checks) on a pure expression and determine its sort.
 * \p op the op to be checked. May be null, which will always be reported as invalid.
 * \p ctx global context, defining available global vars and mems
 * \p sort_out optionally returns the sort of the expression, if it is valid
 * \p report_out optionally returns a readable report containing details about why the validation failed
 * \return whether the given op is valid under \p ctx
 */
RZ_API bool rz_il_validate_pure(RZ_NULLABLE RzILOpPure *op, RZ_NONNULL RzILValidateGlobalContext *ctx,
	RZ_NULLABLE RZ_OUT RzILSortPure *sort_out, RZ_NULLABLE RZ_OUT RzILValidateReport *report_out) {
	LocalContext local_ctx;
	if (!local_context_init(&local_ctx, ctx)) {
		if (report_out) {
			*report_out = NULL;
		}
		return false;
	}
	RzStrBuf report_builder;
	rz_strbuf_init(&report_builder);
	RzILSortPure sort;
	bool valid = validate_pure(op, &sort, &report_builder, &local_ctx, NULL);
	local_context_fini(&local_ctx);
	if (sort_out) {
		*sort_out = sort;
	}
	if (report_out) {
		*report_out = rz_strbuf_is_empty(&report_builder) ? NULL : rz_str_trim_tail(rz_strbuf_drain_nofree(&report_builder));
	}
	rz_strbuf_fini(&report_builder);
	return valid;
}

/// @}

/////////////////////////////////////////////////////////
/**
 * \name Effect
 * @{
 */

#undef VALIDATOR_PURE_ARGS
#undef VALIDATOR_PURE_NAME
#undef VALIDATOR_PURE
#undef VALIDATOR_DESCEND

// clang-format off
#define VALIDATOR_EFFECT_ARGS \
	RZ_NULLABLE RzILOpEffect *op, \
	RZ_NONNULL RzILTypeEffect *type_out, \
	RZ_NONNULL RzStrBuf *report_builder, \
	RZ_NONNULL LocalContext *ctx
// clang-format on

static bool validate_effect(VALIDATOR_EFFECT_ARGS);
typedef bool (*ValidateEffectFn)(VALIDATOR_EFFECT_ARGS);

#define VALIDATOR_EFFECT_NAME(op) validate_effect_##op
#define VALIDATOR_EFFECT(op)      static bool VALIDATOR_EFFECT_NAME(op)(VALIDATOR_EFFECT_ARGS)
#define VALIDATOR_DESCEND_PURE(op, sort) \
	do { \
		if (!validate_pure(op, sort, report_builder, ctx, NULL)) { \
			return false; \
		} \
	} while (0)
#define VALIDATOR_DESCEND_EFFECT(op, etype, ectx, cleanup) \
	do { \
		if (!validate_effect(op, etype, report_builder, ectx)) { \
			cleanup return false; \
		} \
	} while (0)

VALIDATOR_EFFECT(empty) {
	*type_out = RZ_IL_TYPE_EFFECT_NONE;
	return true;
}

VALIDATOR_EFFECT(nop) {
	*type_out = RZ_IL_TYPE_EFFECT_NONE;
	return true;
}

VALIDATOR_EFFECT(store) {
	RzILOpArgsStore *args = &op->op.store;
	bool found = false;
	ut64 htm = ht_uu_find(ctx->global_ctx->mems, args->mem, &found);
	VALIDATOR_ASSERT(found, "Mem %u referenced by store op does not exist.\n", (unsigned int)args->mem);
	ut32 key_len = htm >> 32;
	ut32 val_len = htm & UT32_MAX;
	RzILSortPure sk;
	VALIDATOR_DESCEND_PURE(args->key, &sk);
	VALIDATOR_ASSERT(sk.type == RZ_IL_TYPE_PURE_BITVECTOR, "Key operand of store op is not a bitvector.\n");
	VALIDATOR_ASSERT(sk.props.bv.length == key_len, "Length of key operand (%u) of store op is not equal to key length %u of mem %u.\n",
		(unsigned int)sk.props.bv.length, (unsigned int)key_len, (unsigned int)args->mem);
	RzILSortPure sv;
	VALIDATOR_DESCEND_PURE(args->value, &sv);
	VALIDATOR_ASSERT(sv.type == RZ_IL_TYPE_PURE_BITVECTOR, "Value operand of store op is not a bitvector.\n");
	VALIDATOR_ASSERT(sv.props.bv.length == val_len, "Length of value operand (%u) of store op is not equal to value length %u of mem %u.\n",
		(unsigned int)sv.props.bv.length, (unsigned int)val_len, (unsigned int)args->mem);
	*type_out = RZ_IL_TYPE_EFFECT_DATA;
	return true;
}

VALIDATOR_EFFECT(storew) {
	RzILOpArgsStoreW *args = &op->op.storew;
	bool found = false;
	ut64 htm = ht_uu_find(ctx->global_ctx->mems, args->mem, &found);
	VALIDATOR_ASSERT(found, "Mem %u referenced by storew op does not exist.\n", (unsigned int)args->mem);
	ut32 key_len = htm >> 32;
	RzILSortPure sk;
	VALIDATOR_DESCEND_PURE(args->key, &sk);
	VALIDATOR_ASSERT(sk.type == RZ_IL_TYPE_PURE_BITVECTOR, "Key operand of storew op is not a bitvector.\n");
	VALIDATOR_ASSERT(sk.props.bv.length == key_len, "Length of key operand (%u) of storew op is not equal to key length %u of mem %u.\n",
		(unsigned int)sk.props.bv.length, (unsigned int)key_len, (unsigned int)args->mem);
	RzILSortPure sv;
	VALIDATOR_DESCEND_PURE(args->value, &sv);
	VALIDATOR_ASSERT(sv.type == RZ_IL_TYPE_PURE_BITVECTOR, "Value operand of storew op is not a bitvector.\n");
	*type_out = RZ_IL_TYPE_EFFECT_DATA;
	return true;
}

VALIDATOR_EFFECT(set) {
	RzILOpArgsSet *args = &op->op.set;
	VALIDATOR_ASSERT(args->v, "Var name of set op is NULL.\n");
	RzILSortPure sx;
	VALIDATOR_DESCEND_PURE(args->x, &sx);
	RzILSortPure *sort = ht_sp_find(
		args->is_local ? ctx->local_vars_known : ctx->global_ctx->global_vars, args->v, NULL);
	VALIDATOR_ASSERT(args->is_local || sort, "Global variable \"%s\" referenced by set op does not exist.\n", args->v);
	if (sort && !rz_il_sort_pure_eq(*sort, sx)) {
		char *svs = rz_il_sort_pure_stringify(*sort);
		char *sxs = rz_il_sort_pure_stringify(sx);
		rz_strbuf_appendf(report_builder, "Types of %sal variable \"%s\" and set op do not agree: %s vs. %s.\n",
			args->is_local ? "loc" : "glob",
			args->v, rz_str_get_null(svs), rz_str_get_null(sxs));
		free(svs);
		free(sxs);
		return false;
	}
	if (args->is_local) {
		if (!sort) {
			sort = RZ_NEW(RzILSortPure);
			if (!sort) {
				return false;
			}
			*sort = sx;
			ht_sp_update(ctx->local_vars_known, args->v, sort);
		}
		ht_sp_update(ctx->local_vars_available, args->v, sort);
	}
	*type_out = RZ_IL_TYPE_EFFECT_DATA;
	return true;
}

VALIDATOR_EFFECT(jmp) {
	RzILOpArgsJmp *args = &op->op.jmp;
	RzILSortPure sd;
	VALIDATOR_DESCEND_PURE(args->dst, &sd);
	VALIDATOR_ASSERT(sd.type == RZ_IL_TYPE_PURE_BITVECTOR, "Dst operand of jmp op is not a bitvector.\n");
	VALIDATOR_ASSERT(sd.props.bv.length == ctx->global_ctx->pc_len,
		"Length of dst operand (%u) of jmp op is not equal to pc length %u.\n",
		(unsigned int)sd.props.bv.length, (unsigned int)ctx->global_ctx->pc_len);
	*type_out = RZ_IL_TYPE_EFFECT_CTRL;
	return true;
}

VALIDATOR_EFFECT(goto) {
	RzILOpArgsGoto *args = &op->op.goto_;
	VALIDATOR_ASSERT(args->lbl, "Label of goto op is NULL.\n");
	// So far, no restrictions on goto because labels are dynamically created. This might change in the future.
	*type_out = RZ_IL_TYPE_EFFECT_CTRL;
	return true;
}

VALIDATOR_EFFECT(seq) {
	RzILOpArgsSeq *args = &op->op.seq;
	RzILTypeEffect tx;
	VALIDATOR_DESCEND_EFFECT(args->x, &tx, ctx, {});
	RzILTypeEffect ty;
	VALIDATOR_DESCEND_EFFECT(args->y, &ty, ctx, {});
	// Code after a jmp/goto makes no sense because the jmp naturally jumps somewhere else already.
	// Intuitively, this could be considered just dead code and valid, but because it is not practically useful,
	// we reject such code completely for now, which gives us more freedom if in the future we do want to define
	// semantics for code after ctrl in some way.
	VALIDATOR_ASSERT(!(tx & RZ_IL_TYPE_EFFECT_CTRL) || !ty, "Encountered further effects after a ctrl effect in seq op.");
	*type_out = tx | ty;
	return true;
}

VALIDATOR_EFFECT(blk) {
	RzILOpArgsBlk *args = &op->op.blk;
	// Semantics of blk are still somewhat undefined in RzIL
	RzILTypeEffect td;
	VALIDATOR_DESCEND_EFFECT(args->data_eff, &td, ctx, {});
	VALIDATOR_ASSERT((td | RZ_IL_TYPE_EFFECT_DATA) == RZ_IL_TYPE_EFFECT_DATA, "Data effect operand of blk op does not only perform data effects.");
	RzILTypeEffect tc;
	VALIDATOR_DESCEND_EFFECT(args->ctrl_eff, &tc, ctx, {});
	VALIDATOR_ASSERT((tc | RZ_IL_TYPE_EFFECT_CTRL) == RZ_IL_TYPE_EFFECT_CTRL, "Control effect operand of blk op does not only perform control effects.");
	*type_out = td | tc;
	return true;
}

VALIDATOR_EFFECT(repeat) {
	RzILOpArgsRepeat *args = &op->op.repeat;
	RzILSortPure sc;
	VALIDATOR_DESCEND_PURE(args->condition, &sc);
	VALIDATOR_ASSERT(sc.type == RZ_IL_TYPE_PURE_BOOL, "Condition of repeat op is not boolean.\n");
	LocalContext loop_ctx;
	if (!local_context_copy(&loop_ctx, ctx)) {
		return false;
	}
	RzILTypeEffect t;
	VALIDATOR_DESCEND_EFFECT(args->data_eff, &t, ctx, { local_context_fini(&loop_ctx); });
	// Enforce (by overapproximation) that there are no effects after a ctrl effect, like in seq.
	// In a loop, we just reject ctrl completely. This also matches BAP's `repeat : bool -> data eff -> data eff`.
	if (!((t | RZ_IL_TYPE_EFFECT_DATA) == RZ_IL_TYPE_EFFECT_DATA)) {
		rz_strbuf_appendf(report_builder, "Body operand of repeat op does not only perform data effects.");
		local_context_fini(&loop_ctx);
		return false;
	}

	bool val = local_context_meet(ctx, &loop_ctx, report_builder, "repeat");
	local_context_fini(&loop_ctx);
	*type_out = t;
	return val;
}

VALIDATOR_EFFECT(branch) {
	RzILOpArgsBranch *args = &op->op.branch;
	RzILSortPure sc;
	VALIDATOR_DESCEND_PURE(args->condition, &sc);
	VALIDATOR_ASSERT(sc.type == RZ_IL_TYPE_PURE_BOOL, "Condition of branch op is not boolean.\n");
	LocalContext false_ctx;
	if (!local_context_copy(&false_ctx, ctx)) {
		return false;
	}
	RzILTypeEffect tt;
	VALIDATOR_DESCEND_EFFECT(args->true_eff, &tt, ctx, { local_context_fini(&false_ctx); });
	RzILTypeEffect tf;
	VALIDATOR_DESCEND_EFFECT(args->false_eff, &tf, &false_ctx, { local_context_fini(&false_ctx); });
	bool val = local_context_meet(ctx, &false_ctx, report_builder, "branch");
	local_context_fini(&false_ctx);
	*type_out = tt | tf;
	return val;
}

static ValidateEffectFn validate_effect_table[RZ_IL_OP_EFFECT_MAX] = {
	[RZ_IL_OP_EMPTY] = VALIDATOR_EFFECT_NAME(empty),
	[RZ_IL_OP_STORE] = VALIDATOR_EFFECT_NAME(store),
	[RZ_IL_OP_STOREW] = VALIDATOR_EFFECT_NAME(storew),
	[RZ_IL_OP_NOP] = VALIDATOR_EFFECT_NAME(nop),
	[RZ_IL_OP_SET] = VALIDATOR_EFFECT_NAME(set),
	[RZ_IL_OP_JMP] = VALIDATOR_EFFECT_NAME(jmp),
	[RZ_IL_OP_GOTO] = VALIDATOR_EFFECT_NAME(goto),
	[RZ_IL_OP_SEQ] = VALIDATOR_EFFECT_NAME(seq),
	[RZ_IL_OP_BLK] = VALIDATOR_EFFECT_NAME(blk),
	[RZ_IL_OP_REPEAT] = VALIDATOR_EFFECT_NAME(repeat),
	[RZ_IL_OP_BRANCH] = VALIDATOR_EFFECT_NAME(branch)
};

static bool validate_effect(VALIDATOR_EFFECT_ARGS) {
	VALIDATOR_ASSERT(op, "Encountered NULL for effect op.\n");
	ValidateEffectFn validator = validate_effect_table[op->code];
	rz_return_val_if_fail(validator, false);
	return validator(op, type_out, report_builder, ctx);
}

/**
 * Run validation (type-checking and other checks) on an effect.
 * \p op the op to be checked. May be null, which will always be reported as invalid.
 * \p ctx global context, defining available global vars and mems
 * \p local_var_sorts_out optionally returns a map of local variable names defined in the effect to their sorts
 * \p type_put optionally returns the type of effects that the ops perform, i.e. ctrl, data, both or none
 * \p report_out optionally returns a readable report containing details about why the validation failed
 * \return whether the given op is valid under \p ctx
 */
RZ_API bool rz_il_validate_effect(RZ_NULLABLE RzILOpEffect *op, RZ_NONNULL RzILValidateGlobalContext *ctx,
	RZ_NULLABLE RZ_OUT HtSP /*<const char *, RzILSortPure *>*/ **local_var_sorts_out,
	RZ_NULLABLE RZ_OUT RzILTypeEffect *type_out,
	RZ_NULLABLE RZ_OUT RzILValidateReport *report_out) {
	LocalContext local_ctx;
	if (!local_context_init(&local_ctx, ctx)) {
		if (report_out) {
			*report_out = NULL;
		}
		return false;
	}
	RzILTypeEffect type = RZ_IL_TYPE_EFFECT_NONE;
	RzStrBuf report_builder;
	rz_strbuf_init(&report_builder);
	bool valid = validate_effect(op, &type, &report_builder, &local_ctx);
	if (valid && local_var_sorts_out) {
		*local_var_sorts_out = local_ctx.local_vars_known;
		local_ctx.local_vars_known = NULL;
	}
	local_context_fini(&local_ctx);
	if (type_out) {
		*type_out = type;
	}
	if (report_out) {
		*report_out = rz_strbuf_is_empty(&report_builder) ? NULL : rz_str_trim_tail(rz_strbuf_drain_nofree(&report_builder));
	}
	rz_strbuf_fini(&report_builder);
	return valid;
}

/// @}
