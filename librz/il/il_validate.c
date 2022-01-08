// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_validate.h>
#include <ht_uu.h>

/////////////////////////////////////////////////////////
// ---------------------- context -----------------------

/**
 * Global (immutable) context
 */
struct rz_il_validate_global_context_t {
	HtPP /*<const char *, RzILSortPure *>*/ *global_vars;
	HtUU /*<RzILMemIndex, ut32:ut32>*/ *mems;
}; /* RzILValidateGlobalContext */

static void var_kv_free(HtPPKv *kv) {
	free(kv->key);
	free(kv->value);
}

RZ_API RzILValidateGlobalContext *rz_il_validate_global_context_new_empty() {
	RzILValidateGlobalContext *ctx = RZ_NEW0(RzILValidateGlobalContext);
	if (!ctx) {
		return NULL;
	}
	ctx->global_vars = ht_pp_new(NULL, var_kv_free, NULL);
	if (!ctx->global_vars) {
		free(ctx);
		return NULL;
	}
	ctx->mems = ht_uu_new0();
	if (!ctx->mems) {
		ht_pp_free(ctx->global_vars);
		free(ctx);
		return NULL;
	}
	return ctx;
}

/**
 * Define a new global variable in \p ctx
 */
RZ_API void rz_il_validate_global_context_add_var(RzILValidateGlobalContext *ctx, const char *name, RzILSortPure sort) {
	RzILSortPure *hts = RZ_NEW(RzILSortPure);
	*hts = sort;
	ht_pp_update(ctx->global_vars, name, hts);
}

/**
 * Define a new memory in \p ctx
 */
RZ_API void rz_il_validate_global_context_add_mem(RzILValidateGlobalContext *ctx, RzILMemIndex idx, ut32 key_len, ut32 val_len) {
	ht_uu_update(ctx->mems, idx, ((ut64)key_len << 32) | (ut64)val_len);
}

/**
 * Create a new context for IL validation based on the global vars and mems in \p vm
 */
RZ_API RzILValidateGlobalContext *rz_il_validate_global_context_new_from_vm(RzILVM *vm) {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty();
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
	ht_pp_free(ctx->global_vars);
	ht_uu_free(ctx->mems);
	free(ctx);
}

typedef struct {
	const RzILValidateGlobalContext *global_ctx;
	HtPP /*<const char *, RzILSortPure *>*/ *local_vars;
} LocalContext;

static bool local_context_init(LocalContext *ctx, RzILValidateGlobalContext *global_ctx) {
	ctx->global_ctx = global_ctx;
	ctx->local_vars = ht_pp_new(NULL, var_kv_free, NULL);
	if (!ctx->local_vars) {
		return false;
	}
	return true;
}

static void local_context_fini(LocalContext *ctx) {
	ht_pp_free(ctx->local_vars);
}

/////////////////////////////////////////////////////////
// ------------------------ pure ------------------------

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

#define VALIDATOR_PURE_ARGS \
	RZ_NULLABLE RzILOpPure *op, \
		RZ_NONNULL RzILSortPure *sort_out, \
		RZ_NONNULL RzStrBuf *report_builder, \
		RZ_NONNULL const LocalContext *ctx, \
		RZ_NULLABLE LocalPureVar *local_pure_var_stack
static bool validate_pure(VALIDATOR_PURE_ARGS);
typedef bool (*ValidatePureFn)(VALIDATOR_PURE_ARGS);
#define VALIDATOR_PURE_NAME(op) validate_pure_##op
#define VALIDATOR_PURE(op)      static bool VALIDATOR_PURE_NAME(op)(VALIDATOR_PURE_ARGS)
#define VALIDATOR_ASSERT(condition, ...) \
	do { \
		if (!(condition)) { \
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
		RzILSortPure *sort = ht_pp_find(ctx->global_ctx->global_vars, args->v, NULL);
		VALIDATOR_ASSERT(sort, "Global variable \"%s\" referenced by var op does not exist.\n", args->v);
		*sort_out = *sort;
		return true;
	}
	case RZ_IL_VAR_KIND_LOCAL:
		return false; // TODO
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

VALIDATOR_PURE(bitv_bool_unop) {
	RzILOpPure *x = op->op.msb.bv; // just msb is fine, all ops in here use the same struct
	RzILSortPure sx;
	VALIDATOR_DESCEND(x, &sx);
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BITVECTOR, "Operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	*sort_out = rz_il_sort_pure_bool();
	return true;
}

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
	[RZ_IL_OP_LOADW] = VALIDATOR_PURE_NAME(loadw)
};

static bool validate_pure(VALIDATOR_PURE_ARGS) {
	if (!op) {
		rz_strbuf_appendf(report_builder, "Encountered NULL for pure op.\n");
		return false;
	}
	ValidatePureFn validator = validate_pure_table[op->code];
	rz_return_val_if_fail(validator, false);
	return validator(op, sort_out, report_builder, ctx, local_pure_var_stack);
}

/////////////////////////////////////////////////////////
// ----------------------- effect -----------------------

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
	RzILSortPure sort = { 0 };
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

RZ_API bool rz_il_validate_effect(RZ_NULLABLE RzILOpEffect *op, RZ_NULLABLE RZ_OUT RzILValidateReport *report_out) {
	return false;
}
