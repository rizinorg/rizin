// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_validate.h>

struct rz_il_validate_context_t {
	HtPP /*<const char *, RzILSortPure *>*/ *global_vars;
}; /* RzILValidateContext */

static void var_kv_free(HtPPKv *kv) {
	free(kv->key);
	free(kv->value);
}

/**
 * Create a new context for IL validation based on the global vars and mems in \p vm
 */
RZ_API RzILValidateContext *rz_il_validate_context_new_from_vm(RzILVM *vm) {
	RzILValidateContext *ctx = RZ_NEW0(RzILValidateContext);
	if (!ctx) {
		return NULL;
	}
	ctx->global_vars = ht_pp_new(NULL, var_kv_free, NULL);
	return NULL;
}

RZ_API void rz_il_validate_context_free(RzILValidateContext *ctx) {
	if (!ctx) {
		return;
	}
}

typedef struct {
	HtPP /*<const char *, RzILSortPure *>*/ *local_vars;
} LocalContext;

/////////////////////////////////////////////////////////
// ------------------------ pure ------------------------

static bool validate_pure(RZ_NULLABLE RzILOpPure *op, RZ_NONNULL RzILSortPure *sort_out, RZ_NONNULL RzStrBuf *report_builder);

#define VALIDATOR_PURE_ARGS RZ_NULLABLE RzILOpPure *op, RZ_NONNULL RzILSortPure *sort_out, RZ_NONNULL RzStrBuf *report_builder
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

VALIDATOR_PURE(invalid) {
	rz_strbuf_appendf(report_builder, "Unimplemented validation for op of type %d.\n", (int)op->code);
	return false;
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
	VALIDATOR_ASSERT(x, "Left operand of %s op is NULL.\n", rz_il_op_pure_code_stringify(op->code));
	VALIDATOR_ASSERT(y, "Right operand of %s op is NULL.\n", rz_il_op_pure_code_stringify(op->code));
	RzILSortPure sx;
	if (!validate_pure(x, &sx, report_builder)) {
		return false;
	}
	VALIDATOR_ASSERT(sx.type == RZ_IL_TYPE_PURE_BITVECTOR, "Left operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	RzILSortPure sy;
	if (!validate_pure(y, &sy, report_builder)) {
		return false;
	}
	VALIDATOR_ASSERT(sy.type == RZ_IL_TYPE_PURE_BITVECTOR, "Right operand of %s op is not a bitvector.\n", rz_il_op_pure_code_stringify(op->code));
	VALIDATOR_ASSERT(sx.props.bv.length == sy.props.bv.length, "Operand sizes of %s op do not agree: %u vs. %u.\n",
		rz_il_op_pure_code_stringify(op->code), (unsigned int)sx.props.bv.length, (unsigned int)sy.props.bv.length);
	*sort_out = sx;
	return true;
}

static ValidatePureFn validate_pure_table[RZ_IL_OP_PURE_MAX] = {
	[RZ_IL_OP_VAR] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_ITE] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_LET] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_B0] = VALIDATOR_PURE_NAME(bool_const),
	[RZ_IL_OP_B1] = VALIDATOR_PURE_NAME(bool_const),
	[RZ_IL_OP_INV] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_AND] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_OR] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_XOR] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_BITV] = VALIDATOR_PURE_NAME(bitv),
	[RZ_IL_OP_MSB] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_LSB] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_IS_ZERO] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_NEG] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_LOGNOT] = VALIDATOR_PURE_NAME(invalid),
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
	[RZ_IL_OP_SHIFTR] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_SHIFTL] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_EQ] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_SLE] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_ULE] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_CAST] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_CONCAT] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_APPEND] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_LOAD] = VALIDATOR_PURE_NAME(invalid),
	[RZ_IL_OP_LOADW] = VALIDATOR_PURE_NAME(invalid)
};

static bool validate_pure(RZ_NULLABLE RzILOpPure *op, RZ_NONNULL RzILSortPure *sort_out, RZ_NONNULL RzStrBuf *report_builder) {
	if (!op) {
		rz_strbuf_appendf(report_builder, "Encountered NULL for pure op.\n");
		return false;
	}
	ValidatePureFn validator = validate_pure_table[op->code];
	rz_return_val_if_fail(validator, false);
	return validator(op, sort_out, report_builder);
}

/////////////////////////////////////////////////////////
// ----------------------- effect -----------------------

RZ_API bool rz_il_validate_pure(RZ_NULLABLE RzILOpPure *op, RZ_NULLABLE RZ_OUT RzILSortPure *sort_out, RZ_NULLABLE RZ_OUT RzILValidateReport *report_out) {
	RzStrBuf report_builder;
	rz_strbuf_init(&report_builder);
	RzILSortPure sort = { 0 };
	bool valid = validate_pure(op, &sort, &report_builder);
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
