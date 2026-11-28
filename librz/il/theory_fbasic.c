// SPDX-FileCopyrightText: 2023 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opcodes.h>
#include <rz_il/rz_il_vm.h>

void *rz_il_handler_float(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFloat op_f = op->op.float_;
	RzBitVector *bv = rz_il_evaluate_bitv(vm, op_f.bv);
	RzFloat *ret = rz_il_float_new(op_f.r, bv);

	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fbits(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFbits op_fbits = op->op.fbits;
	RzFloat *f = rz_il_evaluate_float(vm, op_fbits.f);
	if (!f) {
		return NULL;
	}
	RzBitVector *ret = rz_bv_dup(f->s);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return ret;
}

void *rz_il_handler_is_finite(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsIsFinite is_finite = op->op.is_finite;
	RzFloat *f = rz_il_evaluate_float(vm, is_finite.f);
	if (!f) {
		return NULL;
	}
	RzILBool *ret = rz_il_bool_new(!rz_float_is_inf(f));

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

void *rz_il_handler_is_nan(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsIsNan is_nan = op->op.is_nan;
	RzFloat *f = rz_il_evaluate_float(vm, is_nan.f);
	if (!f) {
		return NULL;
	}
	RzILBool *ret = rz_il_bool_new(rz_float_is_nan(f));

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

void *rz_il_handler_is_inf(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsIsInf is_inf = op->op.is_inf;
	RzFloat *f = rz_il_evaluate_float(vm, is_inf.f);
	if (!f) {
		return NULL;
	}
	RzILBool *ret = rz_il_bool_new(rz_float_is_inf(f));

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

void *rz_il_handler_is_fzero(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsIsFzero is_fzero = op->op.is_fzero;
	RzFloat *f = rz_il_evaluate_float(vm, is_fzero.f);
	if (!f) {
		return NULL;
	}
	RzILBool *ret = rz_il_bool_new(rz_float_is_zero(f));

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

void *rz_il_handler_is_fneg(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsIsFneg is_fneg = op->op.is_fneg;
	RzFloat *f = rz_il_evaluate_float(vm, is_fneg.f);
	if (!f) {
		return NULL;
	}
	RzILBool *ret = rz_il_bool_new(rz_float_is_negative(f));

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

void *rz_il_handler_is_fpos(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsIsFpos is_fpos = op->op.is_fpos;
	RzFloat *f = rz_il_evaluate_float(vm, is_fpos.f);
	if (!f) {
		return NULL;
	}
	RzILBool *ret = rz_il_bool_new(!rz_float_is_negative(f));

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

void *rz_il_handler_fneg(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFneg fneg = op->op.fneg;
	RzFloat *f = rz_il_evaluate_float(vm, fneg.f);
	if (!f) {
		return NULL;
	}
	RzFloat *ret = rz_float_neg(f);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fabs(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFabs fabs = op->op.fabs;
	RzFloat *f = rz_il_evaluate_float(vm, fabs.f);
	if (!f) {
		return NULL;
	}
	RzFloat *ret = rz_float_abs(f);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

static bool resolve_rmode(RzILVM *vm, RzILOpPureCode code, const RzILOpArgFloatRMode *arg, RzFloatRMode *out);

void *rz_il_handler_fcast_int(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFCastint cast_int = op->op.fcast_int;
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &cast_int.rmode, &mode)) {
		return NULL;
	}
	RzFloat *f = rz_il_evaluate_float(vm, cast_int.f);
	if (!f) {
		return NULL;
	}
	ut32 length = cast_int.length;
	RzBitVector *ret = rz_float_cast_int(f, length, mode);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return ret;
}

void *rz_il_handler_fcast_sint(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFCastint cast_sint = op->op.fcast_sint;
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &cast_sint.rmode, &mode)) {
		return NULL;
	}
	RzFloat *f = rz_il_evaluate_float(vm, cast_sint.f);
	if (!f) {
		return NULL;
	}
	ut32 length = cast_sint.length;
	RzBitVector *ret = rz_float_cast_sint(f, length, mode);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return ret;
}

void *rz_il_handler_fcast_float(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFCastUFloat cast = op->op.fcast_float;
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &cast.rmode, &mode)) {
		return NULL;
	}
	RzBitVector *bv = rz_il_evaluate_bitv(vm, cast.bv);
	if (!bv) {
		return NULL;
	}
	RzFloatFormat format = cast.format;
	RzFloat *ret = rz_float_cast_float(bv, format, mode);

	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fcast_sfloat(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFCastSFloat cast = op->op.fcast_sfloat;
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &cast.rmode, &mode)) {
		return NULL;
	}
	RzBitVector *bv = rz_il_evaluate_bitv(vm, cast.bv);
	if (!bv) {
		return NULL;
	}
	RzFloatFormat format = cast.format;
	RzFloat *ret = rz_float_cast_sfloat(bv, format, mode);

	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

static RzFloatRMode normalize_rmode(ut64 value, RzILOpPureCode code) {
	switch (value) {
	case RZ_FLOAT_RMODE_RNE:
	case RZ_FLOAT_RMODE_RNA:
	case RZ_FLOAT_RMODE_RTP:
	case RZ_FLOAT_RMODE_RTN:
	case RZ_FLOAT_RMODE_RTZ:
		return (RzFloatRMode)value;
	default:
		RZ_LOG_WARN("IL: %s got an invalid rounding-mode value 0x%" PFMT64x "; falling back to RNE\n",
			rz_il_op_pure_code_stringify(code), value);
		return RZ_FLOAT_RMODE_RNE;
	}
}

static bool resolve_rmode(RzILVM *vm, RzILOpPureCode code, const RzILOpArgFloatRMode *arg, RzFloatRMode *out) {
	switch (arg->kind) {
	case RZ_IL_OP_ARG_FLOAT_RMODE_STATIC:
		*out = normalize_rmode((ut64)arg->value.static_mode, code);
		return true;
	case RZ_IL_OP_ARG_FLOAT_RMODE_DYNAMIC: {
		if (!arg->value.dynamic_mode) {
			rz_warn_if_reached();
			return false;
		}
		RzBitVector *value = rz_il_evaluate_bitv(vm, arg->value.dynamic_mode);
		if (!value) {
			return false;
		}
		ut32 length = rz_bv_len(value);
		if (length != 32) {
			RZ_LOG_ERROR("IL: rounding-mode operand of %s must be 32 bits, got %u\n",
				rz_il_op_pure_code_stringify(code), (unsigned int)length);
			rz_bv_free(value);
			return false;
		}
		*out = normalize_rmode(rz_bv_to_ut64(value), code);
		rz_bv_free(value);
		return true;
	}
	default:
		rz_warn_if_reached();
		RZ_LOG_ERROR("IL: %s has an invalid rounding-mode argument kind %u\n",
			rz_il_op_pure_code_stringify(code), (unsigned int)arg->kind);
		return false;
	}
}

void *rz_il_handler_fconvert(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFconvert convert = op->op.fconvert;
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &convert.rmode, &mode)) {
		return NULL;
	}
	RzFloat *f = rz_il_evaluate_float(vm, convert.f);
	if (!f) {
		return NULL;
	}
	RzFloatFormat format = convert.format;
	RzFloat *ret = rz_float_convert(f, format, mode);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_frequal(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFrequal frequal = op->op.frequal;
	RzILBool *ret = rz_il_bool_new(frequal.x == frequal.y);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

void *rz_il_handler_fsucc(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFsucc fsucc = op->op.fsucc;
	RzFloat *f = rz_il_evaluate_float(vm, fsucc.f);
	if (!f) {
		return NULL;
	}
	RzFloat *ret = rz_float_succ(f);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fpred(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFpred fpred = op->op.fpred;
	RzFloat *f = rz_il_evaluate_float(vm, fpred.f);
	if (!f) {
		return NULL;
	}
	RzFloat *ret = rz_float_pred(f);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_forder(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsForder forder = op->op.forder;
	RzFloat *x = rz_il_evaluate_float(vm, forder.x);
	RzFloat *y = rz_il_evaluate_float(vm, forder.y);
	RzILBool *order = rz_il_bool_new(rz_float_cmp(x, y) == -1);

	rz_float_free(x);
	rz_float_free(y);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return order;
}

static void float_merge_operand_exceptions(RzFloat *ret, const RzFloat *x, const RzFloat *y, const RzFloat *z);

/* RzIL float operations are pure, so binary80 results must not depend on the
 * caller's thread-local SoftFloat precision. */
static bool float_full_precision_begin(bool has_binary80_operand, RzFloatRPrecision *saved) {
	*saved = RZ_FLOAT_RPREC_UNK;
	if (!has_binary80_operand) {
		return true;
	}
	*saved = rz_float_ext80_get_rounding_precision();
	if (*saved == RZ_FLOAT_RPREC_UNK || !rz_float_ext80_set_rounding_precision(RZ_FLOAT_RPREC_80)) {
		rz_warn_if_reached();
		return false;
	}
	return true;
}

static void float_full_precision_end(RzFloatRPrecision saved) {
	if (saved != RZ_FLOAT_RPREC_UNK) {
		rz_warn_if_fail(rz_float_ext80_set_rounding_precision(saved));
	}
}

static RzFloat *float_unop_full_precision(RzFloat *x, RzFloatRMode mode, RzFloat *(*operation)(RzFloat *, RzFloatRMode)) {
	RzFloatRPrecision saved;
	if (!float_full_precision_begin(x && x->r == RZ_FLOAT_IEEE754_BIN_80, &saved)) {
		return NULL;
	}
	RzFloat *ret = operation(x, mode);
	float_full_precision_end(saved);
	return ret;
}

static RzFloat *float_binop_full_precision(RzFloat *x, RzFloat *y, RzFloatRMode mode, RzFloat *(*operation)(RzFloat *, RzFloat *, RzFloatRMode)) {
	RzFloatRPrecision saved;
	bool has_binary80_operand = (x && x->r == RZ_FLOAT_IEEE754_BIN_80) || (y && y->r == RZ_FLOAT_IEEE754_BIN_80);
	if (!float_full_precision_begin(has_binary80_operand, &saved)) {
		return NULL;
	}
	RzFloat *ret = operation(x, y, mode);
	float_full_precision_end(saved);
	return ret;
}

static RzFloat *float_terop_full_precision(RzFloat *x, RzFloat *y, RzFloat *z, RzFloatRMode mode,
	RzFloat *(*operation)(RzFloat *, RzFloat *, RzFloat *, RzFloatRMode)) {
	RzFloatRPrecision saved;
	bool has_binary80_operand = (x && x->r == RZ_FLOAT_IEEE754_BIN_80) ||
		(y && y->r == RZ_FLOAT_IEEE754_BIN_80) || (z && z->r == RZ_FLOAT_IEEE754_BIN_80);
	if (!float_full_precision_begin(has_binary80_operand, &saved)) {
		return NULL;
	}
	RzFloat *ret = operation(x, y, z, mode);
	float_full_precision_end(saved);
	return ret;
}

static RzFloat *float_hybrid_full_precision(RzFloat *x, RzBitVector *n, RzFloatRMode mode,
	RzFloat *(*operation)(RzFloat *, RzBitVector *, RzFloatRMode)) {
	RzFloatRPrecision saved;
	if (!float_full_precision_begin(x && x->r == RZ_FLOAT_IEEE754_BIN_80, &saved)) {
		return NULL;
	}
	RzFloat *ret = operation(x, n, mode);
	float_full_precision_end(saved);
	return ret;
}

void *rz_il_handler_fround(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFround fround = op->op.fround;
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &fround.rmode, &mode)) {
		return NULL;
	}
	RzFloat *f = rz_il_evaluate_float(vm, fround.f);
	if (!f) {
		return NULL;
	}
	RzFloat *ret = rz_float_round_to_integral(f, mode);
	float_merge_operand_exceptions(ret, f, NULL, NULL);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fsqrt(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFsqrt sqrt = op->op.fsqrt;
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &sqrt.rmode, &mode)) {
		return NULL;
	}
	RzFloat *n = rz_il_evaluate_float(vm, sqrt.f);
	if (!n) {
		return NULL;
	}
	RzFloat *ret = float_unop_full_precision(n, mode, rz_float_sqrt);
	float_merge_operand_exceptions(ret, n, NULL, NULL);

	rz_float_free(n);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fexcept(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFexcept args = op->op.fexcept;
	RzFloat *n = rz_il_evaluate_float(vm, args.x);
	if (!n) {
		return NULL;
	}

	bool e = false;
	RzILEventException exception = RZ_IL_EVENT_EXC_NONE;
	switch (args.e) {
	case RZ_FLOAT_E_DIV_ZERO:
		e = n->exception & RZ_FLOAT_E_DIV_ZERO;
		exception = RZ_IL_EVENT_EXC_FP_DIV_ZERO;
		break;
	case RZ_FLOAT_E_OVERFLOW:
		e = n->exception & RZ_FLOAT_E_OVERFLOW;
		exception = RZ_IL_EVENT_EXC_FP_OVERFLOW;
		break;
	case RZ_FLOAT_E_UNDERFLOW:
		e = n->exception & RZ_FLOAT_E_UNDERFLOW;
		exception = RZ_IL_EVENT_EXC_FP_UNDERFLOW;
		break;
	case RZ_FLOAT_E_INEXACT:
		e = n->exception & RZ_FLOAT_E_INEXACT;
		exception = RZ_IL_EVENT_EXC_FP_INEXACT;
		break;
	case RZ_FLOAT_E_INVALID_OP:
		e = n->exception & RZ_FLOAT_E_INVALID_OP;
		exception = RZ_IL_EVENT_EXC_FP_INVALID_OP;
		break;
	default:;
	}
	if (e) {
		rz_il_vm_event_add(vm, rz_il_event_exception_new(exception));
	}

	RzILBool *ret = rz_il_bool_new(e);
	rz_float_free(n);

	*type = RZ_IL_TYPE_PURE_BOOL;
	return ret;
}

static void float_merge_operand_exceptions(RzFloat *ret, const RzFloat *x, const RzFloat *y, const RzFloat *z) {
	if (!ret) {
		return;
	}
	if (x) {
		ret->exception |= x->exception;
	}
	if (y) {
		ret->exception |= y->exception;
	}
	if (z) {
		ret->exception |= z->exception;
	}
}

static void *handle_float_unop(RzILVM *vm, RzILOpPure *op, RzILTypePure *type,
	const RzILOpArgsFloatAlgUnop *args,
	RzFloat *(*operation)(RzFloat *, RzFloatRMode)) {
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &args->rmode, &mode)) {
		return NULL;
	}
	RzFloat *x = rz_il_evaluate_float(vm, args->f);
	if (!x) {
		return NULL;
	}
	RzFloat *ret = float_unop_full_precision(x, mode, operation);
	float_merge_operand_exceptions(ret, x, NULL, NULL);
	rz_float_free(x);
	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

static void *handle_float_binop(RzILVM *vm, RzILOpPure *op, RzILTypePure *type,
	const RzILOpArgsFloatAlgBinop *args,
	RzFloat *(*operation)(RzFloat *, RzFloat *, RzFloatRMode)) {
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &args->rmode, &mode)) {
		return NULL;
	}
	RzFloat *x = rz_il_evaluate_float(vm, args->x);
	if (!x) {
		return NULL;
	}
	RzFloat *y = rz_il_evaluate_float(vm, args->y);
	if (!y) {
		rz_float_free(x);
		return NULL;
	}
	RzFloat *ret = float_binop_full_precision(x, y, mode, operation);
	float_merge_operand_exceptions(ret, x, y, NULL);
	rz_float_free(x);
	rz_float_free(y);
	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

/* The integer operand of rootn, pown and compound is a signed two's
 * complement integer of any width, it carries no exception flags. */
static void *handle_float_hybrid_binop(RzILVM *vm, RzILOpPure *op, RzILTypePure *type,
	const RzILOpArgsFloatAlgHybridBinop *args,
	RzFloat *(*operation)(RzFloat *, RzBitVector *, RzFloatRMode)) {
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &args->rmode, &mode)) {
		return NULL;
	}
	RzFloat *x = rz_il_evaluate_float(vm, args->f);
	if (!x) {
		return NULL;
	}
	RzBitVector *n = rz_il_evaluate_bitv(vm, args->n);
	if (!n) {
		rz_float_free(x);
		return NULL;
	}
	RzFloat *ret = float_hybrid_full_precision(x, n, mode, operation);
	float_merge_operand_exceptions(ret, x, NULL, NULL);
	rz_float_free(x);
	rz_bv_free(n);
	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_frsqrt(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.frsqrt, rz_float_rsqrt);
}

void *rz_il_handler_fadd(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_binop(vm, op, type, &op->op.binop_float_alg, rz_float_add);
}

void *rz_il_handler_fsub(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_binop(vm, op, type, &op->op.binop_float_alg, rz_float_sub);
}

void *rz_il_handler_fdiv(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_binop(vm, op, type, &op->op.binop_float_alg, rz_float_div);
}

void *rz_il_handler_fmul(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_binop(vm, op, type, &op->op.binop_float_alg, rz_float_mul);
}

void *rz_il_handler_fmod(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_binop(vm, op, type, &op->op.binop_float_alg, rz_float_mod);
}

void *rz_il_handler_fhypot(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_binop(vm, op, type, &op->op.fhypot, rz_float_hypot);
}

void *rz_il_handler_fpow(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_binop(vm, op, type, &op->op.fpow, rz_float_pow);
}

void *rz_il_handler_fmad(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFmad fmad = op->op.fmad;
	RzFloatRMode mode;
	if (!resolve_rmode(vm, op->code, &fmad.rmode, &mode)) {
		return NULL;
	}
	RzFloat *x = rz_il_evaluate_float(vm, fmad.x);
	if (!x) {
		return NULL;
	}
	RzFloat *y = rz_il_evaluate_float(vm, fmad.y);
	if (!y) {
		rz_float_free(x);
		return NULL;
	}
	RzFloat *z = rz_il_evaluate_float(vm, fmad.z);
	if (!z) {
		rz_float_free(x);
		rz_float_free(y);
		return NULL;
	}
	RzFloat *ret = float_terop_full_precision(x, y, z, mode, rz_float_fma);
	float_merge_operand_exceptions(ret, x, y, z);

	rz_float_free(x);
	rz_float_free(y);
	rz_float_free(z);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_frootn(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_hybrid_binop(vm, op, type, &op->op.frootn, rz_float_rootn);
}

void *rz_il_handler_fpown(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_hybrid_binop(vm, op, type, &op->op.fpown, rz_float_pown);
}

void *rz_il_handler_fcompound(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_hybrid_binop(vm, op, type, &op->op.fcompound, rz_float_compound);
}

void *rz_il_handler_fexp(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fexp, rz_float_exp);
}

void *rz_il_handler_fexpm1(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fexpm1, rz_float_expm1);
}

void *rz_il_handler_fexp2(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fexp2, rz_float_exp2);
}

void *rz_il_handler_fexp2m1(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fexp2m1, rz_float_exp2m1);
}

void *rz_il_handler_fexp10(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fexp10, rz_float_exp10);
}

void *rz_il_handler_fexp10m1(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fexp10m1, rz_float_exp10m1);
}

void *rz_il_handler_flog(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.flog, rz_float_log);
}

void *rz_il_handler_flog2(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.flog2, rz_float_log2);
}

void *rz_il_handler_flog10(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.flog10, rz_float_log10);
}

void *rz_il_handler_flogp1(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.flogp1, rz_float_logp1);
}

void *rz_il_handler_flog2p1(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.flog2p1, rz_float_log2p1);
}

void *rz_il_handler_flog10p1(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.flog10p1, rz_float_log10p1);
}

void *rz_il_handler_fsin(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fsin, rz_float_sin);
}

void *rz_il_handler_fcos(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fcos, rz_float_cos);
}

void *rz_il_handler_ftan(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.ftan, rz_float_tan);
}

void *rz_il_handler_fsinpi(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fsinpi, rz_float_sinpi);
}

void *rz_il_handler_fcospi(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fcospi, rz_float_cospi);
}

void *rz_il_handler_ftanpi(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.ftanpi, rz_float_tanpi);
}

void *rz_il_handler_fasin(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fasin, rz_float_asin);
}

void *rz_il_handler_facos(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.facos, rz_float_acos);
}

void *rz_il_handler_fatan(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fatan, rz_float_atan);
}

void *rz_il_handler_fasinpi(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fasinpi, rz_float_asinpi);
}

void *rz_il_handler_facospi(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.facospi, rz_float_acospi);
}

void *rz_il_handler_fatanpi(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fatanpi, rz_float_atanpi);
}

void *rz_il_handler_fsinh(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fsinh, rz_float_sinh);
}

void *rz_il_handler_fcosh(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fcosh, rz_float_cosh);
}

void *rz_il_handler_ftanh(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.ftanh, rz_float_tanh);
}

void *rz_il_handler_fasinh(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fasinh, rz_float_asinh);
}

void *rz_il_handler_facosh(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.facosh, rz_float_acosh);
}

void *rz_il_handler_fatanh(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_unop(vm, op, type, &op->op.fatanh, rz_float_atanh);
}

void *rz_il_handler_fatan2(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	// the first operand is the ordinate, as for rz_float_atan2(y, x)
	return handle_float_binop(vm, op, type, &op->op.binop_float_alg, rz_float_atan2);
}

void *rz_il_handler_fatan2pi(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	// the first operand is the ordinate, as for rz_float_atan2pi(y, x)
	return handle_float_binop(vm, op, type, &op->op.binop_float_alg, rz_float_atan2pi);
}

void *rz_il_handler_fpowr(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return handle_float_binop(vm, op, type, &op->op.fpowr, rz_float_powr);
}
