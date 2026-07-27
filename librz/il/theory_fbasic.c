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

void *rz_il_handler_fcast_int(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFCastint cast_int = op->op.fcast_int;
	RzFloat *f = rz_il_evaluate_float(vm, cast_int.f);
	if (!f) {
		return NULL;
	}
	ut32 length = cast_int.length;
	RzFloatRMode mode = cast_int.mode;
	RzBitVector *ret = rz_float_cast_int(f, length, mode);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return ret;
}

void *rz_il_handler_fcast_sint(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFCastint cast_sint = op->op.fcast_sint;
	RzFloat *f = rz_il_evaluate_float(vm, cast_sint.f);
	if (!f) {
		return NULL;
	}
	ut32 length = cast_sint.length;
	RzFloatRMode mode = cast_sint.mode;
	RzBitVector *ret = rz_float_cast_sint(f, length, mode);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return ret;
}

void *rz_il_handler_fcast_float(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFCastUFloat cast = op->op.fcast_float;
	RzBitVector *bv = rz_il_evaluate_bitv(vm, cast.bv);
	RzFloatFormat format = cast.format;
	RzFloatRMode mode = cast.mode;
	RzFloat *ret = rz_float_cast_float(bv, format, mode);

	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fcast_sfloat(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFCastSFloat cast = op->op.fcast_sfloat;
	RzBitVector *bv = rz_il_evaluate_bitv(vm, cast.bv);
	RzFloatFormat format = cast.format;
	RzFloatRMode mode = cast.mode;
	RzFloat *ret = rz_float_cast_sfloat(bv, format, mode);

	rz_bv_free(bv);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fconvert(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFconvert convert = op->op.fconvert;
	RzFloat *f = rz_il_evaluate_float(vm, convert.f);
	if (!f) {
		return NULL;
	}
	RzFloatFormat format = convert.format;
	RzFloatRMode mode = convert.mode;
	RzFloat *ret = rz_float_convert(f, format, mode);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fwith_rprec(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFwithRprec args = op->op.fwith_rprec;
	RzFloatRPrecision saved = rz_float_ext80_get_rounding_precision();
	if (saved == RZ_FLOAT_RPREC_UNK || !rz_float_ext80_set_rounding_precision(args.precision)) {
		return NULL;
	}
	RzFloat *ret = rz_il_evaluate_float(vm, args.f);
	rz_float_ext80_set_rounding_precision(saved);
	if (!ret || ret->r != RZ_FLOAT_IEEE754_BIN_80) {
		rz_float_free(ret);
		return NULL;
	}

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

void *rz_il_handler_fround(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFround fround = op->op.fround;
	RzFloat *f = rz_il_evaluate_float(vm, fround.f);
	if (!f) {
		return NULL;
	}
	RzFloatRMode mode = fround.rmode;
	RzFloat *ret = rz_float_round_to_integral(f, mode);
	float_merge_operand_exceptions(ret, f, NULL, NULL);

	rz_float_free(f);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fsqrt(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFsqrt sqrt = op->op.fsqrt;
	RzFloat *n = rz_il_evaluate_float(vm, sqrt.f);
	RzFloatRMode mode = sqrt.rmode;
	RzFloat *ret = rz_float_sqrt(n, mode);
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

void *rz_il_handler_frsqrt(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	// TODO : float todo unimplemented
	rz_return_val_if_fail(vm && op && type, NULL);
	return NULL;
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

void *rz_il_handler_fadd(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFadd fadd = op->op.fadd;
	RzFloat *x = rz_il_evaluate_float(vm, fadd.x);
	RzFloat *y = rz_il_evaluate_float(vm, fadd.y);
	RzFloatRMode mode = fadd.rmode;
	RzFloat *ret = rz_float_add(x, y, mode);
	float_merge_operand_exceptions(ret, x, y, NULL);

	rz_float_free(x);
	rz_float_free(y);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fsub(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFsub fsub = op->op.fsub;
	RzFloat *x = rz_il_evaluate_float(vm, fsub.x);
	RzFloat *y = rz_il_evaluate_float(vm, fsub.y);
	RzFloatRMode mode = fsub.rmode;
	RzFloat *ret = rz_float_sub(x, y, mode);
	float_merge_operand_exceptions(ret, x, y, NULL);

	rz_float_free(x);
	rz_float_free(y);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fdiv(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFdiv fdiv = op->op.fdiv;
	RzFloat *x = rz_il_evaluate_float(vm, fdiv.x);
	RzFloat *y = rz_il_evaluate_float(vm, fdiv.y);
	RzFloatRMode mode = fdiv.rmode;
	RzFloat *ret = rz_float_div(x, y, mode);
	float_merge_operand_exceptions(ret, x, y, NULL);

	rz_float_free(x);
	rz_float_free(y);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fmul(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFmul fmul = op->op.fmul;
	RzFloat *x = rz_il_evaluate_float(vm, fmul.x);
	RzFloat *y = rz_il_evaluate_float(vm, fmul.y);
	RzFloatRMode mode = fmul.rmode;
	RzFloat *ret = rz_float_mul(x, y, mode);
	float_merge_operand_exceptions(ret, x, y, NULL);

	rz_float_free(x);
	rz_float_free(y);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_fmod(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFmod fmod = op->op.fmod;
	RzFloat *x = rz_il_evaluate_float(vm, fmod.x);
	RzFloat *y = rz_il_evaluate_float(vm, fmod.y);
	RzFloatRMode mode = fmod.rmode;
	RzFloat *ret = rz_float_mod(x, y, mode);
	float_merge_operand_exceptions(ret, x, y, NULL);

	rz_float_free(x);
	rz_float_free(y);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

static bool runtime_rmode_from_value(const RzBitVector *value, RzFloatRMode *out) {
	if (rz_bv_len(value) != 32) {
		rz_warn_if_reached();
		return false;
	}
	ut64 v = rz_bv_to_ut64(value);
	if (v >= RZ_FLOAT_RMODE_UNK) {
		rz_warn_if_reached();
		return false;
	}
	*out = (RzFloatRMode)v;
	return true;
}

void *rz_il_handler_float_with_rmode(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpBitVector *rmode_op = rz_il_op_pure_float_rmode_operand(op);
	if (!rmode_op) {
		rz_warn_if_reached();
		return NULL;
	}

	RzBitVector *rmode_value = rz_il_evaluate_bitv(vm, rmode_op);
	if (!rmode_value) {
		return NULL;
	}
	RzFloatRMode rmode;
	if (!runtime_rmode_from_value(rmode_value, &rmode)) {
		RZ_LOG_ERROR("IL: %s got an invalid rounding-mode value 0x%" PFMT64x "\n",
			rz_il_op_pure_code_stringify(op->code), rz_bv_to_ut64(rmode_value));
		rz_bv_free(rmode_value);
		return NULL;
	}
	rz_bv_free(rmode_value);

	RzILOpPure delegated = { 0 };
	RzILOpPureHandler handler;
	switch (op->code) {
	case RZ_IL_OP_FCONVERT_WITH_RMODE:
		delegated.code = RZ_IL_OP_FCONVERT;
		delegated.op.fconvert = (RzILOpArgsFconvert){
			.format = op->op.fconvert_with_rmode.format,
			.mode = rmode,
			.f = op->op.fconvert_with_rmode.f,
		};
		handler = rz_il_handler_fconvert;
		break;
	case RZ_IL_OP_FROUND_WITH_RMODE:
	case RZ_IL_OP_FSQRT_WITH_RMODE: {
		/* fround_with_rmode and fsqrt_with_rmode share
		 * RzILOpArgsFloatAlgUnopWithRmode. */
		bool is_round = op->code == RZ_IL_OP_FROUND_WITH_RMODE;
		delegated.code = is_round ? RZ_IL_OP_FROUND : RZ_IL_OP_FSQRT;
		delegated.op.fround = (RzILOpArgsFround){
			.rmode = rmode,
			.f = op->op.fround_with_rmode.f,
		};
		handler = is_round ? rz_il_handler_fround : rz_il_handler_fsqrt;
		break;
	}
	case RZ_IL_OP_FADD_WITH_RMODE:
	case RZ_IL_OP_FSUB_WITH_RMODE:
	case RZ_IL_OP_FMUL_WITH_RMODE:
	case RZ_IL_OP_FDIV_WITH_RMODE:
	case RZ_IL_OP_FMOD_WITH_RMODE: {
		/* All binop-with-rmode args share RzILOpArgsFloatAlgBinopWithRmode. */
		const RzILOpArgsFloatAlgBinopWithRmode *args = &op->op.fadd_with_rmode;
		delegated.op.binop_float_alg = (RzILOpArgsFloatAlgBinop){
			.rmode = rmode,
			.x = args->x,
			.y = args->y,
		};
		switch (op->code) {
		case RZ_IL_OP_FADD_WITH_RMODE:
			delegated.code = RZ_IL_OP_FADD;
			handler = rz_il_handler_fadd;
			break;
		case RZ_IL_OP_FSUB_WITH_RMODE:
			delegated.code = RZ_IL_OP_FSUB;
			handler = rz_il_handler_fsub;
			break;
		case RZ_IL_OP_FMUL_WITH_RMODE:
			delegated.code = RZ_IL_OP_FMUL;
			handler = rz_il_handler_fmul;
			break;
		case RZ_IL_OP_FDIV_WITH_RMODE:
			delegated.code = RZ_IL_OP_FDIV;
			handler = rz_il_handler_fdiv;
			break;
		default:
			delegated.code = RZ_IL_OP_FMOD;
			handler = rz_il_handler_fmod;
			break;
		}
		break;
	}
	default:
		rz_warn_if_reached();
		return NULL;
	}
	return handler(vm, &delegated, type);
}

void *rz_il_handler_fhypot(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	// TODO : float todo unimplemented
	rz_return_val_if_fail(vm && op && type, NULL);
	return NULL;
}

void *rz_il_handler_fpow(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	// TODO : float todo unimplemented
	rz_return_val_if_fail(vm && op && type, NULL);
	return NULL;
}

void *rz_il_handler_fmad(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFmad fmad = op->op.fmad;
	RzFloat *x = rz_il_evaluate_float(vm, fmad.x);
	RzFloat *y = rz_il_evaluate_float(vm, fmad.y);
	RzFloat *z = rz_il_evaluate_float(vm, fmad.z);
	RzFloatRMode mode = fmad.rmode;
	RzFloat *ret = rz_float_fma(x, y, z, mode);
	float_merge_operand_exceptions(ret, x, y, z);

	rz_float_free(x);
	rz_float_free(y);
	rz_float_free(z);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

void *rz_il_handler_frootn(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	// TODO : float todo unimplemented
	rz_return_val_if_fail(vm && op && type, NULL);
	return NULL;
}

void *rz_il_handler_fpown(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	// TODO : float todo unimplemented
	rz_return_val_if_fail(vm && op && type, NULL);
	return NULL;
}

void *rz_il_handler_fcompound(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	// TODO : float todo unimplemented
	rz_return_val_if_fail(vm && op && type, NULL);
	return NULL;
}
