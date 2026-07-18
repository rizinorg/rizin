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

void *rz_il_handler_fround(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsFround fround = op->op.fround;
	RzFloat *f = rz_il_evaluate_float(vm, fround.f);
	if (!f) {
		return NULL;
	}
	RzFloatRMode mode = fround.rmode;
	RzFloat *ret = rz_float_round_to_integral(f, mode);

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

void *rz_il_handler_fadd(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsFadd fadd = op->op.fadd;
	RzFloat *x = rz_il_evaluate_float(vm, fadd.x);
	RzFloat *y = rz_il_evaluate_float(vm, fadd.y);
	RzFloatRMode mode = fadd.rmode;
	RzFloat *ret = rz_float_add(x, y, mode);

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

	rz_float_free(x);
	rz_float_free(y);

	*type = RZ_IL_TYPE_PURE_FLOAT;
	return ret;
}

static RzFloatRMode runtime_rmode_from_value(const RzBitVector *value) {
	switch (rz_bv_to_ut64(value)) {
	case RZ_FLOAT_RMODE_RNE:
		return RZ_FLOAT_RMODE_RNE;
	case RZ_FLOAT_RMODE_RNA:
		return RZ_FLOAT_RMODE_RNA;
	case RZ_FLOAT_RMODE_RTP:
		return RZ_FLOAT_RMODE_RTP;
	case RZ_FLOAT_RMODE_RTN:
		return RZ_FLOAT_RMODE_RTN;
	case RZ_FLOAT_RMODE_RTZ:
		return RZ_FLOAT_RMODE_RTZ;
	default:
		return RZ_FLOAT_RMODE_RNE;
	}
}

void *rz_il_handler_float_with_rmode(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpBitVector *rmode_op;
	switch (op->code) {
	case RZ_IL_OP_FCONVERT_WITH_RMODE:
		rmode_op = op->op.fconvert_with_rmode.rmode;
		break;
	case RZ_IL_OP_FROUND_WITH_RMODE:
		rmode_op = op->op.fround_with_rmode.rmode;
		break;
	case RZ_IL_OP_FSQRT_WITH_RMODE:
		rmode_op = op->op.fsqrt_with_rmode.rmode;
		break;
	case RZ_IL_OP_FADD_WITH_RMODE:
		rmode_op = op->op.fadd_with_rmode.rmode;
		break;
	case RZ_IL_OP_FSUB_WITH_RMODE:
		rmode_op = op->op.fsub_with_rmode.rmode;
		break;
	case RZ_IL_OP_FMUL_WITH_RMODE:
		rmode_op = op->op.fmul_with_rmode.rmode;
		break;
	case RZ_IL_OP_FDIV_WITH_RMODE:
		rmode_op = op->op.fdiv_with_rmode.rmode;
		break;
	case RZ_IL_OP_FMOD_WITH_RMODE:
		rmode_op = op->op.fmod_with_rmode.rmode;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}

	RzBitVector *rmode_value = rz_il_evaluate_bitv(vm, rmode_op);
	if (!rmode_value) {
		return NULL;
	}
	RzFloatRMode rmode = runtime_rmode_from_value(rmode_value);
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
		delegated.code = RZ_IL_OP_FROUND;
		delegated.op.fround = (RzILOpArgsFround){
			.rmode = rmode,
			.f = op->op.fround_with_rmode.f,
		};
		handler = rz_il_handler_fround;
		break;
	case RZ_IL_OP_FSQRT_WITH_RMODE:
		delegated.code = RZ_IL_OP_FSQRT;
		delegated.op.fsqrt = (RzILOpArgsFsqrt){
			.rmode = rmode,
			.f = op->op.fsqrt_with_rmode.f,
		};
		handler = rz_il_handler_fsqrt;
		break;
	case RZ_IL_OP_FADD_WITH_RMODE:
		delegated.code = RZ_IL_OP_FADD;
		delegated.op.fadd = (RzILOpArgsFadd){
			.rmode = rmode,
			.x = op->op.fadd_with_rmode.x,
			.y = op->op.fadd_with_rmode.y,
		};
		handler = rz_il_handler_fadd;
		break;
	case RZ_IL_OP_FSUB_WITH_RMODE:
		delegated.code = RZ_IL_OP_FSUB;
		delegated.op.fsub = (RzILOpArgsFsub){
			.rmode = rmode,
			.x = op->op.fsub_with_rmode.x,
			.y = op->op.fsub_with_rmode.y,
		};
		handler = rz_il_handler_fsub;
		break;
	case RZ_IL_OP_FMUL_WITH_RMODE:
		delegated.code = RZ_IL_OP_FMUL;
		delegated.op.fmul = (RzILOpArgsFmul){
			.rmode = rmode,
			.x = op->op.fmul_with_rmode.x,
			.y = op->op.fmul_with_rmode.y,
		};
		handler = rz_il_handler_fmul;
		break;
	case RZ_IL_OP_FDIV_WITH_RMODE:
		delegated.code = RZ_IL_OP_FDIV;
		delegated.op.fdiv = (RzILOpArgsFdiv){
			.rmode = rmode,
			.x = op->op.fdiv_with_rmode.x,
			.y = op->op.fdiv_with_rmode.y,
		};
		handler = rz_il_handler_fdiv;
		break;
	case RZ_IL_OP_FMOD_WITH_RMODE:
		delegated.code = RZ_IL_OP_FMOD;
		delegated.op.fmod = (RzILOpArgsFmod){
			.rmode = rmode,
			.x = op->op.fmod_with_rmode.x,
			.y = op->op.fmod_with_rmode.y,
		};
		handler = rz_il_handler_fmod;
		break;
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
