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

	RzILOpArgsFCastfloat cast = op->op.fcast_float;
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

	RzILOpArgsFCastsfloat cast = op->op.fcast_sfloat;
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
	switch (args.e) {
	case RZ_FLOAT_E_DIV_ZERO:
		e = n->exception & RZ_FLOAT_E_DIV_ZERO;
		rz_il_vm_event_add(vm, rz_il_event_exception_new(RZ_IL_EVENT_EXC_FP_DIV_ZERO));
		break;
	case RZ_FLOAT_E_OVERFLOW:
		e = n->exception & RZ_FLOAT_E_OVERFLOW;
		rz_il_vm_event_add(vm, rz_il_event_exception_new(RZ_IL_EVENT_EXC_FP_OVERFLOW));
		break;
	case RZ_FLOAT_E_UNDERFLOW:
		e = n->exception & RZ_FLOAT_E_UNDERFLOW;
		rz_il_vm_event_add(vm, rz_il_event_exception_new(RZ_IL_EVENT_EXC_FP_UNDERFLOW));
		break;
	case RZ_FLOAT_E_INEXACT:
		e = n->exception & RZ_FLOAT_E_INEXACT;
		rz_il_vm_event_add(vm, rz_il_event_exception_new(RZ_IL_EVENT_EXC_FP_INEXACT));
		break;
	default:;
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
