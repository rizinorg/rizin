// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file m68k_il_fpu_trans.inc
 * RzIL for the MC6888X/M68040FPSP transcendental instructions (FACOS through
 * FTWOTOX and FSINCOS, M68000PM/AD REV.1 Section 5). Included by m68k_il.c.
 *
 * MC68881/MC68882 UM 4.3.2 leaves the exact result of these functions
 * unspecified: the error bound is one double-precision ulp. The lifter uses
 * the correctly rounded IEEE 754-2019 9.2 RzIL operations on the operand
 * converted exactly to binary128, truncated and rounded to odd, so that the
 * single rounding to the FPCR precision and mode below is the correct
 * rounding of the exact value. Special operands follow the M68000PRM
 * operation tables and UM Tables 6-2 and 6-3.
 */

#define TRANS_FMT RZ_FLOAT_IEEE754_BIN_128
#define TRANS_RNE RZ_FLOAT_RMODE_RNE

typedef enum {
	TRANS_SIN,
	TRANS_COS,
	TRANS_TAN,
	TRANS_ASIN,
	TRANS_ACOS,
	TRANS_ATAN,
	TRANS_ATANH,
	TRANS_SINH,
	TRANS_COSH,
	TRANS_TANH,
	TRANS_ETOX,
	TRANS_ETOXM1,
	TRANS_TWOTOX,
	TRANS_TENTOX,
	TRANS_LOGN,
	TRANS_LOGNP1,
	TRANS_LOG2,
	TRANS_LOG10,
} M68KTransFn;

typedef RzILOpFloat *(*TransUnop)(RzFloatRMode mode, RzILOpFloat *x);

static bool trans_fn_for_insn(ut32 insn_id, M68KTransFn *fn) {
	switch (insn_id) {
	case M68K_INS_FSIN: *fn = TRANS_SIN; return true;
	case M68K_INS_FCOS: *fn = TRANS_COS; return true;
	case M68K_INS_FTAN: *fn = TRANS_TAN; return true;
	case M68K_INS_FASIN: *fn = TRANS_ASIN; return true;
	case M68K_INS_FACOS: *fn = TRANS_ACOS; return true;
	case M68K_INS_FATAN: *fn = TRANS_ATAN; return true;
	case M68K_INS_FATANH: *fn = TRANS_ATANH; return true;
	case M68K_INS_FSINH: *fn = TRANS_SINH; return true;
	case M68K_INS_FCOSH: *fn = TRANS_COSH; return true;
	case M68K_INS_FTANH: *fn = TRANS_TANH; return true;
	case M68K_INS_FETOX: *fn = TRANS_ETOX; return true;
	case M68K_INS_FETOXM1: *fn = TRANS_ETOXM1; return true;
	case M68K_INS_FTWOTOX: *fn = TRANS_TWOTOX; return true;
	case M68K_INS_FTENTOX: *fn = TRANS_TENTOX; return true;
	case M68K_INS_FLOGN: *fn = TRANS_LOGN; return true;
	case M68K_INS_FLOGNP1: *fn = TRANS_LOGNP1; return true;
	case M68K_INS_FLOG2: *fn = TRANS_LOG2; return true;
	case M68K_INS_FLOG10: *fn = TRANS_LOG10; return true;
	default: return false;
	}
}

static TransUnop trans_op(M68KTransFn fn) {
	switch (fn) {
	case TRANS_SIN: return rz_il_op_new_fsin;
	case TRANS_COS: return rz_il_op_new_fcos;
	case TRANS_TAN: return rz_il_op_new_ftan;
	case TRANS_ASIN: return rz_il_op_new_fasin;
	case TRANS_ACOS: return rz_il_op_new_facos;
	case TRANS_ATAN: return rz_il_op_new_fatan;
	case TRANS_ATANH: return rz_il_op_new_fatanh;
	case TRANS_SINH: return rz_il_op_new_fsinh;
	case TRANS_COSH: return rz_il_op_new_fcosh;
	case TRANS_TANH: return rz_il_op_new_ftanh;
	case TRANS_ETOX: return rz_il_op_new_fexp;
	case TRANS_ETOXM1: return rz_il_op_new_fexpm1;
	case TRANS_TWOTOX: return rz_il_op_new_fexp2;
	case TRANS_TENTOX: return rz_il_op_new_fexp10;
	case TRANS_LOGN: return rz_il_op_new_flog;
	case TRANS_LOGNP1: return rz_il_op_new_flogp1;
	case TRANS_LOG2: return rz_il_op_new_flog2;
	case TRANS_LOG10: return rz_il_op_new_flog10;
	default: return NULL;
	}
}

/* dst = op(trans_x) truncated and rounded to odd in binary128; exact is
 * set when the IEEE operation reports an exact result. Rounding this
 * value once more to 24, 53 or 64 bits in any mode equals the rounding of
 * the exact result, and truncation keeps overflow finite. */
static RzILOpEffect *trans_compute(TransUnop op, const char *dst, const char *exact) {
	return SEQ3(
		SETL("trans_rz", op(RZ_FLOAT_RMODE_RTZ, VARL("trans_x"))),
		SETL(exact, INV(FEXCEPT(RZ_FLOAT_E_INEXACT, VARL("trans_rz")))),
		SETL(dst, BV2F(TRANS_FMT, LOGOR(F2BV(VARL("trans_rz")), BOOL_TO_BV(INV(VARL(exact)), 128)))));
}

static RzILOpFloat *trans_zero(void) {
	return BV2F(TRANS_FMT, UN(128, 0));
}

static RzILOpFloat *trans_one(void) {
	return BV2F(TRANS_FMT, APPEND(U64(0x3fff000000000000ULL), U64(0)));
}

static RzILOpPure *trans_fp80_exponent(RzILOpFloat *fp80) {
	return UNSIGNED(16, LOGAND(SHIFTR0(F2BV(fp80), U8(64)), UN(80, 0x7fff)));
}

/* Rounds trans_v once to the FPCR precision and mode into res_fp.
 * exact_exp and tiny_result follow the arithmetic instructions (UM 6.1.4,
 * 6.1.5; tininess before rounding, MC68040 UM 9.7.5). INEX2 is set unless
 * trans_v is the exact result and the rounding kept it (UM 6.1.7). */
static RzILOpEffect *trans_round_effect(const char *v, const char *exact, const char *res, const char *inex2) {
	RzILOpPure *min_exp = ITE(EQ(VARL("precision"), U32(1)), U16(0x3f81),
		ITE(EQ(VARL("precision"), U32(2)), U16(0x3c01), U16(1)));
	return SEQ4(
		SETL(res, fpu_result_with_fpcr_precision(VARL(v))),
		SETL("exact_exp", trans_fp80_exponent(FCONVERT(RZ_FLOAT_IEEE754_BIN_80, TRANS_RNE, VARL(v)))),
		SETL("tiny_result", AND(ULT(trans_fp80_exponent(FCONVERT(RZ_FLOAT_IEEE754_BIN_80, RZ_FLOAT_RMODE_RTZ, VARL(v))), min_exp), INV(IS_FZERO(VARL(v))))),
		SETL(inex2, OR(INV(VARL(exact)), INV(EQ(F2BV(FCONVERT(TRANS_FMT, TRANS_RNE, VARL(res))), F2BV(VARL(v)))))));
}

/* trans_x is the operand converted exactly to binary128. */
static RzILOpEffect *trans_prologue(M68KILCtx *ctx) {
	return SEQ5(
		SETL("round_mode", fpu_fpcr_round_mode()),
		SETL("precision", fpu_fpcr_precision(ctx)),
		SETL("trans_x", FCONVERT(TRANS_FMT, TRANS_RNE, VARL("src_fp"))),
		SETL("trans_ax", FABS(VARL("trans_x"))),
		SETL("trans_xneg", IS_FNEG(VARL("trans_x"))));
}

static RzILOpBool *trans_is_nan(void) {
	return IS_FNAN(VARL("trans_x"));
}

static RzILOpBool *trans_is_inf(void) {
	return IS_FINF(VARL("trans_x"));
}

static RzILOpBool *trans_is_zero(void) {
	return IS_FZERO(VARL("trans_x"));
}

static RzILOpFloat *trans_fp80_const(ut16 sign_exp, ut64 mantissa) {
	return BV2F(RZ_FLOAT_IEEE754_BIN_80, fpu_const80_bits(sign_exp, mantissa));
}

static RzILOpFloat *trans_fp80_one(bool negative) {
	return trans_fp80_const(negative ? 0xbfff : 0x3fff, 0x8000000000000000ULL);
}

static RzILOpFloat *trans_fp80_inf(bool negative) {
	return trans_fp80_const(negative ? 0xffff : 0x7fff, 0x8000000000000000ULL);
}

/* The operand itself, for the signed zeros and infinities the operation
 * tables pass through. */
static RzILOpFloat *trans_fp80_src(void) {
	return FCONVERT(RZ_FLOAT_IEEE754_BIN_80, TRANS_RNE, VARL("trans_x"));
}

/* Table 6-2: operand errors. A NaN never compares, so it is excluded. */
static RzILOpBool *trans_operr(M68KTransFn fn) {
	switch (fn) {
	case TRANS_SIN:
	case TRANS_COS:
	case TRANS_TAN:
		return trans_is_inf();
	case TRANS_ASIN:
	case TRANS_ACOS:
	case TRANS_ATANH:
		return OR(trans_is_inf(), FGT(VARL("trans_ax"), trans_one()));
	case TRANS_LOGN:
	case TRANS_LOG2:
	case TRANS_LOG10:
		return AND(INV(trans_is_nan()), AND(VARL("trans_xneg"), INV(trans_is_zero())));
	case TRANS_LOGNP1:
		return FLT(VARL("trans_x"), FNEG(trans_one()));
	default:
		return IL_FALSE;
	}
}

/* Table 6-3: divide-by-zero. */
static RzILOpBool *trans_dz(M68KTransFn fn) {
	switch (fn) {
	case TRANS_ATANH:
		return FEQ(VARL("trans_ax"), trans_one());
	case TRANS_LOGN:
	case TRANS_LOG2:
	case TRANS_LOG10:
		return trans_is_zero();
	case TRANS_LOGNP1:
		return FEQ(VARL("trans_x"), FNEG(trans_one()));
	default:
		return IL_FALSE;
	}
}

/* UM 6.1.6: the FLOGx instructions return minus infinity. For FATANH both
 * that section and the M68000PRM FATANH description return -infinity
 * for a source of +1 and +infinity for -1. */
static RzILOpFloat *trans_dz_result(M68KTransFn fn) {
	if (fn == TRANS_ATANH) {
		return ITE(VARL("trans_xneg"), trans_fp80_inf(false), trans_fp80_inf(true));
	}
	return trans_fp80_inf(true);
}

/* Exact entries of the operation tables. Other special operands go
 * through trans_compute(): FACOS of zero is pi/2 and FATAN of an
 * infinity is +-pi/2, both rounded. */
static RzILOpBool *trans_special(M68KTransFn fn) {
	switch (fn) {
	case TRANS_SIN:
	case TRANS_COS:
	case TRANS_TAN:
	case TRANS_ASIN:
	case TRANS_ATAN:
	case TRANS_ATANH:
		return trans_is_zero();
	case TRANS_LOGNP1:
		return OR(trans_is_zero(), AND(trans_is_inf(), INV(VARL("trans_xneg"))));
	case TRANS_SINH:
	case TRANS_COSH:
	case TRANS_TANH:
	case TRANS_ETOX:
	case TRANS_ETOXM1:
	case TRANS_TWOTOX:
	case TRANS_TENTOX:
		return OR(trans_is_zero(), trans_is_inf());
	case TRANS_LOGN:
	case TRANS_LOG2:
	case TRANS_LOG10:
		return AND(trans_is_inf(), INV(VARL("trans_xneg")));
	default:
		return IL_FALSE;
	}
}

static RzILOpFloat *trans_special_result(M68KTransFn fn) {
	switch (fn) {
	case TRANS_COS:
		return trans_fp80_one(false);
	case TRANS_COSH:
		return ITE(trans_is_zero(), trans_fp80_one(false), trans_fp80_inf(false));
	case TRANS_TANH:
		return ITE(trans_is_zero(), trans_fp80_src(), ITE(VARL("trans_xneg"), trans_fp80_one(true), trans_fp80_one(false)));
	case TRANS_ETOX:
	case TRANS_TWOTOX:
	case TRANS_TENTOX:
		return ITE(trans_is_zero(), trans_fp80_one(false),
			ITE(VARL("trans_xneg"), trans_fp80_const(0, 0), trans_fp80_inf(false)));
	case TRANS_ETOXM1:
		return ITE(AND(trans_is_inf(), VARL("trans_xneg")), trans_fp80_one(true), trans_fp80_src());
	default:
		return trans_fp80_src();
	}
}

static RzILOpEffect *trans_set_fpsr(RzILOpBool *ovfl) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(LOGOR(
					  ITE(VARL("trans_operr"), U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
					  ITE(VARL("trans_dz"), U32((1u << M68K_FPSR_EXC_DZ) | (1u << M68K_FPSR_AEXC_DZ)), U32(0))),
		LOGOR(LOGOR(
			      ITE(AND(VARL("trans_generic"), ovfl), U32((1u << M68K_FPSR_EXC_OVFL) | (1u << M68K_FPSR_AEXC_OVFL) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)),
			      ITE(AND(VARL("trans_generic"), VARL("tiny_result")), U32(1u << M68K_FPSR_EXC_UNFL), U32(0))),
			LOGOR(
				ITE(AND(VARL("trans_generic"), AND(VARL("tiny_result"), VARL("trans_inex2"))), U32(1u << M68K_FPSR_AEXC_UNFL), U32(0)),
				ITE(AND(VARL("trans_generic"), VARL("trans_inex2")), U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)))));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_src_snan(flags)));
}

static RzILOpFloat *trans_nan_result(void) {
	return BV2F(RZ_FLOAT_IEEE754_BIN_80, fpu_quiet_fp80_nan_bits(VARL("src_bits")));
}

static bool trans_load_source(M68KILCtx *ctx, const cs_m68k_op *src, RzILOpEffect **seq) {
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	return fpu_operand_to_float_local(ctx, "src_fp", "src_bits", src, bits, seq);
}

/* FACOS ... FTWOTOX: M68000PRM 5-xx operation tables, MC68881/MC68882 UM
 * Tables 6-2 and 6-3. Condition codes follow the result. The quotient
 * byte is unchanged. */
static RzILOpEffect *lift_fpu_trans_data(M68KILCtx *ctx, ut32 insn_id) {
	M68KTransFn fn;
	if (!trans_fn_for_insn(insn_id, &fn) || ctx->m68k->op_count < 1) {
		return NULL;
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_unary_dst_op(ctx->insn, src, &hidden_dst);
	if (!dst || !rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}
	RzILOpEffect *seq = NULL;
	if (!trans_load_source(ctx, src, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, src);
	}
	RzILOpEffect *compute = trans_compute(trans_op(fn), "trans_v", "trans_exact");
	seq = SEQ6(seq,
		trans_prologue(ctx),
		SETL("trans_operr", trans_operr(fn)),
		SETL("trans_dz", trans_dz(fn)),
		SETL("trans_special", trans_special(fn)),
		SETL("trans_generic", AND(INV(trans_is_nan()), AND(INV(VARL("trans_operr")), AND(INV(VARL("trans_dz")), INV(VARL("trans_special")))))));
	return SEQ8(seq,
		BRANCH(VARL("trans_generic"), compute, SEQ2(SETL("trans_v", trans_zero()), SETL("trans_exact", IL_TRUE))),
		trans_round_effect("trans_v", "trans_exact", "res_fp", "trans_inex2"),
		SETL("res_fp", ITE(VARL("trans_special"), trans_special_result(fn), ITE(VARL("trans_operr"), fpu_default_nan(), ITE(VARL("trans_dz"), trans_dz_result(fn), VARL("res_fp"))))),
		SETL("res_fp", ITE(trans_is_nan(), trans_nan_result(), VARL("res_fp"))),
		m68k_write_reg_sized(ctx, dst->reg, 80, F2BV(VARL("res_fp"))),
		set_fpsr_cc_from_float_local("res_fp"),
		trans_set_fpsr(fpu_result_overflows_precision()));
}

/* FSINCOS (M68000PRM 5-121): the cosine is stored first, so the sine wins
 * when FPc and FPs are the same register. Condition codes and UNFL follow
 * the sine; OVFL is cleared. */
static RzILOpEffect *lift_fpu_sincos_data(M68KILCtx *ctx) {
	ut16 extension;
	if (ctx->m68k->op_count < 1 || !rz_m68k_fpu_insn_extension_word(ctx->insn, &extension)) {
		return NULL;
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	m68k_reg fpc = M68K_REG_FP0 + (extension & 7);
	m68k_reg fps = M68K_REG_FP0 + ((extension >> 7) & 7);
	RzILOpEffect *seq = NULL;
	if (!trans_load_source(ctx, src, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, src);
	}
	seq = SEQ6(seq,
		trans_prologue(ctx),
		SETL("trans_operr", trans_is_inf()),
		SETL("trans_dz", IL_FALSE),
		SETL("trans_special", trans_is_zero()),
		SETL("trans_generic", AND(INV(trans_is_nan()), AND(INV(VARL("trans_operr")), INV(VARL("trans_special"))))));
	seq = SEQ4(seq,
		BRANCH(VARL("trans_generic"),
			SEQ2(trans_compute(rz_il_op_new_fsin, "trans_v", "trans_exact"), trans_compute(rz_il_op_new_fcos, "trans_vc", "trans_exactc")),
			SEQ4(SETL("trans_v", trans_zero()), SETL("trans_exact", IL_TRUE), SETL("trans_vc", trans_one()), SETL("trans_exactc", IL_TRUE))),
		trans_round_effect("trans_vc", "trans_exactc", "trans_resc", "trans_inex2c"),
		trans_round_effect("trans_v", "trans_exact", "res_fp", "trans_inex2"));
	return SEQN(10, seq,
		SETL("trans_inex2", OR(VARL("trans_inex2"), VARL("trans_inex2c"))),
		SETL("trans_resc", ITE(VARL("trans_special"), trans_fp80_one(false), ITE(VARL("trans_operr"), fpu_default_nan(), VARL("trans_resc")))),
		SETL("trans_resc", ITE(trans_is_nan(), trans_nan_result(), VARL("trans_resc"))),
		SETL("res_fp", ITE(VARL("trans_special"), trans_fp80_src(), ITE(VARL("trans_operr"), fpu_default_nan(), VARL("res_fp")))),
		SETL("res_fp", ITE(trans_is_nan(), trans_nan_result(), VARL("res_fp"))),
		m68k_write_reg_sized(ctx, fpc, 80, F2BV(VARL("trans_resc"))),
		m68k_write_reg_sized(ctx, fps, 80, F2BV(VARL("res_fp"))),
		set_fpsr_cc_from_float_local("res_fp"),
		trans_set_fpsr(IL_FALSE));
}

#undef TRANS_RNE
#undef TRANS_FMT
