// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// static const ut32 ADD_NAN __attribute__((unused)) = 0x7fc00001;
// static const ut32 DIV_NAN __attribute__((unused)) = 0x7fc00008;
// static const ut32 MUL_NAN __attribute__((unused)) = 0x7fc00002;
// static const ut32 SQRT_NAN __attribute__((unused)) = 0x7fc00004;
//
// static const ut32 HP_MAX_VALUE __attribute__((unused)) = 65504;
// static const ut32 HP_MIN_NORMAL __attribute__((unused)) = 1024 * 16;

static const ut32 HP_NEG_INFINITY = 0xfc00;
static const ut32 HP_POS_INFINITY = 0x7c00;

// static const ut32 NEG_INFINITY __attribute__((unused)) = 0xff800000;
// static const ut32 POS_INFINITY __attribute__((unused)) = 0x7f800000;

#define F2SINT32(x, m) F2SINT(32, m, x)

static inline RzILOpPure *denorm_to_zero(RzILOpFloat *x) {
	return LET("tmp", x,
		ITE(AND(FLT(VARLP("tmp"), F32(0.0)), FGT(VARLP("tmp"), F32(powf(-2, -126)))), FNEG(F32(0)),
			ITE(AND(FGT(VARLP("tmp"), F32(0)), FLT(VARLP("tmp"), F32(powf(2, -126)))), F32(0),
				VARLP("tmp"))));
}

static inline RzILOpPure *is_denorm(RzILOpPure *x) {
	return AND(IS_ZERO(BITS32(x, 23, 8)), NON_ZERO(BITS32(DUP(x), 0, 23)));
}

/**
 * \brief Returns the Q31 format value ‘x’ as an infinitely accurate real value.
 */
static inline RzILOpFloat *q_real(ut32 x) {
	float y = x & 0x80000000 ? -1.f : 0.f;
	for (int i = 0; i < 31; ++i) {
		ut32 m = 1 << (30 - i);
		float b = 1.f / (float)(2 << i);
		if (x & m) {
			y += b;
		}
	}
	RzFloat *value = rz_float_new_from_f32(y);
	if (!value) {
		return NULL;
	}
	return rz_il_op_new_float_from_rz_float(value);
}

static inline RzILOpEffect *q_real_set_v(const char *k, RzILOpPure *x) {
	return SEQ4(
		SETL("_x", x),
		SETL("_i", U32(0)),
		SETL(k, ITE(MSB(VARL("_x")), F32(-1.), F32(0.f))),
		REPEAT(
			ULT(VARL("_i"), U32(31)),
			SEQ4(
				SETL("_i", ADD(VARL("_i"), U32(1))),
				SETL("_m", SHIFTL0(U32(1), SUB(U32(30), VARL("_i")))),
				SETL("_b", FDIV(RZ_FLOAT_RMODE_RNE, F32(1.f), FLOATV32(SHIFTL0(U32(2), VARL("_i"))))),
				BRANCH(
					NON_ZERO(LOGAND(VARL(k), VARL("_m"))),
					SETL(k, ADD(VARL(k), VARL("_b"))),
					NOP()))));
}

static inline RzILOpPure *round_to_integer(RzILOpPure *x, RzILOpPure *mode) {
	return LET("_mode", UNSIGNED(8, mode),
		LET("_x", x,
			ITE(EQ(VARLP("_mode"), U32(0)),
				F2SINT(32, RZ_FLOAT_RMODE_RNE, VARLP("_x")),
				ITE(EQ(VARLP("_mode"), U8(1)),
					F2SINT(32, RZ_FLOAT_RMODE_RNA, VARLP("_x")),
					ITE(EQ(VARLP("_mode"), U8(2)),
						F2SINT(32, RZ_FLOAT_RMODE_RTN, VARLP("_x")),
						ITE(EQ(VARLP("_mode"), U8(3)),
							F2SINT(32, RZ_FLOAT_RMODE_RTP, VARLP("_x")),
							ITE(EQ(VARLP("_mode"), U8(4)),
								F2SINT(32, RZ_FLOAT_RMODE_RTZ, VARLP("_x")),
								U32(UT32_MAX))))))));
}

static RzILOpPure *minmax(const char *k, st64 min, st64 max, RzILOpPure *x) {
	return ITE(IS_FNAN(VARL(k)), U32(0),
		ITE(FGT(VARL(k), F32(max)),
			U32(max),
			ITE(FLT(VARL(k), F32(min)),
				U32(min),
				x)));
}

static RzILOpPure *minmax_q31(const char *k, RzILOpPure *x) {
	return ITE(FGT(VARL(k), q_real(0x7FFFFFFF)),
		U32(0x7FFFFFFF),
		ITE(FLT(VARL(k), F32(-1.0)),
			U32(0x80000000),
			x));
}

/**
 * \brief Convert single precision to a half precision
 *
 * Convert the contents of data register D[a] from IEEE-754-2008 32-bit single precision floating point to IEEE-754-2008
 * 16-bit half precision (data interchange) floating point format. The rounded result is put in data register D[c][15:0].
 * D[c][31:16] is set to zero.
 */
static RzAnalysisLiftedILOp ftohp(RzAsmTriCoreContext *ctx) {
	const char *a = R(1);
	const char *c = R(0);

	// if(sign_32bit(D[a])) then {
	//	D[c][15:0] = HP_NEG_INFINITY;
	// } else {
	//	D[c][15:0] = HP_POS_INFINITY;
	// }
	RzILOpEffect *inf_eff = BRANCH(sign_32bit(VARG(a)),
		SETG(c, U32(HP_NEG_INFINITY)),
		SETG(c, U32(HP_POS_INFINITY)));

	// D[c][15] = sign_32bit(D[a]);
	// D[c][14:10] = 1FH;
	// D[c][9:8] = D[a][22:21];
	// D[c][7:0] = D[a][7:0];
	// Ensure NaN value is preserved
	// if ((D[c][9:0] == 0)) then {
	//	D[c][8] = 1B;
	// }
	RzILOpPure *dc = LOGAND(VARG(a), U32(1U << 31));
	dc = LOGOR(dc, SHL0(U32(0x1f), 10));
	dc = LOGOR(dc, SHL0(BITS32(VARG(a), 21, 2), 8));
	dc = LOGOR(dc, BITS32(VARG(a), 0, 8));
	RzILOpEffect *nan_eff = SEQ2(SETL("D_c", dc),
		SETG(c, ITE(EQ(BITS32(VARL("D_c"), 0, 10), U32(0)), BITS32_U(VARL("D_c"), 8, 1, U32(1)), VARL("D_c"))));

	// f = denorm_to_zero(D[a]);
	// f_rounded = ieee754_round_16bit(f, PSW.RM);
	// Handle overflow & underflow and convert to 16-bit format
	// D[a][15:0] = ieee754_16bit_format(f_rounded);
	RzILOpPure *f = denorm_to_zero(FLOATV32(VARG(a)));
	//	RzILOpPure *f_rounded = FROUND(/*TODO: PSW_RM()*/ 0, f);
	RzILOpEffect *else_eff = SETG(c,
		BITS32_U(VARG(a), 0, 16, UNSIGNED(32, F2BV(FCONVERT(RZ_FLOAT_IEEE754_BIN_16, 0, f)))));

	return BRANCH(IS_FINF(FLOATV32(VARG(a))), inf_eff,
		BRANCH(IS_FNAN(FLOATV32(VARG(a))), nan_eff, else_eff));
}

/**
 * D[c], D[a] (RR)
 * if(is_nan(D[a])) then result = 0;
 * else if(f_real(D[a]) > 2^31-1) then result = 7FFFFFFFH;
 * else if(f_real(D[a]) < -2^31) then result = 80000000H;
 * else result = round_to_integer(D[a], PSW.RM);
 * D[c] = result[31:0];
 */
static RzAnalysisLiftedILOp ftoi(RzAsmTriCoreContext *ctx) {
	return SEQ3(
		SETL("_fa", FLOATV32(VARG(R(1)))),
		SETL("_res", minmax("_fa", ST32_MAX, ST32_MIN, round_to_integer(VARL("_a"), PSW_RM()))),
		SETG(R(0), VARL("_res")));
}

/**
 * FTOIZ D[c], D[a] (RR)
 * if(is_nan(D[a])) then result = 0;
 * else if(f_real(D[a]) > 2^31-1) then result = 7FFFFFFFH;
 * else if(f_real(D[a]) < -2^31) then result = 80000000H;
 * else result = round_to_integer(D[a], 11B);
 * D[c] = result[31:0];
 */
static RzAnalysisLiftedILOp ftoiz(RzAsmTriCoreContext *ctx) {
	return SEQ3(
		SETL("_fa", FLOATV32(VARG(R(1)))),
		SETL("_res", minmax("_fa", ST32_MAX, ST32_MIN, F2SINT32(VARL("_a"), RZ_FLOAT_RMODE_RTZ))),
		SETG(R(0), VARL("_res")));
}

static RzAnalysisLiftedILOp ftou(RzAsmTriCoreContext *ctx) {
	return SEQ3(
		SETL("_fa", FLOATV32(VARG(R(1)))),
		SETL("_res", minmax("_fa", UT32_MAX, UT32_MIN, round_to_integer(VARL("_a"), PSW_RM()))),
		SETG(R(0), VARL("_res")));
}

static RzAnalysisLiftedILOp ftouz(RzAsmTriCoreContext *ctx) {
	return SEQ3(
		SETL("_fa", FLOATV32(VARG(R(1)))),
		SETL("_res", minmax("_fa", UT32_MAX, UT32_MIN, F2SINT32(VARL("_a"), RZ_FLOAT_RMODE_RTZ))),
		SETG(R(0), VARL("_res")));
}

/**
 * FTOQ31 D[c], D[a], D[b] (RR)
 * arg_a = denorm_to_zero(f_real(D[a]);
 * if(is_nan(D[a])) then result = 0;
 * else precise_result = mul(arg_a, 2^-D[b][8:0]);
 * if(precise_result > q_real(7FFFFFFFH)) then result = 7FFFFFFFH;
 * else if(precise_result < -1.0) then result = 80000000H;
 * else result = round_to_q31(precise_result);
 * D[c] = result[31:0];
 */
static RzAnalysisLiftedILOp ftoq31(RzAsmTriCoreContext *ctx) {
	return SEQ6(
		SETL("_a", VARG(R(1))),
		SETL("_arg_a", U32(0)),
		q_real_set_v("_arg_a", VARL("_a")),
		SETL("_arg_a", denorm_to_zero(VARL("_arg_a"))),
		SETL("_res",
			ITE(IS_FNAN(FLOATV32(VARL("_a"))),
				U32(0),
				LET("_precise_result", FDIV(0, VARL("_arg_a"), FPOW(0, F32(2), FLOATV32(LOGAND(VARG(R(3)), U32(0x1ff))))),
					minmax_q31("_precise_result", round_to_integer(VARL("_precise_result"), PSW_RM()))))),
		SETG(R(0), VARL("_res")));
}

static RzAnalysisLiftedILOp ftoq31z(RzAsmTriCoreContext *ctx) {
	return SEQ6(
		SETL("_a", VARG(R(1))),
		SETL("_arg_a", U32(0)),
		q_real_set_v("_arg_a", VARL("_a")),
		SETL("_arg_a", denorm_to_zero(VARL("_arg_a"))),
		SETL("_res",
			ITE(IS_FNAN(FLOATV32(VARL("_a"))),
				U32(0),
				LET("_precise_result", FDIV(0, VARL("_arg_a"), FPOW(0, F32(2), FLOATV32(LOGAND(VARG(R(3)), U32(0x1ff))))),
					minmax_q31("_precise_result", F2SINT32(VARL("_precise_result"), RZ_FLOAT_RMODE_RTZ))))),
		SETG(R(0), VARL("_res")));
}

static RzAnalysisLiftedILOp f_cmp(RzAsmTriCoreContext *ctx) {
	const char *rc = R(0);
	const char *ra = R(1);
	const char *rb = R(2);
	return SETG(rc,
		f_op2_chain6(rz_il_op_new_log_or,
			BOOL_TO_BV32(FLT(FLOATV32(VARG(ra)), FLOATV32(VARG(rb)))),
			SHL0(BOOL_TO_BV32(FEQ(FLOATV32(VARG(ra)), FLOATV32(VARG(rb)))), 1),
			SHL0(BOOL_TO_BV32(FGT(FLOATV32(VARG(ra)), FLOATV32(VARG(rb)))), 2),
			SHL0(BOOL_TO_BV32(OR(IS_FNAN(FLOATV32(VARG(ra))), IS_FNAN(FLOATV32(VARG(rb))))), 3),
			SHL0(BOOL_TO_BV32(is_denorm(VARG(ra))), 4),
			SHL0(BOOL_TO_BV32(is_denorm(VARG(rb))), 5)));
}
