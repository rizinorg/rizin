// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

// static const ut32 ADD_NAN __attribute__((unused)) = 0x7fc00001;
// static const ut32 DIV_NAN __attribute__((unused)) = 0x7fc00008;
// static const ut32 MUL_NAN __attribute__((unused)) = 0x7fc00002;
// static const ut32 SQRT_NAN __attribute__((unused)) = 0x7fc00004;
//
static const ut32 HP_MAX_VALUE __attribute__((unused)) = 65504;
static const ut32 HP_MIN_NORMAL __attribute__((unused)) = 1024 * 16;

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

#define FCAST(f, _1, x, mode) \
	LET("_mode", UNSIGNED(8, mode), \
		LET("_x", x, \
			ITE(EQ(VARLP("_mode"), U8(0)), \
				f(_1, RZ_FLOAT_RMODE_RNE, VARLP("_x")), \
				ITE(EQ(VARLP("_mode"), U8(1)), \
					f(_1, RZ_FLOAT_RMODE_RNA, VARLP("_x")), \
					ITE(EQ(VARLP("_mode"), U8(2)), \
						f(_1, RZ_FLOAT_RMODE_RTN, VARLP("_x")), \
						ITE(EQ(VARLP("_mode"), U8(3)), \
							f(_1, RZ_FLOAT_RMODE_RTP, VARLP("_x")), \
							ITE(EQ(VARLP("_mode"), U8(4)), \
								f(_1, RZ_FLOAT_RMODE_RTZ, VARLP("_x")), \
								U32(UT32_MAX))))))))

#define round_to_integer(x, m) FCAST(F2SINT, 32, x, m)

static RzILOpPure *minmax(const char *k, st64 min, st64 max, RzILOpPure *x) {
	return ITE(IS_FNAN(VARL(k)), U32(0),
		ITE(FGT(VARL(k), F64(max)),
			U32(max),
			ITE(FLT(VARL(k), F64(min)),
				U32(min),
				x)));
}

#define Q31_MAX q_real(0x7FFFFFFF)
#define Q31_MIN F32(-1.f)

static RzILOpPure *minmax_q31(const char *k, RzILOpPure *x) {
	return ITE(FGT(VARL(k), q_real(0x7FFFFFFF)),
		U32(0x7FFFFFFF),
		ITE(FLT(VARL(k), F32(-1.0)),
			U32(0x80000000),
			x));
}

#define not_in(x, min, max) OR(FGT(x, max), FLT(DUP(x), min))

#define not_in_q31(x) not_in(x, Q31_MIN, Q31_MAX)
#define not_in_u32(x) not_in(x, F64(0.f), F64(UT32_MAX))
#define not_in_i32(x) not_in(x, F64(ST32_MIN), F64(ST32_MAX))

#define set_FPU_s(k, x) SETG("set_" #k, x)

#define set_FPU(k, x) SEQ2( \
	SETG("set_" #k, x), \
	BRANCH(VARG("set_" #k), set_PSW_##k(x), NOP()))

static RzILOpPure *ieee754_16bit_underflow(RzILOpPure *x) {
	return AND(FLT(x, FLOATV32(U32(HP_MIN_NORMAL))), FGT(DUP(x), F32(0)));
}

static RzILOpPure *ieee754_16bit_overflow(RzILOpFloat *x) {
	return FGT(x, FLOATV32(U32(HP_MAX_VALUE)));
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
	RzILOpEffect *else_eff =
		SEQ3(SETL("_fa", denorm_to_zero(FLOATV32(VARG(a)))),
			SETL("_f_rounded", FCAST(FCONVERT, RZ_FLOAT_IEEE754_BIN_16, VARL("_fa"), PSW_RM())),
			SETG(c, BITS32_U(VARG(c), 0, 16, UNSIGNED(32, VARL("_f_rounded")))));

	RzILOpEffect *set_status = SEQ5(
		set_FPU(FX, FNE(VARL("_fa"), FLOATV32(UNSIGNED(16, VARG(R(1)))))),
		set_FPU(FU, AND(ieee754_16bit_underflow(VARL("_fa")), VARG("set_FX"))),
		set_FPU(FV, ieee754_16bit_overflow(VARL("_fa"))),
		set_FPU(FI, IS_FNAN(VARG(R(1)))),
		set_PSW_FS(f_op2_chain4(rz_il_op_new_bool_or, VARG("set_FI"), VARG("set_FV"), VARG("set_FU"), VARG("set_FX"))));

	return SEQ4(
		SETL("_fa", F32(0)),
		SETL("_f_rounded", F32(0)),
		BRANCH(IS_FINF(FLOATV32(VARG(a))), inf_eff,
			BRANCH(IS_FNAN(FLOATV32(VARG(a))), nan_eff, else_eff)),
		set_status);
}

/**
 * HPTOF D[c], D[a] (RR)
 * hp = D[a][15:0];
 * if (is_inf_16bit(hp)) then {
 *   // Signed Infinity
 *   if(sign_16bit(hp)) then {
 *     D[c][31:0] = NEG_INFINITY;
 *   } else {
 *     D[c][31:0] = POS_INFINITY;
 *   }
 * } else if (is_nan_16bit(hp)) then {
 *     // Signed NaN
 *     D[c][31] = sign_16bit(hp);
 *     D[c][30:23] = FFH;
 *     D[c][22:21] = D[a][9:8];
 *     D[c][20:8] = 0;
 *     D[c][7:0] = D[a][7:0];
 * } else {
 *   f = f_real_16bit(hp);
 *   D[c] = ieee754_32bit_format(f);
 * }
 */
static RzAnalysisLiftedILOp hptof(RzAsmTriCoreContext *ctx) {
	return SEQ4(
		SETL("_hp", UNSIGNED(16, VARG(R(1)))),
		SETL("_res", FCONVERT(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNA, FLOATV16(VARL("_hp")))),
		SETG(R(0), VARL("_res")),
		SEQ2(set_FPU(FI, IS_FNAN(VARL("_hp"))),
			set_PSW_FS(VARG("set_FI"))));
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
	return SEQ4(
		SETL("_fa", FLOATV64(VARG(R(1)))),
		SETL("_res", minmax("_fa", ST32_MAX, ST32_MIN, round_to_integer(VARL("_fa"), PSW_RM()))),
		SETG(R(0), VARL("_res")),
		SEQ3(set_FPU(FI, OR(not_in_i32(VARL("_fa")), IS_FNAN(VARL("_fa")))),
			set_FPU(FX, FNE(VARL("_fa"), VARL("_res"))),
			set_PSW_FS(OR(VARG("set_FX"), VARG("set_FI")))));
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
	return SEQ4(
		SETL("_fa", FLOATV64(VARG(R(1)))),
		SETL("_res", minmax("_fa", ST32_MAX, ST32_MIN, F2SINT32(VARL("_fa"), RZ_FLOAT_RMODE_RTZ))),
		SETG(R(0), VARL("_res")),
		SEQ3(set_FPU(FI, OR(not_in_u32(VARL("_fa")), IS_FNAN(VARL("_fa")))),
			set_FPU(FX, FNE(VARL("_fa"), VARL("_res"))),
			set_PSW_FS(OR(VARG("set_FX"), VARG("set_FI")))));
}

/**
 * D[c], D[a] (RR)
 *
 * rounded_result = ieee754_round(i_real(D[a]), PSW.RM);
 * result = ieee754_32bit_format(rounded_result);
 * D[c] = result[31:0];
 */
static RzAnalysisLiftedILOp itof(RzAsmTriCoreContext *ctx) {
	return SEQ4(
		SETL("_a", VARG(R(1))),
		SETL("_res", FCAST(SINT2F, 32, VARL("_a"), PSW_RM())),
		SETG(R(0), VARL("_res")),
		SEQ2(set_FPU(FX, FNE(VARL("_fa"), VARL("_res"))),
			set_PSW_FS(VARG("set_FX"))));
}

static RzAnalysisLiftedILOp ftou(RzAsmTriCoreContext *ctx) {
	return SEQ4(
		SETL("_fa", FLOATV64(VARG(R(1)))),
		SETL("_res", minmax("_fa", UT32_MAX, UT32_MIN, round_to_integer(VARL("_fa"), PSW_RM()))),
		SETG(R(0), VARL("_res")),
		SEQ3(set_FPU(FI, OR(not_in_u32(VARL("_fa")), IS_FNAN(VARL("_fa")))),
			set_FPU(FX, FNE(VARL("_fa"), VARL("_res"))),
			set_PSW_FS(OR(VARG("set_FX"), VARG("set_FI")))));
}

static RzAnalysisLiftedILOp ftouz(RzAsmTriCoreContext *ctx) {
	return SEQ4(
		SETL("_fa", FLOATV64(VARG(R(1)))),
		SETL("_res", minmax("_fa", UT32_MAX, UT32_MIN, F2SINT32(VARL("_fa"), RZ_FLOAT_RMODE_RTZ))),
		SETG(R(0), VARL("_res")),
		SEQ3(set_FPU(FI, OR(not_in_u32(VARL("_fa")), IS_FNAN(VARL("_fa")))),
			set_FPU(FX, FNE(VARL("_fa"), VARL("_res"))),
			set_PSW_FS(OR(VARG("set_FX"), VARG("set_FI")))));
}

static RzAnalysisLiftedILOp utof(RzAsmTriCoreContext *ctx) {
	return SEQ4(
		SETL("_a", VARG(R(1))),
		SETL("_res", FCAST(INT2F, 32, VARL("_a"), PSW_RM())),
		SETG(R(0), VARL("_res")),
		SEQ2(set_FPU(FX, FNE(VARL("_fa"), VARL("_res"))),
			set_PSW_FS(VARG("set_FX"))));
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
	return SEQ8(
		SETL("_a", VARG(R(1))),
		SETL("_arg_a", U32(0)),
		q_real_set_v("_arg_a", VARL("_a")),
		SETL("_arg_a", denorm_to_zero(VARL("_arg_a"))),
		SETL("_precise_result", FDIV(0, VARL("_arg_a"), FPOW(0, F32(2), FLOATV32(LOGAND(VARG(R(2)), U32(0x1ff)))))),
		SETL("_res",
			ITE(IS_FNAN(FLOATV32(VARL("_a"))),
				U32(0),
				minmax_q31("_precise_result", round_to_integer(VARL("_precise_result"), PSW_RM())))),
		SETG(R(0), VARL("_res")),
		SEQ5(SETL("_res_q_real", U32(0)),
			q_real_set_v("_res_q_real", VARL("_res")),
			set_FPU(FI, OR(not_in_q31(VARL("_precise_result")), IS_FNAN(FLOATV32(VARL("_a"))))),
			set_FPU(FX, FNE(FLOATV32(VARL("_a")), VARL("_res_q_real"))),
			set_PSW_FS(OR(VARG("set_FX"), VARG("set_FI")))));
}

static RzAnalysisLiftedILOp ftoq31z(RzAsmTriCoreContext *ctx) {
	return SEQ8(
		SETL("_a", VARG(R(1))),
		SETL("_arg_a", U32(0)),
		q_real_set_v("_arg_a", VARL("_a")),
		SETL("_arg_a", denorm_to_zero(VARL("_arg_a"))),
		SETL("_precise_result", FDIV(0, VARL("_arg_a"), FPOW(0, F32(2), FLOATV32(LOGAND(VARG(R(2)), U32(0x1ff)))))),
		SETL("_res",
			ITE(IS_FNAN(FLOATV32(VARL("_a"))),
				U32(0),
				minmax_q31("_precise_result", F2SINT32(VARL("_precise_result"), RZ_FLOAT_RMODE_RTZ)))),
		SETG(R(0), VARL("_res")),
		SEQ5(SETL("_res_q_real", U32(0)),
			q_real_set_v("_res_q_real", VARL("_res")),
			set_FPU(FI, OR(not_in_q31(VARL("_precise_result")), IS_FNAN(FLOATV32(VARL("_a"))))),
			set_FPU(FX, FNE(FLOATV32(VARL("_a")), VARL("_res_q_real"))),
			set_PSW_FS(OR(VARG("set_FX"), VARG("set_FI")))));
}

/**
 * Q31TOF D[c], D[a], D[b] (RR)
 *
 * precise_result = mul(q_real(D[a]),2^D[b][8:0]);
 * rounded_result = ieee754_round(precise_result, PSW.RM);
 * result = ieee754_32bit_format(rounded_result);
 * D[c] = result[31:0];
 */
static RzAnalysisLiftedILOp q31tof(RzAsmTriCoreContext *ctx) {
	return SEQ7(
		SETL("_a", VARG(R(1))),
		SETL("_qa", U32(0)),
		q_real_set_v("_qa", VARL("_a")),
		SETL("_precise_result", FMUL(RZ_FLOAT_RMODE_RNE, VARL("_qa"), FPOW(0, F64(2.), FLOATV32(LOGAND(VARG(R(2)), U32(0x1ff)))))),
		SETL("_res", FCAST(FCONVERT, RZ_FLOAT_IEEE754_BIN_32, VARL("_precise_result"), PSW_RM())),
		SETG(R(0), VARL("_res")),
		SEQ3(set_FPU(FX, FNE(VARL("_precise_result"), VARL("_res"))),
			set_FPU(FU, FLT(FABS(VARL("_precise_result")), F32(1. / 0x2p126))),
			set_PSW_FS(VARG("set_FX"))));
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
