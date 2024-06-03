// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/// The maximum of IEEE-754-2008 16-bit half precision floating point
static const ut32 HP_MAX_VALUE = 65504;
/// The minimum positive normalized number of IEEE-754-2008 16-bit half precision floating point
static const ut32 HP_MIN_NORMAL = 1024 * 16;
/// This represents all positive numbers that are too big to be represented accurately as a normalized number.
static const ut32 HP_NEG_INFINITY = 0xfc00;
/// This represents all negative numbers with an absolute value that is too big to be represented accurately as a normalized number.
static const ut32 HP_POS_INFINITY = 0x7c00;

#define F2SINT32(x, m) F2SINT(32, m, x)

#define denorm_to_zere_(T, x) \
	LET("tmp", x, \
		ITE(AND(FLT(VARLP("tmp"), T(0.0)), FGT(VARLP("tmp"), T(powf(-2, -126)))), FNEG(T(0)), \
			ITE(AND(FGT(VARLP("tmp"), T(0)), FLT(VARLP("tmp"), T(powf(2, -126)))), T(0), \
				VARLP("tmp"))))

#define denorm_to_zere64(x) denorm_to_zere_(F64, x)

#define F6432(x)  FCONVERT(RZ_FLOAT_IEEE754_BIN_32, 0, x)
#define F3264(x)  FCONVERT(RZ_FLOAT_IEEE754_BIN_64, 0, x)
#define _32F64(x) F3264(FLOATV32(x))
#define i32F32(x) SINT2F(RZ_FLOAT_IEEE754_BIN_32, 0, x)
#define i32F64(x) F3264(i32F32(x))

static inline RzILOpPure *is_denorm(RzILOpPure *x) {
	return AND(IS_ZERO(BITS32(x, 23, 8)), NON_ZERO(BITS32(DUP(x), 0, 23)));
}

/**
 * \brief Returns the Q31 format value ‘x’ as an infinitely accurate real value.
 */
static inline RzILOpFloat *q_real(ut32 x) {
	float y = x & 0x80000000 ? -1.f : 0.f;
	for (int i = 0; i < 31; ++i) {
		ut32 m = 1u << (30 - i);
		float b = 1.f / (float)(2u << i);
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
					NON_ZERO(LOGAND(VARL("_x"), VARL("_m"))),
					SETL(k, FADD(0, VARL(k), VARL("_b"))),
					NOP()))));
}

#define FCAST_(f, _1, x, mode, _default) \
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
								_default)))))))

#define FCAST32(f, _1, x, mode) FCAST_(f, _1, x, mode, F32(0))
#define FCAST64(f, _1, x, mode) FCAST_(f, _1, x, mode, F64(0))
#define round_to_integer(x, m)  FCAST_(F2SINT, 32, x, m, U32(UT32_MAX))

static RzILOpPure *minmax(const char *k, st64 min, st64 max, RzILOpPure *x) {
	return ITE(IS_FNAN(VARL(k)),
		U32(0),
		ITE(FGT(VARL(k), F64(max)),
			U32(max),
			ITE(FLT(VARL(k), F64(min)),
				U32(min),
				x)));
}

// The maximum of the Q31 format value
#define Q31_MAX q_real(0x7FFFFFFF)
// The minimum of the Q31 format value
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
	BRANCH(VARG("set_" #k), set_PSW_##k(U32(1)), NOP()))

static RzILOpPure *ieee754_16bit_underflow(RzILOpPure *x) {
	return AND(FLT(x, FLOATV32(U32(HP_MIN_NORMAL))), FGT(DUP(x), F32(0)));
}

static RzILOpPure *ieee754_16bit_overflow(RzILOpFloat *x) {
	return FGT(x, FLOATV32(U32(HP_MAX_VALUE)));
}

#define set_PSW_FSb(x)        set_PSW_FS(BOOL_TO_BV32(x))
#define set_FS_or_FI_FV_FU_FX set_PSW_FSb(f_op2_chain4(rz_il_op_new_bool_or, VARG("set_FI"), VARG("set_FV"), VARG("set_FU"), VARG("set_FX")))

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
		SEQ3(SETL("_fa", denorm_to_zere64(FLOATV32(VARG(a)))),
			SETL("_f_rounded", FCAST32(FCONVERT, RZ_FLOAT_IEEE754_BIN_16, VARL("_fa"), PSW_RM())),
			SETG(c, BITS32_U(VARG(c), 0, 16, UNSIGNED(32, VARL("_f_rounded")))));

	RzILOpEffect *set_status = SEQ5(
		set_FPU(FX, FNE(VARL("_fa"), FLOATV32(UNSIGNED(16, VARG(R(1)))))),
		set_FPU(FU, AND(ieee754_16bit_underflow(VARL("_fa")), VARG("set_FX"))),
		set_FPU(FV, ieee754_16bit_overflow(VARL("_fa"))),
		set_FPU(FI, IS_FNAN(VARG(R(1)))),
		set_FS_or_FI_FV_FU_FX);

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
		SETL("_result", FCONVERT(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNA, FLOATV16(VARL("_hp")))),
		SETG(R(0), F2BV(VARL("_result"))),
		SEQ2(set_FPU(FI, IS_FNAN(VARL("_hp"))),
			set_PSW_FSb((VARG("set_FI")))));
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
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_result_i", minmax("_fa", ST32_MAX, ST32_MIN, round_to_integer(VARL("_fa"), PSW_RM()))),
		SETG(R(0), VARL("_result_i")),
		SEQ3(set_FPU(FI, OR(not_in_i32(VARL("_fa")), IS_FNAN(VARL("_fa")))),
			set_FPU(FX, FNE(VARL("_fa"), i32F64(VARL("_result_i")))),
			set_PSW_FSb(OR(VARG("set_FX"), VARG("set_FI")))));
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
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_result_i", minmax("_fa", ST32_MAX, ST32_MIN, F2SINT32(VARL("_fa"), RZ_FLOAT_RMODE_RTZ))),
		SETG(R(0), VARL("_result_i")),
		SEQ3(set_FPU(FI, OR(not_in_u32(VARL("_fa")), IS_FNAN(VARL("_fa")))),
			set_FPU(FX, FNE(VARL("_fa"), i32F64(VARL("_result_i")))),
			set_PSW_FSb((OR(VARG("set_FX"), VARG("set_FI"))))));
}

/**
 * D[c], D[a] (RR)
 *
 * rounded_result = ieee754_round(i_real(D[a]), PSW.RM);
 * result = ieee754_32bit_format(rounded_result);
 * D[c] = result[31:0];
 */
static RzAnalysisLiftedILOp itof(RzAsmTriCoreContext *ctx) {
	return SEQ6(
		SETL("_a", VARG(R(1))),
		SETL("_result64", FCAST64(SINT2F, RZ_FLOAT_IEEE754_BIN_64, VARL("_a"), PSW_RM())),
		SETL("_result32", FCAST32(SINT2F, RZ_FLOAT_IEEE754_BIN_32, VARL("_a"), PSW_RM())),
		SETL("_result32_64", FCAST64(FCONVERT, RZ_FLOAT_IEEE754_BIN_64, VARL("_result32"), PSW_RM())),
		SETG(R(0), F2BV(VARL("_result32"))),
		SEQ2(set_FPU(FX, FNE(VARL("_result32_64"), VARL("_result64"))),
			set_PSW_FSb((VARG("set_FX")))));
}

static RzAnalysisLiftedILOp ftou(RzAsmTriCoreContext *ctx) {
	return SEQ4(
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_result_i", minmax("_fa", UT32_MAX, UT32_MIN, round_to_integer(VARL("_fa"), PSW_RM()))),
		SETG(R(0), VARL("_result_i")),
		SEQ3(set_FPU(FI, OR(not_in_u32(VARL("_fa")), IS_FNAN(VARL("_fa")))),
			set_FPU(FX, FNE(VARL("_fa"), i32F64(VARL("_result_i")))),
			set_PSW_FSb(OR(VARG("set_FX"), VARG("set_FI")))));
}

static RzAnalysisLiftedILOp ftouz(RzAsmTriCoreContext *ctx) {
	return SEQ4(
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_result_i", minmax("_fa", UT32_MAX, UT32_MIN, F2SINT32(VARL("_fa"), RZ_FLOAT_RMODE_RTZ))),
		SETG(R(0), VARL("_result_i")),
		SEQ3(set_FPU(FI, OR(not_in_u32(VARL("_fa")), IS_FNAN(VARL("_fa")))),
			set_FPU(FX, FNE(VARL("_fa"), i32F64(VARL("_result_i")))),
			set_PSW_FSb(OR(VARG("set_FX"), VARG("set_FI")))));
}

static RzAnalysisLiftedILOp utof(RzAsmTriCoreContext *ctx) {
	return SEQ4(
		SETL("_a", VARG(R(1))),
		SETL("_result", FCAST32(INT2F, RZ_FLOAT_IEEE754_BIN_32, VARL("_a"), PSW_RM())),
		SETG(R(0), F2BV(VARL("_result"))),
		SEQ2(set_FPU(FX, FNE(i32F32(VARL("_a")), VARL("_result"))),
			set_PSW_FSb(VARG("set_FX"))));
}

/**
 * FTOQ31 D[c], D[a], D[b] (RR)
 * arg_a = denorm_to_zere64(f_real(D[a]);
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
		SETL("_arg_a", F32(0)),
		q_real_set_v("_arg_a", VARL("_a")),
		SETL("_arg_a", denorm_to_zere_(F32, VARL("_arg_a"))),
		SETL("_precise_result", FDIV(0, VARL("_arg_a"), FPOW(0, F32(2), FLOATV32(LOGAND(VARG(R(2)), U32(0x1ff)))))),
		SETL("_result_i",
			ITE(IS_FNAN(FLOATV32(VARL("_a"))),
				U32(0),
				minmax_q31("_precise_result", round_to_integer(VARL("_precise_result"), PSW_RM())))),
		SETG(R(0), VARL("_result_i")),
		SEQ5(SETL("_res_q_real", F32(0)),
			q_real_set_v("_res_q_real", VARL("_result_i")),
			set_FPU(FI, OR(not_in_q31(VARL("_precise_result")), IS_FNAN(FLOATV32(VARL("_a"))))),
			set_FPU(FX, FNE(FLOATV32(VARL("_a")), VARL("_res_q_real"))),
			set_PSW_FSb(OR(VARG("set_FX"), VARG("set_FI")))));
}

static RzAnalysisLiftedILOp ftoq31z(RzAsmTriCoreContext *ctx) {
	return SEQ9(
		SETL("_a", VARG(R(1))),
		SETL("_fa", FLOATV32(VARL("_a"))),
		SETL("_arg_a", F32(0)),
		q_real_set_v("_arg_a", VARL("_a")),
		SETL("_arg_a", denorm_to_zere_(F32, VARL("_arg_a"))),
		SETL("_precise_result", FDIV(0, VARL("_arg_a"), FPOW(0, F32(2), FLOATV32(LOGAND(VARG(R(2)), U32(0x1ff)))))),
		SETL("_result_i",
			ITE(IS_FNAN(VARL("_fa")),
				U32(0),
				minmax_q31("_precise_result", F2SINT32(VARL("_precise_result"), RZ_FLOAT_RMODE_RTZ)))),
		SETG(R(0), VARL("_result_i")),
		SEQ5(SETL("_res_q_real", F32(0)),
			q_real_set_v("_res_q_real", VARL("_result_i")),
			set_FPU(FI, OR(not_in_q31(VARL("_precise_result")), IS_FNAN(FLOATV32(VARL("_a"))))),
			set_FPU(FX, FNE(VARL("_fa"), VARL("_res_q_real"))),
			set_PSW_FSb(OR(VARG("set_FX"), VARG("set_FI")))));
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
		SETL("_qa", F32(0)),
		q_real_set_v("_qa", VARL("_a")),
		SETL("_precise_result", FMUL(RZ_FLOAT_RMODE_RNE, VARL("_qa"), FPOW(0, F32(2.), FLOATV32(LOGAND(VARG(R(2)), U32(0x1ff)))))),
		SETL("_result", FCAST32(FCONVERT, RZ_FLOAT_IEEE754_BIN_32, VARL("_precise_result"), PSW_RM())),
		SETG(R(0), F2BV(VARL("_result"))),
		SEQ3(set_FPU(FX, FNE(VARL("_precise_result"), VARL("_result"))),
			set_FPU(FU, FLT(FABS(VARL("_precise_result")), F32(1. / 0x2p126))),
			set_PSW_FSb(VARG("set_FX"))));
}

static RzAnalysisLiftedILOp cmp_f(RzAsmTriCoreContext *ctx) {
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

#define SEQ10(e0, e1, e2, e3, e4, e5, e6, e7, e8, e9) SEQN(10, e0, e1, e2, e3, e4, e5, e6, e7, e8, e9)

/**
 * ADD.F D[c], D[d], D[a] (RRR)
 * arg_a = denorm_to_zere64(f_real(D[a]);
 * arg_b = denorm_to_zere64(f_real(D[d]);
 * if(is_nan(D[a]) OR is_nan(D[d])) then result = QUIET_NAN;
 * else if(is_pos_inf(D[a]) AND is_neg_inf(D[d])) then result = ADD_NAN;
 * else if(is_neg_inf(D[a]) AND is_pos_inf(D[d])) then result = ADD_NAN;
 * else {
 *   precise_result = add(arg_a,arg_b);
 *   normal_result = denorm_to_zere64(precise_result);
 *   rounded_result = ieee754_round(normal_result, PSW.RM);
 *   result = ieee754_32bit_format(rounded_result);
 * }
 * D[c] = result[31:0];
 */
static RzAnalysisLiftedILOp add_f(RzAsmTriCoreContext *ctx) {
	RzAnalysisLiftedILOp set_status = SEQ6(
		set_FPU(FI, OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb")))),
		set_FPU(FV, FGE(VARL("_rounded_result"), F32(0x2p128))),
		set_FPU(FU, FLT(FABS(VARL("_precise_result")), F64(0x2p-126))),
		set_FPU_s(FX, FNE(VARL("_precise_result"), FCONVERT(RZ_FLOAT_IEEE754_BIN_64, 0, VARL("_result")))),
		set_PSW_FX(BOOL_TO_BV32(AND(VARG("set_FX"), INV(VARG("set_FI"))))),
		set_FS_or_FI_FV_FU_FX);

	return SEQ10(
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_fb", _32F64(VARG(R(2)))),
		SETL("_arg_a", denorm_to_zere64(VARL("_fa"))),
		SETL("_arg_b", denorm_to_zere64(VARL("_fb"))),
		SETL("_precise_result", FADD(0, VARL("_arg_a"), VARL("_arg_b"))),
		SETL("_normal_result", denorm_to_zere64(VARL("_precise_result"))),
		SETL("_rounded_result", FCAST32(FCONVERT, RZ_FLOAT_IEEE754_BIN_32, VARL("_normal_result"), PSW_RM())),
		SETL("_result",
			ITE(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_32),
				ITE(AND(IS_FINF(VARL("_fa")), IS_FINF(VARL("_fb"))),
					IL_FSNAN(RZ_FLOAT_IEEE754_BIN_32),
					VARL("_rounded_result")))),
		SETG(R(0), F2BV(VARL("_result"))),
		set_status);
}

static RzAnalysisLiftedILOp sub_f(RzAsmTriCoreContext *ctx) {
	RzAnalysisLiftedILOp set_status = SEQ6(
		set_FPU(FI, OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb")))),
		set_FPU(FV, FGE(VARL("_rounded_result"), F32(0x2p128))),
		set_FPU(FU, FLT(FABS(VARL("_precise_result")), F64(0x2p-126))),
		set_FPU_s(FX, FNE(VARL("_precise_result"), FCONVERT(RZ_FLOAT_IEEE754_BIN_64, 0, VARL("_result")))),
		set_PSW_FX(BOOL_TO_BV32(AND(VARG("set_FX"), INV(VARG("set_FI"))))),
		set_FS_or_FI_FV_FU_FX);

	return SEQ10(
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_fb", _32F64(VARG(R(2)))),
		SETL("_arg_a", denorm_to_zere64(VARL("_fa"))),
		SETL("_arg_b", denorm_to_zere64(VARL("_fb"))),
		SETL("_precise_result", FADD(0, FNEG(VARL("_arg_a")), VARL("_arg_b"))),
		SETL("_normal_result", denorm_to_zere64(VARL("_precise_result"))),
		SETL("_rounded_result", FCAST32(FCONVERT, RZ_FLOAT_IEEE754_BIN_32, VARL("_normal_result"), PSW_RM())),
		SETL("_result",
			ITE(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_32),
				ITE(AND(IS_FINF(VARL("_fa")), IS_FINF(VARL("_fb"))),
					IL_FSNAN(RZ_FLOAT_IEEE754_BIN_32),
					VARL("_rounded_result")))),
		SETG(R(0), F2BV(VARL("_result"))),
		set_status);
}

static RzAnalysisLiftedILOp mul_f(RzAsmTriCoreContext *ctx) {
	RzAnalysisLiftedILOp set_status = SEQ6(
		set_FPU(FI, OR(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))), IS_FNAN(VARL("_result")))),
		set_FPU(FV, FGE(VARL("_rounded_result"), F32(0x2p128))),
		set_FPU(FU, FLT(FABS(VARL("_precise_result")), F64(0x2p-126))),
		set_FPU_s(FX, FNE(VARL("_precise_result"), FCONVERT(RZ_FLOAT_IEEE754_BIN_64, 0, VARL("_result")))),
		set_PSW_FX(BOOL_TO_BV32(AND(VARG("set_FX"), INV(VARG("set_FI"))))),
		set_FS_or_FI_FV_FU_FX);

	return SEQ10(
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_fb", _32F64(VARG(R(2)))),
		SETL("_arg_a", denorm_to_zere64(VARL("_fa"))),
		SETL("_arg_b", denorm_to_zere64(VARL("_fb"))),
		SETL("_precise_result", FMUL(0, VARL("_arg_a"), VARL("_arg_b"))),
		SETL("_normal_result", denorm_to_zere64(VARL("_precise_result"))),
		SETL("_rounded_result", FCAST32(FCONVERT, RZ_FLOAT_IEEE754_BIN_32, VARL("_normal_result"), PSW_RM())),
		SETL("_result",
			ITE(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_32),
				ITE(OR(AND(IS_FINF(VARL("_fa")), IS_FZERO(VARL("_fb"))),
					    AND(IS_FZERO(VARL("_fa")), IS_FINF(VARL("_fb")))),
					IL_FSNAN(RZ_FLOAT_IEEE754_BIN_32),
					VARL("_rounded_result")))),
		SETG(R(0), F2BV(VARL("_result"))),
		set_status);
}

static RzAnalysisLiftedILOp div_f(RzAsmTriCoreContext *ctx) {
	RzAnalysisLiftedILOp set_status = SEQ7(
		set_FPU(FI, OR(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))), IS_FNAN(VARL("_result")))),
		set_FPU(FV, FGE(VARL("_rounded_result"), F32(0x2p128))),
		set_FPU(FZ, AND(IS_FZERO(VARL("_fb")), INV(IS_FINF(VARL("_fa"))))),
		set_FPU(FU, FLT(FABS(VARL("_precise_result")), F64(0x2p-126))),
		set_FPU_s(FX, FNE(VARL("_precise_result"), FCONVERT(RZ_FLOAT_IEEE754_BIN_64, 0, VARL("_result")))),
		set_PSW_FX(BOOL_TO_BV32(AND(VARG("set_FX"), INV(VARG("set_FI"))))),
		set_FS_or_FI_FV_FU_FX);

	return SEQ10(
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_fb", _32F64(VARG(R(2)))),
		SETL("_arg_a", denorm_to_zere64(VARL("_fa"))),
		SETL("_arg_b", denorm_to_zere64(VARL("_fb"))),
		SETL("_precise_result", FDIV(0, VARL("_arg_a"), VARL("_arg_b"))),
		SETL("_normal_result", denorm_to_zere64(VARL("_precise_result"))),
		SETL("_rounded_result", FCAST32(FCONVERT, RZ_FLOAT_IEEE754_BIN_32, VARL("_normal_result"), PSW_RM())),
		SETL("_result",
			ITE(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_32),
				ITE(OR(AND(IS_FINF(VARL("_fa")), IS_FINF(VARL("_fb"))),
					    AND(IS_FZERO(VARL("_fa")), IS_FZERO(VARL("_fb")))),
					IL_FSNAN(RZ_FLOAT_IEEE754_BIN_32),
					VARL("_rounded_result")))),
		SETG(R(0), F2BV(VARL("_result"))),
		set_status);
}

static RzAnalysisLiftedILOp qseed_f(RzAsmTriCoreContext *ctx) {
	RzAnalysisLiftedILOp set_status = SEQ2(
		set_FPU(FI, OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_result")))),
		set_PSW_FSb(VARG("set_FI")));

	return SEQ6(
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_arg_a", denorm_to_zere64(VARL("_fa"))),
		SETL("_normal_result", FCAST32(FCONVERT, RZ_FLOAT_IEEE754_BIN_32, FRSQRT(0, VARL("_arg_a")), PSW_RM())),
		SETL("_result",
			ITE(IS_FZERO(VARL("_arg_a")),
				F32(0),
				ITE(FLT(VARL("_fa"), F64(0)),
					IL_FSNAN(RZ_FLOAT_IEEE754_BIN_32),
					VARL("_normal_result")))),
		SETG(R(0), F2BV(VARL("_result"))),
		set_status);
}

static RzAnalysisLiftedILOp madd_f(RzAsmTriCoreContext *ctx) {
	RzAnalysisLiftedILOp set_status = SEQ6(
		set_FPU(FI, OR(OR(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))), IS_FNAN(VARL("_fc"))), IS_FNAN(VARL("_result")))),
		set_FPU(FV, FGE(VARL("_rounded_result"), F32(0x2p128))),
		set_FPU(FU, FLT(FABS(VARL("_precise_result")), F64(0x2p-126))),
		set_FPU_s(FX, FNE(VARL("_precise_result"), FCONVERT(RZ_FLOAT_IEEE754_BIN_64, 0, VARL("_result")))),
		set_PSW_FX(BOOL_TO_BV32(AND(VARG("set_FX"), INV(VARG("set_FI"))))),
		set_FS_or_FI_FV_FU_FX);

	return SEQN(12,
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_fb", _32F64(VARG(R(2)))),
		SETL("_fc", _32F64(VARG(R(3)))),
		SETL("_arg_a", denorm_to_zere64(VARL("_fa"))),
		SETL("_arg_b", denorm_to_zere64(VARL("_fb"))),
		SETL("_arg_c", denorm_to_zere64(VARL("_fc"))),
		SETL("_precise_mul_result", FMUL(0, VARL("_arg_a"), VARL("_arg_b"))),
		SETL("_precise_result", FADD(0, VARL("_precise_mul_result"), VARL("_arg_c"))),
		SETL("_normal_result", denorm_to_zere64(VARL("_precise_result"))),
		SETL("_rounded_result", FCAST32(FCONVERT, RZ_FLOAT_IEEE754_BIN_32, VARL("_normal_result"), PSW_RM())),
		SETL("_result",
			ITE(OR(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))), IS_FNAN(VARL("_fc"))),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_32),
				ITE(OR(OR(AND(IS_FINF(VARL("_fa")), IS_FZERO(VARL("_fb"))),
					       AND(IS_FZERO(VARL("_fa")), IS_FINF(VARL("_fb")))),
					    AND(AND(IS_FINF(VARL("_fa")), IS_FINF(VARL("_fa"))),
						    IS_FINF(VARL("_fc")))),
					IL_FSNAN(RZ_FLOAT_IEEE754_BIN_32),
					VARL("_rounded_result")))),
		SETG(R(0), F2BV(VARL("_result"))),
		set_status);
}

static RzAnalysisLiftedILOp msub_f(RzAsmTriCoreContext *ctx) {
	RzAnalysisLiftedILOp set_status = SEQ6(
		set_FPU(FI, OR(OR(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))), IS_FNAN(VARL("_fc"))), IS_FNAN(VARL("_result")))),
		set_FPU(FV, FGE(VARL("_rounded_result"), F32(0x2p128))),
		set_FPU(FU, FLT(FABS(VARL("_precise_result")), F64(0x2p-126))),
		set_FPU_s(FX, FNE(VARL("_precise_result"), FCONVERT(RZ_FLOAT_IEEE754_BIN_64, 0, VARL("_result")))),
		set_PSW_FX(BOOL_TO_BV32(AND(VARG("set_FX"), INV(VARG("set_FI"))))),
		set_FS_or_FI_FV_FU_FX);

	return SEQN(12,
		SETL("_fa", _32F64(VARG(R(1)))),
		SETL("_fb", _32F64(VARG(R(2)))),
		SETL("_fc", _32F64(VARG(R(3)))),
		SETL("_arg_a", denorm_to_zere64(VARL("_fa"))),
		SETL("_arg_b", denorm_to_zere64(VARL("_fb"))),
		SETL("_arg_c", denorm_to_zere64(VARL("_fc"))),
		SETL("_precise_mul_result", FMUL(0, VARL("_arg_a"), VARL("_arg_b"))),
		SETL("_precise_result", FADD(0, FNEG(VARL("_precise_mul_result")), VARL("_arg_c"))),
		SETL("_normal_result", denorm_to_zere64(VARL("_precise_result"))),
		SETL("_rounded_result", FCAST32(FCONVERT, RZ_FLOAT_IEEE754_BIN_32, VARL("_normal_result"), PSW_RM())),
		SETL("_result",
			ITE(OR(OR(IS_FNAN(VARL("_fa")), IS_FNAN(VARL("_fb"))), IS_FNAN(VARL("_fc"))),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_32),
				ITE(OR(OR(AND(IS_FINF(VARL("_fa")), IS_FZERO(VARL("_fb"))),
					       AND(IS_FZERO(VARL("_fa")), IS_FINF(VARL("_fb")))),
					    AND(AND(IS_FINF(VARL("_fa")), IS_FINF(VARL("_fa"))),
						    IS_FINF(VARL("_fc")))),
					IL_FSNAN(RZ_FLOAT_IEEE754_BIN_32),
					VARL("_rounded_result")))),
		SETG(R(0), F2BV(VARL("_result"))),
		set_status);
}