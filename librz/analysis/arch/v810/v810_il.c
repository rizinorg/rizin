// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "v810.h"
#include <rz_il/rz_il_opbuilder_begin.h>

static const char *registers[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	"r16",
	"r17",
	"r18",
	"r19",
	"r20",
	"r21",
	"r22",
	"r23",
	"r24",
	"r25",
	"r26",
	"r27",
	"r28",
	"r29",
	"r30",
	"r31",
	"EIPC",
	"EIPSW",
	"FEPC",
	"FEPSW",
	"ECR",
	"PSW",
	"PIR",
	"TKCW",
	"Reserved_8",
	"Reserved_9",
	"Reserved_10",
	"Reserved_11",
	"Reserved_12",
	"Reserved_13",
	"Reserved_14",
	"Reserved_15",
	"Reserved_16",
	"Reserved_17",
	"Reserved_18",
	"Reserved_19",
	"Reserved_20",
	"Reserved_21",
	"Reserved_22",
	"Reserved_23",
	"CHCW",
	"ADTRE",
	"Reserved_26",
	"Reserved_27",
	"Reserved_28",
	"Reserved_29",
	"Reserved_30",
	"Reserved_31",
	NULL
};

static const char *GR[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	"r16",
	"r17",
	"r18",
	"r19",
	"r20",
	"r21",
	"r22",
	"r23",
	"r24",
	"r25",
	"r26",
	"r27",
	"r28",
	"r29",
	"r30",
	"r31",
	NULL
};

static const char **SR = registers + 32;

RzAnalysisILConfig *v810_il_config(RzAnalysis *a) {
	rz_return_val_if_fail(a, NULL);
	rz_return_val_if_fail(RZ_STR_EQ(SR[0], "EIPC"), NULL);

	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	cfg->reg_bindings = registers;
	return cfg;
}

static inline int32_t sext32(uint32_t X, unsigned B) {
	rz_warn_if_fail(B > 0 && B <= 32);
	return (int32_t)(X << (32 - B)) >> (32 - B);
}

#define COPCODE ((ctx->w1 >> 10) & 0x3F)
#define R1      (GR[((ctx->w1) & 0x1F)])
#define R2      (GR[(((ctx->w1) >> 5) & 0x1F)])
#define I5      REG1((ctx->w1))
#define I9      (ctx->w1 & 0X1FF)
#define I16     (ctx->w2)
#define I26     (ctx->w2 | ((ctx->w1 & 0x3ff) << 16))
#define CCOND   (((ctx->w1) >> 9) & 0xF)
#define SUBOPC  (((ctx->w2) >> 10) & 0x3F)

#define R1V    VARG(R1)
#define R2V    VARG(R2)
#define SEXT5  S32(sext32(I5, 5))
#define SEXT9  S32(sext32(I9, 9))
#define SEXT16 S32(sext32(I16, 16))
#define SEXT26 S32(sext32(I26, 26))
#define ZEXT5  U32(I5)
#define ZEXT9  U32(I9)
#define ZEXT16 U32(I16)
#define ZEXT26 U32(I26)

#define R1F FLOATV32(VARG(R1))
#define R2F FLOATV32(VARG(R2))

static RzILOpPure *shl0(RzILOpPure *a, RzILOpPure *b) {
	return SHIFTL0(a, b);
}

static RzILOpPure *shr0(RzILOpPure *a, RzILOpPure *b) {
	return SHIFTR0(a, b);
}

static RzILOpPure *fadd_(RzILOpPure *a, RzILOpPure *b) {
	return FADD(0, a, b);
}

static RzILOpPure *fsub_(RzILOpPure *a, RzILOpPure *b) {
	return FSUB(0, a, b);
}

static RzILOpPure *fmul_(RzILOpPure *a, RzILOpPure *b) {
	return FMUL(0, a, b);
}

static RzILOpPure *fdiv_(RzILOpPure *a, RzILOpPure *b) {
	return FSUB(0, a, b);
}

static RzILOpPure *bv2f32(RzILOpPure *x) {
	return FLOATV32(x);
}

static RzILOpPure *f32_2int(RzILOpPure *x) {
	return F2SINT(32, 0, x);
}

static RzILOpPure *f32_trunc2int(RzILOpPure *x) {
	return F2SINT(32, 0, FROUND(0, x));
}

typedef struct {
	const char *p;
	const char *x;
	unsigned i;
	unsigned b;
} FLG;

static const FLG flags[] = {
	{ "PSW", "RFU", 20, 12 },
	{ "PSW", "I3", 19, 1 },
	{ "PSW", "I2", 18, 1 },
	{ "PSW", "I1", 17, 1 },
	{ "PSW", "I0", 16, 1 },
	{ "PSW", "NP", 15, 1 },
	{ "PSW", "EP", 14, 1 },
	{ "PSW", "AE", 13, 1 },
	{ "PSW", "ID", 12, 1 },
	{ "PSW", "RFU", 10, 2 },
	{ "PSW", "FRO", 9, 1 },
	{ "PSW", "FIV", 8, 1 },
	{ "PSW", "FZD", 7, 1 },
	{ "PSW", "FOV", 6, 1 },
	{ "PSW", "FUD", 5, 1 },
	{ "PSW", "FPR", 4, 1 },
	{ "PSW", "CY", 3, 1 },
	{ "PSW", "OV", 2, 1 },
	{ "PSW", "S", 1, 1 },
	{ "PSW", "Z", 0, 1 },

	{ "PIR", "RFU", 16, 16 },
	{ "PIR", "PT", 4, 12 },
	{ "PIR", "NECRV", 0, 4 },

	{ "TKCW", "RFU", 9, 24 },
	{ "TKCW", "OTM", 8, 1 },
	{ "TKCW", "FIT", 7, 1 },
	{ "TKCW", "FZT", 6, 1 },
	{ "TKCW", "FVT", 5, 1 },
	{ "TKCW", "FUT", 4, 1 },
	{ "TKCW", "FPT", 3, 1 },
	{ "TKCW", "RDI", 2, 1 },
	{ "TKCW", "RD", 0, 2 },

	{ "CHCW", "SA", 8, 25 },
	{ "CHCW", "CEN", 20, 12 },
	{ "CHCW", "CEC", 8, 12 },
	{ "CHCW", "RFU", 6, 2 },
	{ "CHCW", "ICR", 5, 1 },
	{ "CHCW", "ICD", 4, 1 },
	{ "CHCW", "RFU", 2, 2 },
	{ "CHCW", "ICE", 1, 1 },
	{ "CHCW", "ICC", 0, 1 },
};

static const FLG *flag_find(const char *p, const char *x) {
	for (int i = 0; i < RZ_ARRAY_SIZE(flags); ++i) {
		const FLG *f = flags + i;
		if (RZ_STR_NE(p, f->p)) {
			continue;
		}
		if (RZ_STR_NE(x, f->x)) {
			continue;
		}
		return f;
	}
	return NULL;
}

static RzILOpPure *VARGb(const char *p, const char *x) {
	const FLG *f = flag_find(p, x);
	if (!f) {
		rz_warn_if_reached();
		return NULL;
	}
	RzILOpPure *y = LET("_v_parent", VARG(p),
		LOGAND(shr0(VARLP("_v_parent"), U32(f->i)), U32(f->b)));
	if (f->b == 1) {
		y = LET("_v_part", y,
			NON_ZERO(VARLP("_v_part")));
	}
	return y;
}

static RzILOpEffect *SETGbs(const char *p, unsigned n, ...) {
	va_list args;
	va_start(args, n);

	RzILOpPure *expr = NULL;
	for (unsigned i = 0; i < n; ++i) {
		const char *x = va_arg(args, const char *);
		RzILOpPure *y = va_arg(args, RzILOpPure *);

		const FLG *f = flag_find(p, x);
		if (!f) {
			rz_warn_if_reached();
			return NULL;
		}

		RzILOpPure *v = shl0(f->b == 1 ? BOOL_TO_BV(y, 32) : y, U32(f->i));
		expr = !expr ? v : LOGOR(expr, v);
	}
	return SETG(p, expr);
}

#define SETGb(p, ...) SETGbs(p, 1, __VA_ARGS__)

static RzILOpPure *overflow(RzILOpPure *x) {
	return LET("_x", x,
		OR(
			SGT(VARLP("_x"), S32(+0x7fffffff)),
			SLT(VARLP("_x"), S32(-0x80000000))));
}

static RzAnalysisLiftedILOp flags_update(const V810AnalysisContext *ctx) {
	switch (COPCODE) {
	case V810_NOT:
	case V810_DIVU:
	case V810_AND:
	case V810_OR:
	case V810_ORI:
	case V810_XOR:
	case V810_XORI:
		return SETGbs("PSW", 3,
			"OV", IL_FALSE,
			"S", SLT(R2V, S32(0)),
			"Z", IS_ZERO(R2V));
	case V810_ANDI:
		return SETGbs("PSW", 3,
			"OV", IL_FALSE,
			"S", IL_FALSE,
			"Z", IS_ZERO(R2V));

	case V810_DIV:
	case V810_MUL:
	case V810_MULU:
		return SETGbs("PSW", 3,
			"OV", overflow(R2V),
			"S", SLT(R2V, S32(0)),
			"Z", IS_ZERO(R2V));

	case V810_CMP_IMM5:
		return SETGbs("PSW", 4,
			"CY", SLT(R2V, SEXT5),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V810_CMP:
	case V810_SUB:
		return SETGbs("PSW", 4,
			"CY", SLT(R2V, R1V),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V810_ADD:
		return SETGbs("PSW", 4,
			"CY", OR(SLT(VARL("result"), R2V), SLT(VARL("result"), R1V)),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V810_ADD_IMM5:
		return SETGbs("PSW", 4,
			"CY", OR(SLT(VARL("result"), R2V), SLT(VARL("result"), SEXT5)),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V810_ADDI:
		return SETGbs("PSW", 4,
			"CY", OR(SLT(VARL("result"), SEXT16), SLT(VARL("result"), R1V)),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V810_SAR:
	case V810_SHR:
		return SETGbs("PSW", 3,
			"CY", AND(NON_ZERO(ZEXT5), NON_ZERO(LOGAND(R2V, SUB(shl0(U32(1), ZEXT5), U32(1))))),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V810_SAR_IMM5:
	case V810_SHR_IMM5:
		return SETGbs("PSW", 3,
			"CY", AND(NON_ZERO(R1V), NON_ZERO(LOGAND(R2V, SUB(shl0(U32(1), R1V), U32(1))))),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));

	case V810_SHL:
		return SETGbs("PSW", 3,
			"CY", AND(NON_ZERO(ZEXT5), NON_ZERO(shr0(R2V, SUB(U32(32), R1V)))),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V810_SHL_IMM5:
		return SETGbs("PSW", 3,
			"CY", AND(NON_ZERO(ZEXT5), NON_ZERO(shr0(R2V, SUB(U32(32), ZEXT5)))),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V810_CAXI:
		return SETGbs("PSW", 4,
			"CY", SLT(R2V, R1V),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V810_EXT: {
		switch (SUBOPC) {
		case V810_EXT_CMPF_S: return SETGbs("PSW", 4,
			"OV", IL_FALSE,
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")),
			"FRO", LET("_x", R2F, OR(IS_FNAN(VARLP("_x")), IS_FINF(VARLP("_x")))) // TODO: denormal number
			// "FPR", // 1 if degradation in precision is detected; otherwise, not affected
		);
		case V810_EXT_CVT_WS: return SETGbs("PSW", 5,
			"CY", INV(IS_FPOS(R2F)),
			"OV", IL_FALSE,
			"S", FLT(R2F, F32(0)),
			"Z", IS_ZERO(R2F),
			"FRO", LET("_x", R2F, OR(IS_FNAN(VARLP("_x")), IS_FINF(VARLP("_x")))) // TODO: denormal number
			// "FPR", // TODO: 1 if degradation in precision is detected; otherwise, not affected
		);
		case V810_EXT_CVT_SW: return SETGbs("PSW", 3,
			"OV", IL_FALSE,
			"S", SLT(R2V, S32(0)),
			"Z", IS_ZERO(R2V)
			// "FRO", LET("_x", R2V, OR(IS_FNAN(VARLP("_x")), IS_FINF(VARLP("_x")))) // TODO: denormal number
			// ,"FIV",//  TODO: invalid operation occurs
			// "FPR", // TODO: 1 if degradation in precision is detected; otherwise, not affected
		);
		case V810_EXT_ADDF_S:
		case V810_EXT_SUBF_S:
		case V810_EXT_MULF_S:
		case V810_EXT_DIVF_S: return SETGbs("PSW", 6,
			"CY", INV(IS_FPOS(VARL("result"))),
			"OV", IL_FALSE,
			"S", FLT(VARL("result"), F32(0)),
			"Z", IS_FZERO(VARL("result")),
			"FRO", OR(IS_FNAN(VARL("result")), IS_FINF(VARL("result"))) // TODO: denormal number
			// ,"FIV",//  TODO: invalid operation occurs
			,
			"FZD", IS_FZERO(R1F)
			// "FOV", // TODO:  1 if result of operation is greater than maximum normalized number that can be expressed;
			// "FUD", // TODO: if result of operation is less than minimum (absolute value) normalized number that can be expressed;
			// "FPR", // TODO: 1 if degradation in precision is detected; otherwise, not affected
		);
		case V810_EXT_XB:
		case V810_EXT_XH:
		case V810_EXT_REV: return NOP();
		case V810_EXT_TRNC_SW: return SETGbs("PSW", 4,
			"OV", IL_FALSE,
			"S", FLT(FLOATV32(VARL("result")), F32(0)),
			"Z", IS_FZERO(FLOATV32(VARL("result"))),
			"FRO", LET("_x", FLOATV32(VARL("result")), OR(IS_FNAN(VARLP("_x")), IS_FINF(VARLP("_x")))) // TODO: denormal number
			// ,"FIV",//  TODO: invalid operation occurs
			// "FPR", // TODO: 1 if degradation in precision is detected; otherwise, not affected
		);
		case V810_EXT_MPYHW:
		default:
			return NOP();
		}
	}
	default:
		return NOP();
	}
}

typedef RzILOpPure *(*F_OP1)(RzILOpPure *);
typedef RzILOpPure *(*F_OP2)(RzILOpPure *, RzILOpPure *);

static RzAnalysisLiftedILOp lift_mov(const V810AnalysisContext *ctx, RzILOpPure *x0) {
	return SETG(R2, x0);
}

static RzAnalysisLiftedILOp lift_op1(const V810AnalysisContext *ctx, RzILOpPure *x0, F_OP1 f) {
	return SEQ2(
		SETG(R2, f(x0)),
		flags_update(ctx));
}

static RzAnalysisLiftedILOp lift_op2(const V810AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return SEQ3(
		SETL("result", f(x0, x1)),
		flags_update(ctx),
		SETG(R2, VARL("result")));
}

static RzAnalysisLiftedILOp lift_fop1(const V810AnalysisContext *ctx, RzILOpPure *x0, F_OP1 f) {
	return SEQ2(
		SETG(R2, F2BV(f(x0))),
		flags_update(ctx));
}

static RzAnalysisLiftedILOp lift_fop2(const V810AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return SEQ3(
		SETL("result", f(x0, x1)),
		flags_update(ctx),
		SETG(R2, F2BV(VARL("result"))));
}

static RzAnalysisLiftedILOp lift_div(const V810AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1) {
	return SEQ3(
		SETG(R2, DIV(x0, x1)),
		SETG(GR[30], MOD(DUP(x0), DUP(x1))),
		flags_update(ctx));
}

static RzAnalysisLiftedILOp lift_mul(const V810AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1) {
	return SEQ4(
		SETL("result", MUL(SIGNED(64, x0), SIGNED(64, x1))),
		SETG(R2, UNSIGNED(32, VARL("result"))),
		SETG(GR[30], UNSIGNED(32, shr0(VARL("result"), U32(32)))),
		flags_update(ctx));
}

static RzAnalysisLiftedILOp lift_mulu(const V810AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1) {
	return SEQ4(
		SETL("result", MUL(UNSIGNED(64, x0), UNSIGNED(64, x1))),
		SETG(R2, UNSIGNED(32, VARL("result"))),
		SETG(GR[30], UNSIGNED(32, shr0(VARL("result"), U32(32)))),
		flags_update(ctx));
}

static RzAnalysisLiftedILOp lift_cmp(const V810AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return SEQ2(
		SETL("result", f(x0, x1)),
		flags_update(ctx));
}

static RzAnalysisLiftedILOp lift_ld(const V810AnalysisContext *ctx, RzILOpPure *addr, unsigned B) {
	RzILOpPure *y = LOADW(B, VARL("_adr"));
	if (B == 8 || B == 16) {
		y = LET("_v", UNSIGNED(32, y), SEXTRACT32(VARLP("_v"), U32(0), U32(B)));
	} else {
		rz_warn_if_fail(B == 32);
	}
	return SEQ2(
		SETL("_adr", addr),
		SETG(R2, y));
}

static RzAnalysisLiftedILOp lift_st(const V810AnalysisContext *ctx, RzILOpPure *addr, unsigned B) {
	RzILOpPure *y = R2V;
	if (B == 8 || B == 16) {
		y = UNSIGNED(B, y);
	} else {
		rz_warn_if_fail(B == 32);
	}
	return SEQ2(
		SETL("_adr", addr),
		STOREW(VARL("_adr"), y));
}

static RzAnalysisLiftedILOp lift_reti(const V810AnalysisContext *ctx) {
	return SEQ3(
		SETL("_pc", ITE(VARGb("PSW", "NP"), VARG("FEPC"), VARG("EIPC"))),
		SETL("PSW", ITE(VARGb("PSW", "NP"), VARG("FEPSW"), VARG("EIPSW"))),
		JMP(VARL("_pc")));
}

static RzAnalysisLiftedILOp lift_jal(const V810AnalysisContext *ctx) {
	return SEQ3(
		SETG(GR[31], ADD(U32(ctx->pc), U32(4))),
		SETL("_pc", ADD(U32(ctx->pc), SEXT26)),
		JMP(VARL("_pc")));
}

static RzAnalysisLiftedILOp lift_jr(const V810AnalysisContext *ctx) {
	return SEQ2(
		SETL("_pc", ADD(S32(ctx->pc), SEXT26)),
		JMP(VARL("_pc")));
}

static RzAnalysisLiftedILOp lift_caxi(const V810AnalysisContext *ctx) {
	return SEQ5(
		SETL("_adr", ADD(R1V, SEXT16)),
		SETL("_tmp", LOADW(32, VARL("_adr"))),
		SETL("result", SUB(R2V, VARL("_tmp"))),
		flags_update(ctx),
		BRANCH(IS_ZERO(VARL("result")),
			SEQ2(
				STOREW(VARL("_adr"), VARG(GR[30])),
				SETG(R2, VARL("_tmp"))),
			SEQ2(
				STOREW(VARL("_adr"), VARL("_tmp")),
				SETG(R2, VARL("_tmp")))));
}

static RzAnalysisLiftedILOp lift_bcond(const V810AnalysisContext *ctx, RzILOpPure *cond) {
	return BRANCH(cond, SEQ2(SETL("_pc", ADD(S32(ctx->pc), SEXT9)), JMP(VARL("_pc"))), NOP());
}

RzAnalysisLiftedILOp v810_il_op(const V810AnalysisContext *ctx) {
	switch (COPCODE) {
	case V810_MOV: return lift_mov(ctx, R1V);
	case V810_MOV_IMM5: return lift_mov(ctx, SEXT5);
	case V810_MOVHI: return lift_mov(ctx, ADD(R1V, shl0(ZEXT16, U32(16))));
	case V810_MOVEA: return lift_mov(ctx, ADD(R1V, SEXT16));
	case V810_LDSR: return SETG(SR[I5], R2V);
	case V810_STSR: return SETG(R2, VARG(SR[I5]));
	case V810_NOT: return lift_op1(ctx, R1V, rz_il_op_new_log_not);
	case V810_DIV:
	case V810_DIVU: return lift_div(ctx, R2V, R1V);
	case V810_OR: return lift_op2(ctx, R2V, R1V, rz_il_op_new_log_or);
	case V810_ORI: return lift_op2(ctx, R2V, ZEXT16, rz_il_op_new_log_or);
	case V810_MUL: return lift_mul(ctx, R2V, R1V);
	case V810_MULU: return lift_mulu(ctx, R2V, R1V);
	case V810_XOR: return lift_op2(ctx, R2V, R1V, rz_il_op_new_log_xor);
	case V810_XORI: return lift_op2(ctx, R2V, ZEXT16, rz_il_op_new_log_xor);
	case V810_AND: return lift_op2(ctx, R2V, R1V, rz_il_op_new_log_and);
	case V810_ANDI: return lift_op2(ctx, R2V, ZEXT16, rz_il_op_new_log_and);
	case V810_CMP: return lift_cmp(ctx, R2V, R1V, rz_il_op_new_sub);
	case V810_CMP_IMM5: return lift_cmp(ctx, R2V, SEXT5, rz_il_op_new_sub);
	case V810_SUB: return lift_op2(ctx, R2V, R1V, rz_il_op_new_sub);
	case V810_ADD: return lift_op2(ctx, R2V, R1V, rz_il_op_new_add);
	case V810_ADDI: return lift_op2(ctx, R1V, SEXT16, rz_il_op_new_add);
	case V810_ADD_IMM5: return lift_op2(ctx, R2V, SEXT5, rz_il_op_new_add);
	case V810_SHR: return lift_op2(ctx, R2V, R1V, shr0);
	case V810_SHR_IMM5: return lift_op2(ctx, R2V, ZEXT5, shr0);
	case V810_SAR: return lift_op2(ctx, R2V, R1V, rz_il_op_new_shiftr_arith);
	case V810_SAR_IMM5: return lift_op2(ctx, R2V, ZEXT5, rz_il_op_new_shiftr_arith);
	case V810_SHL: return lift_op2(ctx, R2V, R1V, shl0);
	case V810_SHL_IMM5: return lift_op2(ctx, R2V, ZEXT5, shl0);

	case V810_INB:
	case V810_LDB: return lift_ld(ctx, ADD(R1V, SEXT16), 8);
	case V810_INH:
	case V810_LDH: return lift_ld(ctx, ADD(R1V, SEXT16), 16);
	case V810_INW:
	case V810_LDW: return lift_ld(ctx, ADD(R1V, SEXT16), 32);

	case V810_OUTB:
	case V810_STB: return lift_st(ctx, ADD(R1V, SEXT16), 8);
	case V810_OUTH:
	case V810_STH: return lift_st(ctx, ADD(R1V, SEXT16), 16);
	case V810_OUTW:
	case V810_STW: return lift_st(ctx, ADD(R1V, SEXT16), 32);

	case V810_HALT:
	case V810_TRAP: return NOP();
	case V810_RETI: return lift_reti(ctx);
	case V810_JMP: return JMP(LOGAND(R1V, U32(0xfffffffe)));
	case V810_JAL: return lift_jal(ctx);
	case V810_JR: return lift_jr(ctx);
	case V810_CLI:
	case V810_SEI: return NOP();
	case V810_CAXI: return lift_caxi(ctx);
	case V810_EXT: {
		switch (SUBOPC) {
		case V810_EXT_CMPF_S: return lift_cmp(ctx, R2F, R1F, fsub_);
		case V810_EXT_CVT_WS: return lift_fop1(ctx, R1V, bv2f32);
		case V810_EXT_CVT_SW: return lift_op1(ctx, R1F, f32_2int);
		case V810_EXT_ADDF_S: return lift_fop2(ctx, R2F, R1F, fadd_);
		case V810_EXT_SUBF_S: return lift_fop2(ctx, R2F, R1F, fsub_);
		case V810_EXT_MULF_S: return lift_fop2(ctx, R2F, R1F, fmul_);
		case V810_EXT_DIVF_S: return lift_fop2(ctx, R2F, R1F, fdiv_);
		case V810_EXT_XB:
		case V810_EXT_XH:
		case V810_EXT_REV: return NOP();
		case V810_EXT_TRNC_SW: return lift_fop1(ctx, R1V, f32_trunc2int);
		case V810_EXT_MPYHW: return NOP();
		default: break;
		}
		break;
	}
	default:
		if (COPCODE >> 3 == 4) {
			RzILOpPure *cnd = NULL;
			switch (CCOND) {
			case C_BGT: cnd = INV(OR(XOR(VARGb("PSW", "S"), VARGb("PSW", "OV")), VARGb("PSW", "Z"))); break;
			case C_BGE: cnd = INV(XOR(VARGb("PSW", "S"), VARGb("PSW", "OV"))); break;
			case C_BLT: cnd = XOR(VARGb("PSW", "S"), VARGb("PSW", "OV")); break;
			case C_BLE: cnd = OR(XOR(VARGb("PSW", "S"), VARGb("PSW", "OV")), VARGb("PSW", "Z")); break;

			case C_BH: cnd = INV(OR(VARGb("PSW", "CY"), VARGb("PSW", "Z"))); break;
			case C_BNL: cnd = INV(VARGb("PSW", "CY")); break;
			case C_BL: cnd = VARGb("PSW", "CY"); break;
			case C_BNH: cnd = OR(VARGb("PSW", "CY"), VARGb("PSW", "Z")); break;

			case C_BE: cnd = VARGb("PSW", "Z"); break;
			case C_BNE: cnd = INV(VARGb("PSW", "Z")); break;

			case C_BV: cnd = VARGb("PSW", "OV"); break;
			case C_BNV: cnd = INV(VARGb("PSW", "OV")); break;
			case C_BN: cnd = VARGb("PSW", "S"); break;
			case C_BP: cnd = INV(VARGb("PSW", "S")); break;
			//		case C_BC: break;
			//		case C_BNC: break;
			//		case C_BZ: break;
			//		case C_BNZ: break;
			case C_BR: cnd = IL_TRUE; break;
			case C_NOP: cnd = IL_FALSE; break;
			default: break;
			}
			return lift_bcond(ctx, cnd);
		}
		break;
	}
	rz_warn_if_reached();
	return NULL;
}

#include <rz_il/rz_il_opbuilder_end.h>
