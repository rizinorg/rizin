// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "v850_il.h"

static const char *v850_registers[] = {
	"r0",
	"r1",
	"r2",
	"sp",
	"gp",
	"tp",
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
	"ep", // EP
	"lp", // LP
	/*PC*/

	/*
	 * \see Section 3.3-3.5  https://www.renesas.com/us/en/document/mas/rh850g3kh-users-manual-software
	 * \see SR_get() in v850_disas.h
	 * regID Symbol*/
	/*0 */ "EIPC",
	/*1 */ "EIPSW",
	/*2 */ "FEPC",
	/*3 */ "FEPSW",
	/*4 */ "ECR",
	/*5 */ "PSW",
	/*6 */ "FPSR",
	/*7 */ "FPEPC",
	/*8 */ "FPST",
	/*9 */ "FPCC",
	/*10*/ "FPCFG",
	/*11*/ "FPEC",
	/*13*/ "EIIC",
	/*14*/ "FEIC",
	/*16*/ "CTPC",
	/*17*/ "CTPSW",
	/*20*/ "CTBP",
	/*28*/ "EIWR",
	/*29*/ "FEWR",
	/*31*/ "BSEL",
	/*0 */ "MCFG0",
	/*2 */ "RBASE",
	/*3 */ "EBASE",
	/*4 */ "INTBP",
	/*5 */ "MCTL",
	/*6 */ "PID",
	/*7 */ "FPIPR",
	/*11*/ "SCCFG",
	/*12*/ "SCBP",
	/*0 */ "HTCFG0",
	/*6 */ "MEA",
	/*7 */ "ASID",
	/*8 */ "MEI",
	/*10*/ "ISPR",
	/*11*/ "PMR",
	/*12*/ "ICSR",
	/*13*/ "INTCFG",
	/*0 */ "MPM",
	/*1 */ "MPRC",
	/*4 */ "MPBRGN",
	/*5 */ "MPTRGN",
	/*8 */ "MCA",
	/*9 */ "MCS",
	/*10*/ "MCC",
	/*11*/ "MCR",
	/*0 */ "MPLA0",
	/*1 */ "MPUA0",
	/*2 */ "MPAT0",
	/*4 */ "MPLA1",
	/*5 */ "MPUT1",
	/*6 */ "MPAT1",
	/*8 */ "MPLA2",
	/*9 */ "MPUA2",
	/*10*/ "MPAT2",
	/*12*/ "MPLA3",
	/*13*/ "MPUA3",
	/*14*/ "MPAT3",
	/*16*/ "MPLA4",
	/*17*/ "MPUA4",
	/*18*/ "MPAT4",
	/*20*/ "MPLA5",
	/*21*/ "MPUA5",
	/*22*/ "MPAT5",
	/*24*/ "MPLA6",
	/*25*/ "MPUA6",
	/*26*/ "MPAT6",
	/*28*/ "MPLA7",
	/*29*/ "MPUA7",
	/*30*/ "MPAT7",
	/*0 */ "MPLA8",
	/*1 */ "MPUA8",
	/*2 */ "MPAT8",
	/*4 */ "MPLA9",
	/*5 */ "MPUT9",
	/*6 */ "MPAT9",
	/*8 */ "MPLA10",
	/*9 */ "MPUA10",
	/*10*/ "MPAT10",
	/*12*/ "MPLA11",
	/*13*/ "MPUA11",
	/*14*/ "MPAT11",
	/*16*/ "MPLA12",
	/*17*/ "MPUA12",
	/*18*/ "MPAT12",
	/*20*/ "MPLA13",
	/*21*/ "MPUA13",
	/*22*/ "MPAT13",
	/*24*/ "MPLA14",
	/*25*/ "MPUA14",
	/*26*/ "MPAT14",
	/*28*/ "MPLA15",
	/*29*/ "MPUA15",
	/*30*/ "MPAT15",
	NULL
};

RzAnalysisILConfig *v850_il_config(RzAnalysis *a) {
	rz_return_val_if_fail(a, NULL);

	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	cfg->reg_bindings = v850_registers;
	return cfg;
}

typedef struct {
	const char *p;
	const char *x;
	unsigned i;
	unsigned b;
} V850_FLG;

static const V850_FLG flags[] = {
	{ "PSW", "UM", 30, 1 },
	{ "PSW", "CU2", 18, 1 },
	{ "PSW", "CU1", 17, 1 },
	{ "PSW", "CU0", 16, 1 },
	{ "PSW", "EBV", 15, 1 },
	{ "PSW", "Debug", 9, 11 },
	{ "PSW", "NP", 7, 1 },
	{ "PSW", "EP", 6, 1 },
	{ "PSW", "ID", 5, 1 },
	{ "PSW", "SAT", 4, 1 },
	{ "PSW", "CY", 3, 1 },
	{ "PSW", "OV", 2, 1 },
	{ "PSW", "S", 1, 1 },
	{ "PSW", "Z", 0, 1 },

	{ "ECR", "FECC", 16, 16 },
	{ "ECR", "EICC", 0, 16 },

	{ "SCCFG", "SIZE", 0, 8 }
};

static const V850_FLG *flag_find(const char *p, const char *x) {
	for (int i = 0; i < RZ_ARRAY_SIZE(flags); ++i) {
		const V850_FLG *f = flags + i;
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

#include <rz_il/rz_il_opbuilder_begin.h>

static RzILOpEffect *SETGbs(const char *p, unsigned n, ...) {
	va_list args;
	va_start(args, n);

	RzILOpPure *expr = NULL;
	for (unsigned i = 0; i < n; ++i) {
		const char *x = va_arg(args, const char *);
		RzILOpPure *y = va_arg(args, RzILOpPure *);

		const V850_FLG *f = flag_find(p, x);
		if (!f) {
			rz_warn_if_reached();
			return NULL;
		}

		RzILOpPure *v = SHIFTL0(f->b == 1 ? BOOL_TO_BV(y, 32) : y, U32(f->i));
		expr = !expr ? v : LOGOR(expr, v);
	}
	return SETG(p, expr);
}
#define SETGb(p, ...) SETGbs(p, 1, __VA_ARGS__)

static RzILOpEffect *SETGp(const char *p, unsigned l, unsigned r, RzILOpPure *x) {
	rz_warn_if_fail(l <= 31 && r <= 31 && r >= l);
	RzILOpPure *updated = LET("_orig", VARG(p),
		LOGOR(LOGAND(VARLP("_orig"), U32(((1ULL << (r + 1 - l)) - 1ULL) << l)), SHIFTL0(x, U32(l))));
	return SETG(p, updated);
}

static RzILOpPure *inth(unsigned b, RzILOpPure *x, RzILOpPure *n) {
	return NON_ZERO(LOGAND(SHIFTR0(x, n), UN(b, 1)));
}
static RzILOpPure *nth(unsigned b, RzILOpPure *x, unsigned n) {
	return inth(b, x, UN(b, n));
}

static RzILOpPure *iset_nth(unsigned b, RzILOpPure *x, RzILOpPure *n, bool v) {
	if (v) {
		return LOGOR(x, SHIFTL0(UN(b, v), n));
	}
	return LOGAND(x, LOGNOT(SHIFTL0(UN(b, v), n)));
}
static RzILOpPure *set_nth(unsigned b, RzILOpPure *x, unsigned n, bool v) {
	if (v) {
		return LOGOR(x, UN(b, (ut32)(v) << n));
	}
	return LOGAND(x, UN(b, ~((ut32)(v) << n)));
}

static RzILOpPure *isext32(RzILOpPure *x, RzILOpPure *i) {
	return SEXTRACT32(x, U32(0), i);
}

#define LH(x) LOGAND(x, U32(0xffff))

#define PSW_NP  nth(32, VARG("PSW"), 7)
#define PSW_EP  nth(32, VARG("PSW"), 6)
#define PSW_ID  nth(32, VARG("PSW"), 5)
#define PSW_SAT nth(32, VARG("PSW"), 4)
#define PSW_CY  nth(32, VARG("PSW"), 3)
#define PSW_OV  nth(32, VARG("PSW"), 2)
#define PSW_S   nth(32, VARG("PSW"), 1)
#define PSW_Z   nth(32, VARG("PSW"), 0)

#define R1_   get_reg1(ctx->x)
#define R2_   get_reg2(ctx->x)
#define R3_   get_reg3(ctx->x)
#define PC_   (ctx->x->addr)
#define PC    U32(ctx->x->addr)
#define R1    (GR_get(R1_))
#define R2    (GR_get(R2_))
#define R3    (GR_get(R3_))
#define R3_1  (GR_get(R3_ + 1))
#define R1V   VARG(R1)
#define R2V   VARG(R2)
#define R3V   VARG(R3)
#define R3V_1 VARG(R3_1)
#define R1F   FLOATV32(VARG(R1))
#define R2F   FLOATV32(VARG(R2))
#define R3F   FLOATV32(VARG(R3))

#define I5    (get_reg1(ctx->x))
#define selID (get_selID(ctx->x))
#define SEXT5 S32(sext32(I5, 5))
#define ZEXT5 U32(I5)

#define I16    (V850_word(ctx->x, 2))
#define SEXT16 S32(sext32(I16, 16))
#define ZEXT16 U32(I16)

#define BCOND_COND  (get_cond(ctx->x))
#define BCOND_DISP_ (ctx->x->disp)
#define BCOND_DISP  S32(sext32(BCOND_DISP_, 9))

#define JUMP_DISP_ (ctx->x->disp)
#define JUMP_DISP  S32(JUMP_DISP_)

#define BIT_BIT (viii_bit(ctx->x))

#define EXT_COND I5

#define EXT2_VEC I5
#define EXT2_IMM I5

#define V850_FORMAT (ctx->x->format)
#define IMM_V       S32(ctx->x->imm)

typedef RzILOpPure *(*F_OP1)(RzILOpPure *);
typedef RzILOpPure *(*F_OP2)(RzILOpPure *, RzILOpPure *);

#define mnull(x) \
	if (!(x)) { \
		return NULL; \
	}
#define merr(x) \
	if (!(x)) { \
		goto err; \
	}

static RzILOpEffect *new_seq2(RzILOpEffect *x, RzILOpEffect *y) {
	RzILOpEffect *seq = RZ_NEW0(RzILOpEffect);
	rz_warn_if_fail(seq);
	merr(seq);
	seq->code = RZ_IL_OP_SEQ;
	seq->op.seq.x = x;
	seq->op.seq.y = y;
	return seq;
err:
	rz_il_op_effect_free(x);
	rz_il_op_effect_free(y);
	return NULL;
}

static bool cons(RzILOpEffect **x, RzILOpEffect *y) {
	RzILOpEffect *last = *x;
	RzILOpEffect *seq = NULL;
	if (last->code != RZ_IL_OP_SEQ) {
		merr(last = new_seq2(last, y));
		*x = last;
		return true;
	}

	while (last->op.seq.y && last->op.seq.y->code == RZ_IL_OP_SEQ) {
		last = last->op.seq.y;
	}
	if (last->op.seq.y) {
		if (!(seq = new_seq2(last->op.seq.y, y))) {
			last->op.seq.y = NULL;
			y = NULL;
			goto err;
		}
		last->op.seq.y = seq;
	} else {
		last->op.seq.y = y;
	}
	return true;
err:
	rz_il_op_effect_free(*x);
	rz_il_op_effect_free(y);
	return false;
}

#define mcons(x, y) mnull(cons((x), (y)))
#define FV(f, v) \
	if (V850_FORMAT == f) \
		return v;

static RzILOpPure *overflow(RzILOpPure *x) {
	return LET("_x", x,
		OR(
			SGT(VARLP("_x"), S32(+0x7fffffff)),
			SLT(VARLP("_x"), S32(-0x80000000))));
}

static RzILOpPure *saturated(RzILOpPure *x) {
	return LET("_x", x,
		ITE(UGE(VARLP("_x"), U32(+0x7fffffff)),
			U32(+0x7fffffff),
			ITE(ULE(VARLP("_x"), U32(0x80000000)),
				U32(0x80000000),
				VARLP("_x"))));
}

static RzILOpPure *shl0(RzILOpPure *a, RzILOpPure *b) {
	return SHIFTL0(a, b);
}

static RzILOpPure *shr0(RzILOpPure *a, RzILOpPure *b) {
	return SHIFTR0(a, b);
}

static RzILOpPure *condition_table(ut8 x) {
	switch (x) {
	case C_BGT: return INV(OR(XOR(PSW_S, PSW_OV), PSW_Z));
	case C_BGE: return INV(XOR(PSW_S, PSW_OV));
	case C_BLT: return XOR(PSW_S, PSW_OV);
	case C_BLE: return OR(XOR(PSW_S, PSW_OV), PSW_Z);

	case C_BH: return INV(OR(PSW_CY, PSW_Z));
	case C_BNL: return INV(PSW_CY);
	case C_BL: return PSW_CY;
	case C_BNH: return OR(PSW_CY, PSW_Z);

	case C_BE: return PSW_Z;
	case C_BNE: return INV(PSW_Z);

	case C_BV: return PSW_OV;
	case C_BNV: return INV(PSW_OV);
	case C_BN: return PSW_S;
	case C_BP: return INV(PSW_S);
	// case C_BC: break;
	// case C_BNC: break;
	// case C_BZ: break;
	// case C_BNZ: break;
	case C_BR: return IL_TRUE;
	case C_NOP: return IL_FALSE;
	default: break;
	}
	rz_warn_if_reached();
	return NULL;
}

static RzAnalysisLiftedILOp flags_update(const V850AnalysisContext *ctx, RzILOpPure *a, RzILOpPure *b) {
	switch (ctx->x->id) {
	case V850_ADD:
	case V850_ADDI:
	case V850_ADF:
	case V850_SBF:
	case V850_CAXI:
	case V850_LOOP:
		return SETGbs("PSW", 4,
			"CY", OR(SLT(VARL("result"), DUP(a)), SLT(VARL("result"), DUP(b))),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V850_SUB:
	case V850_SUBR:
	case V850_CMP:
		return SETGbs("PSW", 4,
			"CY", SLT(DUP(b), DUP(a)),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V850_DIVH:
		return SETGbs("PSW", 3,
			"OV", IS_ZERO(LH(R1V)),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V850_SHL: return SETGbs("PSW", 4,
		"CY", AND(NON_ZERO(DUP(b)), NON_ZERO(shr0(DUP(a), SUB(U32(32), DUP(b))))),
		"OV", IL_FALSE,
		"S", SLT(VARL("result"), S32(0)),
		"Z", IS_ZERO(VARL("result")));
	case V850_SHR:
	case V850_SAR: return SETGbs("PSW", 4,
		"CY", AND(NON_ZERO(DUP(b)), NON_ZERO(LOGAND(DUP(a), SUB(SHIFTL0(U32(1), DUP(b)), U32(1))))),
		"OV", IL_FALSE,
		"S", SLT(VARL("result"), S32(0)),
		"Z", IS_ZERO(VARL("result")));
	case V850_ROTL: return SETGbs("PSW", 4,
		"CY", AND(LSB(VARL("result")), NON_ZERO(DUP(b))),
		"OV", IL_FALSE,
		"S", SLT(VARL("result"), S32(0)),
		"Z", IS_ZERO(VARL("result")));
	case V850_SATADD:
	case V850_SATSUB:
	case V850_SATSUBI:
	case V850_SATSUBR: return SETGbs("PSW", 5,
		"CY", OR(SLT(VARL("result"), DUP(a)), SLT(VARL("result"), DUP(b))),
		"OV", overflow(VARL("result")),
		"S", SLT(VARL("result"), S32(0)),
		"Z", IS_ZERO(VARL("result")),
		"SAT", ITE(PSW_OV, IL_TRUE, PSW_SAT));
	case V850_XOR:
	case V850_XORI:
	case V850_OR:
	case V850_ORI:
	case V850_TST:
	case V850_BINS:
		return SETGbs("PSW", 3,
			"OV", IL_FALSE,
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V850_AND:
	case V850_ANDI: return SETGbs("PSW", 3,
		"OV", IL_FALSE,
		"S", IL_FALSE,
		"Z", IS_ZERO(VARL("result")));
	case V850_BSH:
	case V850_HSH:
		return SETGbs("PSW", 4,
			"CY", IS_ZERO(LH(VARL("result"))),
			"OV", IL_FALSE,
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(LH(VARL("result"))));
	case V850_BSW:
	case V850_HSW:
		return SETGbs("PSW", 4,
			"CY", IS_ZERO(VARL("result")),
			"OV", IL_FALSE,
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	default: return NOP();
	}
}

static RzAnalysisLiftedILOp lift_op1(const V850AnalysisContext *ctx, RzILOpPure *x0, F_OP1 f) {
	return SEQ2(
		SETG(R2, f(x0)),
		flags_update(ctx, x0, NULL));
}

static RzAnalysisLiftedILOp lift_op2_(const V850AnalysisContext *ctx, const char *dst, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return SEQ3(
		SETL("result", f(x0, x1)),
		flags_update(ctx, x0, x1),
		SETG(dst, VARL("result")));
}

static RzAnalysisLiftedILOp lift_op2(const V850AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return lift_op2_(ctx, R2, x0, x1, f);
}

static RzAnalysisLiftedILOp lift_satop2_(const V850AnalysisContext *ctx, const char *dst, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return SEQ3(
		SETL("result", saturated(f(x0, x1))),
		flags_update(ctx, x0, x1),
		SETG(dst, VARL("result")));
}
static RzAnalysisLiftedILOp lift_satop2(const V850AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return lift_satop2_(ctx, R2, x0, x1, f);
}

static RzAnalysisLiftedILOp lift_bcond(const V850AnalysisContext *ctx) {
	return BRANCH(condition_table(BCOND_COND),
		SEQ2(SETL("_pc", ADD(S32(PC_), BCOND_DISP)), JMP(VARL("_pc"))), NOP());
}

static RzAnalysisLiftedILOp lift_bit(const V850AnalysisContext *ctx, RzILOpPure *adr, bool v) {
	FV(VIII_bit,
		SEQ4(
			SETL("_adr", adr),
			SETL("_val", LOADW(8, VARL("_adr"))),
			SETGb("PSW", "Z", INV(nth(8, VARL("_val"), BIT_BIT))),
			STOREW(VARL("_adr"), set_nth(8, VARL("_val"), BIT_BIT, v))));
	FV(IX_extended1,
		SEQ4(
			SETL("_adr", R1V),
			SETL("_val", LOADW(8, VARL("_adr"))),
			SETGb("PSW", "Z", INV(inth(8, VARL("_val"), R2V))),
			STOREW(VARL("_adr"), iset_nth(8, VARL("_val"), R2V, v))));
	NOT_IMPLEMENTED;
}

static RzAnalysisLiftedILOp lift_cmp(const V850AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return SEQ2(
		SETL("result", f(x0, x1)),
		flags_update(ctx, x0, x1));
}

static RzAnalysisLiftedILOp lift_jarl(const V850AnalysisContext *ctx) {
	switch (V850_FORMAT) {
	case V_jump: return SEQ3(
		SETG(R2, ADD(U32(PC_), U32(4))),
		SETL("_pc", ADD(U32(PC_), JUMP_DISP)),
		JMP(VARL("_pc")));
	case VI_3operand: return SEQ3(
		SETG(R1, ADD(U32(PC_), U32(6))),
		SETL("_pc", ADD(U32(PC_), JUMP_DISP)),
		JMP(VARL("_pc")));
	case XI_extended3: return SEQ3(
		SETG(R3, ADD(U32(PC_), U32(4))),
		SETL("_pc", R1V),
		JMP(VARL("_pc")));
	default: rz_warn_if_reached(); return NULL;
	}
}

static RzAnalysisLiftedILOp lift_ld(const V850AnalysisContext *ctx) {
	RzILOpPure *src_val = NULL;
	RzILOpPure *addr = NULL;
	st32 disp = 0;
	ut8 reg_dst = 0;
	ut8 B = 0;
	bool sign = true;

	if (V850_FORMAT == VII_load_store32) {
		reg_dst = R2_;
		disp = sext32(ctx->x->disp, 16);
	} else if (V850_FORMAT == XIV_load_store48) {
		reg_dst = R3_;
		disp = sext32(ctx->x->disp, 23);
	} else if (V850_FORMAT == IV_load_store16) {
		reg_dst = V850_EP;
	} else {
		goto err;
	}

	switch (ctx->x->id) {
	case V850_SLDB:
	case V850_LDB: B = 8; break;
	case V850_SLDBU:
	case V850_LDBU:
		B = 8;
		sign = false;
		break;
	case V850_SLDH:
	case V850_LDH: B = 16; break;
	case V850_SLDHU:
	case V850_LDHU:
		B = 16;
		sign = false;
		break;
	case V850_SLDW:
	case V850_LDW: B = 32; break;
	case V850_LDDW: B = 64; break;
	default: goto err;
	}

	addr = ADD(R1V, S32(disp));
	src_val = LOADW(B, VARL("_adr"));
	if (B == 8 || B == 16) {
		src_val = sign
			? LET("_v", UNSIGNED(32, src_val), SEXTRACT32(VARLP("_v"), U32(0), U32(B)))
			: UNSIGNED(32, src_val);
	}
	if (B <= 32) {
		return SEQ2(
			SETL("_adr", addr),
			SETG(GR_get(reg_dst), src_val));
	} else {
		return SEQ4(
			SETL("_adr", addr),
			SETL("_src_v", src_val),
			SETG(GR_get(reg_dst), UNSIGNED(32, VARL("_src_v"))),
			SETG(GR_get(reg_dst + 1), UNSIGNED(32, shr0(VARL("_src_v"), U32(32)))));
	}
err:
	return NULL;
}

static RzAnalysisLiftedILOp lift_st(const V850AnalysisContext *ctx) {
	RzILOpPure *src = NULL;
	RzILOpPure *addr = NULL;
	const char *addr_reg = R1;
	RzILOpPure *v = NULL;
	ut8 B = 0;
	if (V850_FORMAT == VII_load_store32) {
		v = R2V;
	} else if (V850_FORMAT == XIV_load_store48) {
		v = R3V;
	} else if (V850_FORMAT == IV_load_store16) {
		addr_reg = "ep";
		v = R2V;
	} else {
		goto err;
	}

	switch (ctx->x->id) {
	case V850_SSTB:
	case V850_STB: B = 8; break;
	case V850_SSTH:
	case V850_STH: B = 16; break;
	case V850_SSTW:
	case V850_STW: B = 32; break;
	case V850_STDW: B = 64; break;
	default: goto err;
	}

	addr = ADD(VARG(addr_reg), S32(ctx->x->disp));
	if (B == 8 || B == 16) {
		src = UNSIGNED(B, v);
	} else if (B == 32) {
		src = v;
	} else {
		src = APPEND(R3V_1, v);
	}
	return SEQ2(
		SETL("_adr", addr),
		STOREW(VARL("_adr"), src));
err:
	return NULL;
}

static RzAnalysisLiftedILOp lift_trap(const V850AnalysisContext *ctx) {
	if (ctx->x->id == V850_TRAP) {
		return SEQ5(
			SETG("EIPC", U32(PC_ + ctx->x->byte_size)),
			SETG("EIPSW", VARG("PSW")),
			SETGb("ECR", "EICC", U32(EXT2_IMM)),
			SETGbs("PSW", 2,
				"EP", IL_TRUE,
				"ID", IL_TRUE),
			JMP((EXT2_VEC >= 0 && EXT2_IMM <= 0xf) ? U32(0x40) : U32(0x50)));
	} else if (ctx->x->id == V850_FETRAP) {
		return SEQ5(
			SETG("FEPC", U32(PC_ + ctx->x->byte_size)),
			SETG("FEPSW", VARG("PSW")),
			SETG("FEIC", U32(i_vec4(ctx->x) + 0x30)),
			SETGbs("PSW", 4,
				"UM", IL_FALSE,
				"NP", IL_TRUE,
				"EP", IL_TRUE,
				"ID", IL_TRUE),
			JMP(U32(i_vec4(ctx->x) + 0x30)));
	}
	rz_warn_if_reached();
	return NULL;
}

static RzAnalysisLiftedILOp lift_rie(const V850AnalysisContext *ctx) {
	return SEQ5(
		SETG("FEPC", U32(PC_)),
		SETG("FEPSW", VARG("PSW")),
		SETG("FEIC", U32(0x60)),
		SETGbs("PSW", 4,
			"UM", IL_FALSE,
			"NP", IL_TRUE,
			"EP", IL_TRUE,
			"ID", IL_TRUE),
		JMP(U32(0x60)));
}

static RzILOpPure *rotl32(RzILOpPure *x, RzILOpPure *y) {
	return LET("_expr", x,
		LET("_n", y,
			LOGOR(SHIFTL0(VARLP("_expr"), VARLP("_n")),
				SHIFTR0(VARLP("_expr"), SUB(U32(32), VARLP("_n"))))));
}

static RzAnalysisLiftedILOp lift_rotl(const V850AnalysisContext *ctx) {
	ut16 k = (ctx->x->d >> 16) & 0xffff & ~(0x1f << 11);
	RzILOpPure *a = NULL;
	RzILOpPure *b = NULL;
	if (k == 0b00011000100) {
		a = R2V;
		b = U32(ctx->x->imm);
	} else if (k == 0b00011000110) {
		a = R2V;
		b = R1V;
	} else {
		rz_warn_if_reached();
		return NULL;
	}
	return SEQ3(
		SETL("result", rotl32(a, b)),
		flags_update(ctx, a, b),
		SETG(R3, VARL("result")));
}

static RzAnalysisLiftedILOp lift_tst(const V850AnalysisContext *ctx) {
	RzILOpPure *a = R2V;
	RzILOpPure *b = R1V;
	return SEQ2(
		SETL("result", LOGAND(a, b)),
		flags_update(ctx, a, b));
}

static RzAnalysisLiftedILOp lift_tst1(const V850AnalysisContext *ctx) {
	FV(VIII_bit,
		SEQ3(
			SETL("_adr", ADD(R1V, SEXT16)),
			SETL("_val", LOADW(8, VARL("_adr"))),
			SETGb("PSW", "Z", INV(nth(8, VARL("_val"), BIT_BIT)))));
	FV(IX_extended1,
		SEQ3(
			SETL("_adr", R1V),
			SETL("_val", LOADW(8, VARL("_adr"))),
			SETGb("PSW", "Z", INV(inth(8, VARL("_val"), R2V)))));
	NOT_IMPLEMENTED;
}

static RzAnalysisLiftedILOp lift_prepare(const V850AnalysisContext *ctx) {
	RzILOpEffect *y = SETL("_tmp", VARG("sp"));
	ut16 list12 = xiii_list(ctx->x);
	ut8 lst[12];
	unsigned n = 0;
	xiii_sorted_list(list12, lst, &n, false);
	for (unsigned i = 0; i < n; ++i) {
		ut8 x = lst[i];
		mcons(&y, SETL("_tmp", SUB(VARL("_tmp"), U32(4))));
		mcons(&y, SETL("_adr", LOGAND(VARL("_tmp"), U32(~0b11))));
		mcons(&y, STOREW(VARL("_adr"), VARG(GR_get(x))));
	}
	mcons(&y, SETG("sp", SUB(VARL("_tmp"), shl0(U32(xiii_imm5(ctx->x)), U32(2)))));
	if ((xiii_sub_r1(ctx->x) & 0x7) == 0b011) {
		if (xiii_ff(ctx->x) == 0b00) {
			mcons(&y, SETG("ep", VARG("sp")));
		} else {
			mcons(&y, SETG("ep", U32(ctx->x->imm)));
		}
	}
	return y;
}

static RzAnalysisLiftedILOp lift_dispose(const V850AnalysisContext *ctx) {
	RzILOpEffect *y = SETL("_tmp", ADD(VARG("sp"), shl0(U32(xiii_imm5(ctx->x)), U32(2))));
	ut16 list12 = xiii_list(ctx->x);
	ut8 lst[12];
	unsigned n = 0;
	xiii_sorted_list(list12, lst, &n, true);
	for (unsigned i = 0; i < n; ++i) {
		ut8 x = lst[i];
		mcons(&y, SETL("_adr", LOGAND(VARL("_tmp"), U32(~0b11))));
		mcons(&y, SETG(GR_get(x), LOADW(32, VARL("_adr"))));
		mcons(&y, SETL("_tmp", ADD(VARL("_tmp"), U32(4))));
	}
	mcons(&y, SETG("sp", VARL("_tmp")));
	ut8 r1 = xiii_sub_r1(ctx->x);
	if (r1) {
		mcons(&y, JMP(VARG(GR_get(r1))))
	}
	return y;
}

static RzAnalysisLiftedILOp lift_mov(const V850AnalysisContext *ctx) {
	switch (V850_FORMAT) {
	case I_reg_reg: return SETG(R2, R1V);
	case II_imm_reg: return SETG(R2, SEXT5);
	case VI_3operand: return SETG(R1, U32(ctx->x->imm));
	default: rz_warn_if_reached(); return NULL;
	}
}

static RzAnalysisLiftedILOp lift_cond_op(const V850AnalysisContext *ctx, RzILOpPure *a, RzILOpPure *b, RzILOpPure *b1, F_OP2 op) {
	RzILOpPure *_b = VARL("_b");
	return SEQ4(
		SETL("_b", ITE(condition_table(xi_cond(ctx->x)), b1, b)),
		SETL("result", ADD(a, _b)),
		flags_update(ctx, a, _b),
		SETG(R3, VARL("result")));
}

static RzAnalysisLiftedILOp lift_bins(const V850AnalysisContext *ctx) {
	ut8 width_add_pos = bins_msb(ctx->x) + 1;
	ut8 pos = bins_pos(ctx->x);
	ut8 width = width_add_pos - pos;
	return SEQ3(
		SETL("result",
			LOGOR(EXTRACT32(R2V, U32(width_add_pos), U32(32 - width_add_pos)),
				LOGOR(EXTRACT32(R1V, U32(0), U32(width)), EXTRACT32(R2V, U32(0), U32(pos))))),
		flags_update(ctx, NULL, NULL),
		SETG(R2, VARL("result")));
}

static RzILOpPure *slice32(RzILOpPure *x, unsigned l, unsigned r) {
	return EXTRACT32(x, U32(l), U32(r + 1 - l));
}
static RzILOpPure *slice32x(RzILOpPure *x, unsigned l, unsigned r) {
	return UNSIGNED(r + 1 - l, EXTRACT32(x, U32(l), U32(r + 1 - l)));
}

static RzAnalysisLiftedILOp lift_bsh(const V850AnalysisContext *ctx) {
	return SEQ3(
		SETL("result",
			APPEND(
				APPEND(slice32x(R2V, 16, 23), slice32x(R2V, 24, 31)),
				APPEND(slice32x(R2V, 0, 7), slice32x(R2V, 8, 15)))),
		flags_update(ctx, NULL, NULL),
		SETG(R3, VARL("result")));
}

static RzAnalysisLiftedILOp lift_bsw(const V850AnalysisContext *ctx) {
	return SEQ3(
		SETL("result",
			APPEND(
				APPEND(slice32x(R2V, 0, 7), slice32x(R2V, 8, 15)),
				APPEND(slice32x(R2V, 16, 23), slice32x(R2V, 24, 31)))),
		flags_update(ctx, NULL, NULL),
		SETG(R3, VARL("result")));
}

static RzAnalysisLiftedILOp lift_callt(const V850AnalysisContext *ctx) {
	return SEQ4(
		SETG("CTPC", ADD(PC, U32(2))),
		SETGp("CTPSW", 0, 4, EXTRACT32(VARG("PSW"), U32(0), U32(5))),
		SETL("_adr", ADD(VARG("CTBP"), U32(ctx->x->imm))),
		JMP(ADD(VARG("CTBP"), UNSIGNED(32, LOADW(16, VARL("_adr"))))));
}

static RzAnalysisLiftedILOp lift_caxi(const V850AnalysisContext *ctx) {
	RzILOpPure *a = R2V;
	RzILOpPure *b = VARL("_token");
	return SEQ6(
		SETL("_adr", R1V),
		SETL("_token", LOADW(32, VARL("_adr"))),
		SETL("result", SUB(a, b)),
		flags_update(ctx, a, b),
		STOREW(VARL("_adr"), ITE(IS_ZERO(VARL("result")), R3V, VARL("_token"))),
		SETG(R3, VARL("_token")));
}

static RzAnalysisLiftedILOp lift_ldl_w(const V850AnalysisContext *ctx) {
	return SEQ2(
		SETL("_adr", R1V),
		SETG(R3, LOADW(32, VARL("_adr")))
		// TODO: LLbit
	);
}

static RzAnalysisLiftedILOp lift_stc_w(const V850AnalysisContext *ctx) {
	return SEQ3(
		SETL("_adr", R1V),
		SETL("_data", R3V),
		STOREW(VARL("_adr"), VARL("_data"))
		// TODO: LLbit
	);
}

static RzAnalysisLiftedILOp lift_popsp(const V850AnalysisContext *ctx) {
	ut8 cur = xi_rt(ctx->x);
	ut8 end = xi_rh(ctx->x);
	if (cur >= end) {
		RzAnalysisLiftedILOp expr = SETL("_tmp", VARG("sp"));
		while (cur >= end) {
			mcons(&expr, SETL("_adr", VARL("_tmp")));
			mcons(&expr, SETG(GR_get(cur), LOADW(32, VARL("_adr"))));
			--cur;
			mcons(&expr, SETL("_tmp", ADD(VARL("_tmp"), U32(4))));
		}
		mcons(&expr, SETG("sp", VARL("_tmp")));
		return expr;
	} else {
		return NOP();
	}
}

static RzAnalysisLiftedILOp lift_pushsp(const V850AnalysisContext *ctx) {
	ut8 cur = xi_rt(ctx->x);
	ut8 end = xi_rh(ctx->x);
	if (cur <= end) {
		RzAnalysisLiftedILOp expr = SETL("_tmp", VARG("sp"));
		while (cur <= end) {
			mcons(&expr, SETL("_tmp", ADD(VARL("_tmp"), U32(4))));
			mcons(&expr, SETL("_adr", VARL("_tmp")));
			mcons(&expr, STOREW(VARL("_adr"), VARG(GR_get(cur))));
			++cur;
		}
		mcons(&expr, SETG("sp", VARL("_tmp")));
		return expr;
	} else {
		return NOP();
	}
}

static RzAnalysisLiftedILOp lift_sch(const V850AnalysisContext *ctx) {
	RzILOpPure *cnd = NULL;
	F_OP2 shift = NULL;
	switch (ctx->x->id) {
	case V850_SCH0L:
		cnd = INV(MSB(VARL("_tmp")));
		shift = shl0;
		break;
	case V850_SCH0R:
		cnd = INV(LSB(VARL("_tmp")));
		shift = shr0;
		break;
	case V850_SCH1L:
		cnd = MSB(VARL("_tmp"));
		shift = shl0;
		break;
	case V850_SCH1R:
		cnd = LSB(VARL("_tmp"));
		shift = shr0;
		break;
	default: rz_warn_if_reached(); return NULL;
	}

	RzAnalysisLiftedILOp expr = SEQ3(
		SETL("_i", U32(0)),
		SETL("_tmp", R2V),
		REPEAT(AND(cnd, ULT(VARL("_i"), U32(32))),
			SEQ2(
				SETL("_i", ADD(VARL("_i"), U32(1))),
				SETL("_tmp", shift(VARL("_tmp"), U32(1))))));
	mcons(&expr, SETG(R3, ITE(EQ(VARL("_i"), U32(32)), U32(0), ADD(VARL("_i"), U32(1)))));
	mcons(&expr,
		SETGbs("PSW", 4,
			"CY", EQ(VARL("_i"), U32(31)),
			"OV", IL_FALSE,
			"S", IL_FALSE,
			"Z", EQ(VARL("_i"), U32(32))));
	return expr;
}

#define SCCFG_SIZE LOGAND(VARG("SCCFG"), U32(0xff))

static RzAnalysisLiftedILOp lift_syscall(const V850AnalysisContext *ctx) {
	return SEQ6(
		SETG("EIPC", ADD(PC, U32(4))),
		SETG("EIPSW", VARG("PSW")),
		SETG("EIIC", U32(0x8000 + x_vector8(ctx->x))),
		SETGbs("PSW", 3,
			"UM", IL_FALSE,
			"EP", IL_TRUE,
			"ID", IL_TRUE),
		SETL("_adr",
			ITE(ULE(U32(x_vector8(ctx->x)), SCCFG_SIZE),
				ADD(VARG("SCBP"), SHIFTL0(U32(x_vector8(ctx->x)), U32(2))), VARG("SCBP"))),
		JMP(ADD(VARG("SCBP"), LOADW(32, VARL("_adr")))));
}

static RzAnalysisLiftedILOp lift_loop(const V850AnalysisContext *ctx) {
	RzILOpPure *a = R1V;
	RzILOpPure *b = U32(1);
	return SEQ4(
		SETL("result", SUB(a, b)),
		flags_update(ctx, a, b),
		SETG(R1, VARL("result")),
		BRANCH(NON_ZERO(VARL("result")),
			JMP(SUB(PC, U32(ctx->x->disp))),
			NOP()));
}

#define companion_I_II(a, b) \
	if (V850_FORMAT == I_reg_reg) \
		return a; \
	else if (V850_FORMAT == II_imm_reg) \
		return b; \
	else \
		rz_warn_if_reached(); \
	return NULL;

#define companion_IX_II_XI(a, b, c) \
	if (V850_FORMAT == IX_extended1) \
		return a; \
	else if (V850_FORMAT == II_imm_reg) \
		return b; \
	else if (V850_FORMAT == XI_extended3) \
		return c; \
	else \
		rz_warn_if_reached(); \
	return NULL;

RzAnalysisLiftedILOp v850_il_op(const V850AnalysisContext *ctx) {
	switch (ctx->x->id) {
	case V850_MOV: return lift_mov(ctx);
	case V850_MOVEA: return SETG(R2, ADD(R1V, SEXT16));
	case V850_MOVHI: return SETG(R2, ADD(R1V, U32((ut32)(I16) << 16)));
	case V850_SSTB:
	case V850_SSTH:
	case V850_SSTW:
	case V850_STB:
	case V850_STH:
	case V850_STW:
	case V850_STDW: return lift_st(ctx);
	case V850_SLDB:
	case V850_SLDH:
	case V850_SLDW:
	case V850_LDB:
	case V850_LDBU:
	case V850_LDH:
	case V850_LDHU:
	case V850_LDW:
	case V850_LDDW:
		return lift_ld(ctx);
	case V850_LDLW: return lift_ldl_w(ctx);
	case V850_STCW: return lift_stc_w(ctx);
	case V850_NOT: return lift_op1(ctx, R1V, rz_il_op_new_log_not);
	case V850_DIVH:
		FV(I_reg_reg, lift_op2(ctx, R2V, isext32(LH(R1V), U32(16)), rz_il_op_new_div));
		FV(XI_extended3,
			SEQ2(lift_op2(ctx, R2V, isext32(LH(R1V), U32(16)), rz_il_op_new_div),
				SETG(R3, MOD(R2V, isext32(LH(R1V), U32(16))))));
		break;
	case V850_DIVHU:
		FV(XI_extended3,
			SEQ2(lift_op2(ctx, R2V, LH(R1V), rz_il_op_new_div),
				SETG(R3, MOD(R2V, LH(R1V)))));
		break;
	case V850_DIVQ:
	case V850_DIVQU:
	case V850_DIV:
	case V850_DIVU:
		FV(XI_extended3,
			SEQ2(lift_op2(ctx, R2V, R1V, rz_il_op_new_div),
				SETG(R3, MOD(R2V, R1V))));
		break;
	case V850_JMP:
		FV(I_reg_reg, JMP(R1V));
		FV(VI_3operand, JMP(ADD(R1V, JUMP_DISP)));
		break;
	case V850_JARL: return lift_jarl(ctx);
	case V850_JR: return JMP(S32(PC_ + JUMP_DISP_));
	case V850_OR: return lift_op2(ctx, R2V, R1V, rz_il_op_new_log_or);
	case V850_ORI: return lift_op2(ctx, ZEXT16, R1V, rz_il_op_new_log_or);
	case V850_MULH: companion_I_II(
		SETG(R2, MUL(LH(R2V), LH(R1V))),
		SETG(R2, MUL(LH(R2V), LH(IMM_V))));
	case V850_MULHI: return SETG(R2, MUL(LH(R1V), U32(I16)));
	case V850_MULU:
		FV(XI_extended3,
			SEQ3(
				SETL("_v", MUL(UNSIGNED(64, R2V), UNSIGNED(64, R1V))),
				SETG(R2, UNSIGNED(32, VARL("_v"))),
				SETG(R3, UNSIGNED(32, shr0(VARL("_v"), U32(32))))));
		FV(XII_extended4,
			SEQ3(
				SETL("_v", MUL(UNSIGNED(64, R2V), UNSIGNED(64, IMM_V))),
				SETG(R2, UNSIGNED(32, VARL("_v"))),
				SETG(R3, UNSIGNED(32, shr0(VARL("_v"), U32(32))))));
		break;
	case V850_MAC:
	case V850_MACU: return SEQ3(
		SETL("result", ADD(MUL(UNSIGNED(64, R2V), UNSIGNED(64, R1V)), APPEND(VARG(GR_get(xi_reg3(ctx->x) + 1)), R3V))),
		SETG(GR_get(xi_reg4(ctx->x)), UNSIGNED(32, VARL("result"))),
		SETG(GR_get(xi_reg4(ctx->x) + 1), UNSIGNED(32, SHIFTR0(VARL("result"), U32(32)))));
	case V850_XOR: return lift_op2(ctx, R2V, R1V, rz_il_op_new_log_xor);
	case V850_XORI: return lift_op2(ctx, R1V, ZEXT16, rz_il_op_new_log_xor);
	case V850_AND: companion_I_II(
		lift_op2(ctx, R2V, R1V, rz_il_op_new_log_and),
		lift_op2(ctx, R2V, IMM_V, rz_il_op_new_log_and));
	case V850_ANDI: return lift_op2(ctx, R1V, ZEXT16, rz_il_op_new_log_and);
	case V850_CMP: companion_I_II(
		lift_cmp(ctx, R2V, R1V, rz_il_op_new_sub),
		lift_cmp(ctx, R2V, IMM_V, rz_il_op_new_sub));
	case V850_CALLT: return lift_callt(ctx);
	case V850_CAXI: return lift_caxi(ctx);
	case V850_CLL: return NOP(); // TODO: LLbit atomic manipulation link
	case V850_CMOV:
		FV(XI_extended3, SETG(R3, ITE(condition_table(xi_cond(ctx->x)), R1V, R2V)));
		FV(XII_extended4, SETG(R3, ITE(condition_table(xi_cond(ctx->x)), SEXT5, R2V)));
		break;
	case V850_CTRET:
		FV(X_extended2, SEQ2(SETGp("PSW", 0, 4, slice32(VARG("CTPSW"), 0, 4)), JMP(VARG("CTPC"))));
		break;
	case V850_TST: return lift_tst(ctx);
	case V850_SUB: return lift_op2(ctx, R2V, R1V, rz_il_op_new_sub);
	case V850_SUBR: return lift_op2(ctx, R1V, R2V, rz_il_op_new_sub);
	case V850_SATADD: companion_I_II(
		lift_satop2(ctx, R2V, R1V, rz_il_op_new_add),
		lift_satop2(ctx, R2V, IMM_V, rz_il_op_new_add));
	case V850_SATSUB:
		FV(I_reg_reg, lift_satop2(ctx, R2V, R1V, rz_il_op_new_sub));
		FV(XI_extended3, lift_satop2_(ctx, R3, R2V, R1V, rz_il_op_new_sub));
		break;
	case V850_SATSUBI: return lift_satop2(ctx, R2V, SEXT16, rz_il_op_new_sub);
	case V850_SATSUBR: return lift_satop2(ctx, R1V, R2V, rz_il_op_new_sub);
	case V850_ADD: companion_I_II(
		lift_op2(ctx, R2V, R1V, rz_il_op_new_add),
		lift_op2(ctx, R2V, IMM_V, rz_il_op_new_add));
	case V850_ADDI: return lift_op2(ctx, R2V, SEXT16, rz_il_op_new_add);
	case V850_ADF: return lift_cond_op(ctx, R1V, R2V, ADD(R2V, U32(1)), rz_il_op_new_add);
	case V850_SBF: return lift_cond_op(ctx, R2V, R1V, ADD(R1V, U32(1)), rz_il_op_new_sub);
	case V850_BCOND: return lift_bcond(ctx);
	case V850_BINS: return lift_bins(ctx);
	case V850_BSH: return lift_bsh(ctx);
	case V850_BSW: return lift_bsw(ctx);
	case V850_CLR1: return lift_bit(ctx, ADD(R1V, SEXT16), 0);
	case V850_SET1: return lift_bit(ctx, ADD(R1V, SEXT16), 1);
	case V850_NOT1: return lift_bit(ctx, ADD(R1V, SEXT16), PSW_Z);
	case V850_TST1: return lift_tst1(ctx);
	case V850_SHL: companion_IX_II_XI(
		lift_op2(ctx, R2V, R1V, shl0),
		lift_op2(ctx, R2V, IMM_V, shl0),
		lift_op2_(ctx, R3, R2V, R1V, shl0));
	case V850_SHR: companion_IX_II_XI(
		lift_op2(ctx, R2V, R1V, shr0),
		lift_op2(ctx, R2V, IMM_V, shr0),
		lift_op2_(ctx, R3, R2V, R1V, shr0));
	case V850_SAR: companion_IX_II_XI(
		lift_op2(ctx, R2V, R1V, rz_il_op_new_shiftr_arith),
		lift_op2(ctx, R2V, IMM_V, rz_il_op_new_shiftr_arith),
		lift_op2_(ctx, R3, R2V, R1V, rz_il_op_new_shiftr_arith));
	case V850_HALT: return NOP();
	case V850_HSH: return SEQ3(SETL("result", R2V), SETG(R3, VARL("result")), flags_update(ctx, NULL, NULL));
	case V850_HSW: return SEQ3(
		SETL("result", APPEND(slice32x(R2V, 0, 15), slice32x(R2V, 16, 31))),
		SETG(R3, VARL("result")), flags_update(ctx, NULL, NULL));
	case V850_SETF: return SETG(R2, ITE(condition_table(EXT_COND), U32((1)), U32(0)));
	case V850_STSR: return SETG(R2, VARG(SR_get(STSR_regID, selID)));
	case V850_SASF: return SETG(R2, LOGOR(SHIFTL0(R2V, U32(1)), ITE(condition_table(get_reg1(ctx->x)), U32(0x1), U32(0))));
	case V850_SCH0L:
	case V850_SCH0R:
	case V850_SCH1L:
	case V850_SCH1R:
		return lift_sch(ctx);
	case V850_SNOOZE:
	case V850_SYNCE:
	case V850_SYNCI:
	case V850_SYNCM:
	case V850_SYNCP:
		return NOP();
	case V850_SWITCH:
		return SEQ2(
			SETL("_adr", ADD(ADD(U32(PC_), U32(2)), SHIFTL0(R1V, U32(1)))),
			JMP(ADD(ADD(U32(PC_), U32(2)), SHIFTL0(isext32(UNSIGNED(32, LOADW(16, VARL("_adr"))), U32(16)), U32(1)))));

	case V850_SXB: return SETG(R1, isext32(R1V, U32(8)));
	case V850_SXH: return SETG(R1, isext32(R1V, U32(16)));
	case V850_ZXB: return SETG(R1, LOGAND(R1V, U32(~0xff)));
	case V850_ZXH: return SETG(R1, LOGAND(R1V, U32(~0xffff)));
	case V850_SYSCALL: return lift_syscall(ctx);

	case V850_LDSR: return SETG(SR_get(LDSR_regID, selID), VARG(R1));
	case V850_TRAP: return lift_trap(ctx);
	case V850_DI: return SETGb("PSW", "ID", IL_TRUE);
	case V850_EI: return SETGb("PSW", "ID", IL_FALSE);
	case V850_EIRET:
		FV(X_extended2, SEQ2(SETG("PSW", VARG("EIPSW")), JMP(VARG("EIPC"))));
		break;
	case V850_FERET:
		FV(X_extended2, SEQ2(SETG("PSW", VARG("FEPSW")), JMP(VARG("FEPC"))));
		break;
	case V850_FETRAP: return lift_trap(ctx);
	case V850_PREPARE: return lift_prepare(ctx);
	case V850_DISPOSE: return lift_dispose(ctx);
	case V850_POPSP: return lift_popsp(ctx);
	case V850_PUSHSP: return lift_pushsp(ctx);
	case V850_RIE: return lift_rie(ctx);
	case V850_ROTL: return lift_rotl(ctx);
	case V850_LOOP: return lift_loop(ctx);
	case V850_ABSF_D:
	case V850_NOP: return NOP();
	default: break;
	}

	return NULL;
}
