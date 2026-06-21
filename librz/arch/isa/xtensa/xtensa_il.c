// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "xtensa.h"

static const char *epc_tbl[] = {
	NULL, "epc1", "epc2", "epc3", "epc4", "epc5", "epc6", "epc7"
};
static const char *eps_tbl[] = {
	NULL, "eps1", "eps2", "eps3", "eps4", "eps5", "eps6", "eps7"
};

#include <rz_il/rz_il_opbuilder_begin.h>

static const char *xAR[] = {
	"a0",
	"a1",
	"a2",
	"a3",
	"a4",
	"a5",
	"a6",
	"a7",
	"a8",
	"a9",
	"a10",
	"a11",
	"a12",
	"a13",
	"a14",
	"a15",
};

static RzILOpPure *x_ARindex(ut8 i) {
	return MUL(U32(4), LOGOR(U32(i & 0x3), SHIFTL0(ADD(VARG("windowbase"), U32((i & 0xc) >> 2)), U32(2))));
}

/**
 * We need to hook VARG and SETG to replace a0-a15 with the actual address according to windowbase and windowstart.
 */
static RzILOpPure *x_varg(const char *name) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(xAR); ++i) {
		if (RZ_STR_EQ(name, xAR[i])) {
			return rz_il_op_new_loadw(1, x_ARindex(i), 32);
		}
	}
	return VARG(name);
}

static RzILOpEffect *x_setg(const char *name, RzILOpPure *x) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(xAR); ++i) {
		if (RZ_STR_EQ(name, xAR[i])) {
			return rz_il_op_new_storew(1, x_ARindex(i), x);
		}
	}
	return SETG(name, x);
}

#undef VARG
#undef SETG
#define VARG x_varg
#define SETG x_setg

#define FORMAT (ctx->insn->detail->xtensa.format)
#define PC     (ctx->insn->address)
#define nextPC (ctx->insn->address + ctx->insn->size)

#define IREG(I)     VARG(REGN(I))
#define IREGi(I, i) VARG(cs_reg_name(ctx->handle, (REGI(I) + i)))
#define IMEM(I)     ADD(VARG(REGNAME(MEM((I))->base)), S32(MEM((I))->disp))
#define IEPC(I)     VARG(epc_tbl[I])
#define IEPS(I)     VARG(eps_tbl[I])

#define ABS(X) ITE(SGT(X, S32(0)), X, NEG(X))
#define V32(X) UNSIGNED(32, (X))
#define V64(X) UNSIGNED(64, (X))

#define B2U32(X) BOOL_TO_BV(X, 32)

typedef RzAnalysisLiftedILOp (*fn_analyze_op_il)(XtensaContext *ctx);
typedef RzILOpPure *(fn_op2)(RzILOpBool * x, RzILOpBool *y);

enum {
	PS_INTLEVEL, /// Interrupt level mask
	PS_EXCM, /// Exception mask
	PS_UM,
	PS_RING,
	PS_OWB, /// Old window base
	PS_CALLINC, /// Call increment
	PS_WOE, /// Window overflow enable
};

enum {
	FCR_RM,
	FCR_EV,
	FCR_EZ,
	FCR_EO,
	FCR_EU,
	FCR_EI,
	FCR_MBZ,
	FCR_IGNORE,
};

enum {
	FSR_I = 1,
	FSR_U = 1 << 1,
	FSR_O = 1 << 2,
	FSR_Z = 1 << 3,
	FSR_V = 1 << 4,
	FSR_MBZ = 1 << 5,
	FSR_IGNORE = 1 << 6,
};

typedef struct {
	ut32 field;
	ut8 offset;
	ut8 width;
} RegField;

typedef struct {
	RegField tbl[64];
	size_t size;
	ut8 width;
} RegFieldTbl;

static const RegFieldTbl ps_field_tbl = {
	.tbl = {
		{ PS_INTLEVEL, 0, 4 },
		{ PS_EXCM, 4, 1 },
		{ PS_UM, 5, 1 },
		{ PS_RING, 6, 2 },
		{ PS_OWB, 8, 4 },
		{ PS_CALLINC, 16, 2 },
		{ PS_WOE, 18, 1 },
	},
	.size = 7,
	.width = 32,
};

static const RegFieldTbl fsr_field_tbl = {
	.tbl = {
		{ FSR_IGNORE, 0, 7 },
		{ FSR_I, 7, 1 },
		{ FSR_U, 8, 1 },
		{ FSR_O, 9, 1 },
		{ FSR_Z, 10, 1 },
		{ FSR_V, 11, 1 },
		{ FSR_MBZ, 12, 20 },
	},
	.size = 7,
	.width = 32,
};

static RzILOpPure *reg_field_set(const RegFieldTbl *tbl, ut32 field, RzILOpPure *orig, RzILOpPure *v) {
	for (size_t i = 0; i < tbl->size; ++i) {
		const RegField *f = tbl->tbl + i;
		if (field == f->field) {
			return tbl->width == 32
				? DEPOSIT32(orig, U32(f->offset), U32(f->width), v)
				: DEPOSIT64(orig, U32(f->offset), U32(f->width), v);
		}
	}
	rz_warn_if_reached();
	return NULL;
}

static RzILOpPure *reg_field_get(const RegFieldTbl *tbl, ut32 field, RzILOpPure *orig) {
	for (size_t i = 0; i < tbl->size; ++i) {
		const RegField *f = tbl->tbl + i;
		if (field == f->field) {
			return tbl->width == 32
				? EXTRACT32(orig, U32(f->offset), U32(f->width))
				: EXTRACT64(orig, U32(f->offset), U32(f->width));
		}
	}
	rz_warn_if_reached();
	return NULL;
}

#define PS_field_set(F, V) SETG("ps", reg_field_set(&ps_field_tbl, (F), VARG("ps"), (V)))
#define PS_field_get(F)    reg_field_get(&ps_field_tbl, (F), VARG("ps"))
#define PS_EXCM_CLEAR      PS_field_set(PS_EXCM, U32(0))

#define FCR_field_set(F, V) SETG("fcr", reg_field_set(&fcr_field_tbl, (F), VARG("fcr"), (V)))
#define FCR_field_get(F)    reg_field_get(&fcr_field_tbl, (F), VARG("fcr"))

#define FSR_field_set(F, V) SETG("fsr", reg_field_set(&fsr_field_tbl, (F), VARG("fsr"), (V)))
#define FSR_field_get(F)    reg_field_get(&fsr_field_tbl, (F), VARG("fsr"))

static RzAnalysisLiftedILOp f_cons_(RzILOpEffect *x, RzILOpEffect *y) {
	if (!(x && x->code == RZ_IL_OP_SEQ)) {
		goto err;
	}
	RzILOpEffect *last = x;
	while (last->op.seq.y && last->op.seq.y->code == RZ_IL_OP_SEQ) {
		last = last->op.seq.y;
	}
	if (last->op.seq.y) {
		RzILOpEffect *seq = RZ_NEW0(RzILOpEffect);
		if (!seq) {
			goto err;
		}
		seq->code = RZ_IL_OP_SEQ;
		seq->op.seq.x = last->op.seq.y;
		seq->op.seq.y = y;
		last->op.seq.y = seq;
	} else {
		last->op.seq.y = y;
	}
	return x;
err:
	rz_warn_if_reached();
	rz_il_op_effect_free(x);
	rz_il_op_effect_free(y);
	return NULL;
}

static RzILOpEffect *FSR_set(ut16 fs, RzILOpPure *v) {
	RzILOpEffect *eff = SEQ2(
		SETL("fsr_v", v),
		NOP());
	if (fs & FSR_V) {
		eff = f_cons_(eff, FSR_field_set(FSR_V, B2U32(FEXCEPT(RZ_FLOAT_E_INVALID_OP, VARL("fsr_v")))));
	}
	if (fs & FSR_I) {
		eff = f_cons_(eff, FSR_field_set(FSR_I, B2U32(FEXCEPT(RZ_FLOAT_E_INEXACT, VARL("fsr_v")))));
	}
	if (fs & FSR_O) {
		eff = f_cons_(eff, FSR_field_set(FSR_O, B2U32(FEXCEPT(RZ_FLOAT_E_OVERFLOW, VARL("fsr_v")))));
	}
	if (fs & FSR_U) {
		eff = f_cons_(eff, FSR_field_set(FSR_U, B2U32(FEXCEPT(RZ_FLOAT_E_UNDERFLOW, VARL("fsr_v")))));
	}
	if (fs & FSR_Z) {
		eff = f_cons_(eff, FSR_field_set(FSR_Z, B2U32(FEXCEPT(RZ_FLOAT_E_DIV_ZERO, VARL("fsr_v")))));
	}
	rz_warn_if_fail(eff);
	return eff;
}

static RzILOpEffect *ARi_set(RzILOpPure *i, RzILOpPure *v) {
	RzILOpEffect *eff03 =
		BRANCH(EQ(DUP(i), U32(3)), SETG("a3", DUP(v)),
			BRANCH(EQ(DUP(i), U32(2)), SETG("a2", DUP(v)),
				BRANCH(EQ(DUP(i), U32(1)), SETG("a1", DUP(v)),
					BRANCH(EQ(DUP(i), U32(0)), SETG("a0", DUP(v)),
						NOP() // Error: Invalid register index
						))));
	RzILOpEffect *eff07 = BRANCH(EQ(DUP(i), U32(7)), SETG("a7", DUP(v)),
		BRANCH(EQ(DUP(i), U32(6)), SETG("a6", DUP(v)),
			BRANCH(EQ(DUP(i), U32(5)), SETG("a5", DUP(v)),
				BRANCH(EQ(DUP(i), U32(4)), SETG("a4", DUP(v)), eff03))));
	RzILOpEffect *eff011 = BRANCH(EQ(DUP(i), U32(11)), SETG("a11", DUP(v)),
		BRANCH(EQ(DUP(i), U32(10)), SETG("a10", DUP(v)),
			BRANCH(EQ(DUP(i), U32(9)), SETG("a9", DUP(v)),
				BRANCH(EQ(DUP(i), U32(8)), SETG("a8", DUP(v)), eff07))));
	return BRANCH(ULT(i, U32(16)),
		BRANCH(EQ(DUP(i), U32(15)), SETG("a15", v),
			BRANCH(EQ(DUP(i), U32(14)), SETG("a14", DUP(v)),
				BRANCH(EQ(DUP(i), U32(13)), SETG("a13", DUP(v)),
					BRANCH(EQ(DUP(i), U32(12)), SETG("a12", DUP(v)),
						eff011)))),
		NOP() // Error: Register index out of range
	);
}

static RzAnalysisLiftedILOp op_abs(XtensaContext *ctx) {
	return SETG(REGN(0), ABS(IREG(1)));
}

static RzAnalysisLiftedILOp op_abs_s(XtensaContext *ctx) {
	return SETG(REGN(0), UNSIGNED(64, F2BV(FABS(FLOATV32(IREG(1))))));
}

static RzAnalysisLiftedILOp op_add(XtensaContext *ctx) {
	return SETG(REGN(0), ADD(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_addi(XtensaContext *ctx) {
	return SETG(REGN(0), ADD(IREG(1), S32(IMM(2))));
}

static RzAnalysisLiftedILOp op_add_s(XtensaContext *ctx) {
	return SEQ3(
		SETL("fres", FADD(RZ_FLOAT_RMODE_RNA, FLOATV32(IREG(1)), FLOATV32(IREG(2)))),
		SETG(REGN(0), UNSIGNED(64, F2BV(VARL("fres")))),
		FSR_set(FSR_V | FSR_O | FSR_I, VARL("fres")));
}

static RzILOpPure *apply2_range2(RzILOpPure *self, fn_op2 fn, RzILOpPure *x, RzILOpPure *y,
	unsigned begin1, unsigned begin2, unsigned length) {
	return DEPOSIT64(
		self,
		U64(begin1), U32(length),
		fn(EXTRACT64(x, U64(begin1), U32(length)), EXTRACT64(y, U64(begin2), U32(length))));
}

static RzILOpPure *f_add_sub127(RzILOpPure *x, RzILOpPure *y) {
	return SUB(ADD(x, y), U64(127));
}

static RzAnalysisLiftedILOp op_addexp_s(XtensaContext *ctx) {
	return SEQ3(
		SETL("FRr", apply2_range2(IREG(0), rz_il_op_new_log_xor, IREG(0), IREG(1), 31, 31, 1)),
		SETL("FRr", apply2_range2(VARL("FRr"), f_add_sub127, IREG(0), IREG(1), 23, 23, 8)),
		SETG(REGN(0), VARL("FRr")));
}

static RzAnalysisLiftedILOp op_addexpm_s(XtensaContext *ctx) {
	return SEQ3(
		SETL("FRr", apply2_range2(IREG(0), rz_il_op_new_log_xor, IREG(0), IREG(1), 31, 22, 1)),
		SETL("FRr", apply2_range2(VARL("FRr"), f_add_sub127, IREG(0), IREG(1), 23, 14, 8)),
		SETG(REGN(0), VARL("FRr")));
}

static RzAnalysisLiftedILOp op_addx2(XtensaContext *ctx) {
	return SETG(REGN(0), ADD(SHIFTL0(IREG(1), U32(1)), IREG(2)));
}

static RzAnalysisLiftedILOp op_addx4(XtensaContext *ctx) {
	return SETG(REGN(0), ADD(SHIFTL0(IREG(1), U32(2)), IREG(2)));
}

static RzAnalysisLiftedILOp op_addx8(XtensaContext *ctx) {
	return SETG(REGN(0), ADD(SHIFTL0(IREG(1), U32(3)), IREG(2)));
}

#if RZ_CHECKS_LEVEL != 0
static uint8_t RRR_s(XtensaContext *ctx) {
	return ctx->insn->bytes[1] & 0xf;
}
#endif

static RzAnalysisLiftedILOp op_binary4(XtensaContext *ctx, fn_op2 f) {
	rz_return_val_if_fail(FORMAT == XTENSA_INSN_FORM_RRR && RRR_s(ctx) % 4 == 0, NULL);
	return SETG(REGN(0), f(f(f(IREGi(1, 0), IREGi(1, 1)), IREGi(1, 2)), IREGi(1, 3)));
}

static RzAnalysisLiftedILOp op_binary8(XtensaContext *ctx, fn_op2 f) {
	rz_return_val_if_fail(FORMAT == XTENSA_INSN_FORM_RRR && RRR_s(ctx) % 8 == 0, NULL);
	RzILOpPure *res03 = f(f(f(IREGi(1, 0), IREGi(1, 1)), IREGi(1, 2)), IREGi(1, 3));
	RzILOpPure *res47 = f(f(f(IREGi(1, 4), IREGi(1, 5)), IREGi(1, 6)), IREGi(1, 7));
	return SETG(REGN(0), f(res03, res47));
}

static RzAnalysisLiftedILOp op_all4(XtensaContext *ctx) {
	return op_binary4(ctx, rz_il_op_new_bool_and);
}

static RzAnalysisLiftedILOp op_all8(XtensaContext *ctx) {
	return op_binary8(ctx, rz_il_op_new_bool_and);
}

static RzAnalysisLiftedILOp op_any4(XtensaContext *ctx) {
	return op_binary4(ctx, rz_il_op_new_bool_or);
}

static RzAnalysisLiftedILOp op_any8(XtensaContext *ctx) {
	return op_binary8(ctx, rz_il_op_new_bool_or);
}

static RzAnalysisLiftedILOp op_and(XtensaContext *ctx) {
	return SETG(REGN(0), LOGAND(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_andb(XtensaContext *ctx) {
	return SETG(REGN(0), AND(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_andbc(XtensaContext *ctx) {
	return SETG(REGN(0), AND(IREG(1), INV(IREG(2))));
}

static RzAnalysisLiftedILOp op_ball(XtensaContext *ctx) {
	return BRANCH(
		IS_ZERO(LOGAND(LOGNOT(IREG(0)), IREG(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bnall(XtensaContext *ctx) {
	return BRANCH(
		NON_ZERO(LOGAND(LOGNOT(IREG(0)), IREG(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bany(XtensaContext *ctx) {
	return BRANCH(
		NON_ZERO(LOGAND(IREG(0), IREG(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bnone(XtensaContext *ctx) {
	return BRANCH(
		IS_ZERO(LOGAND(IREG(0), IREG(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzILOpPure *msbFirst_n(XtensaContext *ctx, unsigned n) {
	bool big_endian = (ctx->mode & CS_MODE_BIG_ENDIAN) == CS_MODE_BIG_ENDIAN;
	return big_endian ? U32((1 << n) - 1) : U32(0);
}

#define msbFirst(n) msbFirst_n(ctx, n)

static RzAnalysisLiftedILOp op_bbc(XtensaContext *ctx) {
	return SEQ2(
		SETL("b", LOGXOR(EXTRACT32(IREG(1), U32(0), U32(5)), msbFirst(5))),
		BRANCH(
			IS_ZERO(EXTRACT32(IREG(0), VARL("b"), U32(1))),
			JMP(U32(PC + IMM(2))),
			NOP()));
}

static RzAnalysisLiftedILOp op_bbs(XtensaContext *ctx) {
	return SEQ2(
		SETL("b", LOGXOR(EXTRACT32(IREG(1), U32(0), U32(5)), msbFirst(5))),
		BRANCH(
			NON_ZERO(EXTRACT32(IREG(0), VARL("b"), U32(1))),
			JMP(U32(PC + IMM(2))),
			NOP()));
}

static RzAnalysisLiftedILOp op_bbci(XtensaContext *ctx) {
	return SEQ2(
		SETL("b", LOGXOR(U32(IMM(1)), msbFirst(5))),
		BRANCH(
			IS_ZERO(EXTRACT32(IREG(0), VARL("b"), U32(1))),
			JMP(U32(PC + IMM(2))),
			NOP()));
}

static RzAnalysisLiftedILOp op_bbsi(XtensaContext *ctx) {
	return SEQ2(
		SETL("b", LOGXOR(U32(IMM(1)), msbFirst(5))),
		BRANCH(
			NON_ZERO(EXTRACT32(IREG(0), VARL("b"), U32(1))),
			JMP(U32(PC + IMM(2))),
			NOP()));
}

static RzAnalysisLiftedILOp op_beq(XtensaContext *ctx) {
	return BRANCH(
		EQ(IREG(0), IREG(1)),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bne(XtensaContext *ctx) {
	return BRANCH(
		NE(IREG(0), IREG(1)),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_beqi(XtensaContext *ctx) {
	return BRANCH(
		EQ(IREG(0), U32(IMM(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bnei(XtensaContext *ctx) {
	return BRANCH(
		NE(IREG(0), U32(IMM(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_beqz(XtensaContext *ctx) {
	return BRANCH(
		EQ(IREG(0), U32(0)),
		JMP(U32(PC + IMM(1))),
		NOP());
}

static RzAnalysisLiftedILOp op_bnez(XtensaContext *ctx) {
	return BRANCH(
		NE(IREG(0), U32(0)),
		JMP(U32(PC + IMM(1))),
		NOP());
}

static RzAnalysisLiftedILOp op_bf(XtensaContext *ctx) {
	return BRANCH(
		IREG(0),
		JMP(U32(PC + IMM(1))),
		NOP());
}

static RzAnalysisLiftedILOp op_bt(XtensaContext *ctx) {
	return BRANCH(
		INV(IREG(0)),
		JMP(U32(PC + IMM(1))),
		NOP());
}

static RzAnalysisLiftedILOp op_bge(XtensaContext *ctx) {
	return BRANCH(
		SGE(IREG(0), IREG(1)),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_blt(XtensaContext *ctx) {
	return BRANCH(
		SLT(IREG(0), IREG(1)),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bgei(XtensaContext *ctx) {
	return BRANCH(
		SGE(IREG(0), S32(IMM(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_blti(XtensaContext *ctx) {
	return BRANCH(
		SLT(IREG(0), S32(IMM(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bgeu(XtensaContext *ctx) {
	return BRANCH(
		UGE(IREG(0), IREG(1)),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bltu(XtensaContext *ctx) {
	return BRANCH(
		ULT(IREG(0), IREG(1)),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bgeui(XtensaContext *ctx) {
	return BRANCH(
		UGE(IREG(0), S32(IMM(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bltui(XtensaContext *ctx) {
	return BRANCH(
		ULT(IREG(0), S32(IMM(1))),
		JMP(U32(PC + IMM(2))),
		NOP());
}

static RzAnalysisLiftedILOp op_bgez(XtensaContext *ctx) {
	return BRANCH(
		SGE(IREG(0), S32(0)),
		JMP(U32(PC + IMM(1))),
		NOP());
}

static RzAnalysisLiftedILOp op_bltz(XtensaContext *ctx) {
	return BRANCH(
		SLT(IREG(0), S32(0)),
		JMP(U32(PC + IMM(1))),
		NOP());
}

/**
 *
 * procedure WindowCheck (wr, ws, wt)
 *   n ← if (wr ≠ 2'b00 or ws ≠ 2'b00 or wt ≠ 2'b00)
 *          and WindowStartWindowBase+1 then 2’b01
 *       else if (wr1 or ws1 or wt1)
 *               and WindowStartWindowBase+2 then 2’b10
 *       else if (wr = 2'b11 or ws = 2'b11 or wt = 2'b11)
 *               and WindowStartWindowBase+3 then 2’b11
 *     else 2’b00
 *   if CWOE = 1 and n ≠ 2’b00 then
 *     PS.OWB ← WindowBase
 *     m ← WindowBase + (2'b00ǁn)
 *     PS.EXCM ← 1
 *     EPC[1] ← PC
 *     nextPC ← if WindowStartm+1 then WindowOverflow4
 *       else if WindowStartm+2 then WindowOverflow8
 *       else WindowOverflow12
 *    WindowBase ← m
 *   endif
 * endprocedure WindowCheck
 */
static RzILOpEffect *WindowCheck(XtensaContext *ctx, RzILOpPure *wr, RzILOpPure *ws, RzILOpPure *wt) {
	return SEQ3(
		SETL("cwoe", ITE(NON_ZERO(PS_field_get(PS_EXCM)), U32(0), PS_field_get(PS_WOE))),
		SETL("n",
			ITE(AND(OR(NON_ZERO(wr), OR(NON_ZERO(ws), NON_ZERO(wt))),
				    NON_ZERO(EXTRACT32(VARG("windowstart"), ADD(VARG("windowbase"), U32(1)), U32(1)))),
				U32(1),
				ITE(AND(OR(NON_ZERO(DUP(wr)), OR(NON_ZERO(DUP(ws)), NON_ZERO(DUP(wt)))),
					    NON_ZERO(EXTRACT32(VARG("windowstart"), ADD(VARG("windowbase"), U32(2)), U32(1)))),
					U32(2),
					ITE(AND(OR(EQ(DUP(wr), U32(3)), OR(EQ(DUP(ws), U32(3)), EQ(DUP(wt), U32(3)))),
						    NON_ZERO(EXTRACT32(VARG("windowstart"), ADD(VARG("windowbase"), U32(3)), U32(1)))),
						U32(3),
						U32(0))))),
		BRANCH(
			AND(EQ(VARL("cwoe"), U32(1)), NE(VARL("n"), U32(0))),
			SEQ6(
				PS_field_set(PS_OWB, VARG("windowbase")),
				SETL("m", ADD(VARG("windowbase"), VARL("n"))),
				PS_field_set(PS_EXCM, U32(1)),
				SETG("epc1", U32(PC)),
				SETG("windowbase", VARL("m")),
				SETL("nextPC", ITE(EQ(VARG("windowstart"), U32(0)), U32(1), ITE(EQ(VARG("windowstart"), U32(1)), U32(2), U32(3))))),
			NOP()));
}

static RzAnalysisLiftedILOp op_break(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_call0(XtensaContext *ctx) {
	return SEQ2(
		SETG("a0", U32(nextPC)),
		JMP(U32((PC + IMM(0)) & ~0x3)));
}

static RzAnalysisLiftedILOp op_call4(XtensaContext *ctx) {
	return SEQ4(
		WindowCheck(ctx, U32(0), U32(0), U32(1)),
		PS_field_set(PS_CALLINC, U32(1)),
		SETG("a4", U32(0x40000000 | (nextPC & 0x3fffffff))),
		JMP(U32((PC + IMM(0)) & ~0x3)));
}

static RzAnalysisLiftedILOp op_call8(XtensaContext *ctx) {
	return SEQ4(
		WindowCheck(ctx, U32(0), U32(0), U32(2)),
		PS_field_set(PS_CALLINC, U32(2)),
		SETG("a8", U32(0x80000000 | (nextPC & 0x3fffffff))),
		JMP(U32((PC + IMM(0)) & ~0x3)));
}

static RzAnalysisLiftedILOp op_call12(XtensaContext *ctx) {
	return SEQ4(
		WindowCheck(ctx, U32(0), U32(0), U32(3)),
		PS_field_set(PS_CALLINC, U32(3)),
		SETG("a12", U32(0xc0000000 | (nextPC & 0x3fffffff))),
		JMP(U32((PC + IMM(0)) & ~0x3)));
}

static RzAnalysisLiftedILOp op_callx0(XtensaContext *ctx) {
	return SEQ3(
		SETL("next", IREG(0)),
		SETG("a0", U32(nextPC)),
		JMP(VARL("next")));
}

static RzAnalysisLiftedILOp op_callx4(XtensaContext *ctx) {
	return SEQ5(
		WindowCheck(ctx, U32(0), U32(0), U32(1)),
		PS_field_set(PS_CALLINC, U32(1)),
		SETL("next", IREG(0)),
		SETG("a4", U32(0x1 << 29 | (nextPC & 0x3fffffff))),
		JMP(VARL("next")));
}

static RzAnalysisLiftedILOp op_callx8(XtensaContext *ctx) {
	return SEQ5(
		WindowCheck(ctx, U32(0), U32(0), U32(2)),
		PS_field_set(PS_CALLINC, U32(2)),
		SETL("next", IREG(0)),
		SETG("a8", U32(0x2 << 29 | (nextPC & 0x3fffffff))),
		JMP(VARL("next")));
}

static RzAnalysisLiftedILOp op_callx12(XtensaContext *ctx) {
	return SEQ5(
		WindowCheck(ctx, U32(0), U32(0), U32(3)),
		PS_field_set(PS_CALLINC, U32(3)),
		SETL("next", IREG(0)),
		SETG("a12", U32(0x3 << 29 | (nextPC & 0x3fffffff))),
		JMP(VARL("next")));
}

static RzAnalysisLiftedILOp op_ceil_s(XtensaContext *ctx) {
	return SEQ3(
		SETL("fres", FMUL(RZ_FLOAT_RMODE_RNA, FLOATV32(IREG(1)), F32(powf(2, IMM(2))))),
		SETG(REGN(0), F2INT(32, RZ_FLOAT_RMODE_RNA, VARL("fres"))),
		FSR_set(FSR_V | FSR_I, VARL("fres")));
}

static RzAnalysisLiftedILOp op_clamps(XtensaContext *ctx) {
	unsigned t = IMM(2);
	return SEQ4(
		SETL("low", F32(pow(-2, t))),
		SETL("high", F32(pow(2, t) - 1)),
		SETL("x", FLOATV32(IREG(1))),
		SETG(REGN(0), F2BV(ITE(FGT(VARL("x"), VARL("high")), VARL("high"), ITE(FLT(VARL("x"), VARL("low")), VARL("low"), VARL("x"))))));
}

static const double const_s_tbl[16] = {
	.0,
	1.,
	2.,
	.5,
	0,
};

static RzAnalysisLiftedILOp op_const_s(XtensaContext *ctx) {
	return SETG(REGN(0), UNSIGNED(64, F2BV(F32(const_s_tbl[IMM(1)]))));
}

/**
 * /see p114 https://www.cadence.com/content/dam/cadence-www/global/en_US/documents/tools/silicon-solutions/compute-ip/isa-summary.pdf
 * /brief All single-precision and double-precision divide and reciprocal sequences start with the
 * following table lookup approximation:
 *
 * The row in the table is determined by the first three mantissa bits after the hidden bit in the
 * divisor. If the divisor is a denormal, then it is normalized and the row in the table is
 * determined by the first three mantissa bits after the ’1’ at the beginning. Which entry in the
 * row is determined by the next four mantissa bits. The decimal number in the table is
 * converted to an 8-bit value, which determines the first eight bits of the first reciprocal
 * approximation, including the hidden bit. This process results in a worst case relative error of
 * 2**-7.485. The values in the table cover the range for a single exponent starting at just over a
 * power of two and going up to just under the next power of two.
 */
// static const ut8 divide_seq[] = {
//	255, 253, 251, 249, 247, 245, 244, 242, 240, 238, 237, 235, 233, 232, 230, 228,
//	227, 225, 224, 222, 221, 219, 218, 216, 215, 213, 212, 211, 209, 208, 207, 205,
//	204, 203, 202, 200, 199, 198, 197, 196, 194, 193, 192, 191, 190, 189, 188, 187,
//	186, 185, 184, 183, 182, 181, 180, 179, 178, 177, 176, 175, 174, 173, 172, 171,
//	170, 169, 168, 168, 167, 166, 165, 164, 163, 163, 162, 161, 160, 159, 159, 158,
//	157, 156, 156, 155, 154, 153, 153, 152, 151, 151, 150, 149, 149, 148, 147, 147,
//	146, 145, 145, 144, 143, 143, 142, 142, 141, 140, 140, 139, 139, 138, 137, 137,
//	136, 136, 135, 135, 134, 133, 133, 132, 132, 131, 131, 130, 130, 129, 129, 129
// };
// FIXME: maybe wrong
static RzAnalysisLiftedILOp op_div0_s(XtensaContext *ctx) {
	return SETG(REGN(0), UNSIGNED(64, F2BV(FDIV(RZ_FLOAT_RMODE_RNA, FLOATV32(IREG(0)), FLOATV32(IREG(1))))));
}

// statusflags: OUI
static RzAnalysisLiftedILOp op_divn_s(XtensaContext *ctx) {
	return SEQ6(
		SETL("fr", FLOATV32(IREG(0))),
		SETL("fs", FLOATV32(IREG(1))),
		SETL("ft", FLOATV32(IREG(2))),
		SETL("fres", FADD(RZ_FLOAT_RMODE_RNA, VARL("fr"), FMUL(RZ_FLOAT_RMODE_RNA, VARL("fs"), FNEG(VARL("ft"))))),
		SETG(REGN(0), UNSIGNED(64, F2BV(VARL("fres")))),
		FSR_set(FSR_O | FSR_U | FSR_I, VARL("fres")));
}

static RzAnalysisLiftedILOp op_dsync(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_entry(XtensaContext *ctx) {
	return SEQ2(
		WindowCheck(ctx, U32(0), PS_field_get(PS_CALLINC), U32(0)),
		BRANCH(OR(UGT(IREG(0), U32(3)), OR(IS_ZERO(PS_field_get(PS_WOE)), EQ(PS_field_get(PS_EXCM), U32(1)))),
			NOP(),
			SEQ3(ARi_set(PS_field_get(PS_CALLINC), SUB(IREG(0), U32(IMM(1)))),
				SETG("windowbase", ADD(VARG("windowbase"), PS_field_get(PS_CALLINC))),
				SETG("windowstart", U32(1)))));
}

static RzAnalysisLiftedILOp op_esync(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_excw(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_extui(XtensaContext *ctx) {
	rz_return_val_if_fail(IMM(3) <= 0xf, NULL);
	ut32 mask = (1 << (IMM(3) + 1)) - 1;
	ut32 sa = IMM(2);
	return SETG(REGN(0),
		LET("at", IREG(1),
			LOGAND(U32(mask), LET("at1", DEPOSIT32(VARLP("at"), U32(31), U32(1), U32(0)), SHIFTR0(VARLP("at1"), U32(sa))))));
}

static RzAnalysisLiftedILOp op_extw(XtensaContext *ctx) {
	return NOP();
}

// statusflags: I
static RzAnalysisLiftedILOp op_float_s(XtensaContext *ctx) {
	return SEQ3(SETL("fres", INT2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNA, DIV(IREG(1), U32(pow(2, -IMM(2)))))),
		SETG(REGN(0), UNSIGNED(64, F2BV(VARL("fres")))),
		FSR_set(FSR_I, VARL("fres")));
}

// statusflags: VI
static RzAnalysisLiftedILOp op_floor_s(XtensaContext *ctx) {
	return SEQ3(
		SETL("fres", FMUL(RZ_FLOAT_RMODE_RNA, FLOATV32(IREG(1)), F32(pow(2, IMM(2))))),
		SETG(REGN(0), F2SINT(32, RZ_FLOAT_RMODE_RNA, VARL("fres"))),
		FSR_set(FSR_V | FSR_I, VARL("fres")));
}

static RzAnalysisLiftedILOp op_isync(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_j(XtensaContext *ctx) {
	return JMP(U32(PC + IMM(0)));
}

static RzAnalysisLiftedILOp op_jx(XtensaContext *ctx) {
	return JMP(IREG(0));
}

static RzAnalysisLiftedILOp op_l8ui(XtensaContext *ctx) {
	return SETG(REGN(0), UNSIGNED(32, LOAD(IMEM(1))));
}

static RzAnalysisLiftedILOp op_l16si(XtensaContext *ctx) {
	return SETG(REGN(0),
		LET("mem16", LOADW(16, IMEM(1)),
			SEXTRACT32(UNSIGNED(32, VARLP("mem16")), U32(0), U32(16))));
}

static RzAnalysisLiftedILOp op_l16ui(XtensaContext *ctx) {
	return SETG(REGN(0),
		LET("mem16", LOADW(16, IMEM(1)),
			UNSIGNED(32, VARLP("mem16"))));
}

// FIXME: ring?
static RzAnalysisLiftedILOp op_l32e(XtensaContext *ctx) {
	return SETG(REGN(0), LOADW(32, ADD(IREG(1), U32(IMM(2)))));
}

static RzAnalysisLiftedILOp op_l32i(XtensaContext *ctx) {
	return SETG(REGN(0), LOADW(32, IMEM(1)));
}

static RzAnalysisLiftedILOp op_l32r(XtensaContext *ctx) {
	return SETG(REGN(0), LOADW(32, U32(L32R(1))));
}

static RzAnalysisLiftedILOp op_lddec(XtensaContext *ctx) {
	return SEQ3(
		SETL("vAddr", SUB(IREG(1), U32(4))),
		SETG(REGN(0), LOADW(32, VARL("vAddr"))),
		SETG(REGN(1), VARL("vAddr")));
}

static RzAnalysisLiftedILOp op_ldinc(XtensaContext *ctx) {
	return SEQ3(
		SETL("vAddr", ADD(IREG(1), U32(4))),
		SETG(REGN(0), LOADW(32, VARL("vAddr"))),
		SETG(REGN(1), VARL("vAddr")));
}

static RzAnalysisLiftedILOp op_loop(XtensaContext *ctx) {
	return SEQ3(
		SETG("lcount", SUB(IREG(0), U32(1))),
		SETG("lbeg", U32(nextPC)),
		SETG("lend", U32(PC + IMM(1))));
}

static RzAnalysisLiftedILOp op_loopgtz(XtensaContext *ctx) {
	return SEQ2(
		op_loop(ctx),
		BRANCH(SLE(IREG(0), S32(0)),
			JMP(U32(PC + IMM(1))), NOP()));
}

static RzAnalysisLiftedILOp op_loopnez(XtensaContext *ctx) {
	return SEQ2(
		op_loop(ctx),
		BRANCH(EQ(IREG(0), S32(0)),
			JMP(U32(PC + IMM(1))), NOP()));
}

static RzAnalysisLiftedILOp op_lsi(XtensaContext *ctx) {
	return SEQ3(
		SETL("vAddr", IMEM(1)),
		SETL("memVal", LOADW(32, VARL("vAddr"))),
		SETG(REGN(0), UNSIGNED(64, VARL("memVal"))));
}

static RzAnalysisLiftedILOp op_lsip(XtensaContext *ctx) {
	return SEQ4(
		SETL("vAddr", IREG(1)),
		SETL("memVal", LOADW(32, VARL("vAddr"))),
		SETG(REGN(0), UNSIGNED(64, VARL("memVal"))),
		SETG(REGN(1), ADD(VARL("vAddr"), U32(IMM(2)))));
}

static RzAnalysisLiftedILOp op_lsx(XtensaContext *ctx) {
	return SEQ3(
		SETL("vAddr", ADD(IREG(1), IREG(2))),
		SETL("memVal", LOADW(32, VARL("vAddr"))),
		SETG(REGN(0), UNSIGNED(64, VARL("memVal"))));
}

static RzAnalysisLiftedILOp op_lsxp(XtensaContext *ctx) {
	return SEQ4(
		SETL("vAddr", IREG(1)),
		SETL("memVal", LOADW(32, VARL("vAddr"))),
		SETG(REGN(0), UNSIGNED(64, VARL("memVal"))),
		SETG(REGN(1), ADD(VARL("vAddr"), IREG(2))));
}

// statusflags: VOUI
static RzAnalysisLiftedILOp op_madd_s(XtensaContext *ctx) {
	return SEQ6(
		SETL("fr", FLOATV32(IREG(0))),
		SETL("fs", FLOATV32(IREG(1))),
		SETL("ft", FLOATV32(IREG(2))),
		SETL("fres", FADD(RZ_FLOAT_RMODE_RNA, VARL("fr"), FMUL(RZ_FLOAT_RMODE_RNA, VARL("fs"), VARL("ft")))),
		FSR_set(FSR_V | FSR_O | FSR_U | FSR_I, VARL("fres")),
		SETG(REGN(0), UNSIGNED(64, F2BV(VARL("fres")))));
}

// statusflags: VOUI
static RzAnalysisLiftedILOp op_msub_s(XtensaContext *ctx) {
	return SEQ6(
		SETL("fr", FLOATV32(IREG(0))),
		SETL("fs", FLOATV32(IREG(1))),
		SETL("ft", FLOATV32(IREG(2))),
		SETL("fres", FSUB(RZ_FLOAT_RMODE_RNA, VARL("fr"), FMUL(RZ_FLOAT_RMODE_RNA, VARL("fs"), VARL("ft")))),
		FSR_set(FSR_V | FSR_O | FSR_U | FSR_I, VARL("fres")),
		SETG(REGN(0), UNSIGNED(64, F2BV(VARL("fres")))));
}

static RzAnalysisLiftedILOp op_max(XtensaContext *ctx) {
	return SETG(REGN(0), ITE(SLT(IREG(1), IREG(2)), IREG(2), IREG(1)));
}

static RzAnalysisLiftedILOp op_maxu(XtensaContext *ctx) {
	return SETG(REGN(0), ITE(ULT(IREG(1), IREG(2)), IREG(2), IREG(1)));
}

static RzAnalysisLiftedILOp op_min(XtensaContext *ctx) {
	return SETG(REGN(0), ITE(SGT(IREG(1), IREG(2)), IREG(2), IREG(1)));
}

static RzAnalysisLiftedILOp op_minu(XtensaContext *ctx) {
	return SETG(REGN(0), ITE(UGT(IREG(1), IREG(2)), IREG(2), IREG(1)));
}

static RzAnalysisLiftedILOp op_memw(XtensaContext *ctx) {
	return NOP();
}

// TODO: float
static RzAnalysisLiftedILOp op_mkdadj_s(XtensaContext *ctx) {
	return NOP();
}

// TODO: float
static RzAnalysisLiftedILOp op_mksadj_s(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_moveqz(XtensaContext *ctx) {
	return BRANCH(
		EQ(IREG(2), U32(0)),
		SETG(REGN(0), IREG(1)),
		NOP());
}

static RzAnalysisLiftedILOp op_movnez(XtensaContext *ctx) {
	return BRANCH(
		NE(IREG(2), U32(0)),
		SETG(REGN(0), IREG(1)),
		NOP());
}

/*
if Windowed Register Option & WindowStartWindowBase-0011..WindowBase-0001 = 03 then
    Exception (AllocaCause)
else
    AR[t] ← AR[s]
endif
*/
static RzAnalysisLiftedILOp op_movsp(XtensaContext *ctx) {
	return BRANCH(
		EQ(EXTRACT32(VARG("windowstart"), SUB(VARG("windowbase"), U32(1)), U32(3)),
			U32(0x03)),
		NOP(),
		SETG(REGN(0), IREG(1)));
}

static RzAnalysisLiftedILOp op_movt(XtensaContext *ctx) {
	return BRANCH(
		IREG(2),
		SETG(REGN(0), IREG(1)),
		NOP());
}

static RzAnalysisLiftedILOp op_movf(XtensaContext *ctx) {
	return BRANCH(
		INV(IREG(2)),
		SETG(REGN(0), IREG(1)),
		NOP());
}

static RzAnalysisLiftedILOp op_movgez(XtensaContext *ctx) {
	return BRANCH(
		SGE(IREG(2), S32(0)),
		SETG(REGN(0), IREG(1)),
		NOP());
}

static RzAnalysisLiftedILOp op_mov(XtensaContext *ctx) {
	return SETG(REGN(0), IREG(1));
}

static RzAnalysisLiftedILOp op_movi(XtensaContext *ctx) {
	return SETG(REGN(0), U32(IMM(1)));
}

static RzAnalysisLiftedILOp op_movltz(XtensaContext *ctx) {
	return BRANCH(
		SLT(IREG(2), S32(0)),
		SETG(REGN(0), IREG(1)),
		NOP());
}

#define LO4(x)  EXTRACT32(x, U32(0), U32(4))
#define HI4(x)  EXTRACT32(x, U32(4), U32(4))
#define LO8(x)  EXTRACT32(x, U32(0), U32(8))
#define HI8(x)  EXTRACT32(x, U32(8), U32(8))
#define LO16(x) EXTRACT32(x, U32(0), U32(16))
#define HI16(x) EXTRACT32(x, U32(16), U32(16))
#define LO32(x) EXTRACT64(x, U32(0), U32(32))
#define HI32(x) EXTRACT64(x, U32(32), U32(32))

static ut8 RRR_half(XtensaContext *ctx) {
	rz_warn_if_fail(FORMAT == XTENSA_INSN_FORM_RRR);
	return ctx->insn->bytes[2] & 0x3;
}

static RzAnalysisLiftedILOp ACC_set(RzILOpPure *v) {
	return SEQ3(
		SETL("acc", v),
		SETG("acclo", UNSIGNED(32, LO32(VARL("acc")))),
		SETG("acchi", UNSIGNED(32, HI32(VARL("acc")))));
}

static RzILOpPure *ACC_val() {
	return APPEND(VARG("acchi"), VARG("acclo"));
}

static RzAnalysisLiftedILOp op_mul_aa(XtensaContext *ctx) {
	ut8 half = RRR_half(ctx);
	return SEQ3(
		SETG("m1", half & 0x1 ? HI16(IREG(0)) : LO16(IREG(0))),
		SETG("m2", half & 0x2 ? HI16(IREG(1)) : LO16(IREG(1))),
		ACC_set(LET("sm1", SEXTRACT64(VARG("m1"), U32(0), U32(16)),
			LET("sm2", SEXTRACT64(VARG("m2"), U32(0), U32(16)),
				MUL(VARLP("sm1"), VARLP("sm2"))))));
}

static RzAnalysisLiftedILOp f_mula__(XtensaContext *ctx, RzILOpPure *r0, RzILOpPure *r1) {
	ut8 half = RRR_half(ctx);
	return SEQ4(
		SETG("m1", half & 0x1 ? HI16(r0) : LO16(DUP(r0))),
		SETG("m2", half & 0x2 ? HI16(r1) : LO16(DUP(r1))),
		SETL("acc", ACC_val()),
		ACC_set(LET("sm1", SEXTRACT64(VARG("m1"), U32(0), U32(16)),
			LET("sm2", SEXTRACT64(VARG("m2"), U32(0), U32(16)),
				ADD(VARL("acc"), MUL(VARLP("sm1"), VARLP("sm2")))))));
}

static RzAnalysisLiftedILOp op_mula_aa(XtensaContext *ctx) {
	return f_mula__(ctx, IREG(0), IREG(1));
}

static RzAnalysisLiftedILOp op_mula_da_lddec(XtensaContext *ctx) {
	return SEQ2(f_mula__(ctx, IREG(2), IREG(3)),
		op_lddec(ctx));
}

static RzAnalysisLiftedILOp op_mula_da_ldinc(XtensaContext *ctx) {
	return SEQ2(f_mula__(ctx, IREG(2), IREG(3)),
		op_ldinc(ctx));
}

// statusflags: VOUI
static RzAnalysisLiftedILOp op_mul_s(XtensaContext *ctx) {
	return SEQ5(
		SETL("frs", FLOATV32(IREG(1))),
		SETL("frt", FLOATV32(IREG(2))),
		SETL("fres", FMUL(RZ_FLOAT_RMODE_RNA, VARL("frs"), VARL("frt"))),
		FSR_set(FSR_V | FSR_O | FSR_U | FSR_I, VARL("fres")),
		SETG(REGN(0), UNSIGNED(64, F2BV(VARL("fres")))));
}

static RzAnalysisLiftedILOp op_mul16s(XtensaContext *ctx) {
	return SEQ3(
		SETL("ars", SEXTRACT32(IREG(1), U32(0), U32(16))),
		SETL("art", SEXTRACT32(IREG(2), U32(0), U32(16))),
		SETG(REGN(0), MUL(VARL("ars"), VARL("art"))));
}

static RzAnalysisLiftedILOp op_mul16u(XtensaContext *ctx) {
	return SEQ3(
		SETL("ars", LO16(IREG(1))),
		SETL("art", LO16(IREG(2))),
		SETG(REGN(0), MUL(VARL("ars"), VARL("art"))));
}

static RzAnalysisLiftedILOp op_mull(XtensaContext *ctx) {
	return SEQ3(
		SETL("ars", UNSIGNED(64, IREG(1))),
		SETL("art", UNSIGNED(64, IREG(2))),
		SETG(REGN(0), UNSIGNED(32, MUL(VARL("ars"), VARL("art")))));
}

static RzAnalysisLiftedILOp f_muls__(XtensaContext *ctx, RzILOpPure *r0, RzILOpPure *r1) {
	ut8 half = RRR_half(ctx);
	return SEQ4(
		SETG("m1", half & 0x1 ? HI16(r0) : LO16(DUP(r0))),
		SETG("m2", half & 0x2 ? HI16(r1) : LO16(DUP(r1))),
		SETL("acc", ACC_val()),
		ACC_set(LET("sm1", SEXTRACT64(VARG("m1"), U32(0), U32(16)),
			LET("sm2", SEXTRACT64(VARG("m2"), U32(0), U32(16)),
				SUB(VARL("acc"), MUL(VARLP("sm1"), VARLP("sm2")))))));
}

static RzAnalysisLiftedILOp op_muls_aa(XtensaContext *ctx) {
	return f_muls__(ctx, IREG(0), IREG(1));
}

static RzAnalysisLiftedILOp op_mulsh(XtensaContext *ctx) {
	return SEQ4(
		SETL("ars", SEXTRACT64(IREG(1), U32(0), U32(32))),
		SETL("art", SEXTRACT64(IREG(2), U32(0), U32(32))),
		SETL("tp", MUL(VARL("ars"), VARL("art"))),
		SETG(REGN(0), UNSIGNED(32, SHIFTR0(VARL("tp"), U32(32)))));
}

static RzAnalysisLiftedILOp op_muluh(XtensaContext *ctx) {
	return SEQ4(
		SETL("ars", UNSIGNED(64, IREG(1))),
		SETL("art", UNSIGNED(64, IREG(2))),
		SETL("tp", MUL(VARL("ars"), VARL("art"))),
		SETG(REGN(0), UNSIGNED(32, SHIFTR0(VARL("tp"), U32(32)))));
}

static RzAnalysisLiftedILOp op_neg(XtensaContext *ctx) {
	return SETG(REGN(0), NEG(IREG(1)));
}

static RzAnalysisLiftedILOp op_neg_s(XtensaContext *ctx) {
	return SETG(REGN(0), UNSIGNED(64, F2BV(FNEG(FLOATV32(IREG(1))))));
}

#define BV2BOOL(N, BV) (ITE(EQ(BV, UN(N, 0)), IL_FALSE, IL_TRUE))

static RzAnalysisLiftedILOp op_nexp01_s(XtensaContext *ctx) {
	return SEQ5(
		SETL("rs", IREG(1)),
		SETL("frs", FLOATV32(VARL("rs"))),
		SETL("frs64", FCONVERT(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNA, VARL("frs"))),
		SETL("rs31", SHIFTL0(BOOL_TO_BV(INV(BV2BOOL(64, EXTRACT64(VARL("rs"), U32(31), U32(1)))), 64), U32(31))),
		SETG(REGN(0),
			ITE(EQ(EXTRACT64(VARL("rs"), U32(23), U32(8)), U64(0xff)),
				LOGOR(EXTRACT64(VARL("rs"), U32(0), U32(23)),
					LOGOR(U64(0x7f << 23),
						VARL("rs31"))),
				ITE(EQ(EXTRACT64(VARL("rs"), U32(0), U32(31)), U64(0)),
					LOGOR(U64(1 << 30), VARL("rs31")),
					// FIXME: LOG2?
					LET("N", FDIV(RZ_FLOAT_RMODE_RNA, FABS(VARL("frs64")), F64(2.)),
						F2BV(FNEG(FDIV(RZ_FLOAT_RMODE_RNA, VARL("frs64"), FPOW(RZ_FLOAT_RMODE_RNA, F64(4.), VARLP("N"))))))))));
}

static RzAnalysisLiftedILOp op_nop(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_nsa(XtensaContext *ctx) {
	RzILOpPure *res01 =
		LET("t1", ITE(VARLP("b2"), LO4(VARLP("t2")), HI4(VARLP("t2"))),
			LET("b1", EQ(VARL("sign"), EXTRACT32(VARLP("t1"), U32(2), U32(2))),
				LET("b0", ITE(VARLP("b1"), EQ(EXTRACT32(VARLP("t1"), U32(0), U32(1)), VARL("sign")), EQ(EXTRACT32(VARLP("t1"), U32(3), U32(1)), VARL("sign"))),
					SUB(LOGOR(
						    SHIFTL0(BOOL_TO_BV(VARLP("b4"), 32), U32(4)),
						    LOGOR(SHIFTL0(BOOL_TO_BV(VARLP("b3"), 32), U32(3)),
							    LOGOR(SHIFTL0(BOOL_TO_BV(VARLP("b2"), 32), U32(2)),
								    LOGOR(SHIFTL0(BOOL_TO_BV(VARLP("b1"), 32), U32(1)),
									    BOOL_TO_BV(VARLP("b0"), 32))))),
						U32(1)))));
	RzILOpPure *res03 =
		ITE(EQ(VARL("sign"), EXTRACT32(VARL("ars"), U32(0), U32(31))), U32(31),
			LET("b4", EQ(VARL("sign"), EXTRACT32(VARL("ars"), U32(16), U32(15))),
				LET("t3", ITE(VARLP("b4"), LO16(VARL("ars")), HI16(VARL("ars"))),
					LET("b3", EQ(VARL("sign"), EXTRACT32(VARLP("t3"), U32(8), U32(8))),
						LET("t2", ITE(VARLP("b3"), LO8(VARLP("t3")), HI8(VARLP("t3"))),
							LET("b2", EQ(VARL("sign"), EXTRACT32(VARLP("t2"), U32(4), U32(4))), res01))))));
	return SEQ3(
		SETL("ars", IREG(1)),
		SETL("sign", EXTRACT32(VARL("ars"), U32(31), U32(1))),
		SETG(REGN(0), res03));
}

static RzAnalysisLiftedILOp op_nsau(XtensaContext *ctx) {
	RzILOpPure *res01 =
		LET("t1", ITE(VARLP("b2"), LO4(VARLP("t2")), HI4(VARLP("t2"))),
			LET("b1", EQ(VARL("sign"), EXTRACT32(VARLP("t1"), U32(2), U32(2))),
				LET("b0", ITE(VARLP("b1"), EQ(EXTRACT32(VARLP("t1"), U32(0), U32(1)), VARL("sign")), EQ(EXTRACT32(VARLP("t1"), U32(3), U32(1)), VARL("sign"))),
					LOGOR(SHIFTL0(BOOL_TO_BV(VARLP("b4"), 32), U32(4)),
						LOGOR(SHIFTL0(BOOL_TO_BV(VARLP("b3"), 32), U32(3)),
							LOGOR(SHIFTL0(BOOL_TO_BV(VARLP("b2"), 32), U32(2)),
								LOGOR(SHIFTL0(BOOL_TO_BV(VARLP("b1"), 32), U32(1)),
									BOOL_TO_BV(VARLP("b0"), 32))))))));
	RzILOpPure *res03 = ITE(EQ(VARL("sign"), VARL("ars")), U32(32),
		LET("b4", EQ(VARL("sign"), EXTRACT32(VARL("ars"), U32(16), U32(16))),
			LET("t3", ITE(VARLP("b4"), LO16(VARL("ars")), HI16(VARL("ars"))),
				LET("b3", EQ(VARL("sign"), EXTRACT32(VARLP("t3"), U32(8), U32(8))),
					LET("t2", ITE(VARLP("b3"), LO8(VARLP("t3")), HI8(VARLP("t3"))),
						LET("b2", EQ(VARL("sign"), EXTRACT32(VARLP("t2"), U32(4), U32(4))),
							res01))))));
	return SEQ3(
		SETL("ars", IREG(1)),
		SETL("sign", U32(0)),
		SETG(REGN(0), res03));
}

static RzAnalysisLiftedILOp f_bool_op2(XtensaContext *ctx, fn_op2 f) {
	return SEQ2(
		SETG(REGN(0), f(FLOATV32(IREG(1)), FLOATV32(IREG(2)))),
		FSR_field_set(FSR_V, B2U32(OR(IS_FNAN(FLOATV32(IREG(1))), IS_FNAN(FLOATV32(IREG(2)))))));
}

// statusflags: V
static RzAnalysisLiftedILOp op_oeq_s(XtensaContext *ctx) {
	return f_bool_op2(ctx, rz_il_op_new_feq);
}

// statusflags: V
static RzAnalysisLiftedILOp op_ole_s(XtensaContext *ctx) {
	return f_bool_op2(ctx, rz_il_op_new_fle);
}

// statusflags: V
static RzAnalysisLiftedILOp op_olt_s(XtensaContext *ctx) {
	return f_bool_op2(ctx, rz_il_op_new_flt);
}

static RzAnalysisLiftedILOp op_or(XtensaContext *ctx) {
	return SETG(REGN(0), LOGOR(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_orb(XtensaContext *ctx) {
	return SETG(REGN(0), OR(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_orbc(XtensaContext *ctx) {
	return SETG(REGN(0), OR(IREG(1), INV(IREG(2))));
}

static RzAnalysisLiftedILOp op_quos(XtensaContext *ctx) {
	return SETG(REGN(0), SDIV(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_quou(XtensaContext *ctx) {
	return SETG(REGN(0), DIV(IREG(1), IREG(2)));
}

// TODO: see Divide and Square Root Sequences
static RzAnalysisLiftedILOp op_recip0_s(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_rems(XtensaContext *ctx) {
	return SETG(REGN(0), SMOD(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_remu(XtensaContext *ctx) {
	return SETG(REGN(0), MOD(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_ret(XtensaContext *ctx) {
	return JMP(VARG("a0"));
}

/*
n ← AR[0]31..30
nextPC ← PC31..30ǁAR[0]29..0
owb ← WindowBase
m ← if WindowStartWindowBase-4’b0001 then 2’b01
    elsif WindowStartWindowBase-4’b0010 then 2’b10
    elsif WindowStartWindowBase-4’b0011 then 2’b11
    else 2’b00
if n=2’b00 | (m≠2’b00 & m≠n) | PS.WOE=0 | PS.EXCM=1 then
    -- undefined operation
    -- may raise illegal instruction exception
else
    if WindowStartWindowBase − (02ǁn) ≠ 0 then
	WindowStartowb ← 0
    else
	-- Underflow exception
	PS.EXCM ← 1
	EPC[1] ← PC
	PS.OWB ← owb
	nextPC ← if n = 2'b01 then WindowUnderflow4
		  else if n = 2'b10 then WindowUnderflow8
		  else WindowUnderflow12
	endif
	WindowBase ← WindowBase − (02ǁn)
	PS.CALLINC ← n -- in some implementations
    endif
*/
static RzAnalysisLiftedILOp op_retw(XtensaContext *ctx) {
	return SEQ5(
		SETL("n", EXTRACT32(VARG("a0"), U32(30), U32(2))),
		SETL("nextPC", LOGOR(U32(PC & (0x3U << 30)), LOGAND(VARG("a0"), U32(0x3fffffff)))),
		SETL("owb", VARG("windowbase")),
		SETL("m",
			ITE(EQ(
				    EXTRACT32(VARG("windowstart"), SUB(VARG("windowbase"), U32(1)), U32(1)),
				    U32(1)),
				U32(1),
				ITE(EQ(EXTRACT32(VARG("windowstart"), SUB(VARG("windowbase"), U32(2)), U32(1)),
					    U32(1)),
					U32(2),
					ITE(EQ(EXTRACT32(VARG("windowstart"), SUB(VARG("windowbase"), U32(3)), U32(1)),
						    U32(1)),
						U32(3),
						U32(0))))),
		BRANCH(OR(AND(NE(VARL("m"), U32(0)), NE(VARL("m"), VARL("n"))),
			       OR(EQ(PS_field_get(PS_WOE), U32(0)),
				       EQ(PS_field_get(PS_EXCM), U32(1)))),
			// Undefined operation, may raise illegal instruction exception
			NOP(),
			SEQ4(
				BRANCH(NE(SUB(VARG("windowstart"), LOGOR(U32(2), VARL("n"))), U32(0)),
					SETG("windowstart", U32(0)),
					SEQ4(
						PS_field_set(PS_EXCM, U32(1)),
						SETG("epc1", U32(PC)),
						PS_field_set(PS_OWB, VARL("owb")),
						SETL("nextPC",
							ITE(EQ(VARL("n"), U32(1)), VARG("windowunderflow4"),
								ITE(EQ(VARL("n"), U32(2)), VARG("windowunderflow8"),
									VARG("windowunderflow12")))))),
				SETG("windowbase", SUB(VARG("windowbase"), LOGOR(U32(2), VARL("n")))),
				PS_field_set(PS_CALLINC, VARL("n")),
				JMP(VARL("nextPC")))));
}

static RzAnalysisLiftedILOp op_rfde(XtensaContext *ctx) {
	return JMP(ITE(VARG("ndepc"), VARG("depc"), IEPC(1)));
}

static RzAnalysisLiftedILOp op_rfe(XtensaContext *ctx) {
	return SEQ2(
		PS_EXCM_CLEAR,
		JMP(IEPC(1)));
}

static RzAnalysisLiftedILOp op_rfi(XtensaContext *ctx) {
	return SEQ2(
		SETG("ps", IEPS(IMM(0))),
		JMP(IEPC(IMM(0))));
}

static RzAnalysisLiftedILOp op_rfr(XtensaContext *ctx) {
	return SETG(REGN(0), UNSIGNED(32, IREG(1)));
}

static RzAnalysisLiftedILOp op_rfwo(XtensaContext *ctx) {
	return SEQ4(
		PS_EXCM_CLEAR,
		SETG("windowstart",
			DEPOSIT32(VARG("windowstart"), VARG("windowbase"), U32(1),
				U32(0))),
		SETG("windowbase", PS_field_get(PS_OWB)),
		JMP(IEPC(1)));
}

static RzAnalysisLiftedILOp op_rfwu(XtensaContext *ctx) {
	return SEQ4(
		PS_EXCM_CLEAR,
		SETG("windowstart",
			DEPOSIT32(VARG("windowstart"), VARG("windowbase"), U32(1),
				U32(1))),
		SETG("windowbase", PS_field_get(PS_OWB)),
		JMP(IEPC(1)));
}

/**
 * Under the Windowed Register Option, ROTW adds a constant to WindowBase, thereby moving
 * the current window into the register file. ROTW is intended for use in exception handlers and
 * context switch code.
 * ROTW is a privileged instruction.
 */
static RzAnalysisLiftedILOp op_rotw(XtensaContext *ctx) {
	// WindowBase ¬ WindowBase + imm4
	return SEQ2(
		SETL("wb", ADD(VARG("windowbase"), U32(IMM(0)))),
		SETG("windowbase", VARL("wb")));
}

// statusflags: VI
static RzAnalysisLiftedILOp op_round_s(XtensaContext *ctx) {
	return SEQ3(SETL("fres", FROUND(RZ_FLOAT_RMODE_RNA, FMUL(RZ_FLOAT_RMODE_RNA, FLOATV32(IREG(1)), F32(pow(2, IMM(2)))))),
		SETG(REGN(0), F2BV(VARL("fres"))),
		FSR_set(FSR_V | FSR_V, VARL("fres")));
}

static RzAnalysisLiftedILOp op_rsil(XtensaContext *ctx) {
	return SEQ2(SETG(REGN(0), VARG("ps")),
		PS_field_set(PS_INTLEVEL, U32(IMM(1))));
}

// FIXME: statusflags: VZI  + reciprocal_square_root_approximation
static RzAnalysisLiftedILOp op_rsqrt0_s(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_rsr(XtensaContext *ctx) {
	return SETG(REGN(0), IREG(1));
}

static RzAnalysisLiftedILOp op_rsync(XtensaContext *ctx) {
	return NOP();
}

#define RUR_IMPL(S) \
	static RzAnalysisLiftedILOp op_rur_##S(XtensaContext *ctx) { \
		return SETG(REGN(0), VARG(#S)); \
	}
#define RUR_AE_IMPL(S) \
	static RzAnalysisLiftedILOp op_rur_ae_##S(XtensaContext *ctx) { \
		return SETG(REGN(0), VARG(#S)); \
	}

RUR_IMPL(accx_0);
RUR_IMPL(accx_1);
RUR_AE_IMPL(bithead);
RUR_AE_IMPL(bitptr);
RUR_AE_IMPL(bitsused);
RUR_AE_IMPL(cbegin0);
RUR_AE_IMPL(cend0);
RUR_AE_IMPL(cwrap);
RUR_AE_IMPL(cw_sd_no);
RUR_AE_IMPL(first_ts);
RUR_AE_IMPL(nextoffset);
RUR_AE_IMPL(overflow);
RUR_AE_IMPL(ovf_sar);
RUR_AE_IMPL(sar);
RUR_AE_IMPL(searchdone);
RUR_AE_IMPL(tablesize);
RUR_AE_IMPL(ts_fts_bu_bp);
RUR_IMPL(fft_bit_width);
RUR_IMPL(gpio_out);
RUR_IMPL(qacc_h_0);
RUR_IMPL(qacc_h_1);
RUR_IMPL(qacc_h_2);
RUR_IMPL(qacc_h_3);
RUR_IMPL(qacc_h_4);
RUR_IMPL(qacc_l_0);
RUR_IMPL(qacc_l_1);
RUR_IMPL(qacc_l_2);
RUR_IMPL(qacc_l_3);
RUR_IMPL(qacc_l_4);
RUR_IMPL(sar_byte);
RUR_IMPL(ua_state_0);
RUR_IMPL(ua_state_1);
RUR_IMPL(ua_state_2);
RUR_IMPL(ua_state_3);

static RzAnalysisLiftedILOp op_s16i(XtensaContext *ctx) {
	return SEQ2(
		SETL("vAddr", IMEM(1)),
		STOREW(VARL("vAddr"), UNSIGNED(16, IREG(0))));
}

static RzAnalysisLiftedILOp op_s32c1i(XtensaContext *ctx) {
	return SEQ4(
		SETL("vAddr", IMEM(1)),
		SETL("mem", LOADW(32, VARL("vAddr"))),
		BRANCH(EQ(VARL("mem"), VARG("scompare1")),
			STOREW(VARL("vAddr"), IREG(0)),
			NOP()),
		SETG(REGN(0), VARL("mem")));
}

// FIXME: ring
static RzAnalysisLiftedILOp op_s32e(XtensaContext *ctx) {
	return SEQ2(
		SETL("vAddr", ADD(IREG(1), S32(IMM(2)))),
		STOREW(VARL("vAddr"), IREG(0)));
}

static RzAnalysisLiftedILOp op_s32i(XtensaContext *ctx) {
	return SEQ2(
		SETL("vAddr", IMEM(1)),
		STOREW(VARL("vAddr"), IREG(0)));
}

static RzAnalysisLiftedILOp op_s8i(XtensaContext *ctx) {
	return SEQ2(
		SETL("vAddr", IMEM(1)),
		STORE(VARL("vAddr"), UNSIGNED(8, IREG(0))));
}

static RzAnalysisLiftedILOp op_sext(XtensaContext *ctx) {
	return SETG(REGN(0), SEXTRACT32(IREG(1), U32(0), U32(IMM(2))));
}

static RzAnalysisLiftedILOp op_simcall(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_sll(XtensaContext *ctx) {
	return SEQ2(
		SETL("sa", EXTRACT32(VARG("sar"), U32(0), U32(5))),
		SETG(REGN(0), SHIFTL0(IREG(1), VARL("sa"))));
}

static RzAnalysisLiftedILOp op_slli(XtensaContext *ctx) {
	return SEQ2(
		SETL("sa", U32(IMM(2))),
		SETG(REGN(0), SHIFTL0(IREG(1), VARL("sa"))));
}

// TODO: see Divide and Square Root Sequences on page 110.
static RzAnalysisLiftedILOp op_sqrt0_s(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_sra(XtensaContext *ctx) {
	return SEQ2(
		SETL("sa", EXTRACT32(VARG("sar"), U32(0), U32(5))),
		SETG(REGN(0), SHIFTRA(IREG(1), VARL("sa"))));
}

static RzAnalysisLiftedILOp op_srai(XtensaContext *ctx) {
	return SEQ2(
		SETL("sa", U32(IMM(2))),
		SETG(REGN(0), SHIFTRA(IREG(1), VARL("sa"))));
}

static RzAnalysisLiftedILOp op_src(XtensaContext *ctx) {
	return SEQ2(
		SETL("sa", EXTRACT32(VARG("sar"), U32(0), U32(5))),
		SETG(REGN(0), UNSIGNED(32, SHIFTR0(APPEND(IREG(1), IREG(2)), VARL("sa")))));
}

static RzAnalysisLiftedILOp op_srl(XtensaContext *ctx) {
	return SEQ2(
		SETL("sa", EXTRACT32(VARG("sar"), U32(0), U32(5))),
		SETG(REGN(0), SHIFTR0(IREG(1), VARL("sa"))));
}

static RzAnalysisLiftedILOp op_srli(XtensaContext *ctx) {
	return SEQ2(
		SETL("sa", U32(IMM(2))),
		SETG(REGN(0), SHIFTR0(IREG(1), VARL("sa"))));
}

static RzAnalysisLiftedILOp op_ssa8l(XtensaContext *ctx) {
	return SETG("sar", SHIFTL0(EXTRACT32(IREG(0), U32(0), U32(2)), U32(3)));
}

static RzAnalysisLiftedILOp op_ssai(XtensaContext *ctx) {
	return SETG("sar", U32(IMM(0)));
}

static RzAnalysisLiftedILOp op_ssi(XtensaContext *ctx) {
	return SEQ2(
		SETL("vAddr", IMEM(1)),
		STOREW(VARL("vAddr"), UNSIGNED(32, IREG(0))));
}

static RzAnalysisLiftedILOp op_ssip(XtensaContext *ctx) {
	return SEQ3(
		SETL("vAddr", IREG(1)),
		STOREW(VARL("vAddr"), IREG(0)),
		SETG(REGN(1), U32(IMM(2))));
}

static RzAnalysisLiftedILOp op_ssl(XtensaContext *ctx) {
	return SEQ2(
		SETL("sa", UNSIGNED(5, IREG(0))),
		SETG("sar", SUB(U32(32), V32(VARL("sa")))));
}

static RzAnalysisLiftedILOp op_ssr(XtensaContext *ctx) {
	return SEQ2(
		SETL("sa", UNSIGNED(5, IREG(0))),
		SETG("sar", V32(VARL("sa"))));
}

static RzAnalysisLiftedILOp op_ssx(XtensaContext *ctx) {
	return SEQ2(
		SETL("vAddr", ADD(IREG(1), IREG(2))),
		STOREW(VARL("vAddr"), V32(IREG(0))));
}

static RzAnalysisLiftedILOp op_ssxp(XtensaContext *ctx) {
	return SEQ3(
		SETL("vAddr", IREG(1)),
		STOREW(VARL("vAddr"), V32(IREG(0))),
		SETG(REGN(1), ADD(VARL("vAddr"), IREG(2))));
}

static RzAnalysisLiftedILOp op_sub(XtensaContext *ctx) {
	return SETG(REGN(0), SUB(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_subx2(XtensaContext *ctx) {
	return SETG(REGN(0), SUB(SHIFTL0(IREG(1), U32(1)), IREG(2)));
}

static RzAnalysisLiftedILOp op_subx4(XtensaContext *ctx) {
	return SETG(REGN(0), SUB(SHIFTL0(IREG(1), U32(2)), IREG(2)));
}

static RzAnalysisLiftedILOp op_subx8(XtensaContext *ctx) {
	return SETG(REGN(0), SUB(SHIFTL0(IREG(1), U32(3)), IREG(2)));
}

// statusflags: VOI
static RzAnalysisLiftedILOp op_sub_s(XtensaContext *ctx) {
	return SEQ3(SETL("fres", FSUB(RZ_FLOAT_RMODE_RNA, FLOATV32(IREG(1)), FLOATV32(IREG(2)))),
		SETG(REGN(0), UNSIGNED(64, F2BV(VARL("fres")))),
		FSR_set(FSR_V | FSR_O | FSR_I, VARL("fres")));
}

static RzAnalysisLiftedILOp op_syscall(XtensaContext *ctx) {
	return NOP();
}

// statusflags: VI
static RzAnalysisLiftedILOp op_trunc_s(XtensaContext *ctx) {
	return SEQ3(SETL("fres", FMUL(RZ_FLOAT_RMODE_RNA, FLOATV32(IREG(1)), F32(pow(2, IMM(2))))),
		SETG(REGN(0), F2SINT(32, RZ_FLOAT_RMODE_RNA, VARL("fres"))),
		FSR_set(FSR_V | FSR_I, VARL("fres")));
}

// statusflags: V
static RzAnalysisLiftedILOp op_ueq_s(XtensaContext *ctx) {
	return f_bool_op2(ctx, rz_il_op_new_feq);
}

// statusflags: I
static RzAnalysisLiftedILOp op_ufloat_s(XtensaContext *ctx) {
	return SEQ3(
		SETL("fs", FMUL(RZ_FLOAT_RMODE_RNA, INT2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNA, IREG(1)), F32(pow(2, -IMM(IMM(2)))))),
		SETG(REGN(0), UNSIGNED(64, F2BV(VARL("fs")))),
		FSR_set(FSR_I, VARL("fs")));
}

// statusflags: V
static RzAnalysisLiftedILOp op_ule_s(XtensaContext *ctx) {
	return f_bool_op2(ctx, rz_il_op_new_fle);
}

// statusflags: V
static RzAnalysisLiftedILOp op_ult_s(XtensaContext *ctx) {
	return f_bool_op2(ctx, rz_il_op_new_flt);
}

static RzAnalysisLiftedILOp op_umul_aa(XtensaContext *ctx) {
	ut8 half = RRR_half(ctx);
	return SEQ3(
		SETG("m1", half & 0x1 ? HI16(IREG(0)) : LO16(IREG(0))),
		SETG("m2", half & 0x2 ? HI16(IREG(1)) : LO16(IREG(1))),
		ACC_set(MUL(V64(VARG("m1")), V64(VARG("m2")))));
}

// statusflags: V
static RzAnalysisLiftedILOp op_un_s(XtensaContext *ctx) {
	return SEQ2(SETG(REGN(0), OR(IS_FNAN(FLOATV32(IREG(1))), IS_FNAN(FLOATV32(IREG(2))))),
		FSR_field_set(FSR_V, B2U32(OR(IS_FNAN(FLOATV32(IREG(1))), IS_FNAN(FLOATV32(IREG(2)))))));
}

// statusflags: VI
static RzAnalysisLiftedILOp op_utrunc_s(XtensaContext *ctx) {
	return SEQ3(SETL("fres", FMUL(RZ_FLOAT_RMODE_RNA, FLOATV32(IREG(1)), F32(pow(2, IMM(2))))),
		SETG(REGN(0), F2INT(32, RZ_FLOAT_RMODE_RNA, VARL("fres"))),
		FSR_set(FSR_V | FSR_I, VARL("fres")));
}

// TODO: interrupt
static RzAnalysisLiftedILOp op_waiti(XtensaContext *ctx) {
	return NOP();
}

// TODO: datatlb
static RzAnalysisLiftedILOp op_wdtlb(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_wer(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_wfr(XtensaContext *ctx) {
	return SETG(REGN(0), V64(IREG(1)));
}

// TODO: datatlb
static RzAnalysisLiftedILOp op_witlb(XtensaContext *ctx) {
	return NOP();
}

static RzAnalysisLiftedILOp op_wsr(XtensaContext *ctx) {
	return SETG(REGN(0), IREG(1));
}

#define WUR_IMPL(S) \
	static RzAnalysisLiftedILOp op_wur_##S(XtensaContext *ctx) { \
		return SETG(#S, IREG(0)); \
	}
#define WUR_AE_IMPL(S) \
	static RzAnalysisLiftedILOp op_wur_ae_##S(XtensaContext *ctx) { \
		return SETG(#S, IREG(0)); \
	}

WUR_IMPL(accx_0);
WUR_IMPL(accx_1);
WUR_AE_IMPL(bithead);
WUR_AE_IMPL(bitptr);
WUR_AE_IMPL(bitsused);
WUR_AE_IMPL(cbegin0);
WUR_AE_IMPL(cend0);
WUR_AE_IMPL(cwrap);
WUR_AE_IMPL(cw_sd_no);
WUR_AE_IMPL(first_ts);
WUR_AE_IMPL(nextoffset);
WUR_AE_IMPL(overflow);
WUR_AE_IMPL(ovf_sar);
WUR_AE_IMPL(sar);
WUR_AE_IMPL(searchdone);
WUR_AE_IMPL(tablesize);
WUR_AE_IMPL(ts_fts_bu_bp);
WUR_IMPL(fcr);
WUR_IMPL(fft_bit_width);
WUR_IMPL(fsr);
WUR_IMPL(gpio_out);
WUR_IMPL(qacc_h_0);
WUR_IMPL(qacc_h_1);
WUR_IMPL(qacc_h_2);
WUR_IMPL(qacc_h_3);
WUR_IMPL(qacc_h_4);
WUR_IMPL(qacc_l_0);
WUR_IMPL(qacc_l_1);
WUR_IMPL(qacc_l_2);
WUR_IMPL(qacc_l_3);
WUR_IMPL(qacc_l_4);
WUR_IMPL(sar_byte);
WUR_IMPL(ua_state_0);
WUR_IMPL(ua_state_1);
WUR_IMPL(ua_state_2);
WUR_IMPL(ua_state_3);

static RzAnalysisLiftedILOp op_xor(XtensaContext *ctx) {
	return SETG(REGN(0), LOGXOR(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_xorb(XtensaContext *ctx) {
	return SETG(REGN(0), XOR(IREG(1), IREG(2)));
}

static RzAnalysisLiftedILOp op_xsr(XtensaContext *ctx) {
	return SEQ3(
		SETL("t0", IREG(0)),
		SETG(REGN(0), IREG(1)),
		SETG(REGN(1), VARL("t0")));
}

#include <rz_il/rz_il_opbuilder_end.h>

static const fn_analyze_op_il fn_tbl[] = {
	[XTENSA_INS_ABS] = op_abs,
	[XTENSA_INS_ABS_S] = op_abs_s,
	[XTENSA_INS_ADD] = op_add,
	[XTENSA_INS_ADD_N] = op_add,
	[XTENSA_INS_ADD_S] = op_add_s,
	[XTENSA_INS_ADDEXP_S] = op_addexp_s,
	[XTENSA_INS_ADDEXPM_S] = op_addexpm_s,
	[XTENSA_INS_ADDI] = op_addi,
	[XTENSA_INS_ADDI_N] = op_addi,
	[XTENSA_INS_ADDMI] = op_addi,
	[XTENSA_INS_ADDX2] = op_addx2,
	[XTENSA_INS_ADDX4] = op_addx4,
	[XTENSA_INS_ADDX8] = op_addx8,
	[XTENSA_INS_ALL4] = op_all4,
	[XTENSA_INS_ALL8] = op_all8,
	[XTENSA_INS_AND] = op_and,
	[XTENSA_INS_ANDB] = op_andb,
	[XTENSA_INS_ANDBC] = op_andbc,
	[XTENSA_INS_ANY4] = op_any4,
	[XTENSA_INS_ANY8] = op_any8,
	[XTENSA_INS_BALL] = op_ball,
	[XTENSA_INS_BNALL] = op_bnall,
	[XTENSA_INS_BANY] = op_bany,
	[XTENSA_INS_BNONE] = op_bnone,
	[XTENSA_INS_BBC] = op_bbc,
	[XTENSA_INS_BBS] = op_bbs,
	[XTENSA_INS_BBCI] = op_bbci,
	[XTENSA_INS_BBSI] = op_bbsi,
	[XTENSA_INS_BEQ] = op_beq,
	[XTENSA_INS_BNE] = op_bne,
	[XTENSA_INS_BEQI] = op_beqi,
	[XTENSA_INS_BNEI] = op_bnei,
	[XTENSA_INS_BEQZ] = op_beqz,
	[XTENSA_INS_BNEZ] = op_bnez,
	[XTENSA_INS_BF] = op_bf,
	[XTENSA_INS_BT] = op_bt,
	[XTENSA_INS_BGE] = op_bge,
	[XTENSA_INS_BLT] = op_blt,
	[XTENSA_INS_BGEI] = op_bgei,
	[XTENSA_INS_BLTI] = op_blti,
	[XTENSA_INS_BGEU] = op_bgeu,
	[XTENSA_INS_BLTU] = op_bltu,
	[XTENSA_INS_BGEUI] = op_bgeui,
	[XTENSA_INS_BLTUI] = op_bltui,
	[XTENSA_INS_BGEZ] = op_bgez,
	[XTENSA_INS_BLTZ] = op_bltz,
	[XTENSA_INS_BREAK] = op_break,
	[XTENSA_INS_BREAK_N] = op_break,
	[XTENSA_INS_CALL0] = op_call0,
	[XTENSA_INS_CALL4] = op_call4,
	[XTENSA_INS_CALL8] = op_call8,
	[XTENSA_INS_CALL12] = op_call12,
	[XTENSA_INS_CALLX0] = op_callx0,
	[XTENSA_INS_CALLX4] = op_callx4,
	[XTENSA_INS_CALLX8] = op_callx8,
	[XTENSA_INS_CALLX12] = op_callx12,
	[XTENSA_INS_CEIL_S] = op_ceil_s,
	[XTENSA_INS_CLAMPS] = op_clamps,
	[XTENSA_INS_CONST_S] = op_const_s,
	[XTENSA_INS_DIV0_S] = op_div0_s,
	[XTENSA_INS_DIVN_S] = op_divn_s,
	[XTENSA_INS_DSYNC] = op_dsync,
	[XTENSA_INS_ENTRY] = op_entry,
	[XTENSA_INS_ESYNC] = op_esync,
	[XTENSA_INS_EXCW] = op_excw,
	[XTENSA_INS_EXTUI] = op_extui,
	[XTENSA_INS_EXTW] = op_extw,
	[XTENSA_INS_FLOAT_S] = op_float_s,
	[XTENSA_INS_FLOOR_S] = op_floor_s,
	[XTENSA_INS_ISYNC] = op_isync,
	[XTENSA_INS_J] = op_j,
	[XTENSA_INS_JX] = op_jx,
	[XTENSA_INS_L8UI] = op_l8ui,
	[XTENSA_INS_L16SI] = op_l16si,
	[XTENSA_INS_L16UI] = op_l16ui,
	[XTENSA_INS_L32E] = op_l32e,
	[XTENSA_INS_L32I] = op_l32i,
	[XTENSA_INS_L32I_N] = op_l32i,
	[XTENSA_INS_L32R] = op_l32r,
	[XTENSA_INS_LDDEC] = op_lddec,
	[XTENSA_INS_LDINC] = op_ldinc,
	[XTENSA_INS_LOOP] = op_loop,
	[XTENSA_INS_LOOPGTZ] = op_loopgtz,
	[XTENSA_INS_LOOPNEZ] = op_loopnez,
	[XTENSA_INS_LSI] = op_lsi,
	[XTENSA_INS_LSIP] = op_lsip,
	[XTENSA_INS_LSX] = op_lsx,
	[XTENSA_INS_LSXP] = op_lsxp,
	[XTENSA_INS_MADD_S] = op_madd_s,
	[XTENSA_INS_MADDN_S] = op_madd_s,
	[XTENSA_INS_MAX] = op_max,
	[XTENSA_INS_MAXU] = op_maxu,
	[XTENSA_INS_MEMW] = op_memw,
	[XTENSA_INS_MIN] = op_min,
	[XTENSA_INS_MINU] = op_minu,
	[XTENSA_INS_MKDADJ_S] = op_mkdadj_s,
	[XTENSA_INS_MKSADJ_S] = op_mksadj_s,
	[XTENSA_INS_MOV_N] = op_mov,
	[XTENSA_INS_MOVEQZ] = op_moveqz,
	[XTENSA_INS_MOVEQZ_S] = op_moveqz,
	[XTENSA_INS_MOVF] = op_movf,
	[XTENSA_INS_MOVF_S] = op_movf,
	[XTENSA_INS_MOVGEZ] = op_movgez,
	[XTENSA_INS_MOVGEZ_S] = op_movgez,
	[XTENSA_INS_MOVI] = op_movi,
	[XTENSA_INS_MOVI_N] = op_movi,
	[XTENSA_INS_MOVLTZ] = op_movltz,
	[XTENSA_INS_MOVLTZ_S] = op_movltz,
	[XTENSA_INS_MOVNEZ] = op_movnez,
	[XTENSA_INS_MOVNEZ_S] = op_movnez,
	[XTENSA_INS_MOVSP] = op_movsp,
	[XTENSA_INS_MOVT] = op_movt,
	[XTENSA_INS_MOVT_S] = op_movt,
	[XTENSA_INS_MSUB_S] = op_msub_s,
	[XTENSA_INS_MUL_AA_LL] = op_mul_aa,
	[XTENSA_INS_MUL_AA_LH] = op_mul_aa,
	[XTENSA_INS_MUL_AA_HL] = op_mul_aa,
	[XTENSA_INS_MUL_AA_HH] = op_mul_aa,
	[XTENSA_INS_MUL_AD_LL] = op_mul_aa,
	[XTENSA_INS_MUL_AD_LH] = op_mul_aa,
	[XTENSA_INS_MUL_AD_HL] = op_mul_aa,
	[XTENSA_INS_MUL_AD_HH] = op_mul_aa,
	[XTENSA_INS_MUL_DD_LL] = op_mul_aa,
	[XTENSA_INS_MUL_DD_LH] = op_mul_aa,
	[XTENSA_INS_MUL_DD_HL] = op_mul_aa,
	[XTENSA_INS_MUL_DD_HH] = op_mul_aa,
	[XTENSA_INS_MUL_S] = op_mul_s,
	[XTENSA_INS_MUL16S] = op_mul16s,
	[XTENSA_INS_MUL16U] = op_mul16u,
	[XTENSA_INS_MULA_AA_LL] = op_mula_aa,
	[XTENSA_INS_MULA_AA_LH] = op_mula_aa,
	[XTENSA_INS_MULA_AA_HL] = op_mula_aa,
	[XTENSA_INS_MULA_AA_HH] = op_mula_aa,
	[XTENSA_INS_MULA_AD_LL] = op_mula_aa,
	[XTENSA_INS_MULA_AD_LH] = op_mula_aa,
	[XTENSA_INS_MULA_AD_HL] = op_mula_aa,
	[XTENSA_INS_MULA_AD_HH] = op_mula_aa,
	[XTENSA_INS_MULA_DA_LL] = op_mula_aa,
	[XTENSA_INS_MULA_DA_LH] = op_mula_aa,
	[XTENSA_INS_MULA_DA_HL] = op_mula_aa,
	[XTENSA_INS_MULA_DA_HH] = op_mula_aa,
	[XTENSA_INS_MULA_DD_LL] = op_mula_aa,
	[XTENSA_INS_MULA_DD_LH] = op_mula_aa,
	[XTENSA_INS_MULA_DD_HL] = op_mula_aa,
	[XTENSA_INS_MULA_DD_HH] = op_mula_aa,
	[XTENSA_INS_MULA_DA_LL_LDDEC] = op_mula_da_lddec,
	[XTENSA_INS_MULA_DA_LH_LDDEC] = op_mula_da_lddec,
	[XTENSA_INS_MULA_DA_HL_LDDEC] = op_mula_da_lddec,
	[XTENSA_INS_MULA_DA_HH_LDDEC] = op_mula_da_lddec,
	[XTENSA_INS_MULA_DA_LL_LDINC] = op_mula_da_ldinc,
	[XTENSA_INS_MULA_DA_LH_LDINC] = op_mula_da_ldinc,
	[XTENSA_INS_MULA_DA_HL_LDINC] = op_mula_da_ldinc,
	[XTENSA_INS_MULA_DA_HH_LDINC] = op_mula_da_ldinc,
	[XTENSA_INS_MULA_DD_LL_LDDEC] = op_mula_da_lddec,
	[XTENSA_INS_MULA_DD_LH_LDDEC] = op_mula_da_lddec,
	[XTENSA_INS_MULA_DD_HL_LDDEC] = op_mula_da_lddec,
	[XTENSA_INS_MULA_DD_HH_LDDEC] = op_mula_da_lddec,
	[XTENSA_INS_MULA_DD_LL_LDINC] = op_mula_da_ldinc,
	[XTENSA_INS_MULA_DD_LH_LDINC] = op_mula_da_ldinc,
	[XTENSA_INS_MULA_DD_HL_LDINC] = op_mula_da_ldinc,
	[XTENSA_INS_MULA_DD_HH_LDINC] = op_mula_da_ldinc,
	[XTENSA_INS_MULL] = op_mull,
	[XTENSA_INS_MULS_AA_LL] = op_muls_aa,
	[XTENSA_INS_MULS_AA_LH] = op_muls_aa,
	[XTENSA_INS_MULS_AA_HL] = op_muls_aa,
	[XTENSA_INS_MULS_AA_HH] = op_muls_aa,
	[XTENSA_INS_MULS_AD_LL] = op_muls_aa,
	[XTENSA_INS_MULS_AD_LH] = op_muls_aa,
	[XTENSA_INS_MULS_AD_HL] = op_muls_aa,
	[XTENSA_INS_MULS_AD_HH] = op_muls_aa,
	[XTENSA_INS_MULS_DA_LL] = op_muls_aa,
	[XTENSA_INS_MULS_DA_LH] = op_muls_aa,
	[XTENSA_INS_MULS_DA_HL] = op_muls_aa,
	[XTENSA_INS_MULS_DA_HH] = op_muls_aa,
	[XTENSA_INS_MULS_DD_LL] = op_muls_aa,
	[XTENSA_INS_MULS_DD_LH] = op_muls_aa,
	[XTENSA_INS_MULS_DD_HL] = op_muls_aa,
	[XTENSA_INS_MULS_DD_HH] = op_muls_aa,
	[XTENSA_INS_MULSH] = op_mulsh,
	[XTENSA_INS_MULUH] = op_muluh,
	[XTENSA_INS_NEG] = op_neg,
	[XTENSA_INS_NEG_S] = op_neg_s,
	[XTENSA_INS_NEXP01_S] = op_nexp01_s,
	[XTENSA_INS_NOP] = op_nop,
	[XTENSA_INS_NSA] = op_nsa,
	[XTENSA_INS_NSAU] = op_nsau,
	[XTENSA_INS_OEQ_S] = op_oeq_s,
	[XTENSA_INS_OLE_S] = op_ole_s,
	[XTENSA_INS_OLT_S] = op_olt_s,
	[XTENSA_INS_OR] = op_or,
	[XTENSA_INS_ORB] = op_orb,
	[XTENSA_INS_ORBC] = op_orbc,
	[XTENSA_INS_QUOS] = op_quos,
	[XTENSA_INS_QUOU] = op_quou,
	[XTENSA_INS_RECIP0_S] = op_recip0_s,
	[XTENSA_INS_REMS] = op_rems,
	[XTENSA_INS_REMU] = op_remu,
	[XTENSA_INS_RER] = op_nop,
	[XTENSA_INS_RET] = op_ret,
	[XTENSA_INS_RETW] = op_retw,
	[XTENSA_INS_RETW_N] = op_retw,
	[XTENSA_INS_RET_N] = op_ret,
	[XTENSA_INS_RFDE] = op_rfde,
	[XTENSA_INS_RFE] = op_rfe,
	[XTENSA_INS_RFI] = op_rfi,
	[XTENSA_INS_RFR] = op_rfr,
	[XTENSA_INS_RFWO] = op_rfwo,
	[XTENSA_INS_RFWU] = op_rfwu,
	[XTENSA_INS_ROTW] = op_rotw,
	[XTENSA_INS_ROUND_S] = op_round_s,
	[XTENSA_INS_RSIL] = op_rsil,
	[XTENSA_INS_RSQRT0_S] = op_rsqrt0_s,
	[XTENSA_INS_RSR] = op_rsr,
	[XTENSA_INS_RSYNC] = op_rsync,
	[XTENSA_INS_RUR_ACCX_0] = op_rur_accx_0,
	[XTENSA_INS_RUR_ACCX_1] = op_rur_accx_1,
	[XTENSA_INS_RUR_AE_BITHEAD] = op_rur_ae_bithead,
	[XTENSA_INS_RUR_AE_BITPTR] = op_rur_ae_bitptr,
	[XTENSA_INS_RUR_AE_BITSUSED] = op_rur_ae_bitsused,
	[XTENSA_INS_RUR_AE_CBEGIN0] = op_rur_ae_cbegin0,
	[XTENSA_INS_RUR_AE_CEND0] = op_rur_ae_cend0,
	[XTENSA_INS_RUR_AE_CWRAP] = op_rur_ae_cwrap,
	[XTENSA_INS_RUR_AE_CW_SD_NO] = op_rur_ae_cw_sd_no,
	[XTENSA_INS_RUR_AE_FIRST_TS] = op_rur_ae_first_ts,
	[XTENSA_INS_RUR_AE_NEXTOFFSET] = op_rur_ae_nextoffset,
	[XTENSA_INS_RUR_AE_OVERFLOW] = op_rur_ae_overflow,
	[XTENSA_INS_RUR_AE_OVF_SAR] = op_rur_ae_ovf_sar,
	[XTENSA_INS_RUR_AE_SAR] = op_rur_ae_sar,
	[XTENSA_INS_RUR_AE_SEARCHDONE] = op_rur_ae_searchdone,
	[XTENSA_INS_RUR_AE_TABLESIZE] = op_rur_ae_tablesize,
	[XTENSA_INS_RUR_AE_TS_FTS_BU_BP] = op_rur_ae_ts_fts_bu_bp,
	[XTENSA_INS_RUR_FFT_BIT_WIDTH] = op_rur_fft_bit_width,
	[XTENSA_INS_RUR_GPIO_OUT] = op_rur_gpio_out,
	[XTENSA_INS_RUR_QACC_H_0] = op_rur_qacc_h_0,
	[XTENSA_INS_RUR_QACC_H_1] = op_rur_qacc_h_1,
	[XTENSA_INS_RUR_QACC_H_2] = op_rur_qacc_h_2,
	[XTENSA_INS_RUR_QACC_H_3] = op_rur_qacc_h_3,
	[XTENSA_INS_RUR_QACC_H_4] = op_rur_qacc_h_4,
	[XTENSA_INS_RUR_QACC_L_0] = op_rur_qacc_l_0,
	[XTENSA_INS_RUR_QACC_L_1] = op_rur_qacc_l_1,
	[XTENSA_INS_RUR_QACC_L_2] = op_rur_qacc_l_2,
	[XTENSA_INS_RUR_QACC_L_3] = op_rur_qacc_l_3,
	[XTENSA_INS_RUR_QACC_L_4] = op_rur_qacc_l_4,
	[XTENSA_INS_RUR_SAR_BYTE] = op_rur_sar_byte,
	[XTENSA_INS_RUR_UA_STATE_0] = op_rur_ua_state_0,
	[XTENSA_INS_RUR_UA_STATE_1] = op_rur_ua_state_1,
	[XTENSA_INS_RUR_UA_STATE_2] = op_rur_ua_state_2,
	[XTENSA_INS_RUR_UA_STATE_3] = op_rur_ua_state_3,
	[XTENSA_INS_S16I] = op_s16i,
	[XTENSA_INS_S32C1I] = op_s32c1i,
	[XTENSA_INS_S32E] = op_s32e,
	[XTENSA_INS_S32I] = op_s32i,
	[XTENSA_INS_S32I_N] = op_s32i,
	[XTENSA_INS_S8I] = op_s8i,
	[XTENSA_INS_SEXT] = op_sext,
	[XTENSA_INS_SIMCALL] = op_simcall,
	[XTENSA_INS_SLL] = op_sll,
	[XTENSA_INS_SLLI] = op_slli,
	[XTENSA_INS_SQRT0_S] = op_sqrt0_s,
	[XTENSA_INS_SRA] = op_sra,
	[XTENSA_INS_SRAI] = op_srai,
	[XTENSA_INS_SRC] = op_src,
	[XTENSA_INS_SRL] = op_srl,
	[XTENSA_INS_SRLI] = op_srli,
	[XTENSA_INS_SSA8L] = op_ssa8l,
	[XTENSA_INS_SSAI] = op_ssai,
	[XTENSA_INS_SSI] = op_ssi,
	[XTENSA_INS_SSIP] = op_ssip,
	[XTENSA_INS_SSL] = op_ssl,
	[XTENSA_INS_SSR] = op_ssr,
	[XTENSA_INS_SSX] = op_ssx,
	[XTENSA_INS_SSXP] = op_ssxp,
	[XTENSA_INS_SUB] = op_sub,
	[XTENSA_INS_SUBX2] = op_subx2,
	[XTENSA_INS_SUBX4] = op_subx4,
	[XTENSA_INS_SUBX8] = op_subx8,
	[XTENSA_INS_SUB_S] = op_sub_s,
	[XTENSA_INS_SYSCALL] = op_syscall,
	[XTENSA_INS_TRUNC_S] = op_trunc_s,
	[XTENSA_INS_UEQ_S] = op_ueq_s,
	[XTENSA_INS_UFLOAT_S] = op_ufloat_s,
	[XTENSA_INS_ULE_S] = op_ule_s,
	[XTENSA_INS_ULT_S] = op_ult_s,
	[XTENSA_INS_UMUL_AA_HH] = op_umul_aa,
	[XTENSA_INS_UMUL_AA_HL] = op_umul_aa,
	[XTENSA_INS_UMUL_AA_LH] = op_umul_aa,
	[XTENSA_INS_UMUL_AA_LL] = op_umul_aa,
	[XTENSA_INS_UN_S] = op_un_s,
	[XTENSA_INS_UTRUNC_S] = op_utrunc_s,
	[XTENSA_INS_WAITI] = op_waiti,
	[XTENSA_INS_WDTLB] = op_wdtlb,
	[XTENSA_INS_WER] = op_wer,
	[XTENSA_INS_WFR] = op_wfr,
	[XTENSA_INS_WITLB] = op_witlb,
	[XTENSA_INS_WSR] = op_wsr,
	[XTENSA_INS_WUR_ACCX_0] = op_wur_accx_0,
	[XTENSA_INS_WUR_ACCX_1] = op_wur_accx_1,
	[XTENSA_INS_WUR_AE_BITHEAD] = op_wur_ae_bithead,
	[XTENSA_INS_WUR_AE_BITPTR] = op_wur_ae_bitptr,
	[XTENSA_INS_WUR_AE_BITSUSED] = op_wur_ae_bitsused,
	[XTENSA_INS_WUR_AE_CBEGIN0] = op_wur_ae_cbegin0,
	[XTENSA_INS_WUR_AE_CEND0] = op_wur_ae_cend0,
	[XTENSA_INS_WUR_AE_CWRAP] = op_wur_ae_cwrap,
	[XTENSA_INS_WUR_AE_CW_SD_NO] = op_wur_ae_cw_sd_no,
	[XTENSA_INS_WUR_AE_FIRST_TS] = op_wur_ae_first_ts,
	[XTENSA_INS_WUR_AE_NEXTOFFSET] = op_wur_ae_nextoffset,
	[XTENSA_INS_WUR_AE_OVERFLOW] = op_wur_ae_overflow,
	[XTENSA_INS_WUR_AE_OVF_SAR] = op_wur_ae_ovf_sar,
	[XTENSA_INS_WUR_AE_SAR] = op_wur_ae_sar,
	[XTENSA_INS_WUR_AE_SEARCHDONE] = op_wur_ae_searchdone,
	[XTENSA_INS_WUR_AE_TABLESIZE] = op_wur_ae_tablesize,
	[XTENSA_INS_WUR_AE_TS_FTS_BU_BP] = op_wur_ae_ts_fts_bu_bp,
	[XTENSA_INS_WUR_FCR] = op_wur_fcr,
	[XTENSA_INS_WUR_FFT_BIT_WIDTH] = op_wur_fft_bit_width,
	[XTENSA_INS_WUR_FSR] = op_wur_fsr,
	[XTENSA_INS_WUR_GPIO_OUT] = op_wur_gpio_out,
	[XTENSA_INS_WUR_QACC_H_0] = op_wur_qacc_h_0,
	[XTENSA_INS_WUR_QACC_H_1] = op_wur_qacc_h_1,
	[XTENSA_INS_WUR_QACC_H_2] = op_wur_qacc_h_2,
	[XTENSA_INS_WUR_QACC_H_3] = op_wur_qacc_h_3,
	[XTENSA_INS_WUR_QACC_H_4] = op_wur_qacc_h_4,
	[XTENSA_INS_WUR_QACC_L_0] = op_wur_qacc_l_0,
	[XTENSA_INS_WUR_QACC_L_1] = op_wur_qacc_l_1,
	[XTENSA_INS_WUR_QACC_L_2] = op_wur_qacc_l_2,
	[XTENSA_INS_WUR_QACC_L_3] = op_wur_qacc_l_3,
	[XTENSA_INS_WUR_QACC_L_4] = op_wur_qacc_l_4,
	[XTENSA_INS_WUR_SAR_BYTE] = op_wur_sar_byte,
	[XTENSA_INS_WUR_UA_STATE_0] = op_wur_ua_state_0,
	[XTENSA_INS_WUR_UA_STATE_1] = op_wur_ua_state_1,
	[XTENSA_INS_WUR_UA_STATE_2] = op_wur_ua_state_2,
	[XTENSA_INS_WUR_UA_STATE_3] = op_wur_ua_state_3,
	[XTENSA_INS_XOR] = op_xor,
	[XTENSA_INS_XORB] = op_xorb,
	[XTENSA_INS_XSR] = op_xsr,

	[XTENSA_INS__L32I] = op_l32i,
	[XTENSA_INS__L32I_N] = op_l32i,
	[XTENSA_INS__MOVI] = op_movi,
	[XTENSA_INS__S32I] = op_s32i,
	[XTENSA_INS__S32I_N] = op_s32i,
	[XTENSA_INS__SLLI] = op_slli,
	[XTENSA_INS__SRLI] = op_srli,
	[XTENSA_INS_MV_QR] = op_nop,
};

void xtensa_il_init_cb(RzAnalysisILVM *vm, RzReg *reg) {
	RzBuffer *buf = rz_buf_new_sparse(0);
	if (!buf) {
		return;
	}
	RzILMem *mem = rz_il_mem_new_owned(buf, 32);
	if (!mem) {
		rz_buf_free(buf);
		return;
	}
	rz_il_vm_add_mem(vm->vm, 1, mem);
}

RzAnalysisILConfig *xtensa_il_config(RzAnalysis *a) {
	rz_return_val_if_fail(a, NULL);

	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, a->big_endian, 32);
	if (!cfg) {
		return NULL;
	}
	cfg->init_state = rz_analysis_il_init_state_new();
	if (!cfg->init_state) {
		rz_analysis_il_config_free(cfg);
		return NULL;
	}
	cfg->init_state->cb = xtensa_il_init_cb;
	RzAnalysisILInitStateVar var = {
		.name = "ps",
		// WOE=1
		.val = rz_il_value_new_bitv(rz_bv_new_from_ut64(32, 1 << 18))
	};
	rz_vector_push(&cfg->init_state->vars, &var);
	return cfg;
}

void xtensa_analyze_op_rzil(XtensaContext *ctx, RzAnalysisOp *op) {
	unsigned id = ctx->insn->id;
	if (id >= RZ_ARRAY_SIZE(fn_tbl)) {
		return;
	}

	fn_analyze_op_il fn = fn_tbl[id];
	if (!fn) {
		return;
	}
	op->il_op = fn(ctx);
}
